"""
DEFT Python Client

Async client for interacting with DEFT daemon REST API.
"""

import asyncio
import aiohttp
from enum import Enum
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from pathlib import Path

from .exceptions import DeftError, AuthenticationError, TransferError, ConnectionError


class TransferPriority(Enum):
    """Transfer priority levels"""
    URGENT = "urgent"
    NORMAL = "normal"
    BATCH = "batch"


class TransferStatus(Enum):
    """Transfer status values"""
    ACTIVE = "active"
    INTERRUPTED = "interrupted"
    COMPLETE = "complete"
    FAILED = "failed"
    QUEUED = "queued"


@dataclass
class Transfer:
    """Transfer information"""
    id: str
    virtual_file: str
    partner_id: str
    direction: str
    status: TransferStatus
    bytes_transferred: int = 0
    total_bytes: int = 0
    progress_percent: float = 0.0

    @classmethod
    def from_dict(cls, data: dict) -> "Transfer":
        return cls(
            id=data.get("id", ""),
            virtual_file=data.get("virtual_file", ""),
            partner_id=data.get("partner_id", ""),
            direction=data.get("direction", ""),
            status=TransferStatus(data.get("status", "active")),
            bytes_transferred=data.get("bytes_transferred", 0),
            total_bytes=data.get("total_bytes", 0),
            progress_percent=data.get("progress_percent", 0.0),
        )


@dataclass
class VirtualFile:
    """Virtual file information"""
    name: str
    path: str
    direction: str
    partner_id: Optional[str] = None
    size: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict) -> "VirtualFile":
        return cls(
            name=data.get("name", ""),
            path=data.get("path", ""),
            direction=data.get("direction", ""),
            partner_id=data.get("partner_id"),
            size=data.get("size"),
        )


class DeftClient:
    """
    Async DEFT client for REST API interaction.
    
    Usage:
        async with DeftClient("http://localhost:7752") as client:
            await client.connect("server-name", "my-identity")
            result = await client.push("/path/to/file", "virtual-file")
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:7752",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None
        self._connected_server: Optional[str] = None

    async def __aenter__(self) -> "DeftClient":
        await self._ensure_session()
        if not self._api_key:
            await self._fetch_api_key()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def _ensure_session(self):
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=self._timeout)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _fetch_api_key(self):
        """Fetch API key from server (localhost only)"""
        try:
            async with self._session.get(f"{self.base_url}/api/auth/key") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self._api_key = data.get("api_key")
                elif resp.status == 403:
                    raise AuthenticationError("API key retrieval only allowed from localhost")
        except aiohttp.ClientError as e:
            raise ConnectionError(f"Failed to fetch API key: {e}")

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Make an authenticated request to the API"""
        await self._ensure_session()
        
        url = f"{self.base_url}{path}"
        headers = self._headers()

        try:
            async with self._session.request(
                method, url, json=json, headers=headers, **kwargs
            ) as resp:
                if resp.status == 401:
                    raise AuthenticationError("Invalid or missing API key")
                
                data = await resp.json()
                
                if resp.status >= 400:
                    error_msg = data.get("error", f"HTTP {resp.status}")
                    raise DeftError(error_msg)
                
                return data
        except aiohttp.ClientError as e:
            raise ConnectionError(f"Request failed: {e}")

    # ============ System ============

    async def health(self) -> Dict[str, Any]:
        """Check server health"""
        return await self._request("GET", "/api/health")

    async def status(self) -> Dict[str, Any]:
        """Get daemon status"""
        return await self._request("GET", "/api/status")

    async def metrics(self) -> Dict[str, Any]:
        """Get Prometheus metrics as JSON"""
        return await self._request("GET", "/api/metrics")

    # ============ Authentication ============

    async def rotate_key(self) -> str:
        """Rotate the API key and return the new key"""
        data = await self._request("POST", "/api/auth/rotate")
        self._api_key = data.get("api_key")
        return self._api_key

    # ============ Transfers ============

    async def list_transfers(self) -> List[Transfer]:
        """List active transfers"""
        data = await self._request("GET", "/api/transfers")
        return [Transfer.from_dict(t) for t in data]

    async def get_transfer(self, transfer_id: str) -> Transfer:
        """Get transfer details"""
        data = await self._request("GET", f"/api/transfers/{transfer_id}")
        return Transfer.from_dict(data)

    async def cancel_transfer(self, transfer_id: str) -> bool:
        """Cancel a transfer"""
        await self._request("DELETE", f"/api/transfers/{transfer_id}")
        return True

    async def pause_transfer(self, transfer_id: str) -> str:
        """Pause a transfer"""
        data = await self._request("POST", f"/api/transfers/{transfer_id}/interrupt")
        return data.get("status", "interrupted")

    async def resume_transfer(self, transfer_id: str) -> str:
        """Resume a paused transfer"""
        data = await self._request("POST", f"/api/transfers/{transfer_id}/resume")
        return data.get("status", "resumed")

    async def retry_transfer(self, transfer_id: str) -> Transfer:
        """Retry a failed transfer"""
        data = await self._request("POST", f"/api/transfers/{transfer_id}/retry")
        return Transfer.from_dict(data)

    async def history(self) -> List[Dict[str, Any]]:
        """Get transfer history"""
        return await self._request("GET", "/api/history")

    # ============ Client Operations ============

    async def connect(
        self,
        server_name: str,
        our_identity: str,
    ) -> List[VirtualFile]:
        """
        Connect to a remote DEFT server.
        
        Args:
            server_name: Name of the trusted server to connect to
            our_identity: Our partner ID for authentication
            
        Returns:
            List of available virtual files
        """
        data = await self._request("POST", "/api/client/connect", json={
            "server_name": server_name,
            "our_identity": our_identity,
        })
        
        if not data.get("success"):
            raise ConnectionError(f"Failed to connect: {data.get('error', 'Unknown error')}")
        
        self._connected_server = server_name
        vfiles = data.get("virtual_files", [])
        return [VirtualFile.from_dict(vf) for vf in vfiles]

    async def push(
        self,
        file_path: str,
        virtual_file: str,
        partner_id: Optional[str] = None,
        priority: TransferPriority = TransferPriority.NORMAL,
    ) -> Dict[str, Any]:
        """
        Push a file to the connected server.
        
        Args:
            file_path: Local path to the file to send
            virtual_file: Target virtual file name
            partner_id: Target partner ID (optional)
            priority: Transfer priority
            
        Returns:
            Transfer result with success status and transfer_id
        """
        payload = {
            "file_path": str(Path(file_path).resolve()),
            "virtual_file": virtual_file,
            "priority": priority.value,
        }
        if partner_id:
            payload["partner_id"] = partner_id

        data = await self._request("POST", "/api/client/push", json=payload)
        
        if not data.get("success"):
            raise TransferError(
                f"Push failed: {data.get('error', 'Unknown error')}",
                transfer_id=data.get("transfer_id"),
            )
        
        return data

    async def pull(
        self,
        virtual_file: str,
        output_path: str,
        priority: TransferPriority = TransferPriority.NORMAL,
    ) -> Dict[str, Any]:
        """
        Pull a file from the connected server.
        
        Args:
            virtual_file: Virtual file to download
            output_path: Local path to save the file
            priority: Transfer priority
            
        Returns:
            Transfer result with success status
        """
        payload = {
            "virtual_file": virtual_file,
            "output_path": str(Path(output_path).resolve()),
            "priority": priority.value,
        }

        data = await self._request("POST", "/api/client/pull", json=payload)
        
        if not data.get("success"):
            raise TransferError(
                f"Pull failed: {data.get('error', 'Unknown error')}",
                transfer_id=data.get("transfer_id"),
            )
        
        return data

    # ============ Virtual Files ============

    async def list_virtual_files(self) -> List[VirtualFile]:
        """List all virtual files"""
        data = await self._request("GET", "/api/virtual-files")
        return [VirtualFile.from_dict(vf) for vf in data]

    async def create_virtual_file(
        self,
        name: str,
        path: str,
        direction: str,
        partner_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new virtual file"""
        payload = {
            "name": name,
            "path": path,
            "direction": direction,
        }
        if partner_id:
            payload["partner_id"] = partner_id
        
        return await self._request("POST", "/api/virtual-files", json=payload)

    async def delete_virtual_file(self, name: str) -> bool:
        """Delete a virtual file"""
        await self._request("DELETE", f"/api/virtual-files/{name}")
        return True

    # ============ Partners ============

    async def list_partners(self) -> List[Dict[str, Any]]:
        """List all partners"""
        return await self._request("GET", "/api/partners")

    async def create_partner(
        self,
        partner_id: str,
        allowed_certs: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a new partner"""
        payload = {"id": partner_id}
        if allowed_certs:
            payload["allowed_certs"] = allowed_certs
        
        return await self._request("POST", "/api/partners", json=payload)

    async def delete_partner(self, partner_id: str) -> bool:
        """Delete a partner"""
        await self._request("DELETE", f"/api/partners/{partner_id}")
        return True

    # ============ Trusted Servers ============

    async def list_trusted_servers(self) -> List[Dict[str, Any]]:
        """List trusted servers"""
        return await self._request("GET", "/api/trusted-servers")

    async def add_trusted_server(
        self,
        name: str,
        address: str,
        cert_fingerprint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a trusted server"""
        payload = {"name": name, "address": address}
        if cert_fingerprint:
            payload["cert_fingerprint"] = cert_fingerprint
        
        return await self._request("POST", "/api/trusted-servers", json=payload)

    async def remove_trusted_server(self, name: str) -> bool:
        """Remove a trusted server"""
        await self._request("DELETE", f"/api/trusted-servers/{name}")
        return True


# Synchronous wrapper for non-async usage
class DeftClientSync:
    """
    Synchronous wrapper for DeftClient.
    
    Usage:
        client = DeftClientSync("http://localhost:7752")
        client.connect("server-name", "my-identity")
        client.push("/path/to/file", "virtual-file")
        client.close()
    """

    def __init__(self, *args, **kwargs):
        self._async_client = DeftClient(*args, **kwargs)
        self._loop = asyncio.new_event_loop()

    def _run(self, coro):
        return self._loop.run_until_complete(coro)

    def __enter__(self):
        self._run(self._async_client.__aenter__())
        return self

    def __exit__(self, *args):
        self._run(self._async_client.__aexit__(*args))

    def close(self):
        self._run(self._async_client.close())
        self._loop.close()

    def health(self):
        return self._run(self._async_client.health())

    def status(self):
        return self._run(self._async_client.status())

    def connect(self, server_name: str, our_identity: str):
        return self._run(self._async_client.connect(server_name, our_identity))

    def push(self, file_path: str, virtual_file: str, **kwargs):
        return self._run(self._async_client.push(file_path, virtual_file, **kwargs))

    def pull(self, virtual_file: str, output_path: str, **kwargs):
        return self._run(self._async_client.pull(virtual_file, output_path, **kwargs))

    def list_transfers(self):
        return self._run(self._async_client.list_transfers())

    def pause_transfer(self, transfer_id: str):
        return self._run(self._async_client.pause_transfer(transfer_id))

    def resume_transfer(self, transfer_id: str):
        return self._run(self._async_client.resume_transfer(transfer_id))
