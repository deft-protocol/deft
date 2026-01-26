"""
Tests for DEFT Python SDK

Run with: pytest tests/
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from deft_client import DeftClient, TransferPriority, TransferStatus
from deft_client.client import Transfer, VirtualFile, DeftClientSync
from deft_client.exceptions import DeftError, AuthenticationError, TransferError


class TestTransferPriority:
    def test_priority_values(self):
        assert TransferPriority.URGENT.value == "urgent"
        assert TransferPriority.NORMAL.value == "normal"
        assert TransferPriority.BATCH.value == "batch"


class TestTransferStatus:
    def test_status_values(self):
        assert TransferStatus.ACTIVE.value == "active"
        assert TransferStatus.INTERRUPTED.value == "interrupted"
        assert TransferStatus.COMPLETE.value == "complete"
        assert TransferStatus.FAILED.value == "failed"


class TestTransfer:
    def test_from_dict(self):
        data = {
            "id": "txn_123",
            "virtual_file": "invoices",
            "partner_id": "partner-a",
            "direction": "send",
            "status": "active",
            "bytes_transferred": 1024,
            "total_bytes": 4096,
            "progress_percent": 25.0,
        }
        transfer = Transfer.from_dict(data)
        
        assert transfer.id == "txn_123"
        assert transfer.virtual_file == "invoices"
        assert transfer.status == TransferStatus.ACTIVE
        assert transfer.progress_percent == 25.0

    def test_from_dict_defaults(self):
        data = {"id": "txn_456", "status": "complete"}
        transfer = Transfer.from_dict(data)
        
        assert transfer.bytes_transferred == 0
        assert transfer.total_bytes == 0


class TestVirtualFile:
    def test_from_dict(self):
        data = {
            "name": "reports",
            "path": "/data/reports/",
            "direction": "receive",
            "partner_id": "partner-b",
        }
        vf = VirtualFile.from_dict(data)
        
        assert vf.name == "reports"
        assert vf.path == "/data/reports/"
        assert vf.direction == "receive"
        assert vf.partner_id == "partner-b"


class TestDeftClient:
    @pytest.fixture
    def client(self):
        return DeftClient(base_url="http://localhost:7752", api_key="test-key")

    def test_init_defaults(self):
        client = DeftClient()
        assert client.base_url == "http://127.0.0.1:7752"
        assert client._api_key is None

    def test_init_custom_url(self):
        client = DeftClient(base_url="http://custom:8080/")
        assert client.base_url == "http://custom:8080"  # trailing slash removed

    def test_headers_with_key(self, client):
        headers = client._headers()
        assert headers["Content-Type"] == "application/json"
        assert headers["X-API-Key"] == "test-key"

    def test_headers_without_key(self):
        client = DeftClient()
        headers = client._headers()
        assert "X-API-Key" not in headers

    @pytest.mark.asyncio
    async def test_context_manager(self):
        with patch.object(DeftClient, '_fetch_api_key', new_callable=AsyncMock):
            async with DeftClient(api_key="preset-key") as client:
                assert client._api_key == "preset-key"


class TestDeftClientRequests:
    @pytest.fixture
    def client(self):
        return DeftClient(base_url="http://localhost:7752", api_key="test-key")

    @pytest.mark.asyncio
    async def test_health(self, client):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"status": "ok"})
        
        with patch('aiohttp.ClientSession.request', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response))):
            await client._ensure_session()
            # Would need proper mocking for full test

    @pytest.mark.asyncio
    async def test_authentication_error(self, client):
        mock_response = MagicMock()
        mock_response.status = 401
        mock_response.json = AsyncMock(return_value={"error": "Invalid API key"})

        with patch('aiohttp.ClientSession.request', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response))):
            await client._ensure_session()
            with pytest.raises(AuthenticationError):
                await client._request("GET", "/api/status")


class TestExceptions:
    def test_deft_error(self):
        error = DeftError("Test error")
        assert str(error) == "Test error"

    def test_authentication_error(self):
        error = AuthenticationError("Invalid key")
        assert str(error) == "Invalid key"

    def test_transfer_error_with_id(self):
        error = TransferError("Transfer failed", transfer_id="txn_123")
        assert str(error) == "Transfer failed"
        assert error.transfer_id == "txn_123"


class TestDeftClientSync:
    def test_init(self):
        client = DeftClientSync(base_url="http://localhost:7752", api_key="test")
        assert client._async_client.base_url == "http://localhost:7752"
        client.close()


# Integration test placeholder (requires running DEFT daemon)
class TestIntegration:
    @pytest.mark.skip(reason="Requires running DEFT daemon")
    @pytest.mark.asyncio
    async def test_full_workflow(self):
        async with DeftClient("http://localhost:7752") as client:
            # Get status
            status = await client.status()
            assert "version" in status

            # List transfers
            transfers = await client.list_transfers()
            assert isinstance(transfers, list)

            # List virtual files
            vfiles = await client.list_virtual_files()
            assert isinstance(vfiles, list)
