"""
DEFT Python SDK - Delta-Enabled File Transfer Client

Usage:
    from deft_client import DeftClient
    
    async with DeftClient("http://localhost:7752") as client:
        await client.connect("remote-server", "my-identity")
        await client.push("/path/to/file", "virtual-file-name")
"""

from .client import DeftClient, TransferPriority, TransferStatus
from .exceptions import DeftError, AuthenticationError, TransferError, ConnectionError

__version__ = "2.3.3"
__all__ = [
    "DeftClient",
    "TransferPriority", 
    "TransferStatus",
    "DeftError",
    "AuthenticationError",
    "TransferError",
    "ConnectionError",
]
