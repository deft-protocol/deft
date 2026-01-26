"""DEFT SDK Exceptions"""


class DeftError(Exception):
    """Base exception for DEFT client errors"""
    pass


class AuthenticationError(DeftError):
    """API key authentication failed"""
    pass


class ConnectionError(DeftError):
    """Failed to connect to DEFT server"""
    pass


class TransferError(DeftError):
    """Transfer operation failed"""
    
    def __init__(self, message: str, transfer_id: str = None):
        super().__init__(message)
        self.transfer_id = transfer_id


class ConfigurationError(DeftError):
    """Configuration error"""
    pass


class TimeoutError(DeftError):
    """Operation timed out"""
    pass
