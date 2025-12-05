"""qssh - Quick SSH session manager."""

__version__ = "0.2.3"
__author__ = "bennet"

from .session import SessionManager
from .connector import SSHConnector

__all__ = ["SessionManager", "SSHConnector", "__version__"]
