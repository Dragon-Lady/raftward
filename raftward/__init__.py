"""Raft Ward: conservative, offline checks of closed data stores."""
from .api import API_VERSION, Result, gate, verify

__version__ = "0.1.2"

__all__ = ["API_VERSION", "Result", "gate", "verify", "__version__"]
