"""Session management for qssh."""

import os
import base64
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List

import yaml


@dataclass
class Session:
    """Represents an SSH session configuration."""
    
    name: str
    host: str
    username: str
    port: int = 22
    auth_type: str = "password"  # "password" or "key"
    password: Optional[str] = None  # base64 encoded
    key_file: Optional[str] = None
    key_passphrase: Optional[str] = None  # base64 encoded
    
    def to_dict(self) -> dict:
        """Convert session to dictionary for storage."""
        data = asdict(self)
        # Don't store None values
        return {k: v for k, v in data.items() if v is not None}
    
    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        """Create session from dictionary."""
        return cls(**data)
    
    def get_password(self) -> Optional[str]:
        """Decode and return the password."""
        if self.password:
            try:
                return base64.b64decode(self.password.encode()).decode()
            except Exception:
                return self.password
        return None
    
    def get_key_passphrase(self) -> Optional[str]:
        """Decode and return the key passphrase."""
        if self.key_passphrase:
            try:
                return base64.b64decode(self.key_passphrase.encode()).decode()
            except Exception:
                return self.key_passphrase
        return None
    
    @staticmethod
    def encode_password(password: str) -> str:
        """Encode password for storage."""
        return base64.b64encode(password.encode()).decode()


class SessionManager:
    """Manages SSH sessions storage and retrieval."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize session manager.
        
        Args:
            config_dir: Custom config directory. Defaults to ~/.qssh
        """
        if config_dir is None:
            config_dir = Path.home() / ".qssh"
        
        self.config_dir = config_dir
        self.sessions_file = config_dir / "sessions.yaml"
        self._ensure_config_dir()
    
    def _ensure_config_dir(self) -> None:
        """Create config directory if it doesn't exist."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Create sessions file if it doesn't exist
        if not self.sessions_file.exists():
            self._save_sessions({})
    
    def _load_sessions(self) -> Dict[str, dict]:
        """Load sessions from file."""
        if not self.sessions_file.exists():
            return {}
        
        with open(self.sessions_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data if data else {}
    
    def _save_sessions(self, sessions: Dict[str, dict]) -> None:
        """Save sessions to file."""
        with open(self.sessions_file, "w", encoding="utf-8") as f:
            yaml.dump(sessions, f, default_flow_style=False, sort_keys=False)
    
    def add(self, session: Session) -> None:
        """Add or update a session.
        
        Args:
            session: Session to add
        """
        sessions = self._load_sessions()
        sessions[session.name] = session.to_dict()
        self._save_sessions(sessions)
    
    def get(self, name: str) -> Optional[Session]:
        """Get a session by name.
        
        Args:
            name: Session name
            
        Returns:
            Session if found, None otherwise
        """
        sessions = self._load_sessions()
        if name in sessions:
            return Session.from_dict(sessions[name])
        return None
    
    def remove(self, name: str) -> bool:
        """Remove a session.
        
        Args:
            name: Session name
            
        Returns:
            True if removed, False if not found
        """
        sessions = self._load_sessions()
        if name in sessions:
            del sessions[name]
            self._save_sessions(sessions)
            return True
        return False
    
    def list_all(self) -> List[Session]:
        """List all sessions.
        
        Returns:
            List of all sessions
        """
        sessions = self._load_sessions()
        return [Session.from_dict(data) for data in sessions.values()]
    
    def exists(self, name: str) -> bool:
        """Check if session exists.
        
        Args:
            name: Session name
            
        Returns:
            True if exists
        """
        sessions = self._load_sessions()
        return name in sessions
    
    def get_config_path(self) -> Path:
        """Get the config directory path."""
        return self.config_dir
