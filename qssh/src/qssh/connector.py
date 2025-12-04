"""SSH connection handler for qssh."""

import os
import sys
import subprocess
import platform
from typing import Optional

from .session import Session


class SSHConnector:
    """Handles SSH connections to remote hosts."""
    
    def __init__(self):
        """Initialize SSH connector."""
        self.system = platform.system().lower()
    
    def connect(self, session: Session) -> int:
        """Connect to a session.
        
        Args:
            session: Session to connect to
            
        Returns:
            Exit code from SSH process
        """
        if session.auth_type == "key":
            return self._connect_with_key(session)
        else:
            return self._connect_with_password(session)
    
    def _connect_with_key(self, session: Session) -> int:
        """Connect using SSH key authentication.
        
        Args:
            session: Session configuration
            
        Returns:
            Exit code
        """
        key_path = os.path.expanduser(session.key_file) if session.key_file else None
        
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-p", str(session.port),
        ]
        
        if key_path:
            cmd.extend(["-i", key_path])
        
        cmd.append(f"{session.username}@{session.host}")
        
        return self._run_ssh(cmd)
    
    def _connect_with_password(self, session: Session) -> int:
        """Connect using password authentication.
        
        Uses sshpass if available, otherwise prompts for password.
        
        Args:
            session: Session configuration
            
        Returns:
            Exit code
        """
        password = session.get_password()
        
        # Check if sshpass is available for automatic password entry
        if password and self._has_sshpass():
            return self._connect_with_sshpass(session, password)
        
        # Fall back to regular SSH (will prompt for password if needed)
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-p", str(session.port),
            f"{session.username}@{session.host}",
        ]
        
        if password:
            # If we have a password but no sshpass, inform the user
            print(f"[qssh] Password stored. Copy it or install 'sshpass' for auto-login.")
            print(f"[qssh] Password: {password}")
            print()
        
        return self._run_ssh(cmd)
    
    def _connect_with_sshpass(self, session: Session, password: str) -> int:
        """Connect using sshpass for automatic password entry.
        
        Args:
            session: Session configuration
            password: Decoded password
            
        Returns:
            Exit code
        """
        cmd = [
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-p", str(session.port),
            f"{session.username}@{session.host}",
        ]
        
        return self._run_ssh(cmd)
    
    def _has_sshpass(self) -> bool:
        """Check if sshpass is available on the system."""
        try:
            subprocess.run(
                ["sshpass", "-V"],
                capture_output=True,
                check=False
            )
            return True
        except FileNotFoundError:
            return False
    
    def _run_ssh(self, cmd: list) -> int:
        """Run SSH command and return exit code.
        
        Args:
            cmd: Command to run
            
        Returns:
            Exit code
        """
        try:
            # Run SSH interactively
            result = subprocess.run(cmd)
            return result.returncode
        except FileNotFoundError:
            print("[qssh] Error: SSH client not found.")
            print("[qssh] Please ensure OpenSSH is installed and in your PATH.")
            if self.system == "windows":
                print("[qssh] On Windows, you can enable it in Settings > Apps > Optional Features")
            return 1
        except KeyboardInterrupt:
            print("\n[qssh] Connection interrupted.")
            return 130
