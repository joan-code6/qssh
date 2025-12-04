"""SSH connection handler for qssh."""

import os
import sys
import select
import subprocess
import platform
from typing import Optional

import paramiko

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
            return self._connect_with_key_paramiko(session)
        else:
            return self._connect_with_paramiko(session)
    
    def _connect_with_key_paramiko(self, session: Session) -> int:
        """Connect using SSH key authentication via paramiko.
        
        Args:
            session: Session configuration
            
        Returns:
            Exit code
        """
        key_path = os.path.expanduser(session.key_file) if session.key_file else None
        passphrase = session.get_key_passphrase() if hasattr(session, 'get_key_passphrase') else None
        
        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Load the private key
            pkey = None
            if key_path and os.path.exists(key_path):
                try:
                    # Try different key types
                    for key_class in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]:
                        try:
                            pkey = key_class.from_private_key_file(key_path, password=passphrase)
                            break
                        except paramiko.SSHException:
                            continue
                except Exception as e:
                    print(f"[qssh] Error loading key: {e}")
                    return 1
            
            # Connect with key
            client.connect(
                hostname=session.host,
                port=session.port,
                username=session.username,
                pkey=pkey,
                look_for_keys=False,
                allow_agent=False,
            )
            
            # Start interactive shell
            self._interactive_shell(client)
            
            client.close()
            return 0
            
        except paramiko.AuthenticationException:
            print("[qssh] Authentication failed. Check your key or passphrase.")
            return 1
        except paramiko.SSHException as e:
            print(f"[qssh] SSH error: {e}")
            return 1
        except FileNotFoundError:
            print(f"[qssh] Key file not found: {key_path}")
            return 1
        except Exception as e:
            print(f"[qssh] Connection error: {e}")
            return 1
    
    def _connect_with_paramiko(self, session: Session) -> int:
        """Connect using paramiko for automatic password authentication.
        
        Args:
            session: Session configuration
            
        Returns:
            Exit code
        """
        password = session.get_password()
        
        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect with password
            client.connect(
                hostname=session.host,
                port=session.port,
                username=session.username,
                password=password,
                look_for_keys=False,
                allow_agent=False,
            )
            
            # Start interactive shell
            self._interactive_shell(client)
            
            client.close()
            return 0
            
        except paramiko.AuthenticationException:
            print("[qssh] Authentication failed. Check your password.")
            return 1
        except paramiko.SSHException as e:
            print(f"[qssh] SSH error: {e}")
            return 1
        except Exception as e:
            print(f"[qssh] Connection error: {e}")
            return 1
    
    def _interactive_shell(self, client: paramiko.SSHClient) -> None:
        """Start an interactive shell session.
        
        Args:
            client: Connected SSH client
        """
        # Get terminal size
        try:
            import shutil
            term_size = shutil.get_terminal_size()
            width, height = term_size.columns, term_size.lines
        except Exception:
            width, height = 80, 24
        
        # Request a pseudo-terminal
        channel = client.invoke_shell(
            term="xterm-256color",
            width=width,
            height=height,
        )
        
        # Make channel non-blocking
        channel.setblocking(0)
        
        if self.system == "windows":
            self._windows_interactive_shell(channel)
        else:
            self._unix_interactive_shell(channel)
    
    def _windows_interactive_shell(self, channel) -> None:
        """Interactive shell for Windows using threads.
        
        Args:
            channel: SSH channel
        """
        import threading
        import msvcrt
        
        running = True
        
        def read_output():
            """Read from channel and print to stdout."""
            while running:
                try:
                    if channel.recv_ready():
                        data = channel.recv(4096)
                        if data:
                            sys.stdout.write(data.decode("utf-8", errors="replace"))
                            sys.stdout.flush()
                        else:
                            break
                except Exception:
                    break
        
        # Start output reader thread
        output_thread = threading.Thread(target=read_output, daemon=True)
        output_thread.start()
        
        try:
            while running and not channel.closed:
                # Check for keyboard input
                if msvcrt.kbhit():
                    char = msvcrt.getwch()
                    if char == '\r':
                        channel.send('\n')
                    elif char == '\x03':  # Ctrl+C
                        channel.send('\x03')
                    elif char == '\x00' or char == '\xe0':  # Special keys
                        # Read the second byte for arrow keys etc.
                        char2 = msvcrt.getwch()
                        # Map arrow keys to ANSI escape sequences
                        key_map = {
                            'H': '\x1b[A',  # Up
                            'P': '\x1b[B',  # Down
                            'M': '\x1b[C',  # Right
                            'K': '\x1b[D',  # Left
                        }
                        if char2 in key_map:
                            channel.send(key_map[char2])
                    else:
                        channel.send(char)
                
                # Small delay to prevent CPU spinning
                if not channel.recv_ready():
                    import time
                    time.sleep(0.01)
                    
        except KeyboardInterrupt:
            pass
        finally:
            running = False
    
    def _unix_interactive_shell(self, channel) -> None:
        """Interactive shell for Unix systems using select.
        
        Args:
            channel: SSH channel
        """
        import tty
        import termios
        
        oldtty = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            channel.settimeout(0.0)
            
            while True:
                r, w, e = select.select([channel, sys.stdin], [], [])
                
                if channel in r:
                    try:
                        data = channel.recv(4096)
                        if len(data) == 0:
                            break
                        sys.stdout.write(data.decode("utf-8", errors="replace"))
                        sys.stdout.flush()
                    except Exception:
                        break
                
                if sys.stdin in r:
                    data = sys.stdin.read(1)
                    if len(data) == 0:
                        break
                    channel.send(data)
                    
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
    
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
