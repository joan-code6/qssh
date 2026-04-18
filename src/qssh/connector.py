"""SSH connection handler for qssh."""

import os
import sys
import signal
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
        # On Windows, native OpenSSH provides the most reliable TUI key handling
        # for key-based sessions. Password sessions must use Paramiko so qssh can
        # supply the stored password non-interactively.
        if self.system == "windows" and session.auth_type == "key":
            native_exit = self._connect_with_system_ssh(session)
            if native_exit != 127:
                return native_exit

        if session.auth_type == "key":
            return self._connect_with_key_paramiko(session)
        else:
            return self._connect_with_paramiko(session)

    def _connect_with_system_ssh(self, session: Session) -> int:
        """Connect using the system ssh client.

        Returns 127 when ssh is not available so callers can fall back.
        """
        cmd = [
            "ssh",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-p", str(session.port),
        ]

        if session.auth_type == "key" and session.key_file:
            cmd.extend(["-i", os.path.expanduser(session.key_file)])

        cmd.append(f"{session.username}@{session.host}")

        try:
            return self._run_ssh(cmd)
        except FileNotFoundError:
            return 127
    
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
                    # Try different key types, but only include classes actually present
                    key_classes = []
                    for name in ("RSAKey", "Ed25519Key", "ECDSAKey", "DSSKey"):
                        cls = getattr(paramiko, name, None)
                        if cls is not None:
                            key_classes.append(cls)

                    for key_class in key_classes:
                        try:
                            pkey = key_class.from_private_key_file(key_path, password=passphrase)
                            break
                        except paramiko.SSHException:
                            continue
                except Exception as e:
                    print(f"[qssh] Error loading key: {e}")
                    return 1

            # If a key file was specified but we couldn't load a pkey, fail early
            if key_path and os.path.exists(key_path) and pkey is None:
                print(f"[qssh] Error loading key: unsupported key type or wrong passphrase for {key_path}")
                return 1
            
            # Connect with key
            # If no explicit pkey was loaded, allow Paramiko to look for keys and agent
            connect_kwargs = dict(
                hostname=session.host,
                port=session.port,
                username=session.username,
                pkey=pkey,
            )

            if pkey is None:
                connect_kwargs.update({
                    "look_for_keys": True,
                    "allow_agent": True,
                })
            else:
                connect_kwargs.update({
                    "look_for_keys": False,
                    "allow_agent": False,
                })

            client.connect(**connect_kwargs)
            
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
        import ctypes
        import msvcrt
        import time
        from ctypes import wintypes
        
        # Windows Console API constants
        STD_INPUT_HANDLE = -10
        ENABLE_PROCESSED_INPUT = 0x0001
        ENABLE_LINE_INPUT = 0x0002
        ENABLE_ECHO_INPUT = 0x0004
        ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200
        
        kernel32 = ctypes.windll.kernel32
        
        # Get console handle
        stdin_handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)
        
        # Save original console mode
        original_mode = wintypes.DWORD()
        kernel32.GetConsoleMode(stdin_handle, ctypes.byref(original_mode))
        
        # Set console to raw mode (disable line/echo for immediate key handling)
        new_mode = original_mode.value & ~(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)
        # Keep VT input disabled here; msvcrt returns stable key codes for arrows.
        new_mode &= ~ENABLE_VIRTUAL_TERMINAL_INPUT
        kernel32.SetConsoleMode(stdin_handle, new_mode)
        
        # Ignore SIGINT at Python level as backup
        original_sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
        
        running = [True]
        
        def read_output():
            """Read from channel and print to stdout."""
            while running[0]:
                try:
                    if channel.recv_ready():
                        data = channel.recv(4096)
                        if data:
                            sys.stdout.write(data.decode("utf-8", errors="replace"))
                            sys.stdout.flush()
                        else:
                            running[0] = False
                            break
                    
                    if channel.closed or channel.exit_status_ready():
                        running[0] = False
                        break
                        
                    time.sleep(0.01)
                except Exception:
                    running[0] = False
                    break
        
        # msvcrt special key map (after prefix \x00 or \xe0)
        special_map = {
            'H': b'\x1b[A',  # Up
            'P': b'\x1b[B',  # Down
            'M': b'\x1b[C',  # Right
            'K': b'\x1b[D',  # Left
            'G': b'\x1b[H',  # Home
            'O': b'\x1b[F',  # End
            'R': b'\x1b[2~', # Insert
            'S': b'\x1b[3~', # Delete
            'I': b'\x1b[5~', # Page Up
            'Q': b'\x1b[6~', # Page Down
            ';': b'\x1bOP',  # F1
            '<': b'\x1bOQ',  # F2
            '=': b'\x1bOR',  # F3
            '>': b'\x1bOS',  # F4
            '?': b'\x1b[15~',# F5
            '@': b'\x1b[17~',# F6
            'A': b'\x1b[18~',# F7
            'B': b'\x1b[19~',# F8
            'C': b'\x1b[20~',# F9
            'D': b'\x1b[21~',# F10
            '5': b'\x1b[23~',# F11
            '6': b'\x1b[24~',# F12
        }
        
        output_thread = threading.Thread(target=read_output, daemon=True)
        output_thread.start()
        
        try:
            while running[0] and not channel.closed:
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()

                    # Extended key prefix: next char identifies the key.
                    if ch in ('\x00', '\xe0'):
                        key = msvcrt.getwch()
                        seq = special_map.get(key)
                        if seq:
                            channel.sendall(seq)
                        continue

                    if ch == '\r':
                        channel.sendall(b'\r')
                    elif ch == '\x08':
                        channel.sendall(b'\x7f')
                    elif ch == '\x03':
                        channel.sendall(b'\x03')
                    elif ch == '\x1b':
                        channel.sendall(b'\x1b')
                    else:
                        channel.sendall(ch.encode('utf-8', errors='replace'))
                else:
                    time.sleep(0.01)
                    
        finally:
            running[0] = False
            output_thread.join(timeout=1.0)
            # Restore original console mode
            kernel32.SetConsoleMode(stdin_handle, original_mode.value)
            signal.signal(signal.SIGINT, original_sigint)
    
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
            return 127
        except KeyboardInterrupt:
            print("\n[qssh] Connection interrupted.")
            return 130
