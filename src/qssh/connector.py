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
        import ctypes
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
        
        # Set console to raw mode (disable processed input to capture Ctrl+C)
        new_mode = original_mode.value & ~(ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)
        new_mode |= ENABLE_VIRTUAL_TERMINAL_INPUT
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
        
        # Structure for reading console input
        class KEY_EVENT_RECORD(ctypes.Structure):
            _fields_ = [
                ("bKeyDown", wintypes.BOOL),
                ("wRepeatCount", wintypes.WORD),
                ("wVirtualKeyCode", wintypes.WORD),
                ("wVirtualScanCode", wintypes.WORD),
                ("uChar", ctypes.c_wchar),
                ("dwControlKeyState", wintypes.DWORD),
            ]
        
        class INPUT_RECORD_UNION(ctypes.Union):
            _fields_ = [("KeyEvent", KEY_EVENT_RECORD)]
        
        class INPUT_RECORD(ctypes.Structure):
            _fields_ = [
                ("EventType", wintypes.WORD),
                ("Event", INPUT_RECORD_UNION),
            ]
        
        KEY_EVENT = 0x0001
        
        # Virtual key codes for special keys
        VK_MAP = {
            0x26: '\x1b[A',  # Up
            0x28: '\x1b[B',  # Down
            0x27: '\x1b[C',  # Right
            0x25: '\x1b[D',  # Left
            0x24: '\x1b[H',  # Home
            0x23: '\x1b[F',  # End
            0x2D: '\x1b[2~', # Insert
            0x2E: '\x1b[3~', # Delete
            0x21: '\x1b[5~', # Page Up
            0x22: '\x1b[6~', # Page Down
        }
        
        output_thread = threading.Thread(target=read_output, daemon=True)
        output_thread.start()
        
        try:
            input_record = INPUT_RECORD()
            events_read = wintypes.DWORD()
            
            while running[0] and not channel.closed:
                # Check if input is available
                events_available = wintypes.DWORD()
                kernel32.GetNumberOfConsoleInputEvents(stdin_handle, ctypes.byref(events_available))
                
                if events_available.value > 0:
                    # Read input event
                    kernel32.ReadConsoleInputW(
                        stdin_handle,
                        ctypes.byref(input_record),
                        1,
                        ctypes.byref(events_read)
                    )
                    
                    if input_record.EventType == KEY_EVENT:
                        key_event = input_record.Event.KeyEvent
                        
                        if key_event.bKeyDown:
                            vk = key_event.wVirtualKeyCode
                            char = key_event.uChar
                            
                            # Check for special keys
                            if vk in VK_MAP:
                                channel.send(VK_MAP[vk])
                            elif char == '\r':
                                channel.send('\r')
                            elif char == '\x08':  # Backspace
                                channel.send('\x7f')
                            elif char:
                                # Send character including control chars (Ctrl+C = \x03)
                                channel.send(char)
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
            return 1
        except KeyboardInterrupt:
            print("\n[qssh] Connection interrupted.")
            return 130
