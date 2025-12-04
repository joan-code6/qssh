# qssh

**Quick SSH session manager** - Save your VM credentials and connect with a single command.

Tired of copy-pasting credentials every time you want to SSH into your VMs? `qssh` lets you save your session configs and connect instantly.

## Installation

```bash
pip install qssh
```

## Quick Start

### 1. Add a new session

```bash
qssh add myserver
```

You'll be prompted for:
- Host (IP address or hostname)
- Username
- Port (default: 22)
- Authentication method (password or key file)

### 2. Connect to your VM

```bash
qssh myserver
```

That's it! You're connected.

## Commands

| Command | Description |
|---------|-------------|
| `qssh <session>` | Connect to a saved session |
| `qssh add <name>` | Add a new session |
| `qssh list` | List all saved sessions |
| `qssh remove <name>` | Remove a session |
| `qssh edit <name>` | Edit an existing session |
| `qssh show <name>` | Show session details |
| `qssh config` | Show config file location |

## Examples

```bash
# Add a session for your myserver VM
qssh add myserver
# Host: 192.168.1.100
# Username: admin
# Port [22]: 22
# Auth type (password/key) [password]: password
# Password: ********

# Now just connect with:
qssh myserver

# List all your sessions
qssh list

# Remove a session
qssh remove old-server

# Show details of a session
qssh show myserver
```

## Using SSH Keys

For key-based authentication:

```bash
qssh add myserver
# Host: example.com
# Username: deploy
# Port [22]: 22
# Auth type (password/key) [password]: key
# Key file path [~/.ssh/id_rsa]: ~/.ssh/my_key
# Key passphrase (leave empty if none): ********
```

Supported key types:
- RSA
- Ed25519
- ECDSA
- DSS

## Configuration

Sessions are stored in `~/.qssh/sessions.yaml`. Passwords and key passphrases are stored encoded (not plaintext) but for maximum security, consider using SSH keys without passphrases or with an SSH agent.

## License

MIT License
