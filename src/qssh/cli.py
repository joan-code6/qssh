"""Command-line interface for qssh."""

import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from . import __version__
from .session import Session, SessionManager
from .connector import SSHConnector


console = Console()
manager = SessionManager()
connector = SSHConnector()


class QSSHGroup(click.Group):
    """Custom group that treats unknown commands as session names."""
    
    def parse_args(self, ctx, args):
        # If we have args and the first arg is NOT a known command, 
        # treat it as a session name
        if args and args[0] not in self.commands:
            # Check if it looks like a flag
            if not args[0].startswith('-'):
                ctx.session_to_connect = args[0]
                args = args[1:]  # Remove the session name from args
        return super().parse_args(ctx, args)
    
    def invoke(self, ctx):
        # If we stored a session name, connect to it
        session_name = getattr(ctx, 'session_to_connect', None)
        if session_name:
            _connect(session_name)
            return
        
        return super().invoke(ctx)


@click.group(cls=QSSHGroup, invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show version")
@click.pass_context
def main(ctx, version: bool):
    """qssh - Quick SSH session manager.
    
    \b
    Connect to a saved session:
        qssh <session-name>
    
    \b
    Manage sessions:
        qssh add <name>      Add a new session
        qssh list            List all sessions
        qssh remove <name>   Remove a session
        qssh edit <name>     Edit a session
        qssh show <name>     Show session details
    """
    if version:
        console.print(f"[bold blue]qssh[/] version [green]{__version__}[/]")
        ctx.exit(0)
    
    # Show help if no subcommand and no session
    if ctx.invoked_subcommand is None and not getattr(ctx, 'session_to_connect', None):
        click.echo(ctx.get_help())


def _connect(name: str) -> None:
    """Connect to a session by name."""
    session = manager.get(name)
    
    if not session:
        console.print(f"[red]Session '[bold]{name}[/bold]' not found.[/]")
        console.print("\nAvailable sessions:")
        _list_sessions_simple()
        console.print(f"\n[dim]Use 'qssh add {name}' to create this session.[/]")
        sys.exit(1)
    
    console.print(f"[bold blue]Connecting to[/] [green]{name}[/] ({session.username}@{session.host}:{session.port})")
    console.print()
    
    exit_code = connector.connect(session)
    sys.exit(exit_code)


def _list_sessions_simple() -> None:
    """List sessions in a simple format."""
    sessions = manager.list_all()
    if not sessions:
        console.print("[dim]  No sessions saved yet.[/]")
        return
    
    for s in sessions:
        console.print(f"  • [cyan]{s.name}[/] → {s.username}@{s.host}")


@main.command("add")
@click.argument("name")
def add_session(name: str):
    """Add a new SSH session."""
    if manager.exists(name):
        if not Confirm.ask(f"Session '[bold]{name}[/]' already exists. Overwrite?"):
            console.print("[yellow]Cancelled.[/]")
            return
    
    console.print(Panel(f"[bold blue]Adding session:[/] [green]{name}[/]", expand=False))
    
    # Gather session info
    host = Prompt.ask("[bold]Host[/] (IP or hostname)")
    username = Prompt.ask("[bold]Username[/]")
    port = Prompt.ask("[bold]Port[/]", default="22")
    
    try:
        port = int(port)
    except ValueError:
        console.print("[red]Invalid port number. Using 22.[/]")
        port = 22
    
    auth_type = Prompt.ask(
        "[bold]Auth type[/]",
        choices=["password", "key"],
        default="password"
    )
    
    password = None
    key_file = None
    key_passphrase = None
    
    if auth_type == "password":
        password_raw = Prompt.ask("[bold]Password[/]", password=True)
        if password_raw:
            password = Session.encode_password(password_raw)
    else:
        key_file = Prompt.ask(
            "[bold]Key file path[/]",
            default="~/.ssh/id_rsa"
        )
        # Ask for passphrase (optional)
        passphrase_raw = Prompt.ask("[bold]Key passphrase[/] (leave empty if none)", password=True, default="")
        if passphrase_raw:
            key_passphrase = Session.encode_password(passphrase_raw)
    
    # Create and save session
    session = Session(
        name=name,
        host=host,
        username=username,
        port=port,
        auth_type=auth_type,
        password=password,
        key_file=key_file,
        key_passphrase=key_passphrase,
    )
    
    manager.add(session)
    console.print(f"\n[green]✓[/] Session '[bold]{name}[/]' saved!")
    console.print(f"[dim]Connect with: qssh {name}[/]")


@main.command("list", short_help="List all saved sessions")
def list_sessions():
    """List all saved sessions."""
    sessions = manager.list_all()
    
    if not sessions:
        console.print("[yellow]No sessions saved yet.[/]")
        console.print("[dim]Use 'qssh add <name>' to add one.[/]")
        return
    
    table = Table(title="SSH Sessions", show_header=True, header_style="bold blue")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Host", style="green")
    table.add_column("User", style="yellow")
    table.add_column("Port", justify="right")
    table.add_column("Auth", style="magenta")
    
    for session in sessions:
        auth_display = "🔑 key" if session.auth_type == "key" else "🔒 pass"
        table.add_row(
            session.name,
            session.host,
            session.username,
            str(session.port),
            auth_display,
        )
    
    console.print(table)


@main.command("remove")
@click.argument("name")
def remove_session(name: str):
    """Remove a saved session."""
    if not manager.exists(name):
        console.print(f"[red]Session '[bold]{name}[/bold]' not found.[/]")
        sys.exit(1)
    
    if Confirm.ask(f"Remove session '[bold]{name}[/]'?"):
        manager.remove(name)
        console.print(f"[green]✓[/] Session '[bold]{name}[/]' removed.")
    else:
        console.print("[yellow]Cancelled.[/]")


@main.command("edit")
@click.argument("name")
def edit_session(name: str):
    """Edit an existing session."""
    session = manager.get(name)
    
    if not session:
        console.print(f"[red]Session '[bold]{name}[/bold]' not found.[/]")
        sys.exit(1)
    
    console.print(Panel(f"[bold blue]Editing session:[/] [green]{name}[/]", expand=False))
    console.print("[dim]Press Enter to keep current value.[/]\n")
    
    # Gather updated info
    host = Prompt.ask("[bold]Host[/]", default=session.host)
    username = Prompt.ask("[bold]Username[/]", default=session.username)
    port = Prompt.ask("[bold]Port[/]", default=str(session.port))
    
    try:
        port = int(port)
    except ValueError:
        port = session.port
    
    auth_type = Prompt.ask(
        "[bold]Auth type[/]",
        choices=["password", "key"],
        default=session.auth_type
    )
    
    password = session.password
    key_file = session.key_file
    key_passphrase = getattr(session, 'key_passphrase', None)
    
    if auth_type == "password":
        if Confirm.ask("Update password?", default=False):
            password_raw = Prompt.ask("[bold]Password[/]", password=True)
            if password_raw:
                password = Session.encode_password(password_raw)
        key_file = None
        key_passphrase = None
    else:
        key_file = Prompt.ask(
            "[bold]Key file path[/]",
            default=session.key_file or "~/.ssh/id_rsa"
        )
        if Confirm.ask("Update key passphrase?", default=False):
            passphrase_raw = Prompt.ask("[bold]Key passphrase[/] (leave empty if none)", password=True, default="")
            if passphrase_raw:
                key_passphrase = Session.encode_password(passphrase_raw)
            else:
                key_passphrase = None
        password = None
    
    # Update session
    updated = Session(
        name=name,
        host=host,
        username=username,
        port=port,
        auth_type=auth_type,
        password=password,
        key_file=key_file,
        key_passphrase=key_passphrase,
    )
    
    manager.add(updated)
    console.print(f"\n[green]✓[/] Session '[bold]{name}[/]' updated!")


@main.command("show")
@click.argument("name")
def show_session(name: str):
    """Show details of a session."""
    session = manager.get(name)
    
    if not session:
        console.print(f"[red]Session '[bold]{name}[/bold]' not found.[/]")
        sys.exit(1)
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Property", style="bold blue")
    table.add_column("Value", style="green")
    
    table.add_row("Name", session.name)
    table.add_row("Host", session.host)
    table.add_row("Username", session.username)
    table.add_row("Port", str(session.port))
    table.add_row("Auth Type", session.auth_type)
    
    if session.auth_type == "key":
        table.add_row("Key File", session.key_file or "~/.ssh/id_rsa")
    else:
        table.add_row("Password", "••••••••" if session.password else "[dim]not set[/]")
    
    console.print(Panel(table, title=f"[bold]Session: {name}[/]", expand=False))
    console.print(f"\n[dim]Connect with: qssh {name}[/]")


@main.command("config")
def show_config():
    """Show configuration file location."""
    config_path = manager.get_config_path()
    console.print(f"[bold blue]Config directory:[/] [green]{config_path}[/]")
    console.print(f"[bold blue]Sessions file:[/]   [green]{config_path / 'sessions.yaml'}[/]")


if __name__ == "__main__":
    main()
