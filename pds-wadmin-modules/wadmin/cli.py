"""
Main CLI application using Click framework.
"""

import os
import sys
import click
from pathlib import Path
from .config import Config
from .api import PDSClient
from .utils import console, print_error


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """
    W Social PDS Admin Tool

    Manage PDS instances, W IDs, invitations, and more.
    """
    # Show help if no command provided
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        return

    # Detect environment from script invocation
    script_name = Path(sys.argv[0]).name

    # Debug: Check environment variable
    env_script_name = os.getenv("WADMIN_SCRIPT_NAME")
    if env_script_name:
        script_name = env_script_name

    try:
        config = Config.from_environment(script_name)

        # Store config and client in context for subcommands
        ctx.ensure_object(dict)
        ctx.obj["config"] = config
        ctx.obj["client"] = PDSClient(config.pds_host, config.admin_password)

        # Show which environment we're using
        if config.environment:
            console.print(f"Using pds/{config.environment}", style="dim")
        else:
            console.print(f"Using {config.pds_host}", style="dim")

    except SystemExit:
        # Config already printed error message
        raise
    except Exception as e:
        print_error(str(e))
        sys.exit(1)


# Command groups will be registered here by importing them
# Phase 2 - Import WID commands
from .commands.wid import wid
cli.add_command(wid)

# Phase 3 - Import Invitation commands
from .commands.invitation import invitation
cli.add_command(invitation)

# Phase 4 - Import Account commands
from .commands.account import account
cli.add_command(account)

# Phase 4 - Import Nomad commands
from .commands.nomad import nomad
cli.add_command(nomad)


@cli.command()
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def goat(ctx, args):
    """
    Pass-through to external goat tool.

    Executes the goat binary with PDS environment variables set.
    """
    import shutil
    import os

    # Check if goat is available
    goat_path = shutil.which("goat")
    if not goat_path:
        print_error(
            "'goat' command not found in PATH",
            "Please install goat or ensure it is in your PATH"
        )
        sys.exit(1)

    # PDS environment variables are already set via config
    config = ctx.obj["config"]
    env = os.environ.copy()
    env["PDS_HOST"] = config.pds_host
    env["PDS_ADMIN_PASSWORD"] = config.admin_password

    # Execute goat with all arguments
    os.execvpe(goat_path, ["goat"] + list(args), env)


if __name__ == "__main__":
    cli()
