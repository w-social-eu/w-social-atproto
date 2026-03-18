"""
Admin commands for server management.
"""

import click
from ..api import PDSClient
from ..utils import console, print_success, print_error
from datetime import datetime


@click.group()
def admin():
    """Server administration commands."""
    pass


@admin.command("build-info")
@click.pass_context
def build_info(ctx):
    """Get PDS build information (version, build time, uptime)."""
    client: PDSClient = ctx.obj["client"]

    console.print("Fetching build information...")
    console.print()

    response = client.call("GET", "io.trustanchor.admin.getBuildInfo")

    if not response.success:
        print_error(f"Failed to fetch build info: {response.error}")
        raise click.Abort()

    if response.data is None:
        print_error("No data returned from API")
        raise click.Abort()

    info = response.data

    # Parse timestamps for display
    try:
        build_time = datetime.fromisoformat(info['buildTime'].replace('Z', '+00:00'))
        build_time_str = build_time.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        build_time_str = info['buildTime']

    try:
        started_at = datetime.fromisoformat(info['startedAt'].replace('Z', '+00:00'))
        started_at_str = started_at.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        started_at_str = info['startedAt']

    # Format uptime
    uptime_seconds = info['uptime']
    days = uptime_seconds // 86400
    hours = (uptime_seconds % 86400) // 3600
    minutes = (uptime_seconds % 3600) // 60
    seconds = uptime_seconds % 60

    if days > 0:
        uptime_str = f"{days}d {hours}h {minutes}m {seconds}s"
    elif hours > 0:
        uptime_str = f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        uptime_str = f"{minutes}m {seconds}s"
    else:
        uptime_str = f"{seconds}s"

    console.print("━" * 63)
    console.print("PDS Build Information", style="bold")
    console.print("━" * 63)
    console.print()
    console.print(f"  Build Hash:    {info['buildHash']}")
    console.print(f"  Build Time:    {build_time_str}")
    console.print(f"  Started At:    {started_at_str}")
    console.print(f"  Uptime:        {uptime_str}")
    console.print(f"  Node Version:  {info['nodeVersion']}")
    console.print()
