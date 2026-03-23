"""
Account management commands.
"""

import click
from typing import Optional
from ..api import PDSClient
from ..config import Config
from ..utils import console, print_success, print_error


@click.group()
def account():
    """Account management commands."""
    pass


@account.command()
@click.argument("did")
@click.pass_context
def delete(ctx, did: str):
    """Delete account permanently (with confirmation)."""
    client: PDSClient = ctx.obj["client"]

    # Fetch account details first
    console.print("Fetching account details...")
    console.print()

    response = client.call("GET", "com.atproto.admin.getNeuroLink", params={"did": did})

    if not response.success:
        print_error("Failed to fetch account details", response.error or "Unknown error")
        raise click.Abort()

    if not response.data:
        print_error("Account not found", f"No account found for DID: {did}")
        raise click.Abort()

    account_info = response.data
    handle = account_info.get("handle") or "N/A"
    email = account_info.get("email") or "N/A"

    # Display account info
    console.print("Account to be deleted:")
    console.print("=" * 63)
    console.print(f"DID:     {did}")
    console.print(f"Handle:  {handle}")
    console.print(f"Email:   {email}")
    console.print()

    # Confirmation prompt
    console.print("⚠️  WARNING: This will PERMANENTLY delete the account and all associated data:")
    console.print("   - Account record")
    console.print("   - Actor record")
    console.print("   - Repository data")
    console.print("   - Email tokens")
    console.print("   - Refresh tokens")
    console.print("   - Neuro identity links (W ID)")
    console.print("   - All user data from sequencer")
    console.print()

    confirm_handle = click.prompt("Type the handle to confirm deletion", type=str)

    if confirm_handle != handle:
        print_error("Handle mismatch. Deletion cancelled.")
        raise click.Abort()

    console.print()
    console.print("Deleting account...")

    delete_response = client.call("POST", "com.atproto.admin.deleteAccount", data={"did": did})

    if not delete_response.success:
        print_error("Failed to delete account", delete_response.error or "Unknown error")
        raise click.Abort()

    print_success("Account deleted successfully")
    console.print(f"  DID: {did}")
    console.print(f"  Handle: {handle}")


@account.command()
@click.argument("did")
@click.argument("target_pds_url")
@click.option("--handle", default=None, help="New handle for the account on target PDS")
@click.pass_context
def rehome(ctx, did: str, target_pds_url: str, handle: Optional[str]):
    """Rehome account to another PDS in cluster."""
    client: PDSClient = ctx.obj["client"]

    console.print(f"Rehoming account: {did}")
    console.print(f"Target PDS: {target_pds_url}")
    if handle:
        console.print(f"New handle: {handle}")
    console.print()

    # Build request data
    data = {
        "did": did,
        "targetPdsUrl": target_pds_url,
    }
    if handle:
        data["targetHandle"] = handle

    response = client.call("POST", "com.atproto.admin.migrateAccount", data=data)

    if not response.success:
        print_error("Rehome failed", response.error or "Unknown error")
        raise click.Abort()

    if not response.data:
        print_error("No data returned from API")
        raise click.Abort()

    result = response.data

    print_success("Rehome completed!")
    console.print()
    console.print(f"  DID:           {result.get('did', 'N/A')}")
    console.print(f"  Source PDS:    {result.get('sourcePds', 'N/A')}")
    console.print(f"  Target PDS:    {result.get('targetPds', 'N/A')}")
    console.print(f"  Status:        {result.get('status', 'N/A')}")
    console.print(f"  Rehomed At:    {result.get('migratedAt', 'N/A')}")


@account.command("create-bot-account")
@click.argument("handle")
@click.option("--email", default=None, help="Email address for the bot account")
@click.pass_context
def create_bot_account(ctx, handle: str, email: Optional[str]):
    """Create a bot account (admin only). Bot accounts are for automated services."""
    client: PDSClient = ctx.obj["client"]

    # Build request body
    data = {"handle": handle}
    if email:
        data["email"] = email

    # Call PDS admin endpoint
    response = client.call("POST", "io.trustanchor.admin.createBotAccount", data=data)

    if not response.success:
        print_error("Failed to create bot account", response.error or "Unknown error")
        raise click.Abort()

    if not response.data:
        print_error("No data returned from API")
        raise click.Abort()

    result = response.data

    print_success("Bot Account Created")
    console.print()
    console.print(f"  Handle:   {result.get('handle', 'N/A')}")
    console.print(f"  DID:      {result.get('did', 'N/A')}")
    console.print(f"  Password: {result.get('appPassword', 'N/A')}")
    console.print()

    # Show deep link if available
    deep_link = result.get("deepLink")
    if deep_link:
        console.print("Deep Link:")
        console.print(f"  {deep_link}")
        console.print()
