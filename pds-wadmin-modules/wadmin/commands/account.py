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


@account.command("set-email")
@click.argument("did")
@click.argument("email")
@click.pass_context
def set_email(ctx, did: str, email: str):
    """Set the email address for an account."""
    client: PDSClient = ctx.obj["client"]

    response = client.call(
        "POST",
        "com.atproto.admin.updateAccountEmail",
        data={"account": did, "email": email},
    )

    if not response.success:
        print_error("Failed to update email", response.error or "Unknown error")
        raise click.Abort()

    print_success(f"Email updated")
    console.print(f"  DID:   {did}")
    console.print(f"  Email: {email}")


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


@account.command("set-main-password")
@click.argument("did_or_handle")
@click.option(
    "--password",
    default=None,
    help="New main password (prompted interactively if omitted)",
)
@click.option(
    "--no-password",
    "remove_password",
    is_flag=True,
    default=False,
    help="Remove the main password, reverting the account to WID-only authentication",
)
@click.pass_context
def set_main_password(ctx, did_or_handle: str, password: Optional[str], remove_password: bool):
    """Set (or remove) the main account password for a DID or handle (admin only).

    Setting a password enables login via https://<pds-host>/account/sign-in
    using the standard username + password form, bypassing WID QR authentication.

    Use --no-password to revert the account to WID-only authentication.

    All existing refresh tokens for the account are revoked in either case.
    """
    client: PDSClient = ctx.obj["client"]

    if remove_password and password is not None:
        print_error("Conflicting options", "Use either --password or --no-password, not both")
        raise click.Abort()

    # Resolve handle to DID if needed
    did = did_or_handle
    if not did_or_handle.startswith("did:"):
        resolve_response = client.call(
            "GET",
            "com.atproto.identity.resolveHandle",
            params={"handle": did_or_handle},
        )
        if not resolve_response.success or not resolve_response.data:
            print_error(
                "Failed to resolve handle",
                resolve_response.error or f"Handle not found: {did_or_handle}",
            )
            raise click.Abort()
        did = resolve_response.data.get("did")
        if not did:
            print_error("Failed to resolve handle", "No DID in response")
            raise click.Abort()
        console.print(f"  Resolved {did_or_handle} → {did}")
        console.print()

    if remove_password:
        data = {"did": did, "removePassword": True}
    else:
        # Prompt for password if not provided on the command line
        if password is None:
            password = click.prompt(
                "New main password",
                hide_input=True,
                confirmation_prompt="Confirm password",
            )
        if len(password) < 8:
            print_error("Password too short", "Must be at least 8 characters")
            raise click.Abort()
        data = {"did": did, "password": password}

    response = client.call(
        "POST",
        "io.trustanchor.admin.setAccountPassword",
        data=data,
    )

    if not response.success:
        print_error(
            "Failed to update password", response.error or "Unknown error"
        )
        raise click.Abort()

    if remove_password:
        print_success("Main password removed (WID-only auth restored)")
        console.print()
        console.print(f"  Account: {did}")
    else:
        print_success("Main password set")
        console.print()
        console.print(f"  Account: {did}")
        console.print()
        console.print(
            "  The account can now sign in at  [bold cyan]<pds-host>/account/sign-in[/bold cyan]"
        )
        console.print("  using the handle and the password you just set.")
    console.print()
    console.print(
        "  [yellow]Note:[/yellow] All existing refresh tokens for this account have been revoked."
    )


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


@account.command("subscribe-to-lists")
@click.argument("did")
@click.option("--list", "lists", multiple=True, required=True, help="AT-URI of list to subscribe to (can be specified multiple times)")
@click.pass_context
def subscribe_to_lists(ctx, did: str, lists: tuple):
    """Subscribe an account to one or more lists."""
    client: PDSClient = ctx.obj["client"]

    console.print(f"Subscribing account {did} to {len(lists)} list(s)...")
    console.print()

    # Build request body
    data = {
        "did": did,
        "lists": list(lists)  # Convert tuple to list
    }

    # Call PDS admin endpoint
    response = client.call("POST", "io.trustanchor.admin.subscribeToLists", data=data)

    if not response.success:
        print_error("Failed to subscribe to lists", response.error or "Unknown error")
        raise click.Abort()

    if not response.data:
        print_error("No data returned from API")
        raise click.Abort()

    result = response.data

    print_success("Subscription Complete")
    console.print()
    console.print(f"  Account:        {did}")
    console.print(f"  Lists Provided: {len(lists)}")
    console.print(f"  Subscribed:     {result.get('subscribedCount', 0)}")
    console.print()

    if lists:
        console.print("Lists:")
        for list_uri in lists:
            console.print(f"  • {list_uri}")


@account.command("set-thread-prefs")
@click.argument("did")
@click.option(
    "--layout",
    type=click.Choice(["threaded", "linear"], case_sensitive=False),
    required=True,
    help="Reply layout: threaded or linear",
)
@click.option(
    "--sort",
    type=click.Choice(
        ["oldest", "newest", "hotness", "most-likes", "random"], case_sensitive=False
    ),
    required=True,
    help="Reply sort order",
)
@click.pass_context
def set_thread_prefs(ctx, did: str, layout: str, sort: str):
    """Set thread view preferences for an account."""
    client: PDSClient = ctx.obj["client"]

    tree_view_enabled = layout.lower() == "threaded"

    console.print(
        f"Setting thread view preferences for account {did}...",
    )
    console.print()

    # Build request body
    data = {"did": did, "treeViewEnabled": tree_view_enabled, "sort": sort.lower()}

    # Call PDS admin endpoint
    response = client.call(
        "POST", "io.trustanchor.admin.setThreadViewPreferences", data=data
    )

    if not response.success:
        print_error(
            "Failed to set thread preferences", response.error or "Unknown error"
        )
        raise click.Abort()

    print_success("Thread Preferences Updated")
    console.print()
    console.print(f"  Account:      {did}")
    console.print(f"  Layout:       {layout} (lab_treeViewEnabled: {tree_view_enabled})")
    console.print(f"  Sort Order:   {sort}")
    console.print()

