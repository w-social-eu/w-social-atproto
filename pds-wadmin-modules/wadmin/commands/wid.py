"""WID (W ID) management commands."""

import json
import os
import re
import subprocess
from datetime import datetime
from typing import Optional

import click
from rich.console import Console
from tabulate import tabulate

from ..api import PDSClient
from ..config import Config
from ..utils import (
    console,
    format_timestamp,
    print_error,
    print_success,
    print_warning,
    print_info,
)


def exec_sqlite(config: Config, sql: str) -> str:
    """
    Execute SQL query in the PDS container via k8s (rancher kubectl exec) or
    Nomad alloc exec, depending on which is configured.

    Uses Node.js + better-sqlite3 inside the container.
    """
    # Build Node.js script (shared by both transports)
    import sys as _sys
    sql_json = json.dumps(sql)

    node_script = f"""
const path=require('path'),fs=require('fs');
const sql={sql_json};
const appRoot='/app';

// Resolve better-sqlite3
let DB;
const directPath=path.join(appRoot,'node_modules','better-sqlite3');
if(fs.existsSync(path.join(directPath,'package.json'))){{
  DB=require(directPath);
}} else {{
  try {{
    const pnpmStore=path.join(appRoot,'node_modules','.pnpm');
    const ent=fs.readdirSync(pnpmStore).find(e=>e.startsWith('better-sqlite3'));
    if(ent) DB=require(path.join(pnpmStore,ent,'node_modules','better-sqlite3'));
  }} catch(e) {{}}
}}
if(!DB){{
  for(const base of [appRoot, process.cwd()]){{
    try {{ DB=require(require.resolve('better-sqlite3',{{paths:[base]}})); break; }} catch(e) {{}}
  }}
}}
if(!DB){{ console.error('ERROR: better-sqlite3 not found in container'); process.exit(1); }}

let dbPath;
const d=process.env.PDS_DATA_DIRECTORY;
if(d){{dbPath=path.join(d,'account.sqlite');}}
else{{for(const p of['/data/account.sqlite','/var/run/account.sqlite','/var/run/pds/account.sqlite']){{if(fs.existsSync(p)){{dbPath=p;break;}}}}}}
if(!dbPath||!fs.existsSync(dbPath)){{console.error('ERROR: account.sqlite not found');process.exit(1);}}
const isWrite=/^\\s*(update|insert|delete|replace|create|drop|alter)\\b/i.test(sql);
const db=new DB(dbPath,{{readonly:!isWrite}});
if(isWrite){{
  const info=db.prepare(sql).run();
  db.close();
  console.log('Changes: '+info.changes);
}} else {{
  const rows=db.prepare(sql).all();
  db.close();
  if(rows.length===0){{console.log('(no rows)');process.exit(0);}}
  const cols=Object.keys(rows[0]);
  const widths=cols.map(c=>Math.max(c.length,...rows.map(r=>String(r[c]??'').length)));
  const fmt=r=>cols.map((c,i)=>String(r[c]??'').padEnd(widths[i])).join('  ');
  console.log(cols.map((c,i)=>c.padEnd(widths[i])).join('  '));
  console.log(widths.map(w=>'-'.repeat(w)).join('  '));
  rows.forEach(r=>console.log(fmt(r)));
}}
"""

    # Execute via k8s (preferred) or Nomad fallback
    if config.has_k8s_config():
        from .nomad import check_k8s_auth, run_kubectl
        from ..config import K8S_NAMESPACE, K8S_POD, K8S_CONTAINER
        kubeconfig = check_k8s_auth(config)
        result = run_kubectl(
            kubeconfig,
            ["-n", K8S_NAMESPACE, "exec", K8S_POD, "-c", K8S_CONTAINER,
             "--", "node", "-e", node_script],
            capture_output=True, text=True
        )
    elif config.has_nomad_config():
        from .nomad import check_nomad_auth
        nomad_addr, nomad_token = check_nomad_auth(config)
        job_name = config.nomad_job_name
        # Get running allocation ID
        status = subprocess.run(
            ["nomad", "status", job_name],
            env={**os.environ, "NOMAD_ADDR": nomad_addr, "NOMAD_TOKEN": nomad_token},
            capture_output=True, text=True
        )
        if status.returncode != 0:
            print_error("Failed to get Nomad job status")
            raise click.Abort()
        alloc_id = None
        for line in status.stdout.split('\n'):
            parts = line.split()
            if len(parts) > 0 and len(parts[0]) == 8:
                try:
                    int(parts[0], 16)
                    if "running" in line.lower():
                        alloc_id = parts[0]
                        break
                except ValueError:
                    continue
        if not alloc_id:
            print_error("No running allocation found", f"Job {job_name} has no running allocations")
            raise click.Abort()
        result = subprocess.run(
            ["nomad", "alloc", "exec", "-task", "pds", alloc_id, "node", "-e", node_script],
            env={**os.environ, "NOMAD_ADDR": nomad_addr, "NOMAD_TOKEN": nomad_token},
            capture_output=True, text=True
        )
    else:
        print_error(
            "Database commands require cluster access",
            "Use pds-wadmin-dev, pds-wadmin-stage, or pds-wadmin-prod"
        )
        raise click.Abort()

    if result.returncode != 0:
        print_error("SQLite query failed", result.stderr or "Unknown error")
        raise click.Abort()

    return result.stdout


@click.group()
def wid():
    """W ID account management commands."""
    pass


@wid.command(name="list")
@click.pass_context
def list_command(ctx):
    """List all W ID accounts."""
    client: PDSClient = ctx.obj["client"]

    # Call API to get neuro accounts
    response = client.call("GET", "com.atproto.admin.listNeuroAccounts", params={"limit": 1000})

    if not response.success:
        print_error(f"Failed to list accounts: {response.error}")
        raise click.Abort()

    if response.data is None:
        print_error("No data returned from API")
        raise click.Abort()

    accounts = response.data.get("accounts", [])

    if not accounts:
        print_info("No accounts found")
        return

    # Process accounts and normalize neuroLinks
    table_data = []
    for account in accounts:
        did = account.get("did", "")
        handle = account.get("handle", "?")
        email = account.get("email", "N/A")

        # Normalize neuroLinks - handle both array format and flat scalar format
        neuro_links = account.get("neuroLinks", [])
        if not isinstance(neuro_links, (list, tuple)):
            # Old API format with flat scalars
            neuro_links = [{
                "jid": account.get("jid"),
                "isTestUser": account.get("isTestUser", 0),
                "linkedAt": account.get("linkedAt"),
                "lastLoginAt": account.get("lastLoginAt"),
            }]

        # Check for duplicates
        has_duplicates = len(neuro_links) > 1

        # Process each neuro link
        for i, link in enumerate(neuro_links):
            jid = link.get("jid", "—")
            linked_at = link.get("linkedAt", "N/A")
            is_test = link.get("isTestUser", 0)

            # Format flags
            flags = []
            if is_test:
                flags.append("TEST")
            if has_duplicates:
                flags.append("DUP")

            flags_str = " ".join(flags) if flags else ""

            # For duplicate entries, only show DID/handle/email on first row
            if i == 0:
                table_data.append([did, handle, email, jid, linked_at, flags_str])
            else:
                table_data.append(["", "", "", jid, linked_at, flags_str])

    # Display table with column-specific colors for readability
    headers = ["DID", "HANDLE", "EMAIL", "JID", "LINKED_AT", "FLAGS"]

    # Print header
    header_parts = []
    header_parts.append(f"[bold cyan]{headers[0]}[/bold cyan]")       # DID - cyan
    header_parts.append(f"[bold green]{headers[1]}[/bold green]")     # HANDLE - green
    header_parts.append(f"[bold yellow]{headers[2]}[/bold yellow]")   # EMAIL - yellow
    header_parts.append(f"[bold magenta]{headers[3]}[/bold magenta]") # JID - magenta
    header_parts.append(f"[bold blue]{headers[4]}[/bold blue]")       # LINKED_AT - blue
    header_parts.append(f"[bold red]{headers[5]}[/bold red]")         # FLAGS - red

    # Use an unbounded-width console so each row is always a single line —
    # no wrapping, no truncation — making grep / piping work correctly.
    wide = Console(width=32000)
    wide.print("  ".join(header_parts), highlight=False)

    # Print rows with colors
    for row in table_data:
        row_parts = []
        row_parts.append(f"[cyan]{row[0]}[/cyan]")         # DID - cyan
        row_parts.append(f"[green]{row[1]}[/green]")       # HANDLE - green
        row_parts.append(f"[yellow]{row[2]}[/yellow]")     # EMAIL - yellow
        row_parts.append(f"[magenta]{row[3]}[/magenta]")   # JID - magenta
        row_parts.append(f"[blue]{row[4]}[/blue]")         # LINKED_AT - blue
        row_parts.append(f"[red]{row[5]}[/red]" if row[5] else "")  # FLAGS - red (only if present)

        wide.print("  ".join(row_parts), highlight=False)


@wid.command()
@click.argument("did")
@click.pass_context
def show(ctx, did: str):
    """Show detailed information for a specific W ID account."""
    client: PDSClient = ctx.obj["client"]

    response = client.call("GET", "com.atproto.admin.getNeuroLink", params={"did": did})

    if not response.success:
        print_error(f"Failed to fetch account details: {response.error}")
        raise click.Abort()

    if response.data is None:
        print_error("No data returned from API")
        raise click.Abort()

    data = response.data

    # Normalize neuroLinks - support both old and new API formats
    neuro_links = data.get("neuroLinks", [])
    if not isinstance(neuro_links, (list, tuple)):
        # Old API format with flat scalars
        neuro_links = [{
            "jid": data.get("jid"),
            "isTestUser": data.get("isTestUser", 0),
            "linkedAt": data.get("linkedAt"),
            "lastLoginAt": data.get("lastLoginAt"),
        }]

    has_duplicates = len(neuro_links) > 1

    # Display basic info
    console.print(f"\n[bold cyan]DID:[/bold cyan] {data.get('did', 'N/A')}")
    console.print(f"[bold cyan]Handle:[/bold cyan] {data.get('handle', 'N/A')}")
    console.print(f"[bold cyan]Email:[/bold cyan] {data.get('email', 'N/A')}")
    console.print(f"[bold cyan]Duplicate links:[/bold cyan] {has_duplicates}")

    # Display neuro links
    console.print(f"\n[bold cyan]Neuro links:[/bold cyan]")
    for link in neuro_links:
        jid = link.get("jid", "—")
        is_test = link.get("isTestUser", 0)
        linked_at = link.get("linkedAt", "N/A")
        last_login = link.get("lastLoginAt", "N/A")

        console.print(f"  [bold]JID (W ID):[/bold] {jid}")
        console.print(f"  [bold]Test user:[/bold] {is_test}")
        console.print(f"  [bold]Linked at:[/bold] {linked_at}")
        console.print(f"  [bold]Last login:[/bold] {last_login}")
        console.print()


@wid.command()
@click.argument("did")
@click.argument("new_jid")
@click.pass_context
def update(ctx, did: str, new_jid: str):
    """Update the W ID (JID) for an account."""
    client: PDSClient = ctx.obj["client"]

    # Validate JID format
    if "@auth" not in new_jid:
        print_error("Invalid JID format (must contain '@auth')")
        raise click.Abort()

    # Call API
    data = {
        "did": did,
        "newJid": new_jid
    }

    response = client.call("POST", "com.atproto.admin.updateNeuroLink", data=data)

    if not response.success:
        print_error(f"Failed to update W ID: {response.error}")
        raise click.Abort()

    if response.data is None:
        print_error("No data returned from API")
        raise click.Abort()

    result = response.data

    print_success("Success!")
    console.print(f"[bold]DID:[/bold] {result.get('did', 'N/A')}")
    console.print(f"[bold]Old W ID:[/bold] {result.get('oldJid', 'None')}")
    console.print(f"[bold]New W ID:[/bold] {result.get('newJid', 'N/A')}")
    console.print(f"[bold]Updated At:[/bold] {result.get('updatedAt', 'N/A')}")


@wid.command()
@click.argument("did1")
@click.argument("did2")
@click.pass_context
def swap(ctx, did1: str, did2: str):
    """Swap W IDs between two accounts."""
    client: PDSClient = ctx.obj["client"]

    if did1 == did2:
        print_error("Cannot swap a DID with itself")
        raise click.Abort()

    console.print("Fetching current JIDs...")

    # Get JID for did1
    response1 = client.call("GET", "com.atproto.admin.getNeuroLink", params={"did": did1})
    if not response1.success:
        print_error(f"Failed to fetch details for {did1}: {response1.error}")
        raise click.Abort()

    if response1.data is None:
        print_error(f"No data returned for {did1}")
        raise click.Abort()

    # Extract JID from response (handle both array and scalar formats)
    neuro_links1 = response1.data.get("neuroLinks", [])
    if not isinstance(neuro_links1, (list, tuple)):
        jid1 = response1.data.get("jid")
    else:
        jid1 = neuro_links1[0].get("jid") if neuro_links1 else None

    if not jid1:
        print_error(f"No JID found for {did1}")
        raise click.Abort()

    # Get JID for did2
    response2 = client.call("GET", "com.atproto.admin.getNeuroLink", params={"did": did2})
    if not response2.success:
        print_error(f"Failed to fetch details for {did2}: {response2.error}")
        raise click.Abort()

    if response2.data is None:
        print_error(f"No data returned for {did2}")
        raise click.Abort()

    # Extract JID from response (handle both array and scalar formats)
    neuro_links2 = response2.data.get("neuroLinks", [])
    if not isinstance(neuro_links2, (list, tuple)):
        jid2 = response2.data.get("jid")
    else:
        jid2 = neuro_links2[0].get("jid") if neuro_links2 else None

    if not jid2:
        print_error(f"No JID found for {did2}")
        raise click.Abort()

    console.print("\nCurrent state:")
    console.print(f"  {did1} → {jid1}")
    console.print(f"  {did2} → {jid2}")
    console.print("\nSwapping JIDs...")

    # Generate temporary JID
    timestamp = int(datetime.utcnow().timestamp())
    temp_jid = f"{jid1.split('@')[0]}-temp-{timestamp}@auth.wsocial.dev"

    # Step 1: Move did1 to temp JID
    console.print("  [1/3] Parking {} at temporary JID...".format(did1))
    response = client.call("POST", "com.atproto.admin.updateNeuroLink", data={"did": did1, "newJid": temp_jid})
    if not response.success:
        print_error(f"Failed to update {did1} to temporary JID: {response.error}")
        raise click.Abort()

    # Step 2: Move did2 to jid1
    console.print(f"  [2/3] Moving {did2} to {jid1}...")
    response = client.call("POST", "com.atproto.admin.updateNeuroLink", data={"did": did2, "newJid": jid1})
    if not response.success:
        print_error(f"Failed to update {did2} to {jid1}: {response.error}")
        print_warning(f"WARNING: {did1} is still at temporary JID {temp_jid}")
        console.print(f"To recover, run: pds-wadmin wid update {did1} {jid1}")
        raise click.Abort()

    # Step 3: Move did1 to jid2
    console.print(f"  [3/3] Moving {did1} to {jid2}...")
    response = client.call("POST", "com.atproto.admin.updateNeuroLink", data={"did": did1, "newJid": jid2})
    if not response.success:
        print_error(f"Failed to update {did1} to {jid2}: {response.error}")
        print_warning("WARNING: Swap is incomplete!")
        console.print(f"  {did1} is at: {temp_jid}")
        console.print(f"  {did2} is at: {jid1}")
        console.print("\nTo recover, run:")
        console.print(f"  pds-wadmin wid update {did1} {jid2}")
        raise click.Abort()

    console.print()
    print_success("Swap completed successfully!")
    console.print("New state:")
    console.print(f"  {did1} → {jid2}")
    console.print(f"  {did2} → {jid1}")


@wid.command()
@click.argument("did")
@click.argument("new_handle")
@click.pass_context
def handle(ctx, did: str, new_handle: str):
    """Update the handle for an account."""
    client: PDSClient = ctx.obj["client"]
    config: Config = ctx.obj["config"]

    # Validate handle format (basic check)
    if "." not in new_handle:
        print_error("Handle must contain at least one dot (e.g. ingmar.wsocial.eu)")
        raise click.Abort()

    console.print(f"Updating handle for {did}")
    console.print(f"  New handle: {new_handle}")
    console.print()

    data = {
        "did": did,
        "handle": new_handle
    }

    response = client.call("POST", "com.atproto.admin.updateAccountHandle", data=data)

    if not response.success:
        print_error(f"Failed to update handle: {response.error}")
        raise click.Abort()

    print_success(f"Handle updated to: {new_handle}")
    console.print("\nNext steps:")
    console.print(f"  1. Verify DNS TXT:  dig TXT _atproto.{new_handle} +short")
    console.print(f"  2. Verify well-known: curl https://{new_handle}/.well-known/atproto-did")
    console.print(f"  3. Verify resolve:  curl '{config.pds_host}/xrpc/com.atproto.identity.resolveHandle?handle={new_handle}'")


@wid.command("check-handle")
@click.argument("handle")
@click.pass_context
def check_handle(ctx, handle: str):
    """Check handle resolution across DNS, well-known, PDS, and AppView."""
    import requests

    client: PDSClient = ctx.obj["client"]
    config: Config = ctx.obj["config"]

    # Get AppView URL from config (fetched from Vault or env vars)
    appview_url = config.bsky_app_view_url

    console.print("═" * 63)
    console.print(f"Handle Resolution Check: {handle}")
    console.print("═" * 63)
    console.print()

    # 1. DNS TXT Record Check
    console.print("1️⃣  DNS TXT Record (_atproto.{})".format(handle))
    console.print("─" * 63)

    dns_did = None
    try:
        result = subprocess.run(
            ["dig", "TXT", f"_atproto.{handle}", "+short"],
            capture_output=True,
            text=True,
            timeout=10
        )
        dns_result = result.stdout.strip()

        if dns_result:
            console.print("✓ Found DNS TXT record:")
            for line in dns_result.split("\n"):
                console.print(f"  {line}")

            # Extract DID
            match = re.search(r'did:plc:[a-z0-9]+', dns_result)
            if match:
                dns_did = match.group(0)
                console.print(f"  Extracted DID: {dns_did}")
        else:
            console.print("✗ No DNS TXT record found")
    except Exception as e:
        console.print(f"✗ DNS query failed: {str(e)}")

    console.print()

    # 2. Well-Known HTTPS Check
    console.print("2️⃣  Well-Known HTTPS (https://{}/.well-known/atproto-did)".format(handle))
    console.print("─" * 63)

    wellknown_did = None
    try:
        response = requests.get(f"https://{handle}/.well-known/atproto-did", timeout=10)

        if response.status_code == 200:
            body = response.text.strip()
            console.print(f"✓ Well-known endpoint accessible (HTTP {response.status_code})")
            console.print(f"  Content: {body}")

            # Validate DID format
            if re.match(r'^did:plc:[a-z0-9]+$', body):
                console.print(f"  Valid DID format: {body}")
                wellknown_did = body
            else:
                console.print("  ⚠️  Response is not a valid DID")
        else:
            console.print(f"✗ Well-known endpoint failed (HTTP {response.status_code})")
            if response.text:
                console.print(f"  Error: {response.text[:200]}")
    except Exception as e:
        console.print(f"✗ Well-known endpoint not accessible: {str(e)}")

    console.print()

    # 3. PDS resolveHandle Check
    console.print("3️⃣  PDS resolveHandle ({}/xrpc/com.atproto.identity.resolveHandle)".format(config.pds_host))
    console.print("─" * 63)

    resolved_did = None
    try:
        response = requests.get(
            f"{config.pds_host}/xrpc/com.atproto.identity.resolveHandle",
            params={"handle": handle},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            if "did" in data:
                resolved_did = data["did"]
                console.print("✓ PDS resolved handle successfully")
                console.print(f"  Resolved DID: {resolved_did}")
            else:
                console.print("✗ PDS resolution failed - no DID in response")
        else:
            console.print("✗ PDS resolution failed")
            try:
                error_data = response.json()
                if "error" in error_data:
                    console.print(f"  Error: {error_data.get('message', error_data.get('error'))}")
            except:
                console.print(f"  HTTP {response.status_code}")
    except Exception as e:
        console.print(f"✗ PDS resolution failed: {str(e)}")

    console.print()

    # 4. AppView resolveHandle Check (if configured)
    appview_did = None
    if appview_url:
        console.print("4️⃣  AppView resolveHandle ({}/xrpc/com.atproto.identity.resolveHandle)".format(appview_url))
        console.print("─" * 63)

        try:
            response = requests.get(
                f"{appview_url}/xrpc/com.atproto.identity.resolveHandle",
                params={"handle": handle},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                if "did" in data:
                    appview_did = data["did"]
                    console.print("✓ AppView resolved handle successfully")
                    console.print(f"  Resolved DID: {appview_did}")
                else:
                    console.print("✗ AppView resolution failed - no DID in response")
            else:
                console.print("✗ AppView resolution failed")
                try:
                    error_data = response.json()
                    if "error" in error_data:
                        console.print(f"  Error: {error_data.get('message', error_data.get('error'))}")
                except:
                    console.print(f"  HTTP {response.status_code}")
        except Exception as e:
            console.print(f"✗ AppView resolution failed: {str(e)}")

        console.print()
    else:
        console.print("4️⃣  AppView resolveHandle")
        console.print("─" * 63)
        console.print("⊘ Skipped (BSKY_APP_VIEW_URL not configured)")
        console.print()

    # 5. PLC Directory DID Document Check
    console.print("5️⃣  PLC Directory DID Document (https://plc.directory/{did})")
    console.print("─" * 63)

    plc_handle = None
    plc_did = dns_did or wellknown_did or resolved_did or appview_did

    if plc_did:
        try:
            response = requests.get(f"https://plc.directory/{plc_did}", timeout=10)

            if response.status_code == 200:
                did_doc = response.json()
                console.print(f"✓ PLC DID document retrieved for {plc_did}")

                # Check alsoKnownAs for handle
                also_known_as = did_doc.get("alsoKnownAs", [])
                if also_known_as:
                    console.print(f"  alsoKnownAs: {also_known_as}")

                    # Check if our handle is in the alsoKnownAs list
                    handle_uri = f"at://{handle}"
                    if handle_uri in also_known_as:
                        plc_handle = handle
                        console.print(f"  ✓ Handle '{handle}' is claimed in DID document")
                    else:
                        console.print(f"  ✗ Handle '{handle}' NOT found in alsoKnownAs")
                        console.print(f"     Expected: {handle_uri}")
                else:
                    console.print("  ⚠️  No alsoKnownAs field in DID document")
            else:
                console.print(f"✗ PLC DID document fetch failed (HTTP {response.status_code})")
        except Exception as e:
            console.print(f"✗ PLC DID document fetch failed: {str(e)}")
    else:
        console.print("⊘ Skipped (no DID available from previous checks)")

    console.print()

    # 6. Summary
    console.print("═" * 63)
    console.print("Summary")
    console.print("═" * 63)

    # Check if handle verification methods are present
    handle_method_ok = bool(dns_did or wellknown_did)
    has_both = bool(dns_did and wellknown_did)

    # Check if all required checks passed (now including PLC)
    all_required_passed = handle_method_ok and resolved_did and plc_handle

    # If AppView was checked, require it too
    all_checks_passed = all_required_passed
    if appview_url:
        all_checks_passed = all_required_passed and bool(appview_did)

    if all_checks_passed:
        console.print("Status: ✓ All checks passed")
        console.print()

        # Determine reference DID
        reference_did = dns_did or wellknown_did

        # Check if all DIDs match
        all_match = True
        if dns_did and dns_did != reference_did:
            all_match = False
        if wellknown_did and wellknown_did != reference_did:
            all_match = False
        if resolved_did != reference_did:
            all_match = False
        if appview_did and appview_did != reference_did:
            all_match = False

        if all_match:
            console.print("DID Consistency: ✓ All methods return same DID")
            console.print(f"  DID: {reference_did}")
            if plc_handle:
                console.print(f"  PLC Handle Claim: ✓ {handle}")

            if has_both:
                console.print()
                console.print("⚠️  Note: Both DNS TXT and well-known are configured")
                console.print("    This is unusual - typically handles use one method or the other")
        else:
            console.print("DID Consistency: ✗ MISMATCH DETECTED")
            if dns_did:
                console.print(f"  DNS TXT:      {dns_did}")
            if wellknown_did:
                console.print(f"  Well-Known:   {wellknown_did}")
            console.print(f"  PDS Resolve:  {resolved_did or 'N/A'}")
            if appview_url:
                console.print(f"  AppView:      {appview_did or 'N/A'}")
            if plc_did:
                console.print(f"  PLC DID:      {plc_did}")
                console.print(f"  PLC Handle:   {'✗ NOT CLAIMED' if not plc_handle else '✓ Claimed'}")
    else:
        console.print("Status: ✗ Some checks failed")
        console.print()
        console.print("Results:")

        if dns_did:
            console.print(f"  DNS TXT:      ✓ {dns_did}")
        elif wellknown_did:
            console.print("  DNS TXT:      ⊘ Not used (well-known configured instead)")
        else:
            console.print("  DNS TXT:      ✗ Not found")

        if wellknown_did:
            console.print(f"  Well-Known:   ✓ {wellknown_did}")
        elif dns_did:
            console.print("  Well-Known:   ⊘ Not used (DNS TXT configured instead)")
        else:
            console.print("  Well-Known:   ✗ Not accessible")

        console.print(f"  PDS Resolve:  {'✓ ' + resolved_did if resolved_did else '✗ Failed'}")

        if appview_url:
            console.print(f"  AppView:      {'✓ ' + appview_did if appview_did else '✗ Failed'}")
        else:
            console.print("  AppView:      ⊘ Skipped (not configured)")

        console.print(f"  PLC Handle:   {'✓ Claimed' if plc_handle else '✗ Not claimed or not checked'}")

        if has_both:
            console.print()
            console.print("⚠️  Note: Both DNS TXT and well-known are configured")
            console.print("    This is unusual - typically handles use one method or the other")

        console.print()
        console.print("Troubleshooting:")
        if not handle_method_ok:
            console.print("  • No handle verification method found - need either:")
            console.print(f"    - DNS TXT record at _atproto.{handle}, OR")
            console.print(f"    - HTTPS endpoint at https://{handle}/.well-known/atproto-did")
        if not resolved_did:
            console.print("  • PDS cannot resolve handle - may need to refresh identity cache")
        if appview_url and not appview_did:
            console.print("  • AppView cannot resolve handle - account may not be indexed yet")
            console.print("    (AppView syncs from PDS; check if account creation was recent)")
        if not plc_handle:
            console.print("  • PLC DID document doesn't claim this handle")
            console.print("    Try re-setting the handle to trigger PLC update:")
            console.print(f"    ./pds-wadmin-{config.environment or 'dev'} wid handle <did> {handle}")

    console.print("═" * 63)


@wid.group()
def inventory():
    """W ID account inventory management."""
    pass


@inventory.command()
@click.argument("json_file", type=click.Path(exists=True))
@click.pass_context
def load(ctx, json_file: str):
    """Load W ID account inventory from CreatedAccounts.json."""
    client: PDSClient = ctx.obj["client"]

    console.print("═" * 63)
    console.print("Loading WID Account Inventory")
    console.print("═" * 63)
    console.print()
    console.print(f"📄 Reading: {json_file}")

    # Read and parse JSON file
    try:
        with open(json_file, 'r') as f:
            inventory_data = json.load(f)
    except Exception as e:
        print_error(f"Failed to read JSON file: {str(e)}")
        raise click.Abort()

    # Transform to API format
    records = inventory_data.get("Records", [])
    request_data = {
        "accounts": [
            {
                "did": record["UserName"],
                "onboardingUrl": record["OnboardingUrl"],
                "qrCodeUrl": record["QrCodeUrl"],
                **({"preferredHandle": record["PreferredHandle"]} if "PreferredHandle" in record else {})
            }
            for record in records
        ],
        "batchName": f"batch-{inventory_data.get('Created', int(datetime.utcnow().timestamp()))}"
    }

    account_count = len(request_data["accounts"])
    console.print(f"📊 Accounts to load: {account_count}")
    console.print()
    console.print("Uploading to PDS...")

    # Call API
    response = client.call("POST", "io.trustanchor.admin.loadInventory", data=request_data)

    if not response.success:
        print_error(f"Failed to load inventory: {response.error}")
        raise click.Abort()

    if response.data is None:
        print_error("No data returned from API")
        raise click.Abort()

    result = response.data
    loaded = result.get("loaded", 0)
    skipped = result.get("skipped", 0)
    total = result.get("total", 0)

    console.print()
    print_success("Import complete!")
    console.print("━" * 63)
    console.print(f"   Loaded:  {loaded}")
    console.print(f"   Skipped: {skipped} (duplicates)")
    console.print(f"   Total:   {total}")


@inventory.command()
@click.pass_context
def status(ctx):
    """Show W ID account inventory status."""
    client: PDSClient = ctx.obj["client"]

    console.print("═" * 63)
    console.print("WID Account Inventory Status")
    console.print("═" * 63)
    console.print()
    console.print("Querying PDS...")

    response = client.call("GET", "io.trustanchor.admin.getInventoryStatus")

    if not response.success:
        print_error(f"Failed to get inventory status: {response.error}")
        raise click.Abort()

    if response.data is None:
        print_error("No data returned from API")
        raise click.Abort()

    result = response.data
    available = result.get("available", 0)
    allocated = result.get("allocated", 0)
    consumed = result.get("consumed", 0)
    total = result.get("total", 0)

    console.print(f"📦 Available:  {available}  (ready to allocate)")
    console.print(f"🔒 Allocated:  {allocated}  (assigned to invitations)")
    console.print(f"✓ Consumed:   {consumed}  (activated accounts)")
    console.print("━" * 63)
    console.print(f"📊 Total:      {total}")
    console.print()

    # Show warning if inventory is low
    if available < 100:
        console.print("⚠️  WARNING: Inventory is low (< 100 available)")
        console.print("   Consider loading more accounts")
    elif available < 500:
        console.print("ℹ️  NOTICE: Inventory is below recommended threshold (< 500)")
    else:
        console.print("✅ Inventory levels are healthy")


@inventory.command(name="list")
@click.option("--status", default="available", help="Filter by status (available, allocated, consumed, all)")
@click.option("--limit", default=100, type=int, help="Maximum number of results")
@click.pass_context
def inventory_list(ctx, status: str, limit: int):
    """List W ID accounts in inventory with optional status filter."""
    config: Config = ctx.obj["config"]

    # Build SQL query based on status filter
    if status == "all":
        where_clause = ""
    elif status in ("available", "allocated", "consumed"):
        where_clause = f"WHERE status = '{status}'"
    else:
        print_error(f"Invalid status: {status}. Must be one of: available, allocated, consumed, all")
        raise click.Abort()

    sql = f"""
SELECT
  did,
  status,
  created_at,
  allocated_at,
  allocated_to_email,
  onboarding_url
FROM wid_account_inventory
{where_clause}
ORDER BY created_at ASC
LIMIT {limit};
"""

    console.print(f"WID Inventory ({status})")
    console.print("=" * 80)
    console.print()

    output = exec_sqlite(config, sql)
    console.print(output)


@inventory.command()
@click.option("--older-than-days", type=int, default=None, help="Only clear accounts older than N days")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def clear(ctx, older_than_days: Optional[int], yes: bool):
    """Clear available (unused) WID accounts from inventory."""
    client: PDSClient = ctx.obj["client"]
    config: Config = ctx.obj["config"]

    console.print("═" * 63)
    console.print("Clear WID Inventory")
    console.print("═" * 63)
    console.print()

    # First, get preview of what will be deleted
    if older_than_days:
        where_clause = f"WHERE status = 'available' AND created_at < datetime('now', '-{older_than_days} days')"
        age_desc = f"older than {older_than_days} days"
    else:
        where_clause = "WHERE status = 'available'"
        age_desc = "all ages"

    # Count how many will be deleted
    count_sql = f"SELECT COUNT(*) as count FROM wid_account_inventory {where_clause};"
    count_result = exec_sqlite(config, count_sql)

    # Parse count from result
    try:
        count_line = [line for line in count_result.split('\n') if line.strip() and not line.startswith('count') and not line.startswith('-')][0]
        count = int(count_line.strip())
    except (IndexError, ValueError):
        count = 0

    if count == 0:
        console.print(f"No available accounts found ({age_desc}).")
        return

    # Get sample accounts for preview
    sample_sql = f"SELECT did, created_at FROM wid_account_inventory {where_clause} ORDER BY created_at ASC LIMIT 3;"
    sample_result = exec_sqlite(config, sample_sql)

    console.print(f"Found {count} available account(s) to delete ({age_desc}):")
    console.print()
    console.print("Sample W IDs:")
    console.print(sample_result)
    console.print()

    if not yes:
        console.print(f"⚠️  This will permanently delete {count} available WID account(s).")
        console.print("   Allocated and consumed accounts will NOT be touched.")
        console.print()

        confirm = click.prompt("Continue? [y/N]", type=str, default="N")
        if confirm.lower() not in ("y", "yes"):
            console.print("Cancelled.")
            raise click.Abort()

    # Call API to clear inventory
    data = {}
    if older_than_days:
        data["olderThanDays"] = older_than_days

    console.print()
    console.print("Deleting accounts...")

    response = client.call("POST", "io.trustanchor.admin.clearInventory", data=data)

    if not response.success:
        print_error(f"Failed to clear inventory: {response.error}")
        raise click.Abort()

    if response.data is None:
        print_error("No data returned from API")
        raise click.Abort()

    deleted = response.data.get("deleted", 0)

    print_success(f"Successfully cleared {deleted} available account(s) from inventory.")


def schema_command(ctx):
    """Show database schema for key tables."""
    config: Config = ctx.obj["config"]

    console.print(f"Database Schema for pds/{config.environment or 'unknown'}")
    console.print("=" * 63)
    console.print()

    # Show neuro_identity_link schema
    console.print("Table: neuro_identity_link")
    console.print("-" * 63)
    output = exec_sqlite(config, "PRAGMA table_info(neuro_identity_link);")
    console.print(output)
    console.print()

    # Show actor schema
    console.print("Table: actor")
    console.print("-" * 63)
    output = exec_sqlite(config, "PRAGMA table_info(actor);")
    console.print(output)
    console.print()

    # Show account schema
    console.print("Table: account")
    console.print("-" * 63)
    output = exec_sqlite(config, "PRAGMA table_info(account);")
    console.print(output)
    console.print()

    # Show pending_invitations schema
    console.print("Table: pending_invitations")
    console.print("-" * 63)
    output = exec_sqlite(config, "PRAGMA table_info(pending_invitations);")
    console.print(output)


def db_command(ctx, query: Optional[str]):
    """Query neuro_identity_link database."""
    config: Config = ctx.obj["config"]

    if query:
        # Execute custom query
        output = exec_sqlite(config, query)
        console.print(output)
    else:
        # Default: full neuro_identity_link dump with duplicate annotation
        sql = """
SELECT
  nil.did,
  COALESCE(a.handle, '?') AS handle,
  CASE WHEN nil.isTestUser = 1 THEN nil.testUserJid ELSE nil.userJid END AS jid,
  nil.isTestUser,
  nil.linkedAt,
  nil.lastLoginAt,
  CASE WHEN cnt.n > 1 THEN '*** DUP (' || cnt.n || ')' ELSE '' END AS dup_flag
FROM neuro_identity_link nil
LEFT JOIN actor a ON a.did = nil.did
JOIN (
  SELECT did, COUNT(*) AS n FROM neuro_identity_link GROUP BY did
) cnt ON cnt.did = nil.did
ORDER BY nil.did, nil.linkedAt;
"""
        output = exec_sqlite(config, sql)
        console.print(output)


def check_db_command(ctx, did: str):
    """Check database consistency for a specific DID."""
    config: Config = ctx.obj["config"]

    console.print("═" * 63)
    console.print(f"Database Consistency Check: {did}")
    console.print("═" * 63)
    console.print()

    issues_found = 0

    # 1. Check actor table
    console.print("1️⃣  Actor Table")
    console.print("─" * 63)

    output = exec_sqlite(config, f"SELECT did, handle, createdAt FROM actor WHERE did='{did}';")
    if did in output:
        console.print("✓ Actor record found")
        # Parse output to show handle and created time
        lines = output.strip().split('\n')
        if len(lines) >= 3:  # Header, separator, data
            console.print(output)
    else:
        console.print("✗ Actor record NOT found", style="error")
        issues_found += 1
    console.print()

    # 2. Check account table
    console.print("2️⃣  Account Table")
    console.print("─" * 63)

    output = exec_sqlite(config, f"SELECT did, email, emailConfirmedAt FROM account WHERE did='{did}';")
    if did in output:
        console.print("✓ Account record found")
        console.print(output)
    else:
        console.print("✗ Account record NOT found", style="error")
        issues_found += 1
    console.print()

    # 3. Check neuro_identity_link table
    console.print("3️⃣  Neuro Identity Link Table")
    console.print("─" * 63)

    output = exec_sqlite(config, f"SELECT did, CASE WHEN isTestUser = 1 THEN testUserJid ELSE userJid END AS jid, isTestUser, linkedAt, lastLoginAt FROM neuro_identity_link WHERE did='{did}';")
    if did in output:
        # Count how many records (lines with the DID, excluding header and separator)
        lines = output.strip().split('\n')
        data_lines = [line for line in lines if did in line]
        count = len(data_lines)

        if count == 1:
            console.print("✓ One W ID link found (correct)")
            console.print(output)
        else:
            console.print(f"✗ DUPLICATE W ID links found: {count} records", style="error")
            console.print(output)
            issues_found += 1
    else:
        console.print("✗ Neuro identity link NOT found", style="error")
        issues_found += 1
    console.print()

    # Summary
    console.print("═" * 63)
    if issues_found == 0:
        console.print("✅ No consistency issues found", style="success")
    else:
        console.print(f"⚠️  Found {issues_found} consistency issue(s)", style="warning")
    console.print("═" * 63)
