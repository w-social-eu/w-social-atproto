#!/usr/bin/env python3
"""
Brevo email integration for invitation system.

This module handles sending invitation emails via Brevo's Transactional Email API.
It is called from pds-wadmin CLI tool, NOT from PDS application code.

Architecture:
- PDS: Manages invitation state lifecycle (pending → consumed)
- CLI (this module): Coordinates PDS API + Brevo API for email delivery
- Benefit: User onboarding never blocked by Brevo API issues

Usage:
    python3 -m brevo_integration send-invitation \
        --api-key="xkeysib-..." \
        --template-id=21 \
        --email="user@example.com" \
        --onboarding-url="https://..." \
        --qr-code-url="https://..." \
        [--preferred-handle="john"]
"""

import argparse
import base64
import sys
import time
from typing import Optional, List, Dict

try:
    import requests
    import sib_api_v3_sdk
    from sib_api_v3_sdk.rest import ApiException
except ImportError as e:
    print(f"ERROR: Missing required Python package: {e}", file=sys.stderr)
    print("Install dependencies with: pip install -r pds-wadmin-modules/requirements.txt", file=sys.stderr)
    sys.exit(1)


# Brevo Configuration (hardcoded for visibility)
BREVO_INVITATION_TEMPLATE_ID = 21  # Update after template creation

# Brevo List IDs
BREVO_WAITLIST_LIST_ID = 23     # Users who signed up for early access
BREVO_INVITED_LIST_ID = 24      # Invitations sent, waiting for onboarding
BREVO_ONBOARDED_LIST_ID = 27    # Completed first login

# Inventory Thresholds
WID_INVENTORY_WARN_THRESHOLD = 500    # Show warning
WID_INVENTORY_CRITICAL_THRESHOLD = 100  # Show error


def fetch_and_encode_qr_code(qr_code_url: str, timeout: int = 10) -> Optional[str]:
    """
    Fetch QR code image from URL and return as base64 data URI.

    Args:
        qr_code_url: URL to QR code image (typically from Neuro)
        timeout: HTTP request timeout in seconds

    Returns:
        Base64 data URI (data:image/png;base64,...) or None if fetch fails
    """
    try:
        response = requests.get(qr_code_url, timeout=timeout)
        response.raise_for_status()

        # Determine content type from response
        content_type = response.headers.get('Content-Type', 'image/png')

        # Encode image as base64
        image_data = base64.b64encode(response.content).decode('utf-8')

        # Return as data URI
        return f"data:{content_type};base64,{image_data}"

    except Exception as e:
        print(f"WARNING: Failed to fetch QR code image: {e}", file=sys.stderr)
        return None


def send_invitation_email(
    api_key: str,
    template_id: int,
    email: str,
    onboarding_url: str,
    qr_code_url: str,
    preferred_handle: Optional[str] = None,
    from_email: str = "invitations@wsocial.app",
    from_name: str = "W Social Team",
    max_retries: int = 3,
) -> dict:
    """
    Send invitation email via Brevo Transactional Email API.

    Args:
        api_key: Brevo API key
        template_id: Brevo template ID
        email: Recipient email address
        onboarding_url: Onboarding URL for invitation
        qr_code_url: URL to QR code image (will be fetched and inlined)
        preferred_handle: Optional suggested handle
        from_email: Sender email address
        from_name: Sender display name
        max_retries: Maximum retry attempts on transient failures

    Returns:
        dict with keys: success (bool), message_id (str), error (str)
    """
    # Configure Brevo API client
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key['api-key'] = api_key
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )

    # Fetch and encode QR code as inline data URI
    inline_qr_code = fetch_and_encode_qr_code(qr_code_url)

    # Prepare template parameters
    params = {
        "ONBOARDING_URL": onboarding_url,
        "QR_CODE_URL": qr_code_url,  # Hosted URL for email clients that prefer it
    }

    # Add inline QR code if fetch succeeded
    if inline_qr_code:
        params["INLINE_QR_CODE"] = inline_qr_code

    # Add preferred handle if provided
    if preferred_handle:
        params["PREFERRED_HANDLE"] = preferred_handle

    # Prepare email
    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": email}],
        template_id=template_id,
        params=params,
        sender={"email": from_email, "name": from_name},
    )

    # Retry logic with exponential backoff
    last_error = None
    for attempt in range(max_retries):
        try:
            # Send email
            response = api_instance.send_transac_email(send_smtp_email)

            # Success
            return {
                "success": True,
                "message_id": response.message_id,
                "from_email": from_email,
                "from_name": from_name,
                "error": None,
            }

        except ApiException as e:
            # Parse error response
            import json
            try:
                error_data = json.loads(e.body)
                error_message = error_data.get('message', str(e))
            except:
                error_message = str(e)

            last_error = error_message

            # Check if retryable (5xx server errors, rate limits)
            if e.status >= 500 or e.status == 429:
                if attempt < max_retries - 1:
                    # Exponential backoff: 1s, 2s, 4s
                    sleep_time = 2 ** attempt
                    print(f"Transient error (attempt {attempt + 1}/{max_retries}): {error_message}", file=sys.stderr)
                    print(f"Retrying in {sleep_time}s...", file=sys.stderr)
                    time.sleep(sleep_time)
                    continue

            # Non-retryable error or max retries reached
            break

        except Exception as e:
            last_error = str(e)
            break

    # All retries failed
    return {
        "success": False,
        "message_id": None,
        "error": last_error or "Unknown error",
    }


def get_list_contacts(api_key: str, list_id: int, limit: int = 500, offset: int = 0) -> Dict:
    """
    Fetch contacts from a Brevo list.

    Args:
        api_key: Brevo API key
        list_id: Brevo list ID
        limit: Maximum number of contacts to fetch (max 500)
        offset: Pagination offset

    Returns:
        dict with keys: contacts (list), count (int), error (str)
    """
    try:
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = api_key
        api_instance = sib_api_v3_sdk.ContactsApi(
            sib_api_v3_sdk.ApiClient(configuration)
        )

        # Fetch contacts from list
        contacts_list = api_instance.get_contacts_from_list(
            list_id=list_id,
            limit=min(limit, 500),  # API max is 500
            offset=offset
        )

        return {
            "success": True,
            "contacts": [{"email": c.email, "id": c.id} for c in contacts_list.contacts],
            "count": contacts_list.count,
            "error": None,
        }

    except ApiException as e:
        return {
            "success": False,
            "contacts": [],
            "count": 0,
            "error": str(e),
        }
    except Exception as e:
        return {
            "success": False,
            "contacts": [],
            "count": 0,
            "error": str(e),
        }


def get_list_count(api_key: str, list_id: int) -> Dict:
    """
    Get contact count for a Brevo list.

    Args:
        api_key: Brevo API key
        list_id: Brevo list ID

    Returns:
        dict with keys: count (int), error (str)
    """
    try:
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = api_key
        api_instance = sib_api_v3_sdk.ContactsApi(
            sib_api_v3_sdk.ApiClient(configuration)
        )

        # Get list details
        list_info = api_instance.get_list(list_id)

        return {
            "success": True,
            "count": list_info.total_subscribers,
            "name": list_info.name,
            "error": None,
        }

    except ApiException as e:
        return {
            "success": False,
            "count": 0,
            "name": None,
            "error": str(e),
        }
    except Exception as e:
        return {
            "success": False,
            "count": 0,
            "name": None,
            "error": str(e),
        }


def move_contact_between_lists(api_key: str, email: str, from_list_id: int, to_list_id: int) -> Dict:
    """
    Move a contact from one Brevo list to another.

    Args:
        api_key: Brevo API key
        email: Contact email address
        from_list_id: Source list ID
        to_list_id: Destination list ID

    Returns:
        dict with keys: success (bool), error (str)
    """
    try:
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = api_key
        api_instance = sib_api_v3_sdk.ContactsApi(
            sib_api_v3_sdk.ApiClient(configuration)
        )

        # Remove from source list
        remove_body = sib_api_v3_sdk.RemoveContactFromList(emails=[email])
        api_instance.remove_contact_from_list(from_list_id, remove_body)

        # Add to destination list
        add_body = sib_api_v3_sdk.AddContactToList(emails=[email])
        api_instance.add_contact_to_list(to_list_id, add_body)

        return {
            "success": True,
            "error": None,
        }

    except ApiException as e:
        return {
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


def main():
    """CLI entry point for Brevo operations."""
    parser = argparse.ArgumentParser(
        description="Brevo integration for W Social invitations"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Subcommand: send-invitation
    send_parser = subparsers.add_parser("send-invitation", help="Send invitation email")
    send_parser.add_argument("--api-key", required=True, help="Brevo API key")
    send_parser.add_argument("--template-id", type=int, required=True, help="Brevo template ID")
    send_parser.add_argument("--email", required=True, help="Recipient email address")
    send_parser.add_argument("--onboarding-url", required=True, help="Onboarding URL")
    send_parser.add_argument("--qr-code-url", required=True, help="QR code image URL")
    send_parser.add_argument("--preferred-handle", help="Suggested handle (optional)")
    send_parser.add_argument("--from-email", default="invitations@wsocial.app", help="Sender email")
    send_parser.add_argument("--from-name", default="W Social Team", help="Sender name")

    # Subcommand: list-contacts
    list_parser = subparsers.add_parser("list-contacts", help="Get contacts from Brevo list")
    list_parser.add_argument("--api-key", required=True, help="Brevo API key")
    list_parser.add_argument("--list-id", type=int, required=True, help="Brevo list ID")
    list_parser.add_argument("--limit", type=int, default=500, help="Max contacts to fetch")
    list_parser.add_argument("--offset", type=int, default=0, help="Pagination offset")

    # Subcommand: list-count
    count_parser = subparsers.add_parser("list-count", help="Get contact count for Brevo list")
    count_parser.add_argument("--api-key", required=True, help="Brevo API key")
    count_parser.add_argument("--list-id", type=int, required=True, help="Brevo list ID")

    # Subcommand: move-contact
    move_parser = subparsers.add_parser("move-contact", help="Move contact between lists")
    move_parser.add_argument("--api-key", required=True, help="Brevo API key")
    move_parser.add_argument("--email", required=True, help="Contact email")
    move_parser.add_argument("--from-list", type=int, required=True, help="Source list ID")
    move_parser.add_argument("--to-list", type=int, required=True, help="Destination list ID")

    args = parser.parse_args()

    # Execute command
    import json

    if args.command == "send-invitation":
        result = send_invitation_email(
            api_key=args.api_key,
            template_id=args.template_id,
            email=args.email,
            onboarding_url=args.onboarding_url,
            qr_code_url=args.qr_code_url,
            preferred_handle=args.preferred_handle,
            from_email=args.from_email,
            from_name=args.from_name,
        )
        print(json.dumps(result))
        sys.exit(0 if result["success"] else 1)

    elif args.command == "list-contacts":
        result = get_list_contacts(
            api_key=args.api_key,
            list_id=args.list_id,
            limit=args.limit,
            offset=args.offset,
        )
        print(json.dumps(result))
        sys.exit(0 if result["success"] else 1)

    elif args.command == "list-count":
        result = get_list_count(
            api_key=args.api_key,
            list_id=args.list_id,
        )
        print(json.dumps(result))
        sys.exit(0 if result["success"] else 1)

    elif args.command == "move-contact":
        result = move_contact_between_lists(
            api_key=args.api_key,
            email=args.email,
            from_list_id=args.from_list,
            to_list_id=args.to_list,
        )
        print(json.dumps(result))
        sys.exit(0 if result["success"] else 1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
