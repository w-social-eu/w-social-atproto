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
from typing import Optional

try:
    import requests
    import sib_api_v3_sdk
    from sib_api_v3_sdk.rest import ApiException
except ImportError as e:
    print(f"ERROR: Missing required Python package: {e}", file=sys.stderr)
    print("Install dependencies with: pip install -r pds-wadmin-modules/requirements.txt", file=sys.stderr)
    sys.exit(1)


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
        "QR_CODE_IMAGE": qr_code_url,  # Hosted URL for email clients that prefer it
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


def main():
    """CLI entry point for sending invitation emails."""
    parser = argparse.ArgumentParser(
        description="Send invitation email via Brevo"
    )
    parser.add_argument("--api-key", required=True, help="Brevo API key")
    parser.add_argument("--template-id", type=int, required=True, help="Brevo template ID")
    parser.add_argument("--email", required=True, help="Recipient email address")
    parser.add_argument("--onboarding-url", required=True, help="Onboarding URL")
    parser.add_argument("--qr-code-url", required=True, help="QR code image URL")
    parser.add_argument("--preferred-handle", help="Suggested handle (optional)")
    parser.add_argument("--from-email", default="invitations@wsocial.app", help="Sender email")
    parser.add_argument("--from-name", default="W Social Team", help="Sender name")

    args = parser.parse_args()

    # Send email
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

    # Output result as JSON for bash script to parse
    import json
    print(json.dumps(result))

    # Exit with appropriate code
    sys.exit(0 if result["success"] else 1)


if __name__ == "__main__":
    main()
