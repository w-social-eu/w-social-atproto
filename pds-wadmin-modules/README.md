# PDS Admin CLI - Python Modules

This directory contains Python modules used by `pds-wadmin` CLI tool for advanced operations.

## Installation

Install Python dependencies:

```bash
cd pds-wadmin-modules
pip install -r requirements.txt
```

Or use a virtual environment (recommended):

```bash
cd pds-wadmin-modules
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Modules

### brevo_integration.py

Handles sending invitation emails via Brevo's Transactional Email API.

**Features:**
- Fetches QR code images and inlines them as base64 data URIs
- Retry logic with exponential backoff for transient failures
- Template-based email sending with customizable parameters

**Usage:**

```bash
python3 brevo_integration.py \
  --api-key="xkeysib-..." \
  --template-id=21 \
  --email="user@example.com" \
  --onboarding-url="https://..." \
  --qr-code-url="https://..." \
  --preferred-handle="john"
```

**Environment Variables for pds-wadmin:**

```bash
export PDS_BREVO_API_KEY="xkeysib-..."      # Get from Vault: pds/dev BREVO_API_KEY
export PDS_BREVO_INVITATION_TEMPLATE_ID=21  # Brevo template ID for invitations
```

**Template Variables:**

The Brevo template receives these variables:
- `ONBOARDING_URL` - Raw URL for onboarding
- `QR_CODE_IMAGE` - Hosted QR code image URL
- `INLINE_QR_CODE` - Base64-encoded data URI for inline display
- `PREFERRED_HANDLE` - Suggested username (optional)

## Architecture

**Principle:** All Brevo operations happen via CLI tools, NOT in PDS application code.

- **PDS Responsibility:** Manage invitation state lifecycle (pending → consumed)
- **CLI Responsibility:** Coordinate PDS API + Brevo API for email delivery
- **Benefit:** User onboarding never blocked by Brevo API issues; clean separation of concerns

## Development

To test email sending locally:

```bash
# Get Brevo API key from Vault
export VAULT_ADDR=https://vault.wsocial.cloud
vault login -method=github
export PDS_BREVO_API_KEY=$(vault kv get -mount=secret -field=BREVO_API_KEY pds/dev)
export PDS_BREVO_INVITATION_TEMPLATE_ID=21

# Create invitation (will automatically send email if Brevo is configured)
./pds-wadmin invitation create test@example.com --handle=testuser
```
