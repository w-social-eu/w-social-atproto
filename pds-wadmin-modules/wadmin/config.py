"""
Configuration management for PDS Admin Tool.

Handles environment detection, Vault authentication, and secret fetching.
"""

import os
import sys
from typing import Optional
from dataclasses import dataclass
from pathlib import Path

# Kubernetes namespace and container name are the same across all environments.
K8S_NAMESPACE = "pds"
K8S_POD = "pds-0"
K8S_CONTAINER = "pds"


@dataclass
class Config:
    """PDS Admin configuration."""

    pds_host: str
    admin_password: str
    environment: Optional[str] = None  # None, "dev", "stage", "prod"
    brevo_api_key: Optional[str] = None
    brevo_template_id: Optional[int] = None
    invitation_email_from: Optional[str] = None
    invitation_mail_from_name: Optional[str] = None
    invitation_email_hash_salt: Optional[str] = None
    bsky_app_view_url: Optional[str] = None
    bsky_app_view_did: Optional[str] = None
    nomad_addr: Optional[str] = None
    nomad_token: Optional[str] = None
    nomad_job_name: Optional[str] = None
    k8s_cluster_id: Optional[str] = None

    @classmethod
    def from_environment(cls, script_name: str) -> "Config":
        """
        Detect environment from script name and load configuration.

        Args:
            script_name: Name of the script being executed (e.g., "pds-wadmin-dev")

        Returns:
            Config instance with appropriate settings

        Raises:
            RuntimeError: If required environment variables are missing
        """
        # Check if script name was passed via environment variable (from wrapper)
        script_name = os.getenv("WADMIN_SCRIPT_NAME", script_name)

        # Extract env from script name (pds-wadmin-dev → dev)
        parts = script_name.split("-")
        env = parts[-1] if len(parts) > 1 and parts[-1] in ("dev", "stage", "prod") else None

        if env:
            return cls._from_vault(env)
        else:
            return cls._from_env_vars()

    @classmethod
    def _from_vault(cls, env: str) -> "Config":
        """
        Fetch all secrets from Vault in one batch operation.

        Args:
            env: Environment name (dev, stage, prod)

        Returns:
            Config instance with Vault-sourced credentials

        Raises:
            RuntimeError: If Vault authentication fails
        """
        try:
            import hvac
        except ImportError:
            raise RuntimeError(
                "ERROR: hvac library not installed.\n"
                "Install with: pip install hvac\n"
                "Or run: cd pds-wadmin-modules && .venv/bin/pip install -r requirements.txt"
            )

        vault_addr = "https://vault.wsocial.cloud"
        client = hvac.Client(url=vault_addr)

        # Check for existing token
        token_file = Path.home() / ".vault-token"
        if token_file.exists():
            client.token = token_file.read_text().strip()

        # Validate authentication
        if not client.is_authenticated():
            print("ERROR: Vault authentication required", file=sys.stderr)
            print("Run: vault login -method=github -path=github", file=sys.stderr)
            sys.exit(1)

        # Batch fetch all secrets for environment
        pds_path = f"pds/{env}"
        try:
            response = client.secrets.kv.v2.read_secret_version(
                path=pds_path,
                mount_point="secret"
            )
            secrets = response["data"]["data"]
        except Exception as e:
            raise RuntimeError(f"Failed to fetch secrets from Vault path '{pds_path}': {e}")

        # Construct config from secrets
        return cls(
            pds_host=f"https://{secrets['HOSTNAME']}",
            admin_password=secrets["ADMIN_PASSWORD"],
            environment=env,
            brevo_api_key=secrets.get("BREVO_API_KEY"),
            brevo_template_id=int(secrets["BREVO_INVITATION_TEMPLATE_ID"]) if "BREVO_INVITATION_TEMPLATE_ID" in secrets else None,
            invitation_email_from=secrets.get("INVITATION_EMAIL_FROM"),
            invitation_mail_from_name=secrets.get("INVITATION_MAIL_FROM_NAME"),
            invitation_email_hash_salt=secrets.get("INVITATION_EMAIL_HASH_SALT"),
            bsky_app_view_url=secrets.get("BSKY_APP_VIEW_URL"),
            bsky_app_view_did=secrets.get("BSKY_APP_VIEW_DID"),
            nomad_addr="https://nomad.wsocial.cloud",
            nomad_job_name=f"pds-{env}",
            k8s_cluster_id=env,
            # Nomad token handled separately (login on demand)
        )

    @classmethod
    def _from_env_vars(cls) -> "Config":
        """
        Load configuration from environment variables.

        Returns:
            Config instance with env var credentials

        Raises:
            RuntimeError: If required env vars are missing
        """
        pds_host = os.getenv("PDS_HOST")
        admin_password = os.getenv("PDS_ADMIN_PASSWORD")

        if not pds_host or not admin_password:
            print("ERROR: PDS_HOST and PDS_ADMIN_PASSWORD environment variables required", file=sys.stderr)
            print("\nExample:", file=sys.stderr)
            print("  export PDS_HOST=https://pds-stage.wsocial.dev", file=sys.stderr)
            print("  export PDS_ADMIN_PASSWORD=your-admin-password", file=sys.stderr)
            print("\nOr use environment-specific commands:", file=sys.stderr)
            print("  pds-wadmin-dev, pds-wadmin-stage, or pds-wadmin-prod", file=sys.stderr)
            sys.exit(1)

        return cls(
            pds_host=pds_host,
            admin_password=admin_password,
            brevo_api_key=os.getenv("PDS_BREVO_API_KEY"),
            brevo_template_id=int(os.getenv("PDS_BREVO_INVITATION_TEMPLATE_ID", 0)) or None,
            invitation_email_from=os.getenv("PDS_INVITATION_EMAIL_FROM"),
            invitation_mail_from_name=os.getenv("PDS_INVITATION_MAIL_FROM_NAME"),
            invitation_email_hash_salt=os.getenv("PDS_INVITATION_EMAIL_HASH_SALT"),
            bsky_app_view_url=os.getenv("BSKY_APP_VIEW_URL"),
            bsky_app_view_did=os.getenv("BSKY_APP_VIEW_DID"),
            nomad_addr=os.getenv("NOMAD_ADDR"),
            nomad_token=os.getenv("NOMAD_TOKEN"),
            nomad_job_name=os.getenv("PDS_NOMAD_JOB_NAME"),
            k8s_cluster_id=os.getenv("K8S_ENV", os.getenv("K8S_CLUSTER_ID")),
        )

    def has_brevo_config(self) -> bool:
        """Check if Brevo email configuration is available."""
        return bool(self.brevo_api_key and self.brevo_template_id)

    def has_nomad_config(self) -> bool:
        """Check if Nomad configuration is available."""
        return bool(self.nomad_addr and self.nomad_job_name)

    def has_k8s_config(self) -> bool:
        """Check if Rancher/k8s configuration is available."""
        return bool(self.k8s_cluster_id)
