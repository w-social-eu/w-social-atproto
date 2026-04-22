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
            return cls._from_k8s(env)
        else:
            return cls._from_env_vars()

    @classmethod
    def _from_k8s(cls, env: str) -> "Config":
        """
        Fetch all secrets from the Kubernetes 'pds' secret via kubectl.

        Args:
            env: Environment name (dev, stage, prod)

        Returns:
            Config instance with k8s-sourced credentials

        Raises:
            SystemExit: If kubectl fails or the kubeconfig is missing
        """
        import subprocess
        import base64
        import json

        kubeconfig = Path.home() / ".wsocial" / "kube" / f"{env}.yaml"
        if not kubeconfig.exists():
            print(f"ERROR: kubeconfig not found: {kubeconfig}", file=sys.stderr)
            sys.exit(1)

        try:
            result = subprocess.run(
                [
                    "kubectl",
                    "--kubeconfig", str(kubeconfig),
                    "get", "secret", "pds",
                    "-n", K8S_NAMESPACE,
                    "-o", "jsonpath={.data}",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"ERROR: kubectl failed: {e.stderr.strip()}", file=sys.stderr)
            sys.exit(1)
        except FileNotFoundError:
            print("ERROR: kubectl not found — install kubectl and ensure it is on your PATH", file=sys.stderr)
            sys.exit(1)

        raw: dict[str, str] = json.loads(result.stdout)
        secrets: dict[str, str] = {
            k: base64.b64decode(v).decode() for k, v in raw.items()
        }

        def get(key: str) -> str | None:
            return secrets.get(key) or None

        # Construct config from secrets
        return cls(
            pds_host=f"https://{secrets['PDS_HOSTNAME']}",
            admin_password=secrets["PDS_ADMIN_PASSWORD"],
            environment=env,
            brevo_api_key=get("PDS_BREVO_API_KEY"),
            brevo_template_id=int(secrets["PDS_BREVO_INVITATION_TEMPLATE_ID"]) if "PDS_BREVO_INVITATION_TEMPLATE_ID" in secrets else None,
            invitation_email_from=get("PDS_INVITATION_EMAIL_FROM"),
            invitation_mail_from_name=get("PDS_INVITATION_EMAIL_FROM_NAME"),
            invitation_email_hash_salt=get("PDS_INVITATION_EMAIL_HASH_SALT"),
            bsky_app_view_url=get("PDS_BSKY_APP_VIEW_URL"),
            bsky_app_view_did=get("PDS_BSKY_APP_VIEW_DID"),
            nomad_addr=None,
            nomad_job_name=None,
            k8s_cluster_id=env,
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
