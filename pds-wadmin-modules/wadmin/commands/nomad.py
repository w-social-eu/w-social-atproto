"""
Nomad cluster management commands.
"""

import os
import click
import subprocess
import sys
from pathlib import Path
from typing import Optional
from ..config import Config, K8S_NAMESPACE, K8S_POD, K8S_CONTAINER
from ..utils import console, print_success, print_error


def check_k8s_auth(config: Config) -> str:
    """
    Verify kubectl is available and the per-env kubeconfig exists.
    Returns the path to the kubeconfig file.

    Prerequisite: ~/.wsocial/kube/<env>.yaml  (download from Rancher UI)

    Raises:
        click.Abort: If kubectl is not installed or kubeconfig is missing
    """
    if not config.has_k8s_config():
        print_error(
            "Kubernetes not configured",
            "Use pds-wadmin-dev, pds-wadmin-stage, or pds-wadmin-prod"
        )
        raise click.Abort()

    result = subprocess.run(["kubectl", "version", "--client", "--output=json"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print_error(
            "kubectl not found",
            "Install with: brew install kubectl"
        )
        raise click.Abort()

    kubeconfig = Path.home() / ".wsocial" / "kube" / f"{config.k8s_cluster_id}.yaml"
    if not kubeconfig.exists():
        print_error(
            f"Kubeconfig not found: {kubeconfig}",
            f"Download from Rancher UI for cluster {config.k8s_cluster_id} and save to {kubeconfig}"
        )
        raise click.Abort()

    return str(kubeconfig)


def run_kubectl(kubeconfig: str, args: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run kubectl with the given per-env kubeconfig."""
    return subprocess.run(
        ["kubectl", "--kubeconfig", kubeconfig] + args,
        **kwargs
    )


@click.group()
def nomad():
    """Nomad cluster management commands."""
    pass


def check_nomad_auth(config: Config) -> tuple[str, str]:
    """
    Ensure Nomad authentication is valid and return (nomad_addr, nomad_token).

    Returns:
        Tuple of (nomad_addr, nomad_token)

    Raises:
        click.Abort: If Nomad is not configured or authentication fails
    """
    if not config.has_nomad_config():
        print_error(
            "Nomad not configured",
            "Set NOMAD_ADDR and PDS_NOMAD_JOB_NAME in environment, or use pds-wadmin-dev/stage/prod"
        )
        raise click.Abort()

    nomad_addr = config.nomad_addr or "https://nomad.wsocial.cloud"
    nomad_token = config.nomad_token

    # If token not set, try to read from cache or login
    if not nomad_token:
        import os
        from pathlib import Path

        token_cache = Path.home() / ".nomad-token"
        if token_cache.exists():
            nomad_token = token_cache.read_text().strip()

        # Check if cached token works
        if nomad_token:
            result = subprocess.run(
                ["nomad", "status"],
                env={**os.environ, "NOMAD_ADDR": nomad_addr, "NOMAD_TOKEN": nomad_token},
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                nomad_token = None  # Token expired or invalid

        # If still no valid token, attempt login
        if not nomad_token:
            console.print("Nomad authentication required...")
            result = subprocess.run(
                ["nomad", "login", "-method=vault-oidc"],
                env={**os.environ, "NOMAD_ADDR": nomad_addr},
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print_error("Nomad login failed", result.stderr or "Unknown error")
                raise click.Abort()

            # Extract Secret ID from output
            for line in result.stdout.split('\n'):
                if line.startswith("Secret ID"):
                    parts = line.split()
                    if len(parts) >= 4:
                        nomad_token = parts[3]
                        # Cache the token
                        token_cache.write_text(nomad_token)
                        token_cache.chmod(0o600)
                        break

            if not nomad_token:
                print_error("Failed to extract token from nomad login output")
                raise click.Abort()

    return nomad_addr, nomad_token


@nomad.command()
@click.pass_context
def status(ctx):
    """Show Nomad job status."""
    config: Config = ctx.obj["config"]

    if config.has_k8s_config():
        kubeconfig = check_k8s_auth(config)
        console.print(f"Checking status (kubeconfig: {kubeconfig})")
        console.print()
        run_kubectl(kubeconfig, ["get", "pods", "-n", K8S_NAMESPACE, "-o", "wide"])
    else:
        nomad_addr, nomad_token = check_nomad_auth(config)
        job_name = config.nomad_job_name
        if not job_name:
            print_error("Nomad job name not configured")
            raise click.Abort()
        console.print(f"Checking status for job: {job_name}")
        console.print()
        result = subprocess.run(
            ["nomad", "status", job_name],
            env={**os.environ, "NOMAD_ADDR": nomad_addr, "NOMAD_TOKEN": nomad_token}
        )
        if result.returncode != 0:
            raise click.Abort()


@nomad.command()
@click.option("--tail", default=None, type=int, help="Number of lines to tail")
@click.option("--follow", "-f", is_flag=True, help="Follow log output")
@click.pass_context
def logs(ctx, tail: Optional[int], follow: bool):
    """Fetch logs from the running PDS container."""
    config: Config = ctx.obj["config"]

    if config.has_k8s_config():
        kubeconfig = check_k8s_auth(config)
        console.print(f"Fetching logs (kubeconfig: {kubeconfig})")
        console.print()
        cmd = ["-n", K8S_NAMESPACE, "logs", K8S_POD, "-c", K8S_CONTAINER]
        if tail:
            cmd += [f"--tail={tail}"]
        if follow:
            cmd.append("-f")
        run_kubectl(kubeconfig, cmd)
    else:
        nomad_addr, nomad_token = check_nomad_auth(config)
        job_name = config.nomad_job_name
        if not job_name:
            print_error("Nomad job name not configured")
            raise click.Abort()
        console.print(f"Fetching logs for job: {job_name}")
        console.print()
        result = subprocess.run(
            ["nomad", "status", job_name],
            env={**os.environ, "NOMAD_ADDR": nomad_addr, "NOMAD_TOKEN": nomad_token},
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print_error("Failed to get job status")
            raise click.Abort()
        alloc_id = None
        for line in result.stdout.split('\n'):
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
        console.print(f"Using allocation: {alloc_id}")
        console.print()
        cmd = ["nomad", "alloc", "logs"]
        if tail:
            cmd.extend(["-tail", "-n", str(tail)])
        if follow:
            cmd.append("-f")
        cmd += [alloc_id, "pds"]
        subprocess.run(cmd, env={**os.environ, "NOMAD_ADDR": nomad_addr, "NOMAD_TOKEN": nomad_token})


@nomad.command()
@click.option("--tail", default=None, type=int, help="Number of lines to tail")
@click.pass_context
def logfile(ctx, tail: Optional[int]):
    """Fetch logs and save to timestamped file (pds-<env>YYYYMMDD-HHMM.log.json)."""
    from datetime import datetime
    from pathlib import Path

    config: Config = ctx.obj["config"]
    env = config.environment or "unknown"

    now = datetime.now()
    base_filename = f"pds-{env}{now.strftime('%Y%m%d-%H%M')}.log.json"
    if Path(base_filename).exists():
        base_filename = f"pds-{env}{now.strftime('%Y%m%d-%H%M%S')}.log.json"

    console.print(f"Saving to: {base_filename}")
    console.print()

    if config.has_k8s_config():
        kubeconfig = check_k8s_auth(config)
        console.print(f"Fetching logs (kubeconfig: {kubeconfig})")
        cmd = ["-n", K8S_NAMESPACE, "logs", K8S_POD, "-c", K8S_CONTAINER]
        if tail:
            cmd += [f"--tail={tail}"]
        with open(base_filename, "w") as f:
            result = run_kubectl(kubeconfig, cmd, stdout=f, stderr=subprocess.STDOUT)
    else:
        nomad_addr, nomad_token = check_nomad_auth(config)
        job_name = config.nomad_job_name
        if not job_name:
            print_error("Nomad job name not configured")
            raise click.Abort()
        console.print(f"Fetching logs for job: {job_name}")
        result = subprocess.run(
            ["nomad", "status", job_name],
            env={**os.environ, "NOMAD_ADDR": nomad_addr, "NOMAD_TOKEN": nomad_token},
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print_error("Failed to get job status")
            raise click.Abort()
        alloc_id = None
        for line in result.stdout.split('\n'):
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
        console.print(f"Using allocation: {alloc_id}")
        cmd = ["nomad", "alloc", "logs"]
        if tail:
            cmd.extend(["-tail", "-n", str(tail)])
        cmd += [alloc_id, "pds"]
        with open(base_filename, "w") as f:
            result = subprocess.run(
                cmd,
                env={**os.environ, "NOMAD_ADDR": nomad_addr, "NOMAD_TOKEN": nomad_token},
                stdout=f, stderr=subprocess.STDOUT
            )

    if result.returncode == 0:
        print_success(f"Logs saved to: {base_filename}")
    else:
        print_error(f"Failed to fetch logs (exit code {result.returncode})")
        raise click.Abort()
