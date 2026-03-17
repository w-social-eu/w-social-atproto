"""
Utility functions for formatting output and handling common operations.
"""

from typing import Optional
from rich.console import Console
from rich.theme import Theme

# Custom theme for consistent styling
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "dim": "dim",
})

console = Console(theme=custom_theme)


def print_error(message: str, suggestion: Optional[str] = None):
    """
    Print an error message with optional suggestion.

    Args:
        message: Error message to display
        suggestion: Optional suggestion for how to fix the error
    """
    console.print(f"❌ ERROR: {message}", style="error")
    if suggestion:
        console.print(f"   {suggestion}", style="dim")


def print_warning(message: str):
    """
    Print a warning message.

    Args:
        message: Warning message to display
    """
    console.print(f"⚠️  WARNING: {message}", style="warning")


def print_success(message: str):
    """
    Print a success message.

    Args:
        message: Success message to display
    """
    console.print(f"✅ {message}", style="success")


def print_info(message: str):
    """
    Print an informational message.

    Args:
        message: Info message to display
    """
    console.print(message, style="info")


def format_timestamp(timestamp: Optional[str]) -> str:
    """
    Format ISO timestamp for display.

    Args:
        timestamp: ISO 8601 timestamp string

    Returns:
        Formatted timestamp string
    """
    if not timestamp:
        return "N/A"

    try:
        from dateutil import parser
        dt = parser.isoparse(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, ImportError):
        return timestamp


def confirm_action(message: str, default: bool = False) -> bool:
    """
    Ask user to confirm an action.

    Args:
        message: Confirmation message to display
        default: Default value if user presses Enter

    Returns:
        True if user confirms, False otherwise
    """
    from rich.prompt import Confirm
    return Confirm.ask(message, default=default, console=console)


def require_brevo_config(config) -> None:
    """
    Check if Brevo configuration is available, exit if not.

    Args:
        config: Config instance to check

    Raises:
        SystemExit: If Brevo is not configured
    """
    if not config.has_brevo_config():
        print_error(
            "Brevo email integration not configured",
            "Set PDS_BREVO_API_KEY and PDS_BREVO_INVITATION_TEMPLATE_ID environment variables"
        )
        raise SystemExit(1)


def require_nomad_config(config) -> None:
    """
    Check if Nomad configuration is available, exit if not.

    Args:
        config: Config instance to check

    Raises:
        SystemExit: If Nomad is not configured
    """
    if not config.has_nomad_config():
        print_error(
            "Nomad integration not configured",
            "Use pds-wadmin-dev/stage/prod or set NOMAD_ADDR and PDS_NOMAD_JOB_NAME"
        )
        raise SystemExit(1)
