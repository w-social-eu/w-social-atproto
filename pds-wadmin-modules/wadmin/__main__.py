"""
Entry point for wadmin CLI when run as a module.
Usage: python -m wadmin [command] [args...]
"""

from .cli import cli

if __name__ == "__main__":
    cli()
