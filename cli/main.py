"""Main CLI entry point."""

import asyncio
import click
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from quantumshield.core.engine import QuantumShieldEngine
from quantumshield.config.logging_config import setup_logging, get_logger
from quantumshield.config.settings import get_settings

logger = get_logger(__name__)


@click.group()
@click.option("--log-level", default="INFO", help="Log level")
def cli(log_level):
    """QuantumShield CLI."""
    setup_logging(log_level)


@cli.command()
def start():
    """Start QuantumShield engine."""
    click.echo("Starting QuantumShield...")
    
    async def run():
        engine = QuantumShieldEngine()
        try:
            await engine.start()
        except KeyboardInterrupt:
            click.echo("\nShutting down...")
            await engine.stop()
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
            await engine.stop()
    
    asyncio.run(run())


@cli.command()
def stop():
    """Stop QuantumShield engine."""
    click.echo("Stopping QuantumShield...")
    # Would implement stop logic


@cli.command()
def status():
    """Show system status."""
    click.echo("QuantumShield Status:")
    click.echo("  Status: Running")
    click.echo("  Version: 1.0.0")


@cli.command()
@click.argument("rule_file")
def load_rules(rule_file):
    """Load firewall rules from file."""
    click.echo(f"Loading rules from {rule_file}...")


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()

