"""Command-line interface for PQC Migration Audit."""

import click


@click.command()
@click.version_option()
def main():
    """PQC Migration Audit CLI - Scan for quantum-vulnerable cryptography."""
    click.echo("🔐 PQC Migration Audit")
    click.echo("This is a placeholder CLI. Implementation coming soon!")


if __name__ == "__main__":
    main()