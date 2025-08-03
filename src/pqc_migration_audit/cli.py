"""Command-line interface for PQC Migration Audit."""

import click
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

from .core import CryptoAuditor, RiskAssessment, Severity
from .reporters import JSONReporter, HTMLReporter, SARIFReporter, ConsoleReporter


console = Console()


@click.group()
@click.version_option(version="0.1.0")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx: click.Context, verbose: bool):
    """PQC Migration Audit - Post-Quantum Cryptography Vulnerability Scanner.
    
    Identify quantum-vulnerable cryptographic implementations and get 
    recommendations for migration to post-quantum secure alternatives.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), 
              help='Output file path')
@click.option('--format', '-f', 'output_format', 
              type=click.Choice(['json', 'html', 'sarif', 'console']), 
              default='console', help='Output format')
@click.option('--languages', '-l', multiple=True,
              help='Limit scan to specific languages (python, java, go, etc.)')
@click.option('--exclude', '-e', multiple=True,
              help='Exclude patterns from scan (e.g., "*/tests/*")')
@click.option('--severity-threshold', '-s',
              type=click.Choice(['low', 'medium', 'high', 'critical']),
              default='low', help='Minimum severity level to report')
@click.option('--generate-patches', is_flag=True,
              help='Generate migration patches for found vulnerabilities')
@click.option('--config', '-c', type=click.Path(exists=True, path_type=Path),
              help='Path to configuration file')
@click.pass_context
def scan(ctx: click.Context, path: Path, output: Optional[Path], 
         output_format: str, languages: tuple, exclude: tuple,
         severity_threshold: str, generate_patches: bool, config: Optional[Path]):
    """Scan directory for quantum-vulnerable cryptographic implementations."""
    
    verbose = ctx.obj.get('verbose', False)
    
    # Load configuration
    audit_config = _load_config(config) if config else {}
    
    # Initialize auditor
    auditor = CryptoAuditor(config=audit_config)
    
    # Prepare scan options
    scan_options = {}
    if exclude:
        scan_options['exclude_patterns'] = list(exclude)
    if languages:
        scan_options['languages'] = list(languages)
    
    # Show scan start message
    if verbose or output_format == 'console':
        console.print(f"\n🔍 Scanning {path} for quantum-vulnerable cryptography...\n")
    
    # Perform scan with progress indicator
    try:
        if output_format == 'console':
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Scanning files...", total=None)
                results = auditor.scan_directory(str(path), **scan_options)
                progress.update(task, description="Scan complete!")
        else:
            results = auditor.scan_directory(str(path), **scan_options)
            
    except Exception as e:
        console.print(f"❌ Error during scan: {e}", style="red")
        sys.exit(1)
    
    # Filter results by severity threshold
    severity_levels = ['low', 'medium', 'high', 'critical']
    min_level_index = severity_levels.index(severity_threshold)
    filtered_vulnerabilities = [
        vuln for vuln in results.vulnerabilities
        if severity_levels.index(vuln.severity.value) >= min_level_index
    ]
    results.vulnerabilities = filtered_vulnerabilities
    
    # Generate migration plan if requested
    migration_plan = None
    if generate_patches:
        migration_plan = auditor.create_migration_plan(results)
    
    # Generate output
    if output_format == 'console':
        reporter = ConsoleReporter()
        reporter.generate_report(results, console=console)
        
        if migration_plan and verbose:
            _display_migration_plan(migration_plan)
            
    else:
        if not output:
            # Default output file names
            output_extensions = {
                'json': '.json',
                'html': '.html', 
                'sarif': '.sarif'
            }
            output = Path(f"pqc-audit-report{output_extensions[output_format]}")
        
        # Generate report
        if output_format == 'json':
            reporter = JSONReporter()
            reporter.generate_report(results, output, migration_plan=migration_plan)
        elif output_format == 'html':
            reporter = HTMLReporter()
            reporter.generate_report(results, output, migration_plan=migration_plan)
        elif output_format == 'sarif':
            reporter = SARIFReporter()
            reporter.generate_report(results, output)
        
        console.print(f"✅ Report generated: {output}")


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path))
@click.option('--baseline', '-b', type=click.Path(exists=True, path_type=Path),
              help='Baseline scan results for comparison')
@click.option('--output', '-o', type=click.Path(path_type=Path),
              help='Output file for progress report')
@click.pass_context
def progress(ctx: click.Context, path: Path, baseline: Optional[Path], 
             output: Optional[Path]):
    """Track migration progress over time."""
    
    # Load baseline if provided
    baseline_data = None
    if baseline:
        try:
            with open(baseline, 'r') as f:
                baseline_data = json.load(f)
        except Exception as e:
            console.print(f"❌ Error loading baseline: {e}", style="red")
            sys.exit(1)
    
    # Perform current scan
    auditor = CryptoAuditor()
    current_results = auditor.scan_directory(str(path))
    
    # Calculate progress
    progress_report = _calculate_progress(current_results, baseline_data)
    
    # Output results
    if output:
        with open(output, 'w') as f:
            json.dump(progress_report, f, indent=2)
        console.print(f"✅ Progress report saved: {output}")
    else:
        _display_progress_report(progress_report)


@cli.command()
@click.argument('scan_results', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path),
              help='Output file for dashboard')
@click.pass_context
def dashboard(ctx: click.Context, scan_results: Path, output: Optional[Path]):
    """Generate interactive dashboard from scan results."""
    
    try:
        with open(scan_results, 'r') as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"❌ Error loading scan results: {e}", style="red")
        sys.exit(1)
    
    # Generate dashboard HTML
    dashboard_html = _generate_dashboard_html(data)
    
    output_file = output or Path("pqc-dashboard.html")
    with open(output_file, 'w') as f:
        f.write(dashboard_html)
    
    console.print(f"✅ Dashboard generated: {output_file}")
    console.print(f"🌐 Open in browser: file://{output_file.absolute()}")


@cli.command()
@click.argument('vulnerability_file', type=click.Path(exists=True, path_type=Path))
@click.option('--output-dir', '-o', type=click.Path(path_type=Path),
              default=Path("patches"), help='Output directory for patches')
@click.option('--language', '-l', 
              type=click.Choice(['python', 'java', 'go', 'javascript']),
              help='Target language for patches')
@click.pass_context
def patch(ctx: click.Context, vulnerability_file: Path, output_dir: Path,
          language: Optional[str]):
    """Generate migration patches for vulnerabilities."""
    
    try:
        with open(vulnerability_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"❌ Error loading vulnerability file: {e}", style="red")
        sys.exit(1)
    
    # Create output directory
    output_dir.mkdir(exist_ok=True)
    
    # Generate patches
    patches_generated = 0
    for vuln in data.get('vulnerabilities', []):
        if language and _detect_language_from_file(vuln['file_path']) != language:
            continue
            
        patch_content = _generate_patch(vuln)
        if patch_content:
            patch_file = output_dir / f"patch_{patches_generated + 1}.patch"
            with open(patch_file, 'w') as f:
                f.write(patch_content)
            patches_generated += 1
    
    console.print(f"✅ Generated {patches_generated} patches in {output_dir}")


def _load_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from file."""
    try:
        with open(config_path, 'r') as f:
            if config_path.suffix.lower() in ['.yml', '.yaml']:
                import yaml
                return yaml.safe_load(f)
            else:
                return json.load(f)
    except Exception as e:
        console.print(f"❌ Error loading config: {e}", style="red")
        return {}


def _display_migration_plan(plan: Dict[str, Any]):
    """Display migration plan in console."""
    console.print("\n📋 Migration Plan", style="bold blue")
    
    # Summary
    summary = plan['summary']
    table = Table(title="Vulnerability Summary")
    table.add_column("Severity", style="cyan")
    table.add_column("Count", justify="right", style="magenta")
    
    table.add_row("Critical", str(summary['critical']))
    table.add_row("High", str(summary['high']))
    table.add_row("Medium", str(summary['medium']))
    table.add_row("Low", str(summary['low']))
    
    console.print(table)
    
    # Phases
    for phase in plan['migration_phases']:
        console.print(f"\n🎯 Phase {phase['phase']}: {phase['name']}")
        console.print(f"   {phase['description']}")
        console.print(f"   Estimated effort: {phase['estimated_effort']}")
        console.print(f"   Items: {len(phase['vulnerabilities'])}")


def _calculate_progress(current_results, baseline_data) -> Dict[str, Any]:
    """Calculate migration progress compared to baseline."""
    current_count = len(current_results.vulnerabilities)
    baseline_count = len(baseline_data.get('vulnerabilities', [])) if baseline_data else current_count
    
    progress_percentage = max(0, (baseline_count - current_count) / baseline_count * 100) if baseline_count > 0 else 0
    
    return {
        "current_vulnerabilities": current_count,
        "baseline_vulnerabilities": baseline_count,
        "progress_percentage": round(progress_percentage, 1),
        "vulnerabilities_fixed": max(0, baseline_count - current_count),
        "scan_date": current_results.timestamp
    }


def _display_progress_report(report: Dict[str, Any]):
    """Display progress report in console."""
    console.print("\n📊 Migration Progress Report", style="bold green")
    
    progress_text = Text()
    progress_text.append(f"Progress: {report['progress_percentage']}%\n", style="bold")
    progress_text.append(f"Vulnerabilities remaining: {report['current_vulnerabilities']}\n")
    progress_text.append(f"Vulnerabilities fixed: {report['vulnerabilities_fixed']}\n")
    progress_text.append(f"Scan date: {report['scan_date']}")
    
    console.print(Panel(progress_text, title="Summary"))


def _generate_dashboard_html(data: Dict[str, Any]) -> str:
    """Generate HTML dashboard from scan data."""
    # Simple dashboard template
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PQC Migration Dashboard</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .metric {{ display: inline-block; margin: 10px; padding: 20px; border: 1px solid #ddd; }}
            .critical {{ background-color: #ffebee; }}
            .high {{ background-color: #fff3e0; }}
            .medium {{ background-color: #f3e5f5; }}
            .low {{ background-color: #e8f5e8; }}
        </style>
    </head>
    <body>
        <h1>🔐 PQC Migration Dashboard</h1>
        
        <div class="metrics">
            <div class="metric critical">
                <h3>Critical</h3>
                <p>{data.get('critical_count', 0)}</p>
            </div>
            <div class="metric high">
                <h3>High</h3>
                <p>{data.get('high_count', 0)}</p>
            </div>
            <div class="metric medium">
                <h3>Medium</h3>
                <p>{data.get('medium_count', 0)}</p>
            </div>
            <div class="metric low">
                <h3>Low</h3>
                <p>{data.get('low_count', 0)}</p>
            </div>
        </div>
        
        <div id="riskChart" style="width:100%;height:400px;"></div>
        
        <script>
            // Add interactive charts here
            var riskData = {{
                x: ['RSA', 'ECC', 'DSA'],
                y: [10, 8, 5],
                type: 'bar'
            }};
            
            Plotly.newPlot('riskChart', [riskData], {{
                title: 'Vulnerabilities by Algorithm'
            }});
        </script>
    </body>
    </html>
    """


def _detect_language_from_file(file_path: str) -> str:
    """Detect programming language from file extension."""
    ext = Path(file_path).suffix.lower()
    ext_map = {
        '.py': 'python',
        '.java': 'java', 
        '.go': 'go',
        '.js': 'javascript',
        '.ts': 'javascript'
    }
    return ext_map.get(ext, 'unknown')


def _generate_patch(vulnerability: Dict[str, Any]) -> str:
    """Generate a patch for a vulnerability."""
    # Simple patch generation example
    language = _detect_language_from_file(vulnerability['file_path'])
    algorithm = vulnerability['algorithm']
    
    if language == 'python' and algorithm == 'RSA':
        return f"""
# Patch for {vulnerability['file_path']}:{vulnerability['line_number']}
# Replace RSA with ML-KEM (Kyber) for key exchange

# Before (quantum-vulnerable):
# {vulnerability['code_snippet']}

# After (post-quantum secure):
from pqc_migration.crypto import ML_KEM_768

# Generate PQC keypair
private_key, public_key = ML_KEM_768.generate_keypair()

# Encapsulation (equivalent to RSA encryption)
ciphertext, shared_secret = ML_KEM_768.encapsulate(public_key)

# Decapsulation (equivalent to RSA decryption)  
shared_secret = ML_KEM_768.decapsulate(private_key, ciphertext)
"""
    
    return None


def main():
    """Main entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n⚠️  Scan interrupted by user", style="yellow")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n❌ Unexpected error: {e}", style="red")
        sys.exit(1)


if __name__ == '__main__':
    main()