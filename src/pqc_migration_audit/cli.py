"""Command-line interface for PQC Migration Audit."""

import click
import json
import sys
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
import traceback

from .core import CryptoAuditor, RiskAssessment
from .types import Severity, CryptoAlgorithm
from .reporters import JSONReporter, HTMLReporter, SARIFReporter, ConsoleReporter
from .patch_generator import PQCPatchGenerator, PatchType
from .dashboard import MigrationDashboard
from .exceptions import (
    PQCAuditException, ScanException, ValidationException, SecurityException,
    FileSystemException, ScanTimeoutException, ExceptionHandler
)
from .validators import InputValidator


console = Console()


@click.group()
@click.version_option(version="0.1.0")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.pass_context
def cli(ctx: click.Context, verbose: bool, debug: bool):
    """PQC Migration Audit - Post-Quantum Cryptography Vulnerability Scanner.
    
    Identify quantum-vulnerable cryptographic implementations and get 
    recommendations for migration to post-quantum secure alternatives.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['debug'] = debug
    
    # Configure logging
    log_level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if debug:
        console.print("🐛 Debug mode enabled", style="yellow")


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
    
    # Perform scan with enhanced error handling
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
    
    except ValidationException as e:
        console.print(f"❌ Input validation error: {e.message}", style="red")
        if verbose:
            console.print(f"Error code: {e.error_code}", style="dim")
            if e.details:
                console.print(f"Details: {e.details}", style="dim")
        sys.exit(1)
    
    except SecurityException as e:
        console.print(f"🚨 Security error: {e.message}", style="red bold")
        if verbose:
            console.print(f"Error code: {e.error_code}", style="dim")
        sys.exit(1)
    
    except FileSystemException as e:
        console.print(f"📁 File system error: {e.message}", style="red")
        if verbose:
            console.print(f"Error code: {e.error_code}", style="dim")
        sys.exit(1)
    
    except ScanTimeoutException as e:
        console.print(f"⏰ Scan timeout: {e.message}", style="yellow")
        console.print("Consider using --exclude patterns to reduce scan scope", style="yellow")
        if verbose:
            console.print(f"Files processed: {e.details.get('files_processed', 0)}", style="dim")
        sys.exit(1)
    
    except ScanException as e:
        console.print(f"❌ Scan error: {e.message}", style="red")
        if verbose:
            console.print(f"Error code: {e.error_code}", style="dim")
            if e.details:
                console.print(f"Details: {e.details}", style="dim")
        sys.exit(1)
    
    except PQCAuditException as e:
        console.print(f"❌ PQC Audit error: {e.message}", style="red")
        if verbose:
            console.print(f"Error type: {type(e).__name__}", style="dim")
            console.print(f"Error code: {e.error_code}", style="dim")
        sys.exit(1)
    
    except KeyboardInterrupt:
        console.print("\n⚠️  Scan interrupted by user", style="yellow")
        sys.exit(130)  # Standard exit code for Ctrl+C
    
    except Exception as e:
        console.print(f"❌ Unexpected error: {str(e)}", style="red")
        if verbose or ctx.obj.get('debug'):
            console.print("\nFull traceback:", style="dim")
            console.print(traceback.format_exc(), style="dim")
        console.print("\nPlease report this issue at: https://github.com/danieleschmidt/pqc-migration-audit/issues", style="blue")
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
@click.argument('path', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path),
              help='Output file for dashboard')
@click.option('--historical-data', type=click.Path(exists=True, path_type=Path),
              help='Path to historical scan data for trend analysis')
@click.pass_context
def dashboard(ctx: click.Context, path: Path, output: Optional[Path], 
             historical_data: Optional[Path]):
    """Generate interactive dashboard from current scan."""
    
    # Perform fresh scan for dashboard
    auditor = CryptoAuditor()
    scan_results = auditor.scan_directory(str(path))
    
    # Load historical data if provided
    historical_data_list = None
    if historical_data:
        try:
            with open(historical_data, 'r') as f:
                historical_data_list = json.load(f)
        except Exception as e:
            console.print(f"⚠️  Warning: Could not load historical data: {e}", style="yellow")
    
    # Generate migration plan
    migration_plan = auditor.create_migration_plan(scan_results)
    
    # Generate dashboard
    dashboard_generator = MigrationDashboard()
    output_file = output or Path("pqc-migration-dashboard.html")
    
    dashboard_html = dashboard_generator.generate_dashboard(
        scan_results, 
        historical_data_list, 
        migration_plan, 
        output_file
    )
    
    console.print(f"✅ Interactive dashboard generated: {output_file}")
    console.print(f"🌐 Open in browser: file://{output_file.absolute()}")
    console.print(f"📊 Dashboard includes: risk metrics, timeline, migration plan, and progress tracking")


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path))
@click.option('--output-dir', '-o', type=click.Path(path_type=Path),
              default=Path("patches"), help='Output directory for patches')
@click.option('--language', '-l', 
              type=click.Choice(['python', 'java', 'go', 'javascript', 'c', 'cpp']),
              help='Target language for patches')
@click.option('--patch-type', '-t',
              type=click.Choice(['replace_rsa', 'replace_ecc', 'replace_dsa', 'hybrid_mode']),
              help='Type of patch to generate')
@click.option('--migration-guide', is_flag=True,
              help='Generate comprehensive migration guide')
@click.pass_context
def patch(ctx: click.Context, path: Path, output_dir: Path,
          language: Optional[str], patch_type: Optional[str], migration_guide: bool):
    """Generate PQC migration patches and guides."""
    
    # Perform scan to get vulnerabilities
    auditor = CryptoAuditor()
    scan_results = auditor.scan_directory(str(path))
    
    if not scan_results.vulnerabilities:
        console.print("✅ No vulnerabilities found - no patches needed!", style="green")
        return
    
    # Create output directory
    output_dir.mkdir(exist_ok=True)
    
    # Initialize patch generator
    patch_generator = PQCPatchGenerator()
    
    # Filter vulnerabilities by language if specified
    vulnerabilities = scan_results.vulnerabilities
    if language:
        vulnerabilities = [
            v for v in vulnerabilities 
            if patch_generator._detect_language(v.file_path) == language
        ]
    
    # Generate patches
    patches_generated = 0
    patch_type_enum = None
    if patch_type:
        patch_type_enum = PatchType(patch_type)
    
    console.print(f"\n🔧 Generating patches for {len(vulnerabilities)} vulnerabilities...")
    
    for i, vuln in enumerate(vulnerabilities):
        patch_content = patch_generator.generate_patch(vuln, patch_type_enum, language)
        if patch_content:
            # Create descriptive filename
            safe_filename = vuln.file_path.replace('/', '_').replace('\\', '_')
            patch_file = output_dir / f"{safe_filename}_line_{vuln.line_number}_{vuln.algorithm.value.lower()}.patch"
            
            with open(patch_file, 'w', encoding='utf-8') as f:
                f.write(patch_content)
            patches_generated += 1
            
            if ctx.obj.get('verbose'):
                console.print(f"  Generated: {patch_file.name}")
    
    # Generate comprehensive migration guide
    if migration_guide or patches_generated > 5:  # Auto-generate for large codebases
        guide_content = patch_generator.generate_migration_guide(vulnerabilities)
        guide_file = output_dir / "PQC_Migration_Guide.md"
        
        with open(guide_file, 'w', encoding='utf-8') as f:
            f.write(guide_content)
        
        console.print(f"📖 Comprehensive migration guide: {guide_file}")
    
    console.print(f"\n✅ Generated {patches_generated} patches in {output_dir}")
    console.print(f"🎯 Patch types: Individual vulnerability fixes and implementation examples")
    console.print(f"📚 Review patches carefully and test in development environment before applying")


@cli.command()
@click.argument('path', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path),
              help='Output file for comprehensive analysis')
@click.option('--include-patches', is_flag=True,
              help='Include patch generation in analysis')
@click.option('--include-dashboard', is_flag=True,
              help='Generate interactive dashboard')
@click.pass_context
def analyze(ctx: click.Context, path: Path, output: Optional[Path],
           include_patches: bool, include_dashboard: bool):
    """Comprehensive PQC security analysis with all features."""
    
    verbose = ctx.obj.get('verbose', False)
    
    console.print("\n🔍 Starting Comprehensive PQC Security Analysis...\n", style="bold blue")
    
    # Step 1: Core vulnerability scan
    console.print("📊 Phase 1: Vulnerability Detection")
    auditor = CryptoAuditor()
    scan_results = auditor.scan_directory(str(path))
    
    if verbose:
        console.print(f"   • Scanned {scan_results.scanned_files} files")
        console.print(f"   • Analyzed {scan_results.total_lines:,} lines of code")
        console.print(f"   • Found {len(scan_results.vulnerabilities)} vulnerabilities")
    
    # Step 2: Risk assessment
    console.print("⚠️  Phase 2: Risk Assessment")
    risk_assessment = RiskAssessment(scan_results)
    hndl_risk = risk_assessment.calculate_harvest_now_decrypt_later_risk()
    migration_hours = risk_assessment.migration_hours
    
    console.print(f"   • HNDL Risk Score: {hndl_risk}/100")
    console.print(f"   • Migration Effort: {migration_hours} hours")
    console.print(f"   • Risk Level: {risk_assessment._get_risk_level(hndl_risk)}")
    
    # Step 3: Migration planning
    console.print("📋 Phase 3: Migration Planning")
    migration_plan = auditor.create_migration_plan(scan_results)
    
    console.print(f"   • Critical items: {migration_plan['summary']['critical']}")
    console.print(f"   • High priority: {migration_plan['summary']['high']}")
    console.print(f"   • Migration phases: {len(migration_plan['migration_phases'])}")
    
    # Step 4: Generate patches if requested
    if include_patches and scan_results.vulnerabilities:
        console.print("🔧 Phase 4: Patch Generation")
        patch_generator = PQCPatchGenerator()
        
        patches_dir = Path("pqc_patches")
        patches_dir.mkdir(exist_ok=True)
        
        patches_generated = 0
        for vuln in scan_results.vulnerabilities[:10]:  # Limit to first 10 for demo
            patch_content = patch_generator.generate_patch(vuln)
            if patch_content:
                safe_filename = vuln.file_path.replace('/', '_').replace('\\', '_')
                patch_file = patches_dir / f"{safe_filename}_line_{vuln.line_number}.patch"
                
                with open(patch_file, 'w', encoding='utf-8') as f:
                    f.write(patch_content)
                patches_generated += 1
        
        # Generate migration guide
        guide_content = patch_generator.generate_migration_guide(scan_results.vulnerabilities)
        guide_file = patches_dir / "Migration_Guide.md"
        with open(guide_file, 'w', encoding='utf-8') as f:
            f.write(guide_content)
        
        console.print(f"   • Generated {patches_generated} patches")
        console.print(f"   • Created migration guide: {guide_file}")
    
    # Step 5: Generate dashboard if requested
    if include_dashboard:
        console.print("📊 Phase 5: Interactive Dashboard")
        dashboard_generator = MigrationDashboard()
        dashboard_file = Path("pqc_analysis_dashboard.html")
        
        dashboard_generator.generate_dashboard(
            scan_results, 
            None,  # No historical data for now
            migration_plan, 
            dashboard_file
        )
        
        console.print(f"   • Dashboard created: {dashboard_file}")
        console.print(f"   • Open in browser: file://{dashboard_file.absolute()}")
    
    # Step 6: Generate comprehensive report
    console.print("📄 Phase 6: Report Generation")
    output_file = output or Path("pqc_comprehensive_analysis.json")
    
    comprehensive_report = {
        "analysis_metadata": {
            "scan_path": str(path),
            "timestamp": scan_results.timestamp,
            "analysis_type": "comprehensive",
            "tool_version": "0.1.0"
        },
        "scan_results": {
            "files_scanned": scan_results.scanned_files,
            "lines_analyzed": scan_results.total_lines,
            "languages_detected": scan_results.languages_detected,
            "scan_duration": scan_results.scan_time
        },
        "vulnerability_summary": {
            "total_vulnerabilities": len(scan_results.vulnerabilities),
            "by_severity": {
                "critical": len([v for v in scan_results.vulnerabilities if v.severity == Severity.CRITICAL]),
                "high": len([v for v in scan_results.vulnerabilities if v.severity == Severity.HIGH]),
                "medium": len([v for v in scan_results.vulnerabilities if v.severity == Severity.MEDIUM]),
                "low": len([v for v in scan_results.vulnerabilities if v.severity == Severity.LOW])
            },
            "by_algorithm": {
                algo.value: len([v for v in scan_results.vulnerabilities if v.algorithm == algo])
                for algo in CryptoAlgorithm
            }
        },
        "risk_assessment": {
            "hndl_risk_score": hndl_risk,
            "risk_level": risk_assessment._get_risk_level(hndl_risk),
            "migration_effort_hours": migration_hours,
            "estimated_cost_usd": migration_hours * 150
        },
        "migration_plan": migration_plan,
        "recommendations": risk_assessment._generate_recommendations(hndl_risk),
        "vulnerabilities": [
            {
                "file_path": vuln.file_path,
                "line_number": vuln.line_number,
                "algorithm": vuln.algorithm.value,
                "severity": vuln.severity.value,
                "description": vuln.description,
                "recommendation": vuln.recommendation,
                "cwe_id": vuln.cwe_id
            }
            for vuln in scan_results.vulnerabilities
        ]
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(comprehensive_report, f, indent=2)
    
    console.print(f"   • Comprehensive report: {output_file}")
    
    # Summary
    console.print("\n✅ Analysis Complete!", style="bold green")
    console.print(f"📊 Found {len(scan_results.vulnerabilities)} vulnerabilities across {scan_results.scanned_files} files")
    console.print(f"⚠️  Risk Level: {risk_assessment._get_risk_level(hndl_risk)}")
    console.print(f"⏱️  Estimated Migration: {migration_hours} hours")
    
    if hndl_risk >= 80:
        console.print("🚨 URGENT: High risk score indicates immediate action required!", style="red bold")
    elif hndl_risk >= 40:
        console.print("⚠️  MODERATE: Plan migration within next 18 months", style="yellow bold")
    else:
        console.print("✅ LOW: Develop migration plan for 2027 deadline", style="green")


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