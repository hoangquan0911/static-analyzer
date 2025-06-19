"""
Command-line interface for the Smart Analyzer.

This module provides a rich CLI with tab completion and comprehensive
command options for analyzing Solidity smart contracts.
"""

import click
import rich.console
import rich.table
import rich.progress
import rich.panel
from pathlib import Path
from typing import List, Optional
from .analyzer import Analyzer
from .utils import timing_context
from .findings import Severity

# Try to import click-shell for tab completion
try:
    from click_shell import shell
    SHELL_AVAILABLE = True
except ImportError:
    SHELL_AVAILABLE = False
    shell = click.group

# Rich console for beautiful output
console = rich.console.Console()


def get_available_commands(ctx, args, incomplete):
    """Get available commands for tab completion."""
    commands = [
        'analyze',
        'test',
        'test-comprehensive',
        'list-detectors',
        'help',
        'version'
    ]
    return [cmd for cmd in commands if incomplete.lower() in cmd.lower()]


def get_available_options(ctx, args, incomplete):
    """Get available options for tab completion."""
    options = [
        '--help',
        '--version',
        '--debug',
        '--verbose',
        '--output',
        '--format',
        '--severity',
        '--detectors',
        '--exclude',
        '--config'
    ]
    return [opt for opt in options if incomplete.lower() in opt.lower()]


@shell(prompt='smart-analyzer> ', intro='🔍 Smart Analyzer - Type "help" for commands')
@click.option('--debug', is_flag=True, help='Enable debug mode for detailed analysis')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--version', is_flag=True, help='Show version information')
@click.pass_context
def cli(ctx, debug: bool, verbose: bool, version: bool):
    """
    🔍 Smart Analyzer - Comprehensive Solidity Security Analysis Tool
    
    A super-pythonic static analyzer for Solidity smart contracts that detects
    a wide range of security vulnerabilities using advanced AST analysis.
    
    \b
    Features:
    • 30+ vulnerability detectors
    • Reentrancy, Oracle manipulation, Signature replay
    • Access control, Flash loan, Front-running
    • Integer overflow, Timestamp dependence
    • And many more security issues
    
    \b
    Quick Start:
    • analyze contracts/
    • test
    • test-comprehensive
    • list-detectors
    """
    
    # Enable debug mode globally
    if debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)
        console.print("[yellow]🔧 Debug mode enabled[/yellow]")
    
    # Show version
    if version:
        console.print("[bold blue]Smart Analyzer v2.0.0[/bold blue]")
        console.print("Comprehensive Solidity Security Analysis Tool")
        return
    
    # Show help if no command provided
    if ctx.invoked_subcommand is None:
        console.print(cli.get_help())


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for results')
@click.option('--format', '-f', type=click.Choice(['table', 'json', 'csv']), default='table', help='Output format')
@click.option('--severity', '-s', type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']), multiple=True, help='Filter by severity')
@click.option('--categories', '-c', multiple=True, help='Detector categories to run (security, best_practices, gas_optimization, documentation)')
@click.option('--detectors', '-d', multiple=True, help='Specific detectors to run')
@click.option('--exclude', '-e', multiple=True, help='Detectors to exclude')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def analyze(path: str, output: Optional[str], format: str, severity: tuple, categories: tuple, detectors: tuple, exclude: tuple, debug: bool, verbose: bool):
    """
    Analyze Solidity smart contracts for security vulnerabilities.
    
    PATH: Directory or file to analyze
    
    \b
    Examples:
    • analyze contracts/
    • analyze contracts/MyContract.sol
    • analyze . --severity HIGH --format json
    • analyze contracts/ --categories security best_practices
    • analyze contracts/ --detectors reentrancy oracle_manipulation
    """
    
    console.print(f"[bold green]🔍 Analyzing: {path}[/bold green]")
    
    # Create analyzer with category filtering
    analyzer = Analyzer(categories=list(categories) if categories else None)
    
    # Configure detectors
    if detectors:
        analyzer.enabled_detectors = list(detectors)
        console.print(f"[blue]📋 Enabled detectors: {', '.join(detectors)}[/blue]")
    
    if exclude:
        analyzer.disabled_detectors = list(exclude)
        console.print(f"[blue]🚫 Excluded detectors: {', '.join(exclude)}[/blue]")
    
    # Analyze
    with timing_context("Analysis completed"):
        if Path(path).is_file():
            findings = analyzer.analyze_contract(path)
        else:
            findings = analyzer.analyze_contracts(path)
    
    # Filter by severity
    if severity:
        severity_levels = [Severity(s.upper()) for s in severity]
        findings = [f for f in findings if f.severity in severity_levels]
    
    # Output results
    if format == 'table':
        display_findings_table(findings, verbose)
    elif format == 'json':
        display_findings_json(findings, output)
    elif format == 'csv':
        display_findings_csv(findings, output)
    
    # Summary
    if findings:
        console.print(f"\n[bold red]⚠️  Found {len(findings)} security issues[/bold red]")
    else:
        console.print(f"\n[bold green]✅ No security issues found[/bold green]")


@cli.command()
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def test(debug: bool, verbose: bool):
    """
    Run basic test suite to verify analyzer functionality.
    
    \b
    Tests:
    • Reentrancy detection
    • Integer overflow detection
    • tx.origin usage detection
    • Unchecked call detection
    • Signature replay detection
    """
    
    console.print("[bold blue]🧪 Running Basic Test Suite[/bold blue]")
    
    # Import and run basic tests
    try:
        import pytest
        import sys
        from pathlib import Path
        
        test_path = Path(__file__).parent.parent / "tests" / "test_basic.py"
        
        if test_path.exists():
            with timing_context("Basic tests completed"):
                result = pytest.main([str(test_path), "-v" if verbose else "-q"])
            
            if result == 0:
                console.print("[bold green]✅ All basic tests passed[/bold green]")
            else:
                console.print("[bold red]❌ Some basic tests failed[/bold red]")
        else:
            console.print("[bold red]❌ Test file not found[/bold red]")
            
    except ImportError:
        console.print("[bold red]❌ pytest not installed. Run: pip install pytest[/bold red]")


@cli.command()
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def test_comprehensive(debug: bool, verbose: bool):
    """
    Run comprehensive test suite with all vulnerability detectors.
    
    \b
    Tests:
    • All 30+ vulnerability detectors
    • Real contract examples
    • False positive prevention
    • Performance tests
    • Edge cases
    """
    
    console.print("[bold blue]🧪 Running Comprehensive Test Suite[/bold blue]")
    
    # Import and run comprehensive tests
    try:
        import pytest
        import sys
        from pathlib import Path
        
        test_path = Path(__file__).parent.parent / "tests" / "test_comprehensive_detectors.py"
        
        if test_path.exists():
            with timing_context("Comprehensive tests completed"):
                result = pytest.main([str(test_path), "-v" if verbose else "-q"])
            
            if result == 0:
                console.print("[bold green]✅ All comprehensive tests passed[/bold green]")
            else:
                console.print("[bold red]❌ Some comprehensive tests failed[/bold red]")
        else:
            console.print("[bold red]❌ Comprehensive test file not found[/bold red]")
            
    except ImportError:
        console.print("[bold red]❌ pytest not installed. Run: pip install pytest[/bold red]")


@cli.command()
def list_detectors():
    """
    List all available detectors organized by category.
    
    \b
    Categories:
    • security: Critical security vulnerabilities
    • best_practices: Code quality and best practices
    • gas_optimization: Gas efficiency issues
    • documentation: Documentation and naming issues
    """
    
    console.print("[bold blue]📋 Available Detectors by Category[/bold blue]")
    
    # Create analyzer to get category information
    analyzer = Analyzer()
    
    # Get category summary
    category_summary = analyzer.get_category_summary()
    
    # Display detectors by category
    for category in sorted(category_summary.keys()):
        detectors = analyzer.get_detectors_by_category(category)
        
        # Category header
        category_name = category.replace('_', ' ').title()
        console.print(f"\n[bold cyan]{category_name} ({len(detectors)} detectors):[/bold cyan]")
        
        # Create table for this category
        table = rich.table.Table(show_header=True, header_style="bold magenta")
        table.add_column("Detector", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Severity", style="yellow")
        
        for name, info in detectors.items():
            severity_color = {
                "LOW": "green",
                "MEDIUM": "yellow", 
                "HIGH": "red",
                "CRITICAL": "bold red"
            }.get(info.severity, "white")
            
            table.add_row(
                info.display_name,
                info.description,
                f"[{severity_color}]{info.severity}[/{severity_color}]"
            )
        
        console.print(table)
    
    # Show category summary
    console.print(f"\n[bold green]📊 Total: {sum(category_summary.values())} detectors across {len(category_summary)} categories[/bold green]")


def display_findings_table(findings: List, verbose: bool = False):
    """Display findings in a rich table format."""
    
    if not findings:
        console.print("[green]✅ No security issues found[/green]")
        return
    
    # Create table
    table = rich.table.Table(title="Security Findings")
    table.add_column("Detector", style="cyan", no_wrap=True)
    table.add_column("Severity", style="yellow")
    table.add_column("Message", style="white")
    table.add_column("Line", style="green")
    table.add_column("File", style="blue")
    
    if verbose:
        table.add_column("Source Code", style="dim")
    
    # Add findings
    for finding in findings:
        file_name = Path(finding.file_path).name if finding.file_path else "Unknown"
        
        row = [
            finding.__class__.__name__.replace("Finding", ""),
            finding.severity.value,
            finding.message,
            str(finding.line_number),
            file_name
        ]
        
        if verbose:
            row.append(finding.source_code[:100] + "..." if len(finding.source_code) > 100 else finding.source_code)
        
        table.add_row(*row)
    
    console.print(table)


def display_findings_json(findings: List, output: Optional[str] = None):
    """Display findings in JSON format."""
    
    import json
    
    findings_data = []
    for finding in findings:
        findings_data.append({
            "detector": finding.__class__.__name__.replace("Finding", ""),
            "severity": finding.severity.value,
            "message": finding.message,
            "line_number": finding.line_number,
            "file_path": finding.file_path,
            "source_code": finding.source_code
        })
    
    json_output = json.dumps(findings_data, indent=2)
    
    if output:
        with open(output, 'w') as f:
            f.write(json_output)
        console.print(f"[green]📄 Results saved to {output}[/green]")
    else:
        console.print(json_output)


def display_findings_csv(findings: List, output: Optional[str] = None):
    """Display findings in CSV format."""
    
    import csv
    import io
    
    output_buffer = io.StringIO()
    writer = csv.writer(output_buffer)
    
    # Write header
    writer.writerow(["Detector", "Severity", "Message", "Line", "File", "Source Code"])
    
    # Write findings
    for finding in findings:
        file_name = Path(finding.file_path).name if finding.file_path else "Unknown"
        writer.writerow([
            finding.__class__.__name__.replace("Finding", ""),
            finding.severity.value,
            finding.message,
            finding.line_number,
            file_name,
            finding.source_code
        ])
    
    csv_output = output_buffer.getvalue()
    
    if output:
        with open(output, 'w') as f:
            f.write(csv_output)
        console.print(f"[green]📄 Results saved to {output}[/green]")
    else:
        console.print(csv_output)


def main():
    """Main entry point for the CLI."""
    if not SHELL_AVAILABLE:
        console.print("[yellow]⚠️  Tab completion not available. Install click-shell: pip install click-shell[/yellow]")
    
    cli()


if __name__ == "__main__":
    main()
