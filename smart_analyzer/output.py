"""
Output formatting for the Solidity Static Analyzer.

This module provides various output formatters and generators
for beautiful, extensible output.
"""

import os
from typing import Dict, Any, List, Iterator
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from .findings import FindingCollector, Finding, Severity


class OutputFormatter:
    """Base class for output formatters."""
    
    def __init__(self, console: Console = None):
        self.console = console or Console()
    
    def format_findings(self, collector: FindingCollector) -> Any:
        """Format findings for output."""
        raise NotImplementedError
    
    def format_summary(self, results: Dict[str, Any]) -> Any:
        """Format summary for output."""
        raise NotImplementedError


class RichFormatter(OutputFormatter):
    """Rich-based output formatter with beautiful tables."""
    
    def format_findings(self, collector: FindingCollector) -> Table:
        """Format findings as a Rich table."""
        return collector.render()
    
    def format_summary(self, results: Dict[str, Any]) -> Table:
        """Format summary as a Rich table."""
        summary = results.get("summary", {})
        
        if not summary:
            return Text("No findings to summarize", style="dim")
        
        table = Table(title="Analysis Summary")
        table.add_column("Vulnerability Type", style="cyan")
        table.add_column("Count", style="yellow")
        
        for vuln_type, count in summary.items():
            table.add_row(vuln_type, str(count))
        
        return table
    
    def format_file_breakdown(self, results: Dict[str, Any]) -> Table:
        """Format file breakdown as a Rich table."""
        findings_by_file = results.get("findings_by_file", {})
        
        if not findings_by_file:
            return Text("No files with findings", style="dim")
        
        table = Table(title="Findings by File")
        table.add_column("File", style="cyan")
        table.add_column("Findings", style="yellow")
        
        for file_name, findings in findings_by_file.items():
            # Show only the contract name, not the full path
            clean_name = os.path.basename(file_name) if file_name else "Unknown"
            table.add_row(clean_name, str(len(findings)))
        
        return table
    
    def format_detector_info(self, analyzer) -> Table:
        """Format detector information as a Rich table."""
        detector_info = analyzer.get_detector_info()
        
        table = Table(title="Detector Information")
        table.add_column("Name", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Severity", style="magenta")
        
        for name, info in detector_info.items():
            table.add_row(info.display_name, info.description, info.severity)
        
        return table


class JSONFormatter(OutputFormatter):
    """JSON-based output formatter."""
    
    def format_findings(self, collector: FindingCollector) -> str:
        """Format findings as JSON."""
        import json
        return json.dumps(collector.to_dict(), indent=2)
    
    def format_summary(self, results: Dict[str, Any]) -> str:
        """Format summary as JSON."""
        import json
        return json.dumps(results, indent=2)


class MarkdownFormatter(OutputFormatter):
    """Markdown-based output formatter."""
    
    def format_findings(self, collector: FindingCollector) -> str:
        """Format findings as Markdown."""
        if not collector:
            return "# Analysis Results\n\n✅ No issues detected!"
        
        md = ["# Analysis Results\n"]
        md.append(f"## Found {len(collector)} Issues\n")
        md.append("| Type | Severity | Message | Line | File |")
        md.append("|------|----------|---------|------|------|")
        
        for finding in collector:
            line_str = str(finding.line_number) if finding.line_number else "N/A"
            file_str = os.path.basename(finding.file_path) if finding.file_path else "N/A"
            md.append(f"| {finding.type} | {finding.severity.value} | {finding.message} | {line_str} | {file_str} |")
        
        return "\n".join(md)
    
    def format_summary(self, results: Dict[str, Any]) -> str:
        """Format summary as Markdown."""
        summary = results.get("summary", {})
        
        if not summary:
            return "## Summary\n\nNo findings to summarize."
        
        md = ["## Summary\n"]
        md.append("| Vulnerability Type | Count |")
        md.append("|-------------------|-------|")
        
        for vuln_type, count in summary.items():
            md.append(f"| {vuln_type} | {count} |")
        
        return "\n".join(md)


class OutputManager:
    """Manager for different output formats."""
    
    def __init__(self, console: Console = None):
        self.console = console or Console()
        self.formatters = {
            "rich": RichFormatter(console),
            "json": JSONFormatter(console),
            "markdown": MarkdownFormatter(console)
        }
    
    def get_formatter(self, format_type: str = "rich") -> OutputFormatter:
        """Get a formatter by type."""
        return self.formatters.get(format_type, self.formatters["rich"])
    
    def print_analysis_results(self, results: Dict[str, Any], format_type: str = "rich") -> None:
        """Print complete analysis results."""
        formatter = self.get_formatter(format_type)
        collector = results["collector"]
        
        # Print findings
        self.console.print(formatter.format_findings(collector))
        
        # Print summary
        if results.get("summary"):
            self.console.print()
            self.console.print(formatter.format_summary(results))
        
        # Print file breakdown
        if results.get("findings_by_file"):
            self.console.print()
            self.console.print(formatter.format_file_breakdown(results))
        
        # Print total
        self.console.print(f"\n[bold]Total findings: {results['total_findings']}[/bold]")
    
    def print_detector_info(self, analyzer, format_type: str = "rich") -> None:
        """Print detector information."""
        formatter = self.get_formatter(format_type)
        self.console.print(formatter.format_detector_info(analyzer))
    
    def save_results(self, results: Dict[str, Any], filename: str, format_type: str = "json") -> None:
        """Save results to a file."""
        formatter = self.get_formatter(format_type)
        
        if format_type == "json":
            content = formatter.format_summary(results)
        elif format_type == "markdown":
            content = formatter.format_findings(results["collector"]) + "\n\n" + formatter.format_summary(results)
        else:
            raise ValueError(f"Unsupported format for file output: {format_type}")
        
        with open(filename, 'w') as f:
            f.write(content)
        
        self.console.print(f"[green]Results saved to {filename}[/green]")


def create_progress_bar(description: str = "Processing", console: Console = None) -> Progress:
    """Create a progress bar with consistent styling."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console or Console()
    )


def print_banner(console: Console = None) -> None:
    """Print a beautiful banner."""
    console = console or Console()
    console.print("[bold blue]🐍 Solidity Static Analyzer - Super-Pythonic Edition[/bold blue]")
    console.print("[dim]Advanced vulnerability detection with beautiful output[/dim]")
    console.print()
