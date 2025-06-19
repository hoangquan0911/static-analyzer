"""
Example plugin for the Solidity Static Analyzer.

This plugin demonstrates how to create custom detectors
that can be loaded dynamically.
"""

from typing import Dict, Any, List
from dataclasses import dataclass
from ..utils import detector, parse_src
from ..findings import Finding, Severity


@dataclass
class ExampleFinding(Finding):
    """Example finding for demonstration."""
    
    def __post_init__(self):
        self.type = "Example Vulnerability"
        if not self.severity:
            self.severity = Severity.LOW


@detector("example_vulnerability", "🔍 Example", "Example vulnerability detector for demonstration")
def detect_example_vulnerability(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """
    Example detector that looks for specific patterns.
    
    This is just for demonstration - it doesn't detect real vulnerabilities.
    """
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        
        # Example: detect calls to a specific function
        if expr.get("nodeType") == "Identifier" and expr.get("name") == "exampleFunction":
            line_num = parse_src(node.get("src"), file_path)
            findings.append(ExampleFinding(
                message="Example vulnerability detected (this is just a demo).",
                severity=Severity.LOW,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            )) 