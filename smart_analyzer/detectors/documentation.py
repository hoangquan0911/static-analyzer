"""
Documentation and naming detectors.

This module provides detectors for documentation quality
and naming convention issues.
"""

from typing import Dict, Any, List
from ..utils import detector, parse_src
from ..findings import (
    HardcodedFinding, DocumentationFinding, NamingFinding, Severity
)


@detector("hardcoded", "🔢 Hardcoded", "Detects hardcoded values", category="documentation")
def detect_hardcoded(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect hardcoded values."""
    if node.get("nodeType") == "Literal":
        value = node.get("value", "")
        if isinstance(value, str) and len(value) > 0:
            # Check for hardcoded addresses, URLs, etc.
            if value.startswith("0x") and len(value) == 42:  # Ethereum address
                line_num = parse_src(node.get("src"), file_path)
                findings.append(HardcodedFinding(
                    message="Hardcoded address detected. Consider using constants.",
                    severity=Severity.LOW,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))
            elif value.startswith("http") or value.startswith("ipfs"):
                line_num = parse_src(node.get("src"), file_path)
                findings.append(HardcodedFinding(
                    message="Hardcoded URL detected. Consider using constants.",
                    severity=Severity.LOW,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))


@detector("documentation", "📚 Documentation", "Detects missing documentation", category="documentation")
def detect_documentation(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect missing documentation."""
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        # Check if function has NatSpec documentation
        has_documentation = False
        
        # Look for documentation in the contract
        if "documentation" in node:
            has_documentation = True
        
        if not has_documentation and function_name not in ["constructor", "fallback", "receive"]:
            line_num = parse_src(node.get("src"), file_path)
            findings.append(DocumentationFinding(
                message=f"Function '{function_name}' lacks documentation.",
                severity=Severity.LOW,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))


@detector("naming", "🏷️ Naming", "Detects poor naming conventions", category="documentation")
def detect_naming(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect poor naming conventions."""
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        
        # Check for poor naming patterns
        poor_patterns = ["func", "test", "temp", "tmp", "var", "data"]
        if any(pattern in function_name.lower() for pattern in poor_patterns):
            line_num = parse_src(node.get("src"), file_path)
            findings.append(NamingFinding(
                message=f"Poor function name '{function_name}'. Use descriptive names.",
                severity=Severity.LOW,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))
    
    elif node.get("nodeType") == "VariableDeclaration":
        var_name = node.get("name", "")
        
        # Check for poor variable naming
        poor_patterns = ["var", "temp", "tmp", "data", "stuff"]
        if any(pattern in var_name.lower() for pattern in poor_patterns):
            line_num = parse_src(node.get("src"), file_path)
            findings.append(NamingFinding(
                message=f"Poor variable name '{var_name}'. Use descriptive names.",
                severity=Severity.LOW,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            )) 