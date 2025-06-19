"""
Reentrancy vulnerability detector.

This module provides detectors for reentrancy vulnerabilities
using the super-pythonic approach.
"""

from typing import Dict, Any, List
from ..utils import detector, parse_src
from ..findings import ReentrancyFinding, UncheckedCallFinding, Severity


@detector("reentrancy", "🔄 Reentrancy", "Detects reentrancy vulnerabilities", category="security")
def detect_reentrancy(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """
    Detect potential reentrancy vulnerabilities via .call() usage.
    
    Args:
        node: AST node to analyze
        findings: List to append findings to
        file_path: Path to the source file
    """
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        
        # Check for direct .call() usage
        if expr.get("nodeType") == "MemberAccess" and expr.get("memberName") == "call":
            line_num = parse_src(node.get("src"), file_path)
            findings.append(ReentrancyFinding(
                message="Potential reentrancy via `.call()`.",
                severity=Severity.HIGH,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))
        
        # Check for .call() with options
        elif expr.get("nodeType") == "FunctionCallOptions":
            inner_expr = expr.get("expression", {})
            if inner_expr.get("nodeType") == "MemberAccess" and inner_expr.get("memberName") == "call":
                line_num = parse_src(node.get("src"), file_path)
                findings.append(ReentrancyFinding(
                    message="Potential reentrancy via `.call()` with options.",
                    severity=Severity.HIGH,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))


@detector("unchecked_call", "⚠️ Unchecked Call", "Detects unchecked external calls without require()")
def detect_unchecked_call(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """
    Detect unchecked external calls.
    
    Args:
        node: AST node to analyze
        findings: List to append findings to
        file_path: Path to the source file
    """
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        
        # Check for direct .call() usage without require
        if expr.get("nodeType") == "MemberAccess" and expr.get("memberName") == "call":
            line_num = parse_src(node.get("src"), file_path)
            findings.append(UncheckedCallFinding(
                message="`call` used without require().",
                severity=Severity.MEDIUM,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))
        
        # Check for .call() with options without require
        elif expr.get("nodeType") == "FunctionCallOptions":
            inner_expr = expr.get("expression", {})
            if inner_expr.get("nodeType") == "MemberAccess" and inner_expr.get("memberName") == "call":
                line_num = parse_src(node.get("src"), file_path)
                findings.append(UncheckedCallFinding(
                    message="`call` used without require().",
                    severity=Severity.MEDIUM,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                )) 