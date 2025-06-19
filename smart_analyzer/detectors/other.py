"""
Other vulnerability detectors.

This module provides detectors for various other vulnerabilities
using the super-pythonic approach.
"""

from typing import Dict, Any, List
from ..utils import detector, parse_src, UncheckedContext
from ..findings import TxOriginFinding, IntegerOverflowFinding, OracleManipulationFinding, UncheckedCallFinding, Severity


@detector("tx_origin", "👤 tx.origin", "Detects tx.origin usage for authorization", category="security")
def detect_tx_origin(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """
    Detect tx.origin usage.
    
    Args:
        node: AST node to analyze
        findings: List to append findings to
        file_path: Path to the source file
    """
    if node.get("nodeType") == "MemberAccess":
        expr = node.get("expression", {})
        if expr.get("nodeType") == "Identifier" and expr.get("name") == "tx" and node.get("memberName") == "origin":
            line_num = parse_src(node.get("src"), file_path)
            findings.append(TxOriginFinding(
                message="Avoid using `tx.origin` for authorization.",
                severity=Severity.MEDIUM,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))


@detector("integer_overflow", "🔢 Integer Overflow", "Detects potential integer overflow", category="security")
def detect_integer_overflow(node: Dict[str, Any], findings: List, file_path: str = None, version: tuple = None, unchecked_context: UncheckedContext = None) -> None:
    """
    Detect integer overflow vulnerabilities.
    
    Args:
        node: AST node to analyze
        findings: List to append findings to
        file_path: Path to the source file
        version: Solidity version tuple
        unchecked_ctx: Unchecked context tracker
    """
    # Only flag for <0.8.0, or inside unchecked block for >=0.8.0
    if version is None:
        return  # Can't determine version, skip
    
    major, minor, patch = version
    is_old = (major, minor) < (0, 8)
    in_unchecked = unchecked_context.get_context_for_node(node) if unchecked_context else False
    
    if not is_old and not in_unchecked:
        return  # Don't flag for >=0.8.0 unless in unchecked
    
    if node.get("nodeType") == "Assignment":
        op = node.get("operator")
        if op in ["+=", "-=", "*="]:
            line_num = parse_src(node.get("src"), file_path)
            findings.append(IntegerOverflowFinding(
                message=f"Potential integer overflow/underflow with operator '{op}'.",
                severity=Severity.MEDIUM,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))
    
    elif node.get("nodeType") == "BinaryOperation":
        op = node.get("operator")
        if op in ["+", "-", "*"]:
            line_num = parse_src(node.get("src"), file_path)
            findings.append(IntegerOverflowFinding(
                message=f"Potential integer overflow/underflow with operator '{op}'.",
                severity=Severity.MEDIUM,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))


@detector("oracle_manipulation", "📊 Oracle Manipulation", "Detects oracle manipulation vulnerabilities", category="security")
def detect_oracle_manipulation(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """
    Detect oracle manipulation vulnerabilities.
    
    Args:
        node: AST node to analyze
        findings: List to append findings to
        file_path: Path to the source file
    """
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        if expr.get("nodeType") == "MemberAccess" and expr.get("memberName") == "latestRoundData":
            line_num = parse_src(node.get("src"), file_path)
            findings.append(OracleManipulationFinding(
                message="Chainlink oracle usage detected. Ensure price data is not reused within the same transaction/block to prevent manipulation.",
                severity=Severity.HIGH,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))


@detector("unchecked_call", "❌ Unchecked Call", "Detects unchecked external calls", category="security")
def detect_unchecked_call(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect unchecked external calls."""
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        
        # Check for low-level calls
        if expr.get("nodeType") == "MemberAccess" and expr.get("memberName") == "call":
            # For now, flag all .call() usage as potentially unchecked
            # In a more sophisticated implementation, we would check if the return value is used
            line_num = parse_src(node.get("src"), file_path)
            findings.append(UncheckedCallFinding(
                message="External call detected. Ensure return value is checked.",
                severity=Severity.MEDIUM,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            )) 