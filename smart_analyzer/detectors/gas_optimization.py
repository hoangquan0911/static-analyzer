"""
Gas optimization detectors.

This module provides detectors for gas efficiency issues
that can help reduce transaction costs.
"""

from typing import Dict, Any, List
from ..utils import detector, parse_src
from ..findings import GasLimitFinding, Severity


@detector("gas_limit", "⛽ Gas Limit", "Detects potential gas limit issues", category="gas_optimization")
def detect_gas_limit(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect gas limit vulnerabilities."""
    if node.get("nodeType") == "ForStatement":
        # Check for unbounded loops
        condition = node.get("condition", {})
        if condition.get("nodeType") == "BinaryOperation":
            # Look for patterns like i < array.length without bounds
            line_num = parse_src(node.get("src"), file_path)
            findings.append(GasLimitFinding(
                message="Unbounded loop detected. May exceed gas limit.",
                severity=Severity.MEDIUM,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            )) 