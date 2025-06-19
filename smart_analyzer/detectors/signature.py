"""
Signature replay vulnerability detector.

This module provides detectors for signature replay vulnerabilities
using the super-pythonic approach.
"""

from typing import Dict, Any, List
from ..utils import detector, parse_src
from ..findings import SignatureReplayFinding, Severity


@detector("signature_replay", "✍️ Signature Replay", "Detects signature replay vulnerabilities", category="security")
def detect_signature_replay(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """
    Detect signature replay vulnerabilities.
    
    Args:
        node: AST node to analyze
        findings: List to append findings to
        file_path: Path to the source file
    """
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        
        # Direct ecrecover calls
        if expr.get("nodeType") == "Identifier" and expr.get("name") == "ecrecover":
            line_num = parse_src(node.get("src"), file_path)
            findings.append(SignatureReplayFinding(
                message="Signature verification detected without replay protection. This allows signature reuse attacks. Add nonce/hash tracking or timestamp validation.",
                severity=Severity.CRITICAL,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))
        
        # ECDSA library calls
        elif expr.get("nodeType") == "MemberAccess" and expr.get("memberName") in ["recover", "toEthSignedMessageHash", "toTypedDataHash"]:
            line_num = parse_src(node.get("src"), file_path)
            findings.append(SignatureReplayFinding(
                message="ECDSA signature verification detected without replay protection. This allows signature reuse attacks. Add nonce/hash tracking or timestamp validation.",
                severity=Severity.CRITICAL,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))
        
        # SignatureChecker calls
        elif expr.get("nodeType") == "MemberAccess" and expr.get("memberName") in ["isValidSignatureNow", "isValidSignature", "isValidERC1271SignatureNow"]:
            line_num = parse_src(node.get("src"), file_path)
            findings.append(SignatureReplayFinding(
                message="SignatureChecker verification detected without replay protection. This allows signature reuse attacks. Add nonce/hash tracking or timestamp validation.",
                severity=Severity.CRITICAL,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))
        
        # Custom signature verification functions
        elif expr.get("nodeType") == "Identifier" and any(keyword in expr.get("name", "").lower() for keyword in ["verify", "signature", "sign", "recover"]):
            line_num = parse_src(node.get("src"), file_path)
            findings.append(SignatureReplayFinding(
                message="Custom signature verification detected without replay protection. This allows signature reuse attacks. Add nonce/hash tracking or timestamp validation.",
                severity=Severity.CRITICAL,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))


@detector("signature_in_loop", "🔄 Signature in Loop", "Detects signature verification in loops", category="security")
def detect_signature_in_loop(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """
    Detect signature verification in loops.
    
    Args:
        node: AST node to analyze
        findings: List to append findings to
        file_path: Path to the source file
    """
    if node.get("nodeType") in ["ForStatement", "WhileStatement"]:
        # Check if loop contains signature verification
        node_str = str(node)
        if any(keyword in node_str for keyword in ["ecrecover", "ECDSA", "signature", "recover"]):
            line_num = parse_src(node.get("src"), file_path)
            findings.append(SignatureReplayFinding(
                message="Signature verification in loop detected. Ensure each iteration uses unique data to prevent replay.",
                severity=Severity.HIGH,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            )) 