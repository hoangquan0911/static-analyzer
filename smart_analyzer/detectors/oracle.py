"""
Oracle manipulation vulnerability detectors.

This module provides detectors for oracle-related vulnerabilities including
price manipulation, signature reuse, and oracle data validation issues.
"""

from typing import Dict, Any, List
from ..utils import detector, parse_src
from ..findings import OracleManipulationFinding, Severity


@detector("oracle_manipulation", "🔮 Oracle Manipulation", "Detects oracle manipulation vulnerabilities including signature reuse", category="security")
def detect_oracle_manipulation(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect oracle manipulation vulnerabilities including signature reuse."""
    
    # Check for Chainlink oracle usage
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        
        # Check for Chainlink oracle calls
        if expr.get("nodeType") == "MemberAccess":
            member_name = expr.get("memberName", "")
            
            # Chainlink oracle patterns
            chainlink_patterns = [
                "latestRoundData", "getPrice", "getAnswer", "getTimestamp",
                "aggregator", "oracle", "priceFeed"
            ]
            
            if any(pattern in member_name.lower() for pattern in chainlink_patterns):
                line_num = parse_src(node.get("src"), file_path)
                findings.append(OracleManipulationFinding(
                    message=f"Chainlink oracle usage detected: {member_name}. Ensure price data is not reused within the same transaction/block to prevent manipulation.",
                    severity=Severity.HIGH,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))
    
    # Check for signature verification without replay protection
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        
        if expr.get("nodeType") == "MemberAccess":
            member_name = expr.get("memberName", "")
            
            # Signature verification patterns
            signature_patterns = [
                "ecrecover", "verify", "signature", "recover"
            ]
            
            if any(pattern in member_name.lower() for pattern in signature_patterns):
                # Check if there's replay protection
                has_replay_protection = check_replay_protection(node, findings, file_path)
                
                if not has_replay_protection:
                    line_num = parse_src(node.get("src"), file_path)
                    findings.append(OracleManipulationFinding(
                        message=f"Signature verification detected without replay protection: {member_name}. This could allow signature reuse attacks.",
                        severity=Severity.HIGH,
                        line_number=line_num,
                        file_path=file_path,
                        source_code=node.get("src")
                    ))
    
    # Check for price oracle reuse patterns
    if node.get("nodeType") == "VariableDeclaration":
        var_name = node.get("name", "")
        
        # Check for price storage variables
        if "price" in var_name.lower() or "oracle" in var_name.lower():
            line_num = parse_src(node.get("src"), file_path)
            findings.append(OracleManipulationFinding(
                message=f"Price/oracle variable detected: {var_name}. Ensure this is not reused across transactions to prevent manipulation.",
                severity=Severity.MEDIUM,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))
    
    # Check for flash loan oracle manipulation
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        
        if "flash" in function_name.lower() or "loan" in function_name.lower():
            # Check if function uses oracle data
            body = node.get("body", {})
            if body.get("nodeType") == "Block":
                for statement in body.get("statements", []):
                    if has_oracle_usage(statement):
                        line_num = parse_src(node.get("src"), file_path)
                        findings.append(OracleManipulationFinding(
                            message=f"Flash loan function '{function_name}' uses oracle data. This could be vulnerable to oracle manipulation.",
                            severity=Severity.HIGH,
                            line_number=line_num,
                            file_path=file_path,
                            source_code=node.get("src")
                        ))
                        break


def check_replay_protection(node: Dict[str, Any], findings: List, file_path: str = None) -> bool:
    """Check if signature verification has replay protection."""
    
    # Look for nonce, timestamp, or unique identifier usage
    parent = node.get("parent", {})
    
    if parent.get("nodeType") == "FunctionDefinition":
        body = parent.get("body", {})
        if body.get("nodeType") == "Block":
            for statement in body.get("statements", []):
                # Check for nonce usage
                if statement.get("nodeType") == "VariableDeclaration":
                    var_name = statement.get("name", "")
                    if "nonce" in var_name.lower():
                        return True
                
                # Check for timestamp usage
                if statement.get("nodeType") == "ExpressionStatement":
                    expr = statement.get("expression", {})
                    if expr.get("nodeType") == "FunctionCall":
                        func_expr = expr.get("expression", {})
                        if func_expr.get("nodeType") == "MemberAccess":
                            if func_expr.get("memberName") == "timestamp":
                                return True
    
    return False


def has_oracle_usage(node: Dict[str, Any]) -> bool:
    """Check if a node contains oracle usage."""
    
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        
        if expr.get("nodeType") == "MemberAccess":
            member_name = expr.get("memberName", "")
            
            oracle_patterns = [
                "latestRoundData", "getPrice", "getAnswer", "getTimestamp",
                "aggregator", "oracle", "priceFeed", "price"
            ]
            
            return any(pattern in member_name.lower() for pattern in oracle_patterns)
    
    # Recursively check child nodes
    for key, value in node.items():
        if isinstance(value, dict):
            if has_oracle_usage(value):
                return True
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and has_oracle_usage(item):
                    return True
    
    return False


@detector("oracle_signature_reuse", "🔐 Oracle Signature Reuse", "Detects oracle signature reuse vulnerabilities", category="security")
def detect_oracle_signature_reuse(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect oracle signature reuse vulnerabilities."""
    
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        
        # Check for signature verification
        if expr.get("nodeType") == "MemberAccess":
            member_name = expr.get("memberName", "")
            
            if "ecrecover" in member_name.lower() or "verify" in member_name.lower():
                # Check for unique signature components
                arguments = node.get("arguments", [])
                
                has_unique_components = False
                for arg in arguments:
                    if arg.get("nodeType") == "BinaryOperation":
                        # Check for timestamp or nonce in signature
                        left = arg.get("left", {})
                        right = arg.get("right", {})
                        
                        if (left.get("nodeType") == "MemberAccess" and 
                            left.get("memberName") == "timestamp"):
                            has_unique_components = True
                            break
                        
                        if (right.get("nodeType") == "MemberAccess" and 
                            right.get("memberName") == "timestamp"):
                            has_unique_components = True
                            break
                
                if not has_unique_components:
                    line_num = parse_src(node.get("src"), file_path)
                    findings.append(OracleManipulationFinding(
                        message="Oracle signature verification without unique components detected. This could allow signature reuse attacks.",
                        severity=Severity.HIGH,
                        line_number=line_num,
                        file_path=file_path,
                        source_code=node.get("src")
                    ))


@detector("oracle_price_manipulation", "💰 Oracle Price Manipulation", "Detects oracle price manipulation vulnerabilities", category="security")
def detect_oracle_price_manipulation(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect oracle price manipulation vulnerabilities."""
    
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        
        # Check for functions that could manipulate oracle prices
        manipulation_patterns = [
            "flash", "loan", "arbitrage", "manipulate", "exploit"
        ]
        
        if any(pattern in function_name.lower() for pattern in manipulation_patterns):
            body = node.get("body", {})
            if body.get("nodeType") == "Block":
                for statement in body.get("statements", []):
                    if has_oracle_usage(statement):
                        line_num = parse_src(node.get("src"), file_path)
                        findings.append(OracleManipulationFinding(
                            message=f"Function '{function_name}' could manipulate oracle prices. Ensure proper safeguards are in place.",
                            severity=Severity.HIGH,
                            line_number=line_num,
                            file_path=file_path,
                            source_code=node.get("src")
                        ))
                        break 