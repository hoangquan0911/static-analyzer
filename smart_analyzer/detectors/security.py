"""
Security vulnerability detectors.

This module provides detectors for critical security vulnerabilities
that could lead to exploits or loss of funds.
"""

from typing import Dict, Any, List
from ..utils import detector, parse_src, UncheckedContext
from ..findings import (
    ReentrancyFinding, SignatureReplayFinding, IntegerOverflowFinding, 
    TxOriginFinding, UncheckedCallFinding, OracleManipulationFinding,
    AccessControlFinding, FlashLoanFinding, FrontRunningFinding,
    TimestampFinding, DelegateCallFinding, UninitializedFinding,
    ZeroAddressFinding, MEVFinding, StorageCollisionFinding, 
    UpgradeFinding, CrossChainFinding, Severity
)


@detector("access_control", "🔐 Access Control", "Detects missing or incorrect access controls", category="security")
def detect_access_control(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect access control vulnerabilities."""
    if node.get("nodeType") == "FunctionDefinition":
        visibility = node.get("visibility", "default")
        if visibility in ["public", "external"]:
            # Skip view and pure functions as they are meant to be publicly accessible
            state_mutability = node.get("stateMutability", "")
            if state_mutability in ["view", "pure"]:
                return
            
            # Skip interface functions - check if file path contains "interface" or ends with "Interface.sol"
            if file_path and ("interface" in file_path.lower() or file_path.endswith("Interface.sol")):
                return
            
            modifiers = node.get("modifiers", [])
            has_access_control = any(
                mod.get("modifierName", {}).get("name") in ["onlyOwner", "onlyRole", "whenNotPaused"]
                for mod in modifiers
            )
            function_name = node.get("name", "")
            dangerous_functions = [
                "withdraw", "transfer", "mint", "burn", "pause", "unpause",
                "upgrade", "set", "update", "delete", "destroy", "kill", "adminonly"
            ]
            # Flag any public/external function with a sensitive name or no modifiers
            if (function_name.lower() in dangerous_functions or not has_access_control) and function_name:
                line_num = parse_src(node.get("src"), file_path)
                findings.append(AccessControlFinding(
                    message=f"Function '{function_name}' lacks access control.",
                    severity=Severity.HIGH,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))


@detector("flash_loan", "⚡ Flash Loan", "Detects potential flash loan vulnerabilities", category="security")
def detect_flash_loan(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect flash loan vulnerabilities."""
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        
        # Check for flash loan patterns
        if expr.get("nodeType") == "MemberAccess":
            member_name = expr.get("memberName", "")
            if member_name in ["flash", "flashLoan", "flashMint"]:
                line_num = parse_src(node.get("src"), file_path)
                findings.append(FlashLoanFinding(
                    message=f"Flash loan function '{member_name}' detected. Ensure proper validation.",
                    severity=Severity.HIGH,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))


@detector("front_running", "🏃 Front Running", "Detects potential front-running vulnerabilities", category="security")
def detect_front_running(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect front-running vulnerabilities."""
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        front_running_patterns = ["mint", "claim", "buy", "sell", "swap"]
        if any(pattern in function_name.lower() for pattern in front_running_patterns):
            line_num = parse_src(node.get("src"), file_path)
            findings.append(FrontRunningFinding(
                message=f"Function '{function_name}' may be vulnerable to front-running.",
                severity=Severity.MEDIUM,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))


@detector("timestamp", "⏰ Timestamp", "Detects timestamp dependence vulnerabilities", category="security")
def detect_timestamp(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect timestamp dependence vulnerabilities."""
    if node.get("nodeType") == "MemberAccess" and node.get("memberName") == "timestamp":
        line_num = parse_src(node.get("src"), file_path)
        findings.append(TimestampFinding(
            message="block.timestamp usage detected. Consider using block.number for better security.",
            severity=Severity.MEDIUM,
            line_number=line_num,
            file_path=file_path,
            source_code=node.get("src")
        ))


@detector("delegate_call", "📞 Delegate Call", "Detects delegate call vulnerabilities", category="security")
def detect_delegate_call(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect delegate call vulnerabilities."""
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        
        if expr.get("nodeType") == "MemberAccess" and expr.get("memberName") == "delegatecall":
            line_num = parse_src(node.get("src"), file_path)
            findings.append(DelegateCallFinding(
                message="delegatecall usage detected. Ensure proper storage layout.",
                severity=Severity.HIGH,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))


@detector("uninitialized", "❓ Uninitialized", "Detects uninitialized variables", category="security")
def detect_uninitialized(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect uninitialized variables."""
    if node.get("nodeType") == "VariableDeclaration":
        if node.get("stateVariable", False):
            initial_value = node.get("value")
            if initial_value is None:
                line_num = parse_src(node.get("src"), file_path)
                findings.append(UninitializedFinding(
                    message="State variable declared without initialization.",
                    severity=Severity.MEDIUM,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))


@detector("zero_address", "📍 Zero Address", "Detects missing zero address checks", category="security")
def detect_zero_address(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect missing zero address checks."""
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        body = node.get("body", {})
        
        # Check if function has address parameters
        parameters = node.get("parameters", {}).get("parameters", [])
        has_address_param = any(
            param.get("typeName", {}).get("name") == "address" 
            for param in parameters
        )
        
        if has_address_param and body.get("nodeType") == "Block":
            # Check if there's a zero address check
            has_zero_check = False
            for statement in body.get("statements", []):
                if statement.get("nodeType") == "ExpressionStatement":
                    expr = statement.get("expression", {})
                    if expr.get("nodeType") == "FunctionCall":
                        func_expr = expr.get("expression", {})
                        if func_expr.get("nodeType") == "Identifier" and func_expr.get("name") == "require":
                            args = expr.get("arguments", [])
                            if args and "address(0)" in str(args[0]):
                                has_zero_check = True
                                break
            
            if not has_zero_check:
                line_num = parse_src(node.get("src"), file_path)
                findings.append(ZeroAddressFinding(
                    message=f"Function '{function_name}' assigns address without zero address check.",
                    severity=Severity.MEDIUM,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))


@detector("mev", "💰 MEV", "Detects MEV vulnerabilities", category="security")
def detect_mev(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect MEV vulnerabilities."""
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        mev_patterns = ["swap", "mint", "burn", "trade", "arbitrage"]
        if any(pattern in function_name.lower() for pattern in mev_patterns):
            line_num = parse_src(node.get("src"), file_path)
            findings.append(MEVFinding(
                message=f"Function '{function_name}' may be vulnerable to MEV attacks.",
                severity=Severity.MEDIUM,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))


@detector("storage_collision", "💾 Storage Collision", "Detects storage collision issues", category="security")
def detect_storage_collision(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect storage collision issues."""
    if node.get("nodeType") == "ContractDefinition":
        state_vars = [n for n in node.get("nodes", []) if n.get("nodeType") == "VariableDeclaration" and n.get("stateVariable", False)]
        if len(state_vars) > 1:
            for var in state_vars:
                line_num = parse_src(var.get("src"), file_path)
                findings.append(StorageCollisionFinding(
                    message="Multiple state variables declared. Ensure proper storage layout in upgradeable contracts.",
                    severity=Severity.MEDIUM,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=var.get("src")
                ))


@detector("upgrade", "⬆️ Upgrade", "Detects upgrade pattern issues", category="security")
def detect_upgrade(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect upgrade pattern issues."""
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        upgrade_patterns = ["upgrade", "upgradeTo", "upgradeAndCall"]
        if any(pattern in function_name.lower() for pattern in upgrade_patterns):
            # Check for access control
            modifiers = node.get("modifiers", [])
            has_access_control = any(
                mod.get("modifierName", {}).get("name") in ["onlyOwner", "onlyRole", "onlyAdmin"]
                for mod in modifiers
            )
            if not has_access_control:
                line_num = parse_src(node.get("src"), file_path)
                findings.append(UpgradeFinding(
                    message=f"Upgrade function '{function_name}' lacks access control.",
                    severity=Severity.HIGH,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))


@detector("cross_chain", "🌉 Cross Chain", "Detects cross-chain vulnerabilities", category="security")
def detect_cross_chain(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect cross-chain vulnerabilities."""
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        cross_chain_patterns = ["bridge", "crosschain", "cross_chain", "multichain"]
        if any(pattern in function_name.lower() for pattern in cross_chain_patterns):
            line_num = parse_src(node.get("src"), file_path)
            findings.append(CrossChainFinding(
                message=f"Cross-chain function '{function_name}' detected. Ensure proper validation.",
                severity=Severity.HIGH,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            )) 