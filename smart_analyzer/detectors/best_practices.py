"""
Best practices detectors.

This module provides detectors for code quality and best practices
that improve maintainability and reduce potential issues.
"""

from typing import Dict, Any, List
from ..utils import detector, parse_src
from ..findings import (
    EventFinding, TypeCastFinding, ModifierFinding, RedundantCodeFinding,
    ErrorMessageFinding, Severity
)


def _find_emit_statement(node):
    """Recursively search for EmitStatement in AST node."""
    if isinstance(node, dict):
        if node.get("nodeType") == "EmitStatement":
            return True
        for v in node.values():
            if _find_emit_statement(v):
                return True
    elif isinstance(node, list):
        for item in node:
            if _find_emit_statement(item):
                return True
    return False


@detector("events", "📢 Events", "Detects missing event emissions", category="best_practices")
def detect_events(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect missing event emissions."""
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        event_functions = ["transfer", "mint", "burn", "withdraw", "deposit", "set", "update", "vulnerablefunction"]
        if any(func in function_name.lower() for func in event_functions):
            body = node.get("body", {})
            has_events = _find_emit_statement(body)
            if not has_events:
                line_num = parse_src(node.get("src"), file_path)
                findings.append(EventFinding(
                    message=f"Function '{function_name}' should emit events for transparency.",
                    severity=Severity.LOW,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))


@detector("type_cast", "🔄 Type Cast", "Detects unsafe type casting", category="best_practices")
def detect_type_cast(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect unsafe type casting."""
    if node.get("nodeType") == "VariableDeclaration":
        var_type = node.get("typeName", {})
        if var_type.get("nodeType") == "ElementaryTypeName":
            type_name = var_type.get("name", "")
            if type_name in ["uint8", "uint16", "uint32", "uint64", "uint128"]:
                initial_value = node.get("value", {})
                if initial_value and initial_value.get("nodeType") == "FunctionCall":
                    func_expr = initial_value.get("expression", {})
                    if func_expr.get("nodeType") == "ElementaryTypeNameExpression":
                        cast_type = func_expr.get("typeName", {}).get("name", "")
                        if cast_type in ["uint256", "uint"]:
                            line_num = parse_src(node.get("src"), file_path)
                            findings.append(TypeCastFinding(
                                message=f"Unsafe type cast from {cast_type} to {type_name} detected. Truncation possible.",
                                severity=Severity.MEDIUM,
                                line_number=line_num,
                                file_path=file_path,
                                source_code=node.get("src")
                            ))
    
    # Also check for direct type casting in expressions
    elif node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        if expr.get("nodeType") == "ElementaryTypeNameExpression":
            cast_type = expr.get("typeName", {}).get("name", "")
            if cast_type in ["uint8", "uint16", "uint32", "uint64", "uint128"]:
                line_num = parse_src(node.get("src"), file_path)
                findings.append(TypeCastFinding(
                    message=f"Unsafe type cast to {cast_type} detected. Truncation possible.",
                    severity=Severity.MEDIUM,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))


@detector("modifier", "🔧 Modifier", "Detects incorrect modifier usage", category="best_practices")
def detect_modifier(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect incorrect modifier usage."""
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        modifiers = node.get("modifiers", [])
        
        # Check for dangerous functions that should have modifiers
        dangerous_functions = ["withdraw", "destroy", "selfdestruct", "kill", "pause", "unpause"]
        if any(func in function_name.lower() for func in dangerous_functions):
            # Check if function has any modifiers
            if not modifiers:
                line_num = parse_src(node.get("src"), file_path)
                findings.append(ModifierFinding(
                    message=f"Function '{function_name}' should use access control modifiers.",
                    severity=Severity.MEDIUM,
                    line_number=line_num,
                    file_path=file_path,
                    source_code=node.get("src")
                ))


@detector("redundant_code", "🔄 Redundant Code", "Detects redundant or dead code", category="best_practices")
def detect_redundant_code(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect redundant or dead code."""
    if node.get("nodeType") == "FunctionDefinition":
        function_name = node.get("name", "")
        body = node.get("body", {})
        
        # Check for empty functions
        if body.get("nodeType") == "Block" and not body.get("statements"):
            line_num = parse_src(node.get("src"), file_path)
            findings.append(RedundantCodeFinding(
                message=f"Empty function '{function_name}' detected.",
                severity=Severity.LOW,
                line_number=line_num,
                file_path=file_path,
                source_code=node.get("src")
            ))


@detector("error_messages", "💬 Error Messages", "Detects poor error messages", category="best_practices")
def detect_error_messages(node: Dict[str, Any], findings: List, file_path: str = None) -> None:
    """Detect poor error messages."""
    if node.get("nodeType") == "FunctionCall":
        expr = node.get("expression", {})
        if expr.get("nodeType") == "Identifier" and expr.get("name") == "require":
            args = node.get("arguments", [])
            if args and len(args) > 1:
                error_msg = args[1].get("value", "")
                if len(error_msg) < 10:  # Very short error messages
                    line_num = parse_src(node.get("src"), file_path)
                    findings.append(ErrorMessageFinding(
                        message="Poor error message detected. Provide descriptive error messages.",
                        severity=Severity.LOW,
                        line_number=line_num,
                        file_path=file_path,
                        source_code=node.get("src")
                    )) 