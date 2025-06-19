"""
Utility functions for the Solidity Static Analyzer.

This module provides decorators, context managers, and AST utilities
in a super-pythonic way.
"""

import json
import subprocess
import os
import re
import time
from typing import Dict, Any, Iterator, Optional, Callable, List
from functools import wraps
from contextlib import contextmanager
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from .findings import Severity


# Registry for detectors
DETECTOR_REGISTRY: Dict[str, Callable] = {}
DETECTOR_INFO: Dict[str, 'DetectorInfo'] = {}


class DetectorInfo:
    """Information about a detector with beautiful names and descriptions."""
    
    def __init__(self, name: str, display_name: str, description: str, severity: str = "MEDIUM", category: str = "general"):
        self.name = name
        self.display_name = display_name
        self.description = description
        self.severity = severity
        self.category = category
    
    def __str__(self) -> str:
        return self.display_name
    
    def __repr__(self) -> str:
        return f"DetectorInfo('{self.display_name}')"
    
    def __len__(self) -> int:
        return len(self.display_name)


def detector(name: str = None, display_name: str = None, description: str = None, severity: str = "MEDIUM", category: str = "general"):
    """
    Decorator to register a detector function with beautiful metadata.
    
    Usage:
        @detector("reentrancy", "🔄 Reentrancy", "Detects reentrancy vulnerabilities", category="security")
        def detect_reentrancy(node, findings):
            # detector logic
    """
    def decorator(func: Callable) -> Callable:
        detector_name = name or func.__name__
        detector_display = display_name or detector_name.replace('_', ' ').title()
        detector_desc = description or f"Detects {detector_name.replace('_', ' ')} vulnerabilities"
        
        DETECTOR_REGISTRY[detector_name] = func
        DETECTOR_INFO[detector_name] = DetectorInfo(
            detector_name, detector_display, detector_desc, severity, category
        )
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def output_formatter(format_type: str):
    """
    Decorator to register an output formatter.
    
    Usage:
        @output_formatter("table")
        def format_table(findings):
            # formatting logic
    """
    def decorator(func: Callable) -> Callable:
        # This would be used in the output module
        return func
    return decorator


@contextmanager
def timing_context(description: str = "Operation"):
    """Context manager for timing operations."""
    start_time = time.time()
    console = Console()
    
    # Clean up the description for temporary directories
    if "/tmp" in description or "/var/folders" in description:
        # Extract meaningful information from temporary paths
        if "Analyzing contracts in" in description:
            # Extract test name from temporary directory path
            # The format is "Analyzing contracts in /path/to/temp/dir"
            # Find the position of "in" and get everything after it
            in_pos = description.find(" in ")
            if in_pos != -1:
                temp_path = description[in_pos + 4:]  # Skip " in "
                # Look for test_ prefix to extract test name
                if "test_" in temp_path:
                    # Extract the test name from the path
                    import re
                    # Look for test_ followed by the test name, but stop at the random suffix
                    match = re.search(r'test_([a-zA-Z0-9_]+)_[a-zA-Z0-9]+$', temp_path)
                    if match:
                        test_name = match.group(1).replace("_", " ").title()
                        clean_description = f"Testing {test_name}"
                    else:
                        clean_description = "Analyzing test contracts"
                else:
                    clean_description = "Analyzing test contracts"
            else:
                clean_description = "Analyzing test contracts"
        elif "Analyzing" in description:
            # For single file analysis, extract filename
            parts = description.split()
            if len(parts) >= 2:
                filename = os.path.basename(parts[-1])
                clean_description = f"Analyzing {filename}"
            else:
                clean_description = description
        else:
            clean_description = description
    else:
        clean_description = description
    
    console.print(f"[dim]Starting {clean_description}...[/dim]")
    
    try:
        yield
    finally:
        elapsed = time.time() - start_time
        console.print(f"[dim]{clean_description} completed in {elapsed:.2f}s[/dim]")


@contextmanager
def error_context(operation: str):
    """Context manager for error handling with rich output."""
    console = Console()
    try:
        yield
    except Exception as e:
        console.print(f"[red]❌ Error during {operation}: {e}[/red]")
        raise


def generate_ast(sol_file: str, project_root: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate AST for a Solidity file using solc.
    
    Args:
        sol_file: Path to the Solidity file
        project_root: Optional project root for multi-file analysis
    
    Returns:
        AST data from solc
    """
    if project_root:
        # Find all .sol files in the project
        all_sol_files = {}
        for root, dirs, files in os.walk(project_root):
            for file in files:
                if file.endswith('.sol'):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, project_root)
                    with open(file_path, 'r') as f:
                        all_sol_files[relative_path] = {"content": f.read()}
        
        standard_input = {
            "language": "Solidity",
            "sources": all_sol_files,
            "settings": {
                "outputSelection": {
                    "*": {
                        "*": ["*"],
                        "": ["ast"]
                    }
                }
            }
        }
    else:
        # Single file analysis
        standard_input = {
            "language": "Solidity",
            "sources": {
                "input.sol": {
                    "content": open(sol_file).read()
                }
            },
            "settings": {
                "outputSelection": {
                    "*": {
                        "*": ["*"],
                        "": ["ast"]
                    }
                }
            }
        }

    cmd = ["solc", "--standard-json"]
    result = subprocess.run(cmd, input=json.dumps(standard_input), text=True, capture_output=True)

    if result.returncode != 0:
        raise Exception(f"solc error: {result.stderr}")

    output = json.loads(result.stdout)

    if "errors" in output:
        for err in output["errors"]:
            if err.get("severity") == "error":
                raise Exception(f"solc error: {err['formattedMessage']}")

    return output


def walk_ast_generator(node: Any) -> Iterator[Dict[str, Any]]:
    """
    Generator-based AST walker that yields nodes as they're discovered.
    
    Args:
        node: AST node to walk
    
    Yields:
        AST nodes with nodeType
    """
    if isinstance(node, dict):
        if "nodeType" in node:
            yield node
        for key in node:
            yield from walk_ast_generator(node[key])
    elif isinstance(node, list):
        for item in node:
            yield from walk_ast_generator(item)


def parse_src(src_string: str, file_path: Optional[str] = None) -> Optional[int]:
    """
    Parse solc src attribute to extract line number.
    
    Args:
        src_string: Source mapping string from solc
        file_path: Path to the source file
    
    Returns:
        Line number or None if parsing fails
    """
    if not src_string or not file_path:
        return None
    
    parts = src_string.split(':')
    if len(parts) >= 2:
        try:
            char_offset = int(parts[0])
            with open(file_path, 'r') as f:
                content = f.read()
            # Count newlines up to char_offset
            line_number = content[:char_offset].count('\n') + 1
            return line_number
        except Exception:
            return None
    return None


def find_sol_files_generator(folder_path: str) -> Iterator[str]:
    """
    Generator that yields .sol files as they're found.
    
    Args:
        folder_path: Path to search for .sol files
    
    Yields:
        Paths to .sol files
    """
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.sol'):
                yield os.path.join(root, file)


def get_solidity_version(sol_file: str) -> Optional[tuple]:
    """
    Extract Solidity version from pragma statement.
    
    Args:
        sol_file: Path to the Solidity file
    
    Returns:
        Tuple of (major, minor, patch) or None
    """
    with open(sol_file, 'r') as f:
        content = f.read()
    match = re.search(r'pragma solidity\s+([\^~]?)([0-9]+)\.([0-9]+)(?:\.([0-9]+))?', content)
    if match:
        major = int(match.group(2))
        minor = int(match.group(3))
        patch = int(match.group(4) or 0)
        return (major, minor, patch)
    return None


def get_line_context(file_path: str, line_number: int, context_lines: int = 2) -> Optional[str]:
    """
    Get context around a specific line number.
    
    Args:
        file_path: Path to the file
        line_number: Line number to get context for
        context_lines: Number of lines before and after
    
    Returns:
        Formatted context string or None
    """
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        if line_number is None or line_number < 1 or line_number > len(lines):
            return None
            
        start_line = max(1, line_number - context_lines)
        end_line = min(len(lines), line_number + context_lines)
        
        context = []
        for i in range(start_line, end_line + 1):
            prefix = ">>> " if i == line_number else "    "
            context.append(f"{prefix}{i:4d}: {lines[i-1].rstrip()}")
        
        return "\n".join(context)
    except:
        return None


class UncheckedContext:
    """Context manager for tracking unchecked blocks."""
    
    def __init__(self):
        self.unchecked_depth = 0
        self._ast_stack = []  # Track AST node stack
    
    def enter(self, node: Dict[str, Any]) -> None:
        """Enter a node and update unchecked depth."""
        self._ast_stack.append(node)
        if node.get('nodeType') == 'UncheckedBlock':
            self.unchecked_depth += 1
    
    def exit(self, node: Dict[str, Any]) -> None:
        """Exit a node and update unchecked depth."""
        if self._ast_stack and self._ast_stack[-1] == node:
            self._ast_stack.pop()
        if node.get('nodeType') == 'UncheckedBlock':
            self.unchecked_depth -= 1
    
    def in_unchecked(self) -> bool:
        """Check if currently inside an unchecked block."""
        return self.unchecked_depth > 0
    
    def get_context_for_node(self, node: Dict[str, Any]) -> bool:
        """Get unchecked context for a specific node by checking its ancestors."""
        # Check if any ancestor is an UncheckedBlock
        for ancestor in self._ast_stack:
            if ancestor.get('nodeType') == 'UncheckedBlock':
                return True
        return False


def with_progress(description: str = "Processing"):
    """
    Decorator to add progress tracking to functions.
    
    Usage:
        @with_progress("Analyzing contracts")
        def analyze_contracts(files):
            # analysis logic
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            console = Console()
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(description, total=None)
                result = func(*args, **kwargs)
                progress.update(task, completed=True)
            return result
        return wrapper
    return decorator


def cached(func: Callable) -> Callable:
    """
    Simple caching decorator.
    
    Usage:
        @cached
        def expensive_operation(x):
            # expensive computation
    """
    cache = {}
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        key = str(args) + str(sorted(kwargs.items()))
        if key not in cache:
            cache[key] = func(*args, **kwargs)
        return cache[key]
    
    return wrapper
