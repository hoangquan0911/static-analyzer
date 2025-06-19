"""
Plugin system for the Solidity Static Analyzer.

This module provides dynamic plugin discovery and loading
for user-contributed detectors.
"""

import os
import importlib
import importlib.util
from typing import List, Dict, Any
from pathlib import Path


def discover_plugins(plugins_dir: str = None) -> List[str]:
    """
    Discover available plugins in the plugins directory.
    
    Args:
        plugins_dir: Path to plugins directory (defaults to this module's directory)
    
    Returns:
        List of plugin module names
    """
    if plugins_dir is None:
        plugins_dir = os.path.dirname(__file__)
    
    plugins = []
    
    for item in os.listdir(plugins_dir):
        item_path = os.path.join(plugins_dir, item)
        
        # Skip __init__.py and non-Python files
        if item == "__init__.py" or not item.endswith('.py'):
            continue
        
        # Extract module name
        module_name = item[:-3]  # Remove .py extension
        plugins.append(module_name)
    
    return plugins


def load_plugin(plugin_name: str, plugins_dir: str = None) -> bool:
    """
    Load a plugin module.
    
    Args:
        plugin_name: Name of the plugin module
        plugins_dir: Path to plugins directory
    
    Returns:
        True if plugin loaded successfully, False otherwise
    """
    if plugins_dir is None:
        plugins_dir = os.path.dirname(__file__)
    
    plugin_path = os.path.join(plugins_dir, f"{plugin_name}.py")
    
    if not os.path.exists(plugin_path):
        return False
    
    try:
        # Load the plugin module
        spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # The plugin should register itself using the @detector decorator
        return True
    
    except Exception as e:
        print(f"Failed to load plugin {plugin_name}: {e}")
        return False


def load_all_plugins(plugins_dir: str = None) -> List[str]:
    """
    Load all available plugins.
    
    Args:
        plugins_dir: Path to plugins directory
    
    Returns:
        List of successfully loaded plugin names
    """
    plugin_names = discover_plugins(plugins_dir)
    loaded_plugins = []
    
    for plugin_name in plugin_names:
        if load_plugin(plugin_name, plugins_dir):
            loaded_plugins.append(plugin_name)
    
    return loaded_plugins


def get_plugin_info(plugin_name: str, plugins_dir: str = None) -> Dict[str, Any]:
    """
    Get information about a plugin.
    
    Args:
        plugin_name: Name of the plugin
        plugins_dir: Path to plugins directory
    
    Returns:
        Dictionary with plugin information
    """
    if plugins_dir is None:
        plugins_dir = os.path.dirname(__file__)
    
    plugin_path = os.path.join(plugins_dir, f"{plugin_name}.py")
    
    if not os.path.exists(plugin_path):
        return {"error": "Plugin not found"}
    
    try:
        with open(plugin_path, 'r') as f:
            content = f.read()
        
        # Extract basic info from file content
        lines = content.split('\n')
        description = ""
        
        for line in lines:
            if line.strip().startswith('"""') or line.strip().startswith("'''"):
                description = line.strip().strip('"\'')
                break
        
        return {
            "name": plugin_name,
            "path": plugin_path,
            "description": description,
            "size": os.path.getsize(plugin_path)
        }
    
    except Exception as e:
        return {"error": str(e)}
