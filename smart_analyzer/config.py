"""
Configuration system for the Solidity Static Analyzer.

This module provides configuration management with YAML support
for customizable analyzer settings.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from contextlib import contextmanager


@dataclass
class AnalyzerConfig:
    """Configuration for the analyzer."""
    
    # Output settings
    output_format: str = "rich"  # rich, json, markdown
    show_progress: bool = True
    show_summary: bool = True
    show_file_breakdown: bool = True
    
    # Analysis settings
    max_file_size_mb: int = 10
    ignore_patterns: List[str] = field(default_factory=lambda: [
        "node_modules/", ".git/", "build/", "dist/"
    ])
    include_patterns: List[str] = field(default_factory=lambda: ["*.sol"])
    
    # Detector settings
    enabled_detectors: List[str] = field(default_factory=list)  # Empty = all enabled
    disabled_detectors: List[str] = field(default_factory=list)
    detector_severity_threshold: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Plugin settings
    plugins_dir: str = "plugins"
    auto_load_plugins: bool = True
    
    # Performance settings
    parallel_analysis: bool = False
    max_workers: int = 4
    
    # Custom settings
    custom_settings: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        if self.output_format not in ["rich", "json", "markdown"]:
            raise ValueError(f"Invalid output format: {self.output_format}")
        
        if self.detector_severity_threshold not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            raise ValueError(f"Invalid severity threshold: {self.detector_severity_threshold}")


class ConfigManager:
    """Manager for configuration files."""
    
    DEFAULT_CONFIG_FILE = "analyzer_config.yaml"
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file or self.DEFAULT_CONFIG_FILE
        self.config = AnalyzerConfig()
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = yaml.safe_load(f)
                
                if config_data:
                    self._update_config_from_dict(config_data)
            except Exception as e:
                print(f"Warning: Failed to load config file: {e}")
    
    def _update_config_from_dict(self, config_data: Dict[str, Any]) -> None:
        """Update configuration from dictionary."""
        for key, value in config_data.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
    
    def save_config(self) -> None:
        """Save current configuration to file."""
        config_dict = {
            "output_format": self.config.output_format,
            "show_progress": self.config.show_progress,
            "show_summary": self.config.show_summary,
            "show_file_breakdown": self.config.show_file_breakdown,
            "max_file_size_mb": self.config.max_file_size_mb,
            "ignore_patterns": self.config.ignore_patterns,
            "include_patterns": self.config.include_patterns,
            "enabled_detectors": self.config.enabled_detectors,
            "disabled_detectors": self.config.disabled_detectors,
            "detector_severity_threshold": self.config.detector_severity_threshold,
            "plugins_dir": self.config.plugins_dir,
            "auto_load_plugins": self.config.auto_load_plugins,
            "parallel_analysis": self.config.parallel_analysis,
            "max_workers": self.config.max_workers,
            "custom_settings": self.config.custom_settings
        }
        
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save config file: {e}")
    
    def create_default_config(self) -> None:
        """Create a default configuration file."""
        if not os.path.exists(self.config_file):
            self.save_config()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return getattr(self.config, key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value."""
        if hasattr(self.config, key):
            setattr(self.config, key, value)
        else:
            self.config.custom_settings[key] = value
    
    def is_detector_enabled(self, detector_name: str) -> bool:
        """Check if a detector is enabled."""
        if self.config.enabled_detectors and detector_name not in self.config.enabled_detectors:
            return False
        
        if detector_name in self.config.disabled_detectors:
            return False
        
        return True
    
    def should_ignore_file(self, file_path: str) -> bool:
        """Check if a file should be ignored."""
        file_path = str(file_path)
        
        # Check ignore patterns
        for pattern in self.config.ignore_patterns:
            if pattern in file_path:
                return True
        
        # Check include patterns
        if self.config.include_patterns:
            for pattern in self.config.include_patterns:
                if file_path.endswith(pattern.replace("*", "")):
                    return False
            return True
        
        return False


# Global configuration instance
_config_manager = None


def get_config() -> ConfigManager:
    """Get the global configuration manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


@contextmanager
def config_context(config_file: str = None):
    """Context manager for temporary configuration changes."""
    global _config_manager
    old_config = _config_manager
    
    try:
        _config_manager = ConfigManager(config_file)
        yield _config_manager
    finally:
        _config_manager = old_config


def create_sample_config() -> str:
    """Create a sample configuration file."""
    sample_config = {
        "output_format": "rich",
        "show_progress": True,
        "show_summary": True,
        "show_file_breakdown": True,
        "max_file_size_mb": 10,
        "ignore_patterns": [
            "node_modules/",
            ".git/",
            "build/",
            "dist/"
        ],
        "include_patterns": ["*.sol"],
        "enabled_detectors": [],  # Empty = all enabled
        "disabled_detectors": [],
        "detector_severity_threshold": "LOW",
        "plugins_dir": "plugins",
        "auto_load_plugins": True,
        "parallel_analysis": False,
        "max_workers": 4,
        "custom_settings": {
            "example_setting": "example_value"
        }
    }
    
    return yaml.dump(sample_config, default_flow_style=False, indent=2) 