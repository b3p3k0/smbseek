"""
SMBSeek Configuration Management

Centralized configuration loading and management for the unified CLI.
Handles the reorganized configuration structure while maintaining compatibility.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, Optional


def get_standard_timestamp() -> str:
    """
    Generate standard timestamp truncated to minutes (no fractional seconds).
    
    Returns:
        ISO format timestamp string (YYYY-MM-DDTHH:MM:SS)
    """
    return datetime.now().replace(second=0, microsecond=0).isoformat()


class SMBSeekConfig:
    """
    Centralized configuration management for SMBSeek.
    
    Loads and manages configuration from JSON files with sensible defaults
    and the new reorganized structure.
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_file: Path to configuration file (default: conf/config.json)
        """
        if config_file is None:
            # Default configuration path from project root
            config_file = os.path.join("conf", "config.json")
        
        self.config_file = config_file
        self.config = self.load_configuration()
    
    def load_configuration(self) -> Dict[str, Any]:
        """
        Load configuration from JSON file with fallback to defaults.
        
        Returns:
            Configuration dictionary with all required sections
        """
        default_config = {
            "shodan": {
                "api_key": "",
                "query_limits": {
                    "max_results": 1000,
                    "timeout": 30
                },
                "query_components": {
                    "base_query": "smb authentication: disabled",
                    "product_filter": "product:\"Samba\"",
                    "additional_exclusions": ["-\"DSL\""],
                    "use_organization_exclusions": True,
                    "string_filters": [],
                    "string_combination": "OR"
                }
            },
            "workflow": {
                "rescan_after_days": 30,
                "pause_between_steps": False,
                "auto_collect_files": True,
                "skip_failed_hosts": True
            },
            "connection": {
                "timeout": 30,
                "port_check_timeout": 10,
                "rate_limit_delay": 3,
                "share_access_delay": 7
            },
            "discovery": {
                "max_concurrent_hosts": 10,
                "max_worker_cap": 20,
                "smart_throttling": False
            },
            "access": {
                "max_concurrent_hosts": 1
            },
            "file_collection": {
                "max_files_per_target": 3,
                "max_total_size_mb": 500,
                "download_delay_seconds": 2,
                "max_directory_depth": 3,
                "enumeration_timeout_seconds": 120,
                "included_extensions": [
                    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv",
                    ".eml", ".msg", ".mbox", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
                    ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".mp3", ".wav", ".zip", ".rar"
                ],
                "excluded_extensions": [
                    ".exe", ".dll", ".sys", ".bat", ".cmd", ".scr", ".com", ".pif", ".msi", 
                    ".bin", ".log", ".tmp", ".temp", ".bak", ".old", ".swp", ".lock"
                ]
            },
            "file_browser": {
                "allow_smb1": True,
                "connect_timeout_seconds": 8,
                "request_timeout_seconds": 10,
                "max_entries_per_dir": 5000,
                "max_depth": 12,
                "max_path_length": 240,
                "download_chunk_mb": 4,
                "quarantine_root": "~/.smbseek/quarantine"
            },
            "security": {
                "ransomware_indicators": [
                    "!want_to_cry.txt",
                    "0XXX_DECRYPTION_README.TXT",
                    "HOW_TO_DECRYPT_FILES.txt",
                    "DECRYPT_INSTRUCTIONS.txt",
                    "_DECRYPT_INFO_.txt",
                    "README_FOR_DECRYPT.txt"
                ],
                "exclusion_file": "conf/exclusion_list.txt"
            },
            "database": {
                "path": "smbseek.db",
                "backup_enabled": True,
                "backup_directory": "db_backups",
                "max_backup_files": 30
            },
            "output": {
                "colors_enabled": True,
                "verbose_by_default": False,
                "executive_summary": True
            }
        }
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
            
            # Merge user config with defaults (deep merge)
            merged_config = self._deep_merge(default_config, user_config)
            return merged_config
            
        except FileNotFoundError:
            print(f"⚠ Configuration file not found: {self.config_file}")
            print("⚠ Using default configuration values")
            return default_config
        except json.JSONDecodeError as e:
            print(f"⚠ Invalid JSON in configuration file: {e}")
            print("⚠ Using default configuration values")
            return default_config
        except Exception as e:
            print(f"⚠ Error loading configuration: {e}")
            print("⚠ Using default configuration values")
            return default_config
    
    def _deep_merge(self, default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep merge user configuration with defaults.
        
        Args:
            default: Default configuration dictionary
            user: User configuration dictionary
            
        Returns:
            Merged configuration dictionary
        """
        result = default.copy()
        
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """
        Get configuration value.
        
        Args:
            section: Configuration section name
            key: Specific key within section (optional)
            default: Default value if not found
            
        Returns:
            Configuration value or default
        """
        if section not in self.config:
            return default
        
        if key is None:
            return self.config[section]
        
        return self.config[section].get(key, default)
    
    def get_shodan_api_key(self) -> str:
        """Get Shodan API key with validation."""
        api_key = self.get("shodan", "api_key", "")
        if not api_key:
            raise ValueError("Shodan API key not configured. Please set 'shodan.api_key' in config.json")
        return api_key
    
    def get_shodan_config(self) -> Dict[str, Any]:
        """Get Shodan configuration section."""
        return self.get("shodan", default={
            "api_key": "",
            "query_limits": {
                "max_results": 1000,
                "timeout": 30
            }
        })
    
    def get_database_path(self) -> str:
        """Get database file path."""
        return self.get("database", "path", "smbseek.db")
    
    def should_rescan_host(self, last_seen_days: int) -> bool:
        """
        Check if a host should be rescanned based on configuration.
        
        Args:
            last_seen_days: Days since host was last scanned
            
        Returns:
            True if host should be rescanned
        """
        rescan_after = self.get("workflow", "rescan_after_days", 30)
        return last_seen_days >= rescan_after
    
    def should_skip_failed_hosts(self) -> bool:
        """Check if failed hosts should be skipped by default."""
        return self.get("workflow", "skip_failed_hosts", True)
    
    def get_exclusion_file_path(self) -> str:
        """Get path to exclusion list file."""
        return self.get("security", "exclusion_file", "conf/exclusion_list.txt")
    
    def get_ransomware_indicators(self) -> list:
        """Get list of ransomware indicator patterns."""
        return self.get("security", "ransomware_indicators", [])
    
    def get_connection_timeout(self) -> int:
        """Get SMB connection timeout."""
        return self.get("connection", "timeout", 30)
    
    def get_rate_limit_delay(self) -> int:
        """Get delay between connection attempts."""
        return self.get("connection", "rate_limit_delay", 3)
    
    def get_share_access_delay(self) -> int:
        """Get delay between share access tests on same host."""
        return self.get("connection", "share_access_delay", 7)

    def get_max_concurrent_hosts(self) -> int:
        """Get maximum concurrent hosts for access operations with validation."""
        value = self.get("access", "max_concurrent_hosts", 1)
        if isinstance(value, int) and value >= 1:
            return value
        else:
            # Fallback to 1 for invalid values (zero, negative, or non-integer)
            return 1

    def get_max_concurrent_discovery_hosts(self) -> int:
        """Get maximum concurrent hosts for discovery operations with validation."""
        value = self.get("discovery", "max_concurrent_hosts", 10)
        if isinstance(value, int) and value >= 1:
            return value
        else:
            # Fallback to 10 for invalid values (zero, negative, or non-integer)
            return 10

    def get_discovery_smart_throttling(self) -> bool:
        """Get whether smart throttling is enabled for discovery."""
        return self.get("discovery", "smart_throttling", False)

    def get_max_worker_cap(self) -> int:
        """Get maximum worker cap for thread pool safety with validation."""
        value = self.get("discovery", "max_worker_cap", 20)
        if isinstance(value, int) and value >= 1:
            return value
        else:
            # Fallback to 20 for invalid values (zero, negative, or non-integer)
            return 20

    def resolve_target_countries(self, args_country: Optional[str] = None) -> list:
        """
        Resolve target countries using explicit argument or global scan.

        Args:
            args_country: Country argument from command line (optional)

        Returns:
            List of country codes to scan, empty list for global scan
        """
        # Use --country flag if provided
        if args_country:
            # Handle comma-separated countries
            return [country.strip().upper() for country in args_country.split(',')]

        # Default to global scan (no country filter)
        return []
    
    def validate_configuration(self) -> bool:
        """
        Validate configuration for common issues.
        
        Returns:
            True if configuration appears valid
        """
        issues = []
        
        # Check Shodan API key
        if not self.get("shodan", "api_key"):
            issues.append("Missing Shodan API key")
        
        # Check exclusion file exists
        exclusion_file = self.get_exclusion_file_path()
        if not os.path.exists(exclusion_file):
            issues.append(f"Exclusion file not found: {exclusion_file}")
        
        # Check reasonable values
        if self.get("workflow", "rescan_after_days", 30) < 1:
            issues.append("rescan_after_days must be at least 1")
        
        if self.get("connection", "timeout", 30) < 5:
            issues.append("connection timeout should be at least 5 seconds")
        
        if issues:
            print("⚠ Configuration validation issues:")
            for issue in issues:
                print(f"  • {issue}")
            return False
        
        return True


def load_config(config_file: Optional[str] = None) -> SMBSeekConfig:
    """
    Convenience function to load SMBSeek configuration.
    
    Args:
        config_file: Path to configuration file
        
    Returns:
        SMBSeekConfig instance
    """
    return SMBSeekConfig(config_file)
