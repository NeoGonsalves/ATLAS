"""
ATLAS Configuration Module

Centralized configuration management for the ATLAS framework.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


def _parse_bool(value: str, default: bool = False) -> bool:
    """Parse bool-like environment values."""
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: str, default: int, minimum: int, maximum: int) -> int:
    """Parse and clamp integer environment values."""
    if value is None:
        return default
    try:
        parsed = int(value.strip())
    except ValueError:
        return default
    return max(minimum, min(maximum, parsed))


@dataclass
class Config:
    """ATLAS Configuration"""
    
    # Paths
    base_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent)
    data_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "data")
    db_path: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "data" / "atlas.db")
    
    # Scan Settings
    default_timeout: int = 30  # seconds
    max_concurrent_checks: int = 5
    
    # Nmap Settings
    nmap_path: Optional[str] = None  # Auto-detect if None
    nmap_default_args: str = "-sV -T4 --top-ports 100"
    nmap_timeout: int = 300  # 5 minutes
    
    # Web UI Settings
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[Path] = None

    # Web terminal security controls
    enable_web_terminal: bool = False
    web_terminal_mode: str = "safe"  # safe | raw (raw is unsafe, dev-only)
    terminal_command_timeout: int = 10
    terminal_output_limit_chars: int = 12000
    terminal_max_input_chars: int = 256

    def __post_init__(self):
        """Ensure data directory exists"""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Override from environment variables
        if env_db := os.getenv("ATLAS_DB_PATH"):
            self.db_path = Path(env_db)
        if env_nmap := os.getenv("ATLAS_NMAP_PATH"):
            self.nmap_path = env_nmap
        if env_log := os.getenv("ATLAS_LOG_LEVEL"):
            self.log_level = env_log
        self.enable_web_terminal = _parse_bool(
            os.getenv("ATLAS_ENABLE_WEB_TERMINAL"), default=False
        )
        self.web_terminal_mode = (
            os.getenv("ATLAS_WEB_TERMINAL_MODE", self.web_terminal_mode).strip().lower()
        )
        if self.web_terminal_mode not in {"safe", "raw"}:
            self.web_terminal_mode = "safe"
        self.terminal_command_timeout = _parse_int(
            os.getenv("ATLAS_TERMINAL_COMMAND_TIMEOUT"),
            default=self.terminal_command_timeout,
            minimum=1,
            maximum=120,
        )
        self.terminal_output_limit_chars = _parse_int(
            os.getenv("ATLAS_TERMINAL_OUTPUT_LIMIT_CHARS"),
            default=self.terminal_output_limit_chars,
            minimum=1000,
            maximum=100000,
        )
        self.terminal_max_input_chars = _parse_int(
            os.getenv("ATLAS_TERMINAL_MAX_INPUT_CHARS"),
            default=self.terminal_max_input_chars,
            minimum=32,
            maximum=2048,
        )


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create global config instance"""
    global _config
    if _config is None:
        _config = Config()
    return _config
