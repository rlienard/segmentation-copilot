"""Pluggable log-source backends."""

from .base import LogSource, LogSourceConfig
from .local import LocalFileSource
from .ssh import SSHSource

__all__ = ["LogSource", "LogSourceConfig", "LocalFileSource", "SSHSource"]
