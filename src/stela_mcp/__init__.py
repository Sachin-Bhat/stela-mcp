"""Stela MCP - A Python package for MCP (Multi-Cloud Platform) operations."""

from .shell import ShellExecutor
from .filesystem import FileSystem

__version__ = "0.1.0"
__all__ = ["ShellExecutor", "FileSystem"]

def hello() -> str:
    return "Hello from stela-mcp!"
