"""Stela MCP - A Python implementation of a Model Context Protocol server."""

__version__ = "0.2.0"

from .filesystem import FileSystem
from .shell import ShellExecutor

__all__ = ["ShellExecutor", "FileSystem"]


def hello() -> str:
    return "Hello from stela-mcp!"
