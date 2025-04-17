"""MCP server implementation.

This module implements the Model Context Protocol (MCP) server for Stela MCP,
providing a secure interface for local system operations. It handles command
execution, file system operations, and directory management with proper
security controls and validation.

The server uses Pydantic models for input validation and provides a standardized
API for interacting with the local system through various tools and operations.
"""

import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from typing import Any, cast

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent
from pydantic import BaseModel, Field

from .filesystem import FileSystem
from .security import SecurityManager, load_security_config
from .shell import ShellExecutor

# Define environment variable names
ENV_ALLOWED_DIRS = "ALLOWED_DIRS"  # Comma-separated list of allowed directories
ENV_ALLOWED_DIR_PRIMARY = "ALLOWED_DIR"  # Primary directory for command execution context

# --- Pydantic Models for Tool Inputs ---


class ReadFileInput(BaseModel):
    """Input model for reading a single file.

    Attributes:
        path (str): Path to the file to read. Must be within allowed directories.
    """

    path: str = Field(..., description="Path to the file to read")


class ReadMultipleFilesInput(BaseModel):
    """Input model for reading multiple files.

    Attributes:
        paths (list[str]): List of file paths to read. All paths must be within allowed directories.
    """

    paths: list[str] = Field(..., description="List of file paths to read")


class WriteFileInput(BaseModel):
    """Input model for writing to a file.

    Attributes:
        path (str): Path to the file to write. Must be within allowed directories.
        content (str): Content to write to the file.
    """

    path: str = Field(..., description="Path to the file to write")
    content: str = Field(..., description="Content to write")


class EditOperation(BaseModel):
    """Model for a single file edit operation.

    Attributes:
        old_text (str): Exact lines to replace, including newlines.
        new_text (str): New lines to insert, including newlines.
    """

    old_text: str = Field(..., description="Exact lines to replace (must include newlines)")
    new_text: str = Field(..., description="Lines to insert (must include newlines)")


class EditFileInput(BaseModel):
    """Input model for editing a file with multiple operations.

    Attributes:
        path (str): Path to the file to edit. Must be within allowed directories.
        edits (list[EditOperation]): List of edit operations.
        dry_run (bool): If True, preview changes without applying.
    """

    path: str = Field(..., description="Path to the file to edit")
    edits: list[EditOperation] = Field(..., description="List of edit operations")
    dry_run: bool = Field(False, description="Preview changes without applying")


class CreateDirectoryInput(BaseModel):
    """Input model for creating a directory.

    Attributes:
        path (str): Path where the directory should be created. Must be within allowed directories.
    """

    path: str = Field(..., description="Path to the directory to create")


class ListDirectoryInput(BaseModel):
    """Input model for listing directory contents.

    Attributes:
        path (str | None): Path to the directory to list. If None, uses current shell directory.
    """

    path: str | None = Field(
        None, description="Path to the directory to list (default: current shell directory)"
    )


class DirectoryTreeInput(BaseModel):
    """Input model for generating a directory tree.

    Attributes:
        path (str | None): Path to the directory. If None, uses current shell directory.
    """

    path: str | None = Field(
        None, description="Path to the directory (default: current shell directory)"
    )


class MoveFileInput(BaseModel):
    """Input model for moving or renaming a file/directory.

    Attributes:
        source (str): Source path to move from. Must be within allowed directories.
        destination (str): Destination path to move to. Must be within allowed directories.
    """

    source: str = Field(..., description="Source path")
    destination: str = Field(..., description="Destination path")


class SearchFilesInput(BaseModel):
    """Input model for searching files and directories.

    Attributes:
        path (str | None): Base directory to search in. If None, uses current shell directory.
        pattern (str): Search pattern for substring matching.
        exclude_patterns (list[str]): List of glob patterns to exclude from search.
    """

    path: str | None = Field(
        None, description="Base directory to search in (default: current shell directory)"
    )
    pattern: str = Field(..., description="Search pattern (substring match)")
    exclude_patterns: list[str] = Field(
        [], description="List of glob patterns to exclude (relative to search path)"
    )


class GetFileInput(BaseModel):
    """Input model for getting file/directory information.

    Attributes:
        path (str): Path to the file or directory. Must be within allowed directories.
    """

    path: str = Field(..., description="Path to the file or directory")


class NoInput(BaseModel):
    """Empty input model for tools that require no arguments."""

    pass


class ExecuteCommandInput(BaseModel):
    """Input model for executing a shell command.

    Attributes:
        command (str): The command string to execute (e.g., 'ls -l').
        working_dir (str | None): Optional directory to run the command in.
            Must be within primary allowed directory.
    """

    command: str = Field(..., description="The command string to execute (e.g., 'ls -l')")
    working_dir: str | None = Field(
        None,
        description="Optional directory path to run the command in "
        "(must be within primary allowed dir)",
    )


class ChangeDirectoryInput(BaseModel):
    """Input model for changing the working directory.

    Attributes:
        path (str): Path to change to. Must be within allowed directories.
    """

    path: str = Field(..., description="Path to change to")


# --- End Pydantic Models ---


class LocalSystemServer:
    """Server implementation for local system operations with security constraints.

    This class implements a Model Context Protocol (MCP) server that provides secure
    access to local system operations including file system operations, command
    execution, and directory management. It uses a security manager to enforce
    access controls and validate operations within allowed directories.

    The server is configured through environment variables:
    - ALLOWED_DIRS: Comma-separated list of directories where operations are allowed
    - ALLOWED_DIR: Primary directory for command execution context

    Attributes:
        server (Server): The underlying MCP server instance
        allowed_directories (list[str]): List of directories where operations are allowed
        shell (ShellExecutor): Executor for shell commands
        filesystem (FileSystem): Manager for file system operations
        security (SecurityManager): Manager for security controls and validation
    """

    def __init__(self) -> None:
        """Initialize the LocalSystemServer with security constraints and components.

        Sets up the server with allowed directories from environment variables,
        initializes core components (ShellExecutor, FileSystem, SecurityManager),
        and registers request handlers.

        The allowed directories are determined from the ALLOWED_DIRS environment
        variable, falling back to the current working directory if not set. The
        primary allowed directory for command execution is determined from
        ALLOWED_DIR, falling back to the first allowed directory or current
        working directory.
        """
        self.server: Server = Server(
            name="StelaMCP",
            version="0.5.0",
            instructions=(
                "A server for local system and filesystem operations with security constraints."
            ),
        )

        # Determine Allowed Directories for FileSystem
        allowed_dirs_str = os.getenv(ENV_ALLOWED_DIRS)
        if allowed_dirs_str:
            # Split by comma, strip whitespace, filter empty strings
            self.allowed_directories = [d.strip() for d in allowed_dirs_str.split(",") if d.strip()]
        else:
            # Default to current working directory if ALLOWED_DIRS is not set
            self.allowed_directories = [os.getcwd()]
        print(f"FileSystem Allowed Directories: {self.allowed_directories}")

        # Determine Primary Allowed Directory for SecurityManager (command execution context)
        primary_allowed_dir = os.getenv(ENV_ALLOWED_DIR_PRIMARY)
        if not primary_allowed_dir:
            # Fallback to the first directory in the list or cwd if list is somehow empty
            primary_allowed_dir = (
                self.allowed_directories[0] if self.allowed_directories else os.getcwd()
            )

        # Initialize components
        self.shell = ShellExecutor()  # Uses os.getcwd() initially, change_directory updates it
        # Initialize FileSystem with potentially multiple allowed directories
        self.filesystem = FileSystem(allowed_directories=self.allowed_directories)

        # Initialize SecurityManager with the single primary allowed directory
        self.security = SecurityManager(
            primary_allowed_dir=primary_allowed_dir,
            security_config=load_security_config(),
        )

        # Register handlers
        self._register_handlers()

    def _register_handlers(self) -> None:
        """Register request handlers for the MCP server.

        This method sets up two main handlers:
        1. A tool call dispatcher that routes incoming tool requests to the appropriate
           implementation method
        2. A tools listing handler that provides information about available tools

        The tool call dispatcher first checks for methods on the LocalSystemServer
        instance, then falls back to checking the FileSystem for unhandled methods.
        Explicit handlers are required for all tools to ensure proper security
        validation and error handling.
        """

        @self.server.call_tool()  # type: ignore[misc]
        async def _dispatch_tool_call(
            # Signature matches what the decorator provides:
            tool_name: str,
            arguments: dict[str, Any],
        ) -> list[TextContent]:
            """Dispatch incoming tool calls to the appropriate implementation method.

            Args:
                tool_name (str): Name of the tool being called
                arguments (dict[str, Any]): Arguments passed to the tool

            Returns:
                list[TextContent]: Results from the tool execution

            Raises:
                ValueError: If the tool name is unknown or invalid
            """
            target_method: Callable[[dict[str, Any]], Awaitable[list[TextContent]]] | None
            target_method = getattr(self, tool_name, None)

            if target_method and callable(target_method):
                # Call the actual implementation method on the LocalSystemServer instance
                result = await target_method(arguments)
                return cast(list[TextContent], result)
            else:
                # Check if it's a filesystem method we haven't explicitly mapped (optional)
                fs_method = getattr(self.filesystem, tool_name, None)
                if fs_method and callable(fs_method):
                    raise ValueError(
                        f"Tool '{tool_name}' exists on FileSystem but needs an "
                        "explicit handler in LocalSystemServer."
                    )
                else:
                    raise ValueError(f"Unknown or invalid tool name: {tool_name}")

        @self.server.list_tools()  # type: ignore[misc]
        async def list_tools_handler() -> list[dict[str, Any]]:
            """Handle the list_tools request by calling the instance method.

            Returns:
                list[dict[str, Any]]: List of available tools and their metadata
            """
            return await self.list_tools_impl()

    # --- Tool Implementations (Updated for new API) ---

    async def execute_command(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Execute a shell command with security validation.

        Args:
            arguments: Dictionary containing command execution parameters:
                - command (str): The shell command to execute
                - working_dir (str, optional): Working directory for command execution

        Returns:
            list[TextContent]: List containing command output as text content

        Raises:
            ValueError: If command is missing or exceeds maximum length
            RuntimeError: If command execution fails with non-zero exit code
        """
        command = arguments.get("command", "")
        working_dir_arg = arguments.get("working_dir")

        if not command:
            raise ValueError("Missing required argument: command")

        if len(command) > self.security.security_config.max_command_length:
            raise ValueError(
                "Command exceeds maximum length of "
                f"{self.security.security_config.max_command_length}"
            )

        validated_command, validated_args = self.security.validate_command(command)
        validated_working_dir = None
        if working_dir_arg:
            validated_working_dir = self.security._normalize_path_for_command_arg(working_dir_arg)

        result = await self.shell.execute_command(
            validated_command, validated_args, validated_working_dir
        )

        if result.get("exit_code", -1) != 0:
            error_output = result.get("stdout", "") + "\n" + result.get("stderr", "")
            error_msg = (
                result.get("error") or f"Command failed with exit code {result.get('exit_code')}"
            )
            raise RuntimeError(f"{error_msg}\nOutput:\n{error_output.strip()}")

        stdout = result.get("stdout", "")
        return [TextContent(type="text", text=stdout)] if stdout else []

    async def change_directory(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Change the shell executor's current working directory.

        Args:
            arguments: Dictionary containing:
                - path (str): Target directory path

        Returns:
            list[TextContent]: List containing confirmation message

        Raises:
            ValueError: If path is missing
            OSError: If directory change fails
        """
        path = arguments.get("path", "")
        if not path:
            raise ValueError("Missing required argument: path")

        normalized_path = self.security._normalize_path_for_command_arg(path)
        result = await self.shell.change_directory(normalized_path)

        if not result.get("success"):
            raise OSError(f"Failed to change directory: {result.get('error')}")

        return [TextContent(type="text", text=f"Changed directory to: {result.get('path')}")]

    async def read_file(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Read contents of a file with filesystem validation.

        Args:
            arguments: Dictionary containing:
                - path (str): Path to the file to read

        Returns:
            list[TextContent]: List containing file contents as text

        Raises:
            ValueError: If path is missing
            FileNotFoundError: If file doesn't exist or is not a file
            PermissionError: If access is denied
            OSError: For other filesystem errors
        """
        path = arguments.get("path", "")
        if not path:
            raise ValueError("Missing required argument: path")

        result = await self.filesystem.read_file(path)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "not a file" in error_msg or "does not exist" in error_msg:
                raise FileNotFoundError(f"Failed to read file: {error_msg}")
            elif "denied" in error_msg or "outside allowed" in error_msg:
                raise PermissionError(f"Failed to read file: {error_msg}")
            else:
                raise OSError(f"Failed to read file: {error_msg}")

        return [TextContent(type="text", text=result.get("content", ""))]

    async def read_multiple_files(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Read multiple files simultaneously with filesystem validation.

        Args:
            arguments: Dictionary containing:
                - paths (list[str]): List of file paths to read

        Returns:
            list[TextContent]: List containing combined file contents

        Raises:
            ValueError: If paths is missing or invalid
            RuntimeError: If internal filesystem error occurs
        """
        paths = arguments.get("paths", [])
        if not isinstance(paths, list) or not paths:
            raise ValueError(
                "Missing or invalid required argument: paths (must be a non-empty list)"
            )

        result = await self.filesystem.read_multiple_files(paths)

        if not result.get("success"):
            raise RuntimeError(
                f"Failed to read multiple files: {result.get('error', 'Unknown internal error')}"
            )

        results_dict = result.get("results", {})
        output_lines = []
        for path, content_or_error in results_dict.items():
            output_lines.append(f"{path}:\n{content_or_error}")

        return [TextContent(type="text", text="\n---\n".join(output_lines))]

    async def write_file(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Write content to a file with filesystem validation.

        Args:
            arguments: Dictionary containing:
                - path (str): Target file path
                - content (str): Content to write

        Returns:
            list[TextContent]: List containing success message

        Raises:
            ValueError: If path or content is missing
            PermissionError: If write access is denied
            OSError: For other filesystem errors
        """
        path = arguments.get("path", "")
        content = arguments.get("content")

        if not path:
            raise ValueError("Missing required argument: path")
        if content is None:
            raise ValueError("Missing required argument: content")

        result = await self.filesystem.write_file(path, content)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "denied" in error_msg or "outside allowed" in error_msg:
                raise PermissionError(f"Failed to write file: {error_msg}")
            else:
                raise OSError(f"Failed to write file: {error_msg}")

        return [TextContent(type="text", text=result.get("message", "File written successfully."))]

    async def edit_file(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Apply edits to a file and return a diff.

        Args:
            arguments: Dictionary containing:
                - path (str): Target file path
                - edits (list[dict]): List of edit operations
                - dry_run (bool, optional): If True, only show diff without applying changes

        Returns:
            list[TextContent]: List containing diff of changes

        Raises:
            ValueError: If path is missing or edits are invalid
            FileNotFoundError: If file doesn't exist
            PermissionError: If access is denied
            OSError: For other filesystem errors
        """
        path = arguments.get("path", "")
        edits = arguments.get("edits", [])
        dry_run = arguments.get("dry_run", False)

        if not path:
            raise ValueError("Missing required argument: path")
        if not isinstance(edits, list):
            raise ValueError("Invalid argument: edits must be a list")
        if edits and not all(
            isinstance(e, dict) and "old_text" in e and "new_text" in e for e in edits
        ):
            raise ValueError(
                "Invalid argument: each edit must be a dict with 'old_text' and 'new_text' keys"
            )

        result = await self.filesystem.edit_file(path, edits, dry_run)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "not a file" in error_msg:
                raise FileNotFoundError(f"Failed to edit file: {error_msg}")
            elif "denied" in error_msg or "outside allowed" in error_msg:
                raise PermissionError(f"Failed to edit file: {error_msg}")
            elif "Could not find exact match" in error_msg:
                raise ValueError(f"Failed to edit file: {error_msg}")
            else:
                raise OSError(f"Failed to edit file: {error_msg}")

        return [TextContent(type="text", text=result.get("diff", ""))]

    async def list_directory(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """List contents of a directory.

        Args:
            arguments: Dictionary containing:
                - path (str, optional): Directory path (defaults to current directory)

        Returns:
            list[TextContent]: List containing directory listing

        Raises:
            FileNotFoundError: If directory doesn't exist
            PermissionError: If access is denied
            OSError: For other filesystem errors
        """
        path = arguments.get("path", ".")

        result = await self.filesystem.list_directory(path)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "not a directory" in error_msg or "does not exist" in error_msg:
                raise FileNotFoundError(f"Failed to list directory: {error_msg}")
            elif "denied" in error_msg or "outside allowed" in error_msg:
                raise PermissionError(f"Failed to list directory: {error_msg}")
            else:
                raise OSError(f"Failed to list directory: {error_msg}")

        # Return the simple listing string from FileSystem
        listing = result.get("listing", "")
        return [
            TextContent(type="text", text=listing if listing else f"Directory is empty: {path}")
        ]

    async def create_directory(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Create a new directory at the specified path.

        Args:
            arguments: Dictionary containing:
                - path (str): The path where the directory should be created

        Returns:
            list[TextContent]: List containing a success message

        Raises:
            ValueError: If path argument is missing
            PermissionError: If access to the path is denied or outside allowed directories
            FileExistsError: If a file already exists at the specified path
            OSError: For other filesystem-related errors
        """
        path = arguments.get("path", "")
        if not path:
            raise ValueError("Missing required argument: path")

        result = await self.filesystem.create_directory(path)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "denied" in error_msg or "outside allowed" in error_msg:
                raise PermissionError(f"Failed to create directory: {error_msg}")
            elif "is not a directory" in error_msg:
                raise FileExistsError(f"Failed to create directory: {error_msg}")
            else:
                raise OSError(f"Failed to create directory: {error_msg}")

        return [
            TextContent(type="text", text=result.get("message", "Directory created successfully."))
        ]

    async def move_file(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Move or rename a file or directory to a new location.

        Args:
            arguments: Dictionary containing:
                - source (str): Path of the file/directory to move
                - destination (str): New path for the file/directory

        Returns:
            list[TextContent]: List containing a success message

        Raises:
            ValueError: If source or destination arguments are missing
            PermissionError: If access to source/destination is denied
            FileNotFoundError: If source file/directory doesn't exist
            FileExistsError: If destination already exists
            OSError: For other filesystem-related errors
        """
        source = arguments.get("source", "")
        destination = arguments.get("destination", "")
        if not source:
            raise ValueError("Missing required argument: source")
        if not destination:
            raise ValueError("Missing required argument: destination")

        result = await self.filesystem.move_file(source, destination)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "denied" in error_msg or "outside allowed" in error_msg:
                raise PermissionError(f"Failed to move: {error_msg}")
            elif "does not exist" in error_msg:
                raise FileNotFoundError(f"Failed to move: {error_msg}")
            elif "already exists" in error_msg:
                raise FileExistsError(f"Failed to move: {error_msg}")
            else:
                raise OSError(f"Failed to move: {error_msg}")

        return [TextContent(type="text", text=result.get("message", "Move successful."))]

    async def search_files(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Search for files and directories matching a pattern.

        Args:
            arguments: Dictionary containing:
                - path (str, optional): Directory to search in (defaults to current directory)
                - pattern (str): Pattern to match files/directories against
                - exclude_patterns (list[str]): Patterns to exclude from results

        Returns:
            list[TextContent]: List containing search results

        Raises:
            ValueError: If pattern is missing or exclude_patterns is not a list
            FileNotFoundError: If search directory doesn't exist
            PermissionError: If access to search directory is denied
            RuntimeError: For other search-related errors
        """
        path = arguments.get("path", ".")
        pattern = arguments.get("pattern", "")
        exclude_patterns = arguments.get("exclude_patterns", [])

        if not pattern:
            raise ValueError("Missing required argument: pattern")
        if not isinstance(exclude_patterns, list):
            raise ValueError("Invalid argument: exclude_patterns must be a list")

        result = await self.filesystem.search_files(path, pattern, exclude_patterns)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "not a directory" in error_msg or "does not exist" in error_msg:
                raise FileNotFoundError(f"File search failed: {error_msg}")
            elif "denied" in error_msg or "outside allowed" in error_msg:
                raise PermissionError(f"File search failed: {error_msg}")
            else:
                raise RuntimeError(f"File search failed: {error_msg}")

        matches = result.get("matches", [])
        if isinstance(matches, str):
            matches_text = matches
        elif not matches:
            matches_text = f"No files found matching pattern '{pattern}' in {path}"
        else:
            matches_text = "\n".join(matches)

        return [TextContent(type="text", text=matches_text)]

    async def directory_tree(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Generate a recursive JSON representation of a directory structure.

        Args:
            arguments: Dictionary containing:
                - path (str, optional): Directory to generate tree for
                  (defaults to current directory)

        Returns:
            list[TextContent]: List containing the directory tree as a JSON string

        Raises:
            FileNotFoundError: If directory doesn't exist
            PermissionError: If access to directory is denied
            RuntimeError: For other errors including JSON serialization failures
        """
        path = arguments.get("path", ".")

        result = await self.filesystem.get_directory_tree(path)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "not a directory" in error_msg or "does not exist" in error_msg:
                raise FileNotFoundError(f"Failed to generate directory tree: {error_msg}")
            elif "denied" in error_msg or "outside allowed" in error_msg:
                raise PermissionError(f"Failed to generate directory tree: {error_msg}")
            else:
                raise RuntimeError(f"Failed to generate directory tree: {error_msg}")

        tree = result.get("tree", {})
        if not tree:
            return [TextContent(type="text", text=f"Directory is empty or inaccessible: {path}")]

        try:
            tree_text = json.dumps(tree, indent=2)
        except TypeError as e:
            raise RuntimeError(f"Failed to serialize directory tree to JSON: {e}") from e

        return [TextContent(type="text", text=tree_text)]

    async def get_file_info(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Get detailed metadata about a file or directory.

        Args:
            arguments: Dictionary containing:
                - path (str): Path to the file/directory

        Returns:
            list[TextContent]: List containing formatted file/directory information

        Raises:
            ValueError: If path argument is missing
            FileNotFoundError: If file/directory doesn't exist
            PermissionError: If access to file/directory is denied
            OSError: For other filesystem-related errors
        """
        path = arguments.get("path", "")
        if not path:
            raise ValueError("Missing required argument: path")

        result = await self.filesystem.get_file_info(path)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "not found" in error_msg:
                raise FileNotFoundError(f"Failed to get file info: {error_msg}")
            elif "denied" in error_msg or "outside allowed" in error_msg:
                raise PermissionError(f"Failed to get file info: {error_msg}")
            else:
                raise OSError(f"Failed to get file info: {error_msg}")

        return [TextContent(type="text", text=result.get("info", ""))]

    async def list_allowed_directories(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """List all directories that the FileSystem is permitted to access.

        Args:
            arguments: Dictionary (ignored)

        Returns:
            list[TextContent]: List containing formatted list of allowed directories

        Raises:
            RuntimeError: If listing allowed directories fails
        """
        result = await self.filesystem.list_allowed_directories()

        if not result.get("success"):
            # This should ideally never fail
            raise RuntimeError(f"Failed to list allowed directories: {result.get('error')}")

        allowed_dirs = result.get("allowed_directories", [])
        output = "Allowed directories:\n" + "\n".join(allowed_dirs)
        return [TextContent(type="text", text=output)]

    async def show_security_rules(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Display the current security configuration for command execution.

        This method shows the security rules managed by the SecurityManager,
        including allowed commands, flags, and execution limits. For filesystem
        access rules, use list_allowed_directories instead.

        Args:
            arguments: Dictionary (ignored)

        Returns:
            list[TextContent]: List containing formatted security configuration
        """
        commands_desc = (
            "All commands allowed"
            if self.security.security_config.allow_all_commands
            else ", ".join(sorted(self.security.security_config.allowed_commands)) or "None"
        )
        flags_desc = (
            "All flags allowed"
            if self.security.security_config.allow_all_flags
            else ", ".join(sorted(self.security.security_config.allowed_flags)) or "None"
        )

        security_info = (
            "Command Execution Security Configuration:\n"
            f"======================================\n"
            f"Primary Working Directory Context: {self.security.primary_allowed_dir}\n"
            f"\nAllowed Commands:\n"
            f"----------------\n"
            f"{commands_desc}\n"
            f"\nAllowed Flags:\n"
            f"-------------\n"
            f"{flags_desc}\n"
            f"\nSecurity Limits:\n"
            f"---------------\n"
            f"Max Command Length: {self.security.security_config.max_command_length} characters\n"
            f"Command Timeout: {self.security.security_config.command_timeout} seconds\n"
        )
        return [TextContent(type="text", text=security_info)]

    # --- Tool Listing Implementation (Updated with Pydantic) ---

    async def list_tools_impl(self) -> list[dict[str, Any]]:
        """Generate a comprehensive list of available tools and their schemas.

        This method constructs a detailed list of all available tools in the MCP server,
        including both filesystem and shell/security operations. Each tool entry contains:
        - A unique name identifier
        - A detailed description of the tool's functionality and constraints
        - The input schema generated from Pydantic models

        The tools are organized into two main categories:
        1. Filesystem Tools: Operations for file and directory management
        2. Shell/Security Tools: Command execution and security configuration tools

        The descriptions include security context information such as:
        - Allowed directories for filesystem operations
        - Primary working directory for shell commands
        - Available commands and flags for execution
        - Security constraints and limitations

        Returns:
            list[dict[str, Any]]: A list of tool definitions, where each tool is represented
                as a dictionary with the following keys:
                - name (str): The tool's identifier
                - description (str): Detailed description of the tool's functionality
                - inputSchema (dict): JSON schema for the tool's input parameters

        Note:
            The security context (allowed directories, commands, flags) is dynamically
            incorporated into the tool descriptions based on the current server configuration.
        """

        commands_desc = (
            "all commands"
            if self.security.security_config.allow_all_commands
            else ", ".join(sorted(self.security.security_config.allowed_commands)) or "none"
        )
        flags_desc = (
            "all flags"
            if self.security.security_config.allow_all_flags
            else ", ".join(sorted(self.security.security_config.allowed_flags)) or "none"
        )
        primary_dir_desc = self.security.primary_allowed_dir
        allowed_dirs_desc = "\n".join([f"- {d}" for d in self.allowed_directories])

        return [
            # --- Filesystem Tools (using FileSystem module) ---
            {
                "name": "read_file",
                "description": (
                    "Read the complete contents of a file from the file system. "
                    "Handles UTF-8 encoding. Fails if the path is not a file or not accessible. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": ReadFileInput.model_json_schema(),
            },
            {
                "name": "read_multiple_files",
                "description": (
                    "Read the contents of multiple files simultaneously."
                    "Returns results separated by '---'."
                    "Individual file read errors are reported inline."
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": ReadMultipleFilesInput.model_json_schema(),
            },
            {
                "name": "write_file",
                "description": (
                    "Create a new file or completely overwrite an existing file with new content. "
                    "Use with caution. Creates parent directories if needed. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": WriteFileInput.model_json_schema(),
            },
            {
                "name": "edit_file",
                "description": (
                    "Make selective edits to a text file based on exact line matches "
                    "(or whitespace normalized). "
                    "Each edit replaces an existing sequence of lines (`old_text`) "
                    "with new lines (`new_text`). "
                    "Returns a git-style diff of the changes. Use `dry_run` to preview. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": EditFileInput.model_json_schema(),
            },
            {
                "name": "create_directory",
                "description": (
                    "Create a new directory, including parent directories if needed. "
                    "Succeeds silently if the directory already exists. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": CreateDirectoryInput.model_json_schema(),
            },
            {
                "name": "list_directory",
                "description": (
                    "List directory contents with [FILE] or [DIR] prefixes. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": ListDirectoryInput.model_json_schema(),
            },
            {
                "name": "directory_tree",
                "description": (
                    "Get a recursive tree view of files and directories as a JSON structure. "
                    "Each entry includes 'name', 'type' (file/directory), "
                    "and potentially 'children' for directories. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": DirectoryTreeInput.model_json_schema(),
            },
            {
                "name": "move_file",
                "description": (
                    "Move or rename files and directories. Fails if the destination already exists."
                    f"Both source and destination must resolve within allowed directories:"
                    f"\n{allowed_dirs_desc}"
                ),
                "inputSchema": MoveFileInput.model_json_schema(),
            },
            {
                "name": "search_files",
                "description": (
                    "Recursively search for files/directories matching a pattern "
                    "(case-insensitive). "
                    "Use `exclude_patterns` (glob format relative to search path) "
                    "to ignore paths. "
                    f"Only searches within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": SearchFilesInput.model_json_schema(),
            },
            {
                "name": "get_file_info",
                "description": (
                    "Retrieve detailed metadata about a file or directory "
                    "(size, dates, type, permissions). "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": GetFileInput.model_json_schema(),
            },
            {
                "name": "list_allowed_directories",
                "description": (
                    "List all directories the server's FileSystem module is allowed to access."
                ),
                "inputSchema": NoInput.model_json_schema(),
            },
            # --- Shell/Security Tools (using ShellExecutor/SecurityManager) ---
            {
                "name": "execute_command",
                "description": (
                    "Execute a shell command in the current shell working directory "
                    "or a specified one. "
                    f"Command execution context is limited to: {primary_dir_desc}\n\n"
                    f"Available commands: {commands_desc}\n"
                    f"Available flags: {flags_desc}\n\n"
                    "Note: Shell operators (&&, |, >, etc.) are NOT supported. "
                    "Paths in arguments are validated against the primary directory context."
                ),
                "inputSchema": ExecuteCommandInput.model_json_schema(),
            },
            {
                "name": "change_directory",
                "description": (
                    "Change the shell's current working directory. "
                    "The path must be within the primary allowed directory context:"
                    f"{primary_dir_desc}"
                ),
                "inputSchema": ChangeDirectoryInput.model_json_schema(),
            },
            {
                "name": "show_security_rules",
                "description": (
                    "Show security configuration for command execution "
                    "(allowed commands, flags, primary directory context)."
                ),
                "inputSchema": NoInput.model_json_schema(),
            },
        ]

    # --- Server Run ---

    async def run(self) -> None:
        """Run the server using standard input/output streams.

        This method initializes and runs the server using stdio communication channels.
        It sets up the necessary read and write streams and configures the server with
        initialization options.

        The server will:
        1. Create stdio communication channels
        2. Configure the server with initialization options
        3. Start listening for incoming requests
        4. Process requests until the server is shut down

        Note:
            This is an async method and should be awaited when called.
            The server will continue running until explicitly shut down.
        """
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )


async def main() -> None:
    """Entry point for the STeLA MCP server.

    This function:
    1. Creates a new instance of LocalSystemServer
    2. Initializes the server with default configuration
    3. Starts the server using stdio communication
    4. Runs until the server is shut down

    The server will handle:
    - File system operations within allowed directories
    - Shell command execution with security constraints
    - Directory navigation and management
    - File content operations (read/write/edit)
    - Security rule management

    Note:
        This is the main entry point when running the server directly.
        It should be called using asyncio.run() to properly handle async execution.
    """
    # Create our server implementation
    server = LocalSystemServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
