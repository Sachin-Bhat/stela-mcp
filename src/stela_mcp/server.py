"""MCP server implementation."""

import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from typing import Any, cast, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent
from pydantic import BaseModel, Field

from .filesystem import FileSystem
from .security import SecurityManager, load_security_config
from .shell import ShellExecutor

# Define environment variable names
ENV_ALLOWED_DIRS = "ALLOWED_DIRS"
ENV_ALLOWED_DIR_PRIMARY = "ALLOWED_DIR" # Keep for primary security context

# --- Pydantic Models for Tool Inputs ---

class ReadFileInput(BaseModel):
    path: str = Field(..., description="Path to the file to read")

class ReadMultipleFilesInput(BaseModel):
    paths: List[str] = Field(..., description="List of file paths to read")

class WriteFileInput(BaseModel):
    path: str = Field(..., description="Path to the file to write")
    content: str = Field(..., description="Content to write")

class EditOperation(BaseModel):
    oldText: str = Field(..., description="Exact lines to replace (must include newlines)")
    newText: str = Field(..., description="Lines to insert (must include newlines)")

class EditFileInput(BaseModel):
    path: str = Field(..., description="Path to the file to edit")
    edits: List[EditOperation] = Field(..., description="List of edit operations")
    dryRun: bool = Field(False, description="Preview changes without applying")

class CreateDirectoryInput(BaseModel):
    path: str = Field(..., description="Path to the directory to create")

class ListDirectoryInput(BaseModel):
    # Optional field - default handled in the method logic
    path: Optional[str] = Field(None, description="Path to the directory to list (default: current shell directory)")

class DirectoryTreeInput(BaseModel):
    # Optional field - default handled in the method logic
    path: Optional[str] = Field(None, description="Path to the directory (default: current shell directory)")

class MoveFileInput(BaseModel):
    source: str = Field(..., description="Source path")
    destination: str = Field(..., description="Destination path")

class SearchFilesInput(BaseModel):
    # Optional path - default handled in the method logic
    path: Optional[str] = Field(None, description="Base directory to search in (default: current shell directory)")
    pattern: str = Field(..., description="Search pattern (substring match)")
    excludePatterns: List[str] = Field([], description="List of glob patterns to exclude (relative to search path)")

class GetFileInput(BaseModel):
    path: str = Field(..., description="Path to the file or directory")

# Models for tools with no input arguments
class NoInput(BaseModel):
    pass

class ExecuteCommandInput(BaseModel):
    command: str = Field(..., description="The command string to execute (e.g., 'ls -l')")
    working_dir: Optional[str] = Field(None, description="Optional directory path to run the command in (must be within primary allowed dir)")

class ChangeDirectoryInput(BaseModel):
    path: str = Field(..., description="Path to change to")

# --- End Pydantic Models ---

class LocalSystemServer:
    def __init__(self) -> None:
        self.server: Server = Server(
            name="StelaMCP",
            version="0.5.0",
            instructions="A server for local system and filesystem operations with security constraints.",
        )

        # Determine Allowed Directories for FileSystem
        allowed_dirs_str = os.getenv(ENV_ALLOWED_DIRS)
        if allowed_dirs_str:
            # Split by comma, strip whitespace, filter empty strings
            self.allowed_directories = [d.strip() for d in allowed_dirs_str.split(',') if d.strip()]
        else:
            # Default to current working directory if ALLOWED_DIRS is not set
            self.allowed_directories = [os.getcwd()]
        print(f"FileSystem Allowed Directories: {self.allowed_directories}")

        # Determine Primary Allowed Directory for SecurityManager (command execution context)
        primary_allowed_dir = os.getenv(ENV_ALLOWED_DIR_PRIMARY)
        if not primary_allowed_dir:
            # Fallback to the first directory in the list or cwd if list is somehow empty
            primary_allowed_dir = self.allowed_directories[0] if self.allowed_directories else os.getcwd()

        # Initialize components
        self.shell = ShellExecutor() # Uses os.getcwd() initially, change_directory updates it
        # Initialize FileSystem with potentially multiple allowed directories
        self.filesystem = FileSystem(allowed_directories=self.allowed_directories)

        # Initialize SecurityManager with the single primary allowed directory
        self.security = SecurityManager(
            primary_allowed_dir=primary_allowed_dir,
            security_config=load_security_config(),
        )

        # Register handlers
        self._register_handlers()

    # --- Handler Registration (Called from __init__) ---
    def _register_handlers(self) -> None:
        """Registers handlers dynamically after self.server is created."""

        @self.server.call_tool()  # type: ignore[misc]
        async def _dispatch_tool_call(
            # Signature matches what the decorator provides:
            tool_name: str,
            arguments: dict[str, Any],
        ) -> list[TextContent]:
            """Dispatches incoming tool calls to the appropriate implementation method."""
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
                    # Basic wrapper for simple filesystem methods (if needed)
                    # This might be too generic, explicit handlers are safer
                    # print(f"Warning: Auto-dispatching to filesystem method {tool_name}")
                    # result_dict = await fs_method(**arguments)
                    # if result_dict.get("success"):
                    #     # Simple text output, may need customization per method
                    #     output = result_dict.get("message") or result_dict.get("content") or str(result_dict)
                    #     return [TextContent(type="text", text=output)]
                    # else:
                    #     raise RuntimeError(f"Filesystem tool '{tool_name}' failed: {result_dict.get('error')}")
                    raise ValueError(f"Tool '{tool_name}' exists on FileSystem but needs an explicit handler in LocalSystemServer.")
                else:
                    raise ValueError(f"Unknown or invalid tool name: {tool_name}")

        # The @self.server.call_tool() decorator registers the handler.
        # We don't need to manually assign to self.server.request_handlers here.

        @self.server.list_tools()  # type: ignore[misc]
        async def list_tools_handler() -> list[dict[str, Any]]:
            """Handles the list_tools request by calling the instance method."""
            return await self.list_tools_impl()

    # --- Tool Implementations (Updated for new API) ---

    async def execute_command(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Execute a shell command (validated by SecurityManager)."""
        command = arguments.get("command", "")
        # Optional working_dir - if provided, security manager validates it;
        # otherwise ShellExecutor uses its current self.working_dir
        working_dir_arg = arguments.get("working_dir")

        if not command:
            raise ValueError("Missing required argument: command")

        if len(command) > self.security.security_config.max_command_length:
            raise ValueError(
                "Command exceeds maximum length of "
                f"{self.security.security_config.max_command_length}"
            )

        # Validate command AND arguments (incl. basic path checks relative to primary_allowed_dir)
        validated_command, validated_args = self.security.validate_command(command)

        # Validate working_dir if provided, using SecurityManager's context
        validated_working_dir = None
        if working_dir_arg:
            validated_working_dir = self.security._normalize_path_for_command_arg(working_dir_arg)

        # Pass validated command, args, and optional validated working_dir to the shell executor
        result = await self.shell.execute_command(validated_command, validated_args, validated_working_dir)

        # Check shell execution result
        if result.get("exit_code", -1) != 0:
            # Combine stdout and stderr for error context, similar to how shells often behave
            error_output = result.get("stdout", "") + "\n" + result.get("stderr", "")
            error_msg = result.get("error") or f"Command failed with exit code {result.get('exit_code')}"
            # Raise RuntimeError for non-zero exit codes or execution errors
            raise RuntimeError(f"{error_msg}\nOutput:\n{error_output.strip()}")

        # Build success output content (only stdout on success)
        stdout = result.get("stdout", "")
        # Return empty list if no stdout, otherwise return stdout
        return [TextContent(type="text", text=stdout)] if stdout else []

    async def change_directory(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Change the shell executor's current working directory (validated by SecurityManager)."""
        path = arguments.get("path", "")
        if not path:
            raise ValueError("Missing required argument: path")

        # Validate path using Security Manager's context (primary allowed dir)
        normalized_path = self.security._normalize_path_for_command_arg(path)
        # Attempt to change directory using ShellExecutor
        result = await self.shell.change_directory(normalized_path)

        if not result.get("success"):
            # Raise OSError for cd failures
            raise OSError(f"Failed to change directory: {result.get('error')}")

        # Return confirmation message
        return [TextContent(type="text", text=f"Changed directory to: {result.get('path')}")]

    async def read_file(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Read the contents of a file (validated by FileSystem)."""
        path = arguments.get("path", "")
        if not path:
            raise ValueError("Missing required argument: path")

        # Call FileSystem directly - it handles validation
        result = await self.filesystem.read_file(path)

        if not result.get("success"):
            # Raise FileNotFoundError or PermissionError based on FileSystem's error
            error_msg = result.get("error", "Unknown error")
            if "not a file" in error_msg or "does not exist" in error_msg:
                 raise FileNotFoundError(f"Failed to read file: {error_msg}")
            elif "denied" in error_msg or "outside allowed" in error_msg:
                 raise PermissionError(f"Failed to read file: {error_msg}")
            else:
                 raise OSError(f"Failed to read file: {error_msg}") # General OS error

        # Return file content
        return [TextContent(type="text", text=result.get("content", ""))]

    async def read_multiple_files(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Read multiple files simultaneously (validated by FileSystem)."""
        paths = arguments.get("paths", [])
        if not isinstance(paths, list) or not paths:
             raise ValueError("Missing or invalid required argument: paths (must be a non-empty list)")

        # Call FileSystem method
        result = await self.filesystem.read_multiple_files(paths)

        # FileSystem's read_multiple_files is designed to always return success=True,
        # with individual errors reported in the 'results' dictionary.
        if not result.get("success"):
             # This shouldn't happen based on current FileSystem logic, but handle defensively
             raise RuntimeError(f"Failed to read multiple files: {result.get('error', 'Unknown internal error')}")

        results_dict = result.get("results", {})
        # Format output similar to TS version (path: content or path: Error - message)
        output_lines = []
        for path, content_or_error in results_dict.items():
            output_lines.append(f"{path}:\n{content_or_error}")

        combined_output = "\n---\n".join(output_lines)
        return [TextContent(type="text", text=combined_output)]

    async def write_file(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Write content to a file (validated by FileSystem)."""
        path = arguments.get("path", "")
        content = arguments.get("content")

        if not path:
            raise ValueError("Missing required argument: path")
        # Allow empty string content, but not None
        if content is None:
            raise ValueError("Missing required argument: content")

        # Call FileSystem directly
        result = await self.filesystem.write_file(path, content)

        if not result.get("success"):
             error_msg = result.get("error", "Unknown error")
             if "denied" in error_msg or "outside allowed" in error_msg:
                 raise PermissionError(f"Failed to write file: {error_msg}")
             else:
                 raise OSError(f"Failed to write file: {error_msg}")

        # Return success message from FileSystem
        return [TextContent(type="text", text=result.get("message", "File written successfully."))]

    async def edit_file(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Apply edits to a file and return a diff (validated by FileSystem)."""
        path = arguments.get("path", "")
        edits = arguments.get("edits", [])
        dry_run = arguments.get("dryRun", False)

        if not path:
            raise ValueError("Missing required argument: path")
        if not isinstance(edits, list):
            raise ValueError("Invalid argument: edits must be a list")
        # Basic check for edit structure - FileSystem does more validation
        if edits and not all(isinstance(e, dict) and 'oldText' in e and 'newText' in e for e in edits):
             raise ValueError("Invalid argument: each edit must be a dict with 'oldText' and 'newText' keys")

        # Call FileSystem method
        result = await self.filesystem.edit_file(path, edits, dry_run)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "not a file" in error_msg:
                 raise FileNotFoundError(f"Failed to edit file: {error_msg}")
            elif "denied" in error_msg or "outside allowed" in error_msg:
                 raise PermissionError(f"Failed to edit file: {error_msg}")
            elif "Could not find exact match" in error_msg:
                 # Use a more specific error type for match failures
                 raise ValueError(f"Failed to edit file: {error_msg}")
            else:
                 raise OSError(f"Failed to edit file: {error_msg}")

        # Return the diff content provided by FileSystem
        return [TextContent(type="text", text=result.get("diff", ""))]

    async def list_directory(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """List contents of a directory (validated by FileSystem)."""
        path = arguments.get("path", ".") # Default to current directory

        # Call FileSystem directly
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
        return [TextContent(type="text", text=listing if listing else f"Directory is empty: {path}")]

    async def create_directory(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Create a new directory (validated by FileSystem)."""
        path = arguments.get("path", "")
        if not path:
            raise ValueError("Missing required argument: path")

        # Call FileSystem directly
        result = await self.filesystem.create_directory(path)

        if not result.get("success"):
             error_msg = result.get("error", "Unknown error")
             if "denied" in error_msg or "outside allowed" in error_msg:
                 raise PermissionError(f"Failed to create directory: {error_msg}")
             elif "is not a directory" in error_msg: # Error if path exists as file
                  raise FileExistsError(f"Failed to create directory: {error_msg}")
             else:
                 raise OSError(f"Failed to create directory: {error_msg}")

        # Return success message from FileSystem
        return [TextContent(type="text", text=result.get("message", "Directory created successfully."))]

    async def move_file(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Move or rename a file or directory (validated by FileSystem)."""
        source = arguments.get("source", "")
        destination = arguments.get("destination", "")
        if not source:
            raise ValueError("Missing required argument: source")
        if not destination:
            raise ValueError("Missing required argument: destination")

        # Call FileSystem directly
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

        # Return success message from FileSystem
        return [TextContent(type="text", text=result.get("message", "Move successful."))]

    async def search_files(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Search for files/dirs matching a pattern (validated by FileSystem)."""
        path = arguments.get("path", ".") # Default to current directory
        pattern = arguments.get("pattern", "")
        exclude_patterns = arguments.get("excludePatterns", []) # Match TS arg name

        if not pattern:
            raise ValueError("Missing required argument: pattern")
        if not isinstance(exclude_patterns, list):
             raise ValueError("Invalid argument: excludePatterns must be a list")

        # Call FileSystem directly
        result = await self.filesystem.search_files(path, pattern, exclude_patterns)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "not a directory" in error_msg or "does not exist" in error_msg:
                 raise FileNotFoundError(f"File search failed: {error_msg}")
            elif "denied" in error_msg or "outside allowed" in error_msg:
                 raise PermissionError(f"File search failed: {error_msg}")
            else:
                 raise RuntimeError(f"File search failed: {error_msg}") # General runtime error

        matches = result.get("matches", [])
        # Handle both list output and the "No matches found" string from FileSystem
        if isinstance(matches, str):
            matches_text = matches # Use the "No matches found" string directly
        elif not matches:
            matches_text = f"No files found matching pattern '{pattern}' in {path}" # Fallback message
        else:
            matches_text = "\n".join(matches)

        return [TextContent(type="text", text=matches_text)]

    async def directory_tree(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Generate a recursive JSON tree view of a directory (validated by FileSystem)."""
        path = arguments.get("path", ".") # Default to current directory

        # Call FileSystem directly
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
        if not tree: # Should not happen if success is true, but good practice
            return [TextContent(type="text", text=f"Directory is empty or inaccessible: {path}")]

        # Format the tree dictionary as a JSON string with indentation
        try:
             tree_text = json.dumps(tree, indent=2)
        except TypeError as e:
            raise RuntimeError(f"Failed to serialize directory tree to JSON: {e}")

        return [TextContent(type="text", text=tree_text)]

    async def get_file_info(
        self,
        arguments: dict[str, Any],
    ) -> list[TextContent]:
        """Get detailed file/directory metadata (validated by FileSystem)."""
        path = arguments.get("path", "")
        if not path:
            raise ValueError("Missing required argument: path")

        # Call FileSystem directly
        result = await self.filesystem.get_file_info(path)

        if not result.get("success"):
            error_msg = result.get("error", "Unknown error")
            if "not found" in error_msg:
                 raise FileNotFoundError(f"Failed to get file info: {error_msg}")
            elif "denied" in error_msg or "outside allowed" in error_msg:
                 raise PermissionError(f"Failed to get file info: {error_msg}")
            else:
                 raise OSError(f"Failed to get file info: {error_msg}")

        # Return the formatted info string from FileSystem
        return [TextContent(type="text", text=result.get("info", ""))]

    async def list_allowed_directories(
        self,
        arguments: dict[str, Any], # Arguments ignored for this tool
    ) -> list[TextContent]:
        """List all directories the FileSystem is allowed to access."""
        # Call FileSystem directly
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
        """Show security configuration for COMMAND EXECUTION."""
        # This only shows rules from SecurityManager (command execution)
        # Use list_allowed_directories for filesystem access rules.
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
        """Provides the list of available tools and their schemas using Pydantic."""

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
                "inputSchema": ReadFileInput.model_json_schema()
            },
            {
                "name": "read_multiple_files",
                "description": (
                    "Read the contents of multiple files simultaneously. Returns results separated by '---'. "
                    "Individual file read errors are reported inline. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": ReadMultipleFilesInput.model_json_schema()
            },
            {
                "name": "write_file",
                "description": (
                    "Create a new file or completely overwrite an existing file with new content. "
                    "Use with caution. Creates parent directories if needed. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": WriteFileInput.model_json_schema()
            },
            {
                "name": "edit_file",
                "description": (
                    "Make selective edits to a text file based on exact line matches (or whitespace normalized). "
                    "Each edit replaces an existing sequence of lines (`oldText`) with new lines (`newText`). "
                    "Returns a git-style diff of the changes. Use `dryRun` to preview. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": EditFileInput.model_json_schema()
            },
            {
                "name": "create_directory",
                "description": (
                    "Create a new directory, including parent directories if needed. "
                    "Succeeds silently if the directory already exists. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": CreateDirectoryInput.model_json_schema()
            },
            {
                "name": "list_directory",
                "description": (
                    "List directory contents with [FILE] or [DIR] prefixes. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": ListDirectoryInput.model_json_schema()
            },
            {
                "name": "directory_tree",
                "description": (
                    "Get a recursive tree view of files and directories as a JSON structure. "
                    "Each entry includes 'name', 'type' (file/directory), and potentially 'children' for directories. "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                 "inputSchema": DirectoryTreeInput.model_json_schema()
            },
            {
                "name": "move_file",
                "description": (
                    "Move or rename files and directories. Fails if the destination already exists. "
                    f"Both source and destination must resolve within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": MoveFileInput.model_json_schema()
            },
            {
                "name": "search_files",
                "description": (
                    "Recursively search for files/directories matching a pattern (case-insensitive). "
                    "Use `excludePatterns` (glob format relative to search path) to ignore paths. "
                    f"Only searches within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": SearchFilesInput.model_json_schema()
            },
             {
                "name": "get_file_info",
                "description": (
                    "Retrieve detailed metadata about a file or directory (size, dates, type, permissions). "
                    f"Only works within allowed directories:\n{allowed_dirs_desc}"
                ),
                "inputSchema": GetFileInput.model_json_schema()
            },
            {
                "name": "list_allowed_directories",
                "description": "List all directories the server's FileSystem module is allowed to access.",
                "inputSchema": NoInput.model_json_schema()
            },

            # --- Shell/Security Tools (using ShellExecutor/SecurityManager) ---
            {
                "name": "execute_command",
                "description": (
                    f"Execute a shell command in the current shell working directory or a specified one. "
                    f"Command execution context is limited to: {primary_dir_desc}\n\n"
                    f"Available commands: {commands_desc}\n"
                    f"Available flags: {flags_desc}\n\n"
                    "Note: Shell operators (&&, |, >, etc.) are NOT supported. Paths in arguments are validated against the primary directory context."
                ),
                "inputSchema": ExecuteCommandInput.model_json_schema()
            },
            {
                "name": "change_directory",
                "description": (
                    "Change the shell's current working directory. "
                    f"The path must be within the primary allowed directory context: {primary_dir_desc}"
                 ),
                "inputSchema": ChangeDirectoryInput.model_json_schema()
            },
            {
                "name": "show_security_rules",
                "description": "Show security configuration for COMMAND EXECUTION (allowed commands, flags, primary directory context).",
                "inputSchema": NoInput.model_json_schema()
            },
        ]

    # --- Server Run ---

    async def run(self) -> None:
        """Run the server using stdio."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )


async def main() -> None:
    # Create our server implementation
    server = LocalSystemServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
