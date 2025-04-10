"""MCP server implementation."""

import asyncio
import os
from collections.abc import Awaitable, Callable
from typing import Any, cast

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent

from .filesystem import FileSystem
from .security import SecurityManager, load_security_config
from .shell import ShellExecutor


class LocalSystemServer:
    def __init__(self) -> None:
        self.server: Server = Server(
            name="StelaMCP",
            version="0.4.0",
            instructions="A server for local system operations",
        )

        self.shell = ShellExecutor()
        self.filesystem = FileSystem()
        self.security = SecurityManager(
            allowed_dir=os.getenv("ALLOWED_DIR", os.getcwd()),
            security_config=load_security_config(),
        )

        # Register the single dispatcher tool
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
            # tool_name is now passed directly by the decorator
            target_method: Callable[[dict[str, Any]], Awaitable[list[TextContent]]] | None
            # Use the outer self (from LocalSystemServer) to find the method
            target_method = getattr(self, tool_name, None)

            if target_method and callable(target_method):
                # Call the actual implementation method on the LocalSystemServer instance
                # No need to pass self explicitly here, getattr provides the bound method
                # Pass the arguments received from the decorator
                result = await target_method(arguments)
                return cast(list[TextContent], result)
            else:
                raise ValueError(f"Unknown or invalid tool name: {tool_name}")

        # The @self.server.call_tool() decorator registers the handler.
        # We don't need to manually assign to self.server.request_handlers here.

        @self.server.list_tools()  # type: ignore[misc]
        async def list_tools_handler() -> list[dict[str, Any]]:
            """Handles the list_tools request by calling the instance method."""
            # Call the actual list_tools implementation method on the LocalSystemServer instance
            return await self.list_tools_impl()

    # --- Tool Implementations (No Decorators Here) ---

    async def execute_command(
        self,
        arguments: dict[str, Any],  # Removed request param
    ) -> list[TextContent]:
        """Execute a shell command in the current working directory."""
        # Exception handling remains, decorator above will catch
        command = arguments.get("command", "")
        working_dir = arguments.get("working_dir")

        if not command:
            raise ValueError("Missing required argument: command")

        if len(command) > self.security.security_config.max_command_length:
            raise ValueError(
                "Command exceeds maximum length of "
                f"{self.security.security_config.max_command_length}"
            )

        # Validate command using security manager
        validated_command, args = self.security.validate_command(command)
        # Pass validated command AND args to the shell executor
        result = await self.shell.execute_command(validated_command, args, working_dir)

        if not result.get("success"):
            raise RuntimeError(f"Command execution failed: {result.get('error')}")

        # Build output content
        content_list = []
        if result.get("stdout"):
            content_list.append(TextContent(type="text", text=result["stdout"]))
        if result.get("stderr"):
            # Represent stderr as text content, let client decide if it's an error
            content_list.append(TextContent(type="text", text=f"stderr: {result['stderr']}"))

        return content_list

    async def change_directory(
        self,
        arguments: dict[str, Any],  # Removed request param
    ) -> list[TextContent]:
        """Change the current working directory."""
        # Exception handling remains
        path = arguments.get("path", "")
        if not path:
            raise ValueError("Missing required argument: path")

        # Validate path using security manager
        normalized_path = self.security._normalize_path(path)
        result = await self.shell.change_directory(normalized_path)

        if not result.get("success"):
            raise OSError(f"Failed to change directory: {result.get('error')}")

        return [TextContent(type="text", text=f"Changed directory to: {result.get('path')}")]

    async def read_file(
        self,
        arguments: dict[str, Any],  # Removed request param
    ) -> list[TextContent]:
        """Read the contents of a file."""
        # Exception handling remains
        path = arguments.get("path", "")
        if not path:
            raise ValueError("Missing required argument: path")

        # Validate path using security manager
        normalized_path = self.security._normalize_path(path)
        result = await self.filesystem.read_file(normalized_path)

        if not result.get("success"):
            raise FileNotFoundError(f"Failed to read file: {result.get('error')}")

        return [TextContent(type="text", text=result.get("content", ""))]

    async def write_file(
        self,
        arguments: dict[str, Any],  # Removed request param
    ) -> list[TextContent]:
        """Write content to a file."""
        # Exception handling remains
        path = arguments.get("path", "")
        content = arguments.get("content")  # Allow empty content

        if not path:
            raise ValueError("Missing required argument: path")
        if content is None:  # Check specifically for None if empty string is valid
            raise ValueError("Missing required argument: content")

        # Validate path using security manager
        normalized_path = self.security._normalize_path(path)
        result = await self.filesystem.write_file(normalized_path, content)

        if not result.get("success"):
            raise OSError(f"Failed to write file: {result.get('error')}")

        return [TextContent(type="text", text=f"File written successfully: {result.get('path')}")]

    async def list_directory(
        self,
        arguments: dict[str, Any],  # Removed request param
    ) -> list[TextContent]:
        """List contents of a directory."""
        # Exception handling remains
        path = arguments.get("path", ".")  # Default to current directory
        # Validate path using security manager
        normalized_path = self.security._normalize_path(path)
        result = await self.filesystem.list_directory(normalized_path)

        if not result.get("success"):
            raise FileNotFoundError(f"Failed to list directory: {result.get('error')}")

        items = result.get("items", [])
        if not items:
            return [TextContent(type="text", text=f"Directory is empty: {normalized_path}")]

        items_text = "\n".join([f"{item['name']} ({item['type']})" for item in items])

        return [TextContent(type="text", text=items_text)]

    async def create_directory(
        self,
        arguments: dict[str, Any],  # Removed request param
    ) -> list[TextContent]:
        """Create a new directory."""
        # Exception handling remains
        path = arguments.get("path", "")
        if not path:
            raise ValueError("Missing required argument: path")

        # Validate path using security manager
        normalized_path = self.security._normalize_path(path)
        result = await self.filesystem.create_directory(normalized_path)

        if not result.get("success"):
            raise OSError(f"Failed to create directory: {result.get('error')}")

        return [
            TextContent(type="text", text=f"Directory created successfully: {result.get('path')}")
        ]

    async def move_file(
        self,
        arguments: dict[str, Any],  # Removed request param
    ) -> list[TextContent]:
        """Move or rename a file or directory."""
        # Exception handling remains
        source = arguments.get("source", "")
        destination = arguments.get("destination", "")
        if not source:
            raise ValueError("Missing required argument: source")
        if not destination:
            raise ValueError("Missing required argument: destination")

        # Validate paths using security manager
        normalized_source = self.security._normalize_path(source)
        normalized_destination = self.security._normalize_path(destination)
        result = await self.filesystem.move_file(normalized_source, normalized_destination)

        if not result.get("success"):
            raise OSError(f"Failed to move file: {result.get('error')}")

        return [
            TextContent(type="text", text=f"File moved successfully to: {result.get('new_path')}")
        ]

    async def search_files(
        self,
        arguments: dict[str, Any],  # Removed request param
    ) -> list[TextContent]:
        """Search for files matching a pattern."""
        # Exception handling remains
        path = arguments.get("path", ".")  # Default to current directory
        pattern = arguments.get("pattern", "")
        if not pattern:
            raise ValueError("Missing required argument: pattern")

        # Validate path using security manager
        normalized_path = self.security._normalize_path(path)
        result = await self.filesystem.search_files(normalized_path, pattern)

        if not result.get("success"):
            raise RuntimeError(f"File search failed: {result.get('error')}")

        matches = result.get("matches", [])
        if not matches:
            return [
                TextContent(
                    type="text",
                    text=f"No files found matching pattern '{pattern}' in {normalized_path}",
                )
            ]

        matches_text = "\n".join(matches)

        return [TextContent(type="text", text=matches_text)]

    async def directory_tree(
        self,
        arguments: dict[str, Any],  # Removed request param
    ) -> list[TextContent]:
        """Generate a recursive tree view of a directory."""
        # Exception handling remains
        path = arguments.get("path", ".")  # Default to current directory
        # Validate path using security manager
        normalized_path = self.security._normalize_path(path)
        result = await self.filesystem.get_directory_tree(normalized_path)

        if not result.get("success"):
            raise FileNotFoundError(f"Failed to generate directory tree: {result.get('error')}")

        tree = result.get("tree", {})
        if not tree:  # Should not happen if success is true, but good practice
            return [
                TextContent(
                    type="text", text=f"Directory is empty or inaccessible: {normalized_path}"
                )
            ]

        tree_lines = []

        def format_tree(node: dict[str, Any], indent: int = 0) -> None:
            prefix = "  " * indent
            name = f"{node['name']}/" if node["type"] == "directory" else node["name"]
            tree_lines.append(f"{prefix}{name}")
            for child in node.get("children", []):
                format_tree(child, indent + 1)

        format_tree(tree)

        # Join all lines into a single string
        tree_text = "\n".join(tree_lines)
        return [TextContent(type="text", text=tree_text)]

    async def show_security_rules(
        self,
        arguments: dict[str, Any],  # Removed request param
    ) -> list[TextContent]:
        """Show current security configuration."""
        # Exception handling remains
        commands_desc = (
            "All commands allowed"
            if self.security.security_config.allow_all_commands
            else ", ".join(sorted(self.security.security_config.allowed_commands))
        )
        flags_desc = (
            "All flags allowed"
            if self.security.security_config.allow_all_flags
            else ", ".join(sorted(self.security.security_config.allowed_flags))
        )

        security_info = (
            "Security Configuration:\n"
            f"==================\n"
            f"Working Directory: {self.security.allowed_dir}\n"
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

    # --- Tool Listing Implementation (No Decorator Here) ---

    async def list_tools_impl(self) -> list[dict[str, Any]]:
        """Actual implementation for listing tools (renamed to avoid conflict)."""
        # This part doesn't need to change. It describes the tools the client
        # *thinks* it's calling directly, even though we dispatch internally.
        commands_desc = (
            "all commands"
            if self.security.security_config.allow_all_commands
            else ", ".join(self.security.security_config.allowed_commands)
        )
        flags_desc = (
            "all flags"
            if self.security.security_config.allow_all_flags
            else ", ".join(self.security.security_config.allowed_flags)
        )

        return [
            {
                "name": "execute_command",
                "description": (
                    f"Execute a shell command in the current working directory\\n\\n"
                    f"Available commands: {commands_desc}\\n"
                    f"Available flags: {flags_desc}\\n\\n"
                    "Note: Shell operators (&&, |, >, >>) are not supported."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "The command to execute"},
                        "working_dir": {
                            "type": "string",
                            "description": "Working directory for the command",
                        },
                    },
                    "required": ["command"],
                },
            },
            {
                "name": "change_directory",
                "description": "Change the current working directory",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string", "description": "Path to change to"}},
                    "required": ["path"],
                },
            },
            {
                "name": "read_file",
                "description": "Read the contents of a file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to the file to read"}
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "write_file",
                "description": "Write content to a file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to the file to write"},
                        "content": {
                            "type": "string",
                            "description": "Content to write to the file",
                        },
                    },
                    "required": ["path", "content"],
                },
            },
            {
                "name": "list_directory",
                "description": "List contents of a directory",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the directory to list",
                        }
                    },
                    # Making path optional here to allow listing current dir by default
                    # "required": ["path"],
                },
            },
            {
                "name": "create_directory",
                "description": "Create a new directory",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to the directory to create",
                        }
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "move_file",
                "description": "Move or rename a file or directory",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source": {"type": "string", "description": "Source path"},
                        "destination": {"type": "string", "description": "Destination path"},
                    },
                    "required": ["source", "destination"],
                },
            },
            {
                "name": "search_files",
                "description": "Search for files matching a pattern",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Base directory to search in",
                        },
                        "pattern": {"type": "string", "description": "Search pattern"},
                    },
                    "required": ["pattern"],  # Path defaults to '.'
                },
            },
            {
                "name": "directory_tree",
                "description": "Generate a recursive tree view of a directory",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Path to the directory"}
                    },
                    # Making path optional here to allow tree of current dir by default
                    # "required": ["path"],
                },
            },
            {
                "name": "show_security_rules",
                "description": "Show current security configuration",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
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
