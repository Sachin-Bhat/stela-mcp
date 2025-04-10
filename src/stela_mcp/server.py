"""MCP server implementation."""

from typing import Any, TypeVar

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Request,
    RequestParams,
)

from .filesystem import FileSystem
from .shell import ShellExecutor

T = TypeVar("T")


class LocalSystemServer:
    def __init__(self, server: Server) -> None:
        self.server = server
        self.shell = ShellExecutor()
        self.filesystem = FileSystem()

        # Register tools after server is created
        self._register_tools()

    def _register_tools(self) -> None:
        """Register all tools with the server."""

        @self.server.call_tool()  # type: ignore[misc]
        async def execute_command(
            request: Request[RequestParams, str], arguments: dict[str, Any]
        ) -> dict[str, Any]:
            """Execute a shell command in the current working directory."""
            return await self.shell.execute_command(
                arguments.get("command", ""), arguments.get("working_dir")
            )

        @self.server.call_tool()  # type: ignore[misc]
        async def change_directory(
            request: Request[RequestParams, str], arguments: dict[str, Any]
        ) -> dict[str, Any]:
            """Change the current working directory."""
            success, result = self.shell.change_directory(arguments.get("path", ""))
            if success:
                return {"success": True, "new_path": result}
            return {"error": result}

        @self.server.call_tool()  # type: ignore[misc]
        async def read_file(
            request: Request[RequestParams, str], arguments: dict[str, Any]
        ) -> dict[str, Any]:
            """Read the contents of a file."""
            return await self.filesystem.read_file(arguments.get("path", ""))

        @self.server.call_tool()  # type: ignore[misc]
        async def write_file(
            request: Request[RequestParams, str], arguments: dict[str, Any]
        ) -> dict[str, Any]:
            """Write content to a file."""
            return await self.filesystem.write_file(
                arguments.get("path", ""), arguments.get("content", "")
            )

        @self.server.call_tool()  # type: ignore[misc]
        async def list_directory(
            request: Request[RequestParams, str], arguments: dict[str, Any]
        ) -> dict[str, Any]:
            """List contents of a directory."""
            return await self.filesystem.list_directory(arguments.get("path", ""))

        @self.server.call_tool()  # type: ignore[misc]
        async def create_directory(
            request: Request[RequestParams, str], arguments: dict[str, Any]
        ) -> dict[str, Any]:
            """Create a new directory."""
            return await self.filesystem.create_directory(arguments.get("path", ""))

        @self.server.call_tool()  # type: ignore[misc]
        async def move_file(
            request: Request[RequestParams, str], arguments: dict[str, Any]
        ) -> dict[str, Any]:
            """Move or rename a file or directory."""
            return await self.filesystem.move_file(
                arguments.get("source", ""), arguments.get("destination", "")
            )

        @self.server.call_tool()  # type: ignore[misc]
        async def search_files(
            request: Request[RequestParams, str], arguments: dict[str, Any]
        ) -> dict[str, Any]:
            """Search for files matching a pattern."""
            return await self.filesystem.search_files(
                arguments.get("path", ""), arguments.get("pattern", "")
            )

        @self.server.call_tool()  # type: ignore[misc]
        async def directory_tree(
            request: Request[RequestParams, str], arguments: dict[str, Any]
        ) -> dict[str, Any]:
            """Generate a recursive tree view of a directory."""
            return await self.filesystem.get_directory_tree(arguments.get("path", ""))

        @self.server.list_tools()  # type: ignore[misc]
        async def list_tools() -> dict[str, Any]:
            """List all available tools."""
            return {
                "tools": [
                    {
                        "name": "execute_command",
                        "description": "Execute a shell command in the current working directory",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "command": {
                                    "type": "string",
                                    "description": "The command to execute",
                                },
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
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Path to change to",
                                },
                            },
                            "required": ["path"],
                        },
                    },
                    {
                        "name": "read_file",
                        "description": "Read the contents of a file",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Path to the file to read",
                                },
                            },
                            "required": ["path"],
                        },
                    },
                    {
                        "name": "write_file",
                        "description": "Write content to a file",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Path to the file to write",
                                },
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
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Path to the directory to list",
                                },
                            },
                            "required": ["path"],
                        },
                    },
                    {
                        "name": "create_directory",
                        "description": "Create a new directory",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Path to the directory to create",
                                },
                            },
                            "required": ["path"],
                        },
                    },
                    {
                        "name": "move_file",
                        "description": "Move or rename a file or directory",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "source": {
                                    "type": "string",
                                    "description": "Source path",
                                },
                                "destination": {
                                    "type": "string",
                                    "description": "Destination path",
                                },
                            },
                            "required": ["source", "destination"],
                        },
                    },
                    {
                        "name": "search_files",
                        "description": "Search for files matching a pattern",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Base directory to search in",
                                },
                                "pattern": {
                                    "type": "string",
                                    "description": "Search pattern",
                                },
                            },
                            "required": ["path", "pattern"],
                        },
                    },
                    {
                        "name": "directory_tree",
                        "description": "Generate a recursive tree view of a directory",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Path to the directory",
                                },
                            },
                            "required": ["path"],
                        },
                    },
                ],
            }


async def main() -> None:
    # Create the server with proper initialization
    server: Server = Server(
        name="StelaMCP",
        version="0.3.1",
        instructions="A server for local system operations",
    )

    # Create our server implementation
    LocalSystemServer(server)

    # Get the stdio transport
    async with stdio_server() as (read_stream, write_stream):
        # Run the server with initialization options
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
