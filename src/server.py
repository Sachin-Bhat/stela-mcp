from typing import Dict, Any
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    ServerCapabilities,
    PromptsCapability,
    ResourcesCapability,
    ToolsCapability,
    Request,
    RequestParams
)
from stela_mcp.shell import ShellExecutor
from stela_mcp.filesystem import FileSystem

class LocalSystemServer:
    def __init__(self, server: Server):
        self.server = server
        self.shell = ShellExecutor()
        self.filesystem = FileSystem()
        
        # Register tools after server is created
        self._register_tools()
        
    def _register_tools(self):
        """Register all tools with the server."""
        @self.server.call_tool()
        async def execute_command(request: Request[RequestParams, str], arguments: Dict[str, Any]) -> Dict[str, Any]:
            """Execute a shell command in the current working directory."""
            return await self.shell.execute_command(
                arguments.get("command", ""),
                arguments.get("working_dir")
            )
            
        @self.server.call_tool()
        async def change_directory(request: Request[RequestParams, str], arguments: Dict[str, Any]) -> Dict[str, Any]:
            """Change the current working directory."""
            success, result = self.shell.change_directory(arguments.get("path", ""))
            if success:
                return {"success": True, "new_path": result}
            return {"error": result}
            
        @self.server.call_tool()
        async def read_file(request: Request[RequestParams, str], arguments: Dict[str, Any]) -> Dict[str, Any]:
            """Read the contents of a file."""
            return await self.filesystem.read_file(arguments.get("path", ""))
            
        @self.server.call_tool()
        async def write_file(request: Request[RequestParams, str], arguments: Dict[str, Any]) -> Dict[str, Any]:
            """Write content to a file."""
            return await self.filesystem.write_file(
                arguments.get("path", ""),
                arguments.get("content", "")
            )
            
        @self.server.call_tool()
        async def list_directory(request: Request[RequestParams, str], arguments: Dict[str, Any]) -> Dict[str, Any]:
            """List contents of a directory."""
            return await self.filesystem.list_directory(arguments.get("path", ""))
            
        @self.server.call_tool()
        async def create_directory(request: Request[RequestParams, str], arguments: Dict[str, Any]) -> Dict[str, Any]:
            """Create a new directory."""
            return await self.filesystem.create_directory(arguments.get("path", ""))
            
        @self.server.call_tool()
        async def move_file(request: Request[RequestParams, str], arguments: Dict[str, Any]) -> Dict[str, Any]:
            """Move or rename a file or directory."""
            return await self.filesystem.move_file(
                arguments.get("source", ""),
                arguments.get("destination", "")
            )
            
        @self.server.call_tool()
        async def search_files(request: Request[RequestParams, str], arguments: Dict[str, Any]) -> Dict[str, Any]:
            """Search for files matching a pattern."""
            return await self.filesystem.search_files(
                arguments.get("path", ""),
                arguments.get("pattern", "")
            )
            
        @self.server.call_tool()
        async def directory_tree(request: Request[RequestParams, str], arguments: Dict[str, Any]) -> Dict[str, Any]:
            """Generate a recursive tree view of a directory."""
            return await self.filesystem.get_directory_tree(arguments.get("path", ""))

async def main():
    server_capabilities = ServerCapabilities(
        tools=ToolsCapability(),
        resources=ResourcesCapability(),
        prompts=PromptsCapability()
    )
    
    init_options = {
        "server_name": "StelaMCP",
        "server_version": "0.1.0",
        "capabilities": server_capabilities,
        "instructions": "A server for local system operations"
    }
    
    # Create the server
    server = Server("StelaMCP")
    
    # Create our server implementation
    local_server = LocalSystemServer(server)
    
    # Get the stdio transport
    async with stdio_server() as (read_stream, write_stream):
        # Run the server
        await server.run(read_stream, write_stream, init_options)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main()) 