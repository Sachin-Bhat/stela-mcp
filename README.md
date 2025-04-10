# STeLA MCP

[![smithery badge](https://smithery.ai/badge/@Sachin-Bhat/stela-mcp)](https://smithery.ai/server/@Sachin-Bhat/stela-mcp)

> A Python implementation of a Model Context Protocol server that provides secure access to local system operations via a standardized API interface.

STeLA (Simple Terminal Language Assistant) MCP is a lightweight server that provides secure access to local machine commands and file operations via a standardized API interface. It acts as a bridge between applications and your local system, implementing the Model Context Protocol (MCP) architecture.

## Overview

STeLA MCP implements the Model Context Protocol (MCP) architecture to provide a secure, standardized way for applications to execute commands and perform file operations on a local machine. It serves as an intermediary layer that accepts requests through a well-defined API, executes operations in a controlled environment, and returns formatted results.

## Features

* **Command Execution**: Run shell commands on the local system with proper error handling
* **File Operations**: Read, write, and manage files on the local system
* **Directory Visualization**: Generate recursive tree views of file systems
* **Working Directory Support**: Execute commands in specific directories
* **Robust Error Handling**: Detailed error messages and validation
* **Comprehensive Output**: Capture and return both stdout and stderr
* **Simple Integration**: Standard I/O interface for easy integration with various clients

## Installation

### Installing via Smithery

To install STeLA for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@Sachin-Bhat/stela-mcp):

```bash
npx -y @smithery/cli install @Sachin-Bhat/stela-mcp --client claude
```

### Prerequisites

* Python 3.12 or higher
* pip or uv package manager

### Installation Steps

1. Clone the repository:
```bash
git clone <repository-url>
cd stela-mcp
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -e .
```

### Creating a Binary Distribution

To create a self-contained binary:

1. Install PyInstaller:
```bash
pip install pyinstaller
```

2. Create the binary:
```bash
pyinstaller --onefile src/stella_mcp//server.py --name stela-mcp
```

The binary will be created in the `dist` directory.

## Project Structure

```
stela-mcp/
├── src/
│   ├── stela_mcp/
│   │   ├── __init__.py
│   │   ├── shell.py        # Shell command execution
│   │   └── filesystem.py   # File system operations
│   └── server.py           # Main server implementation
├── pyproject.toml          # Project configuration
└── README.md
```

## Usage

### Starting the Server

Run the server using:
```bash
uv run python -m src.stella_mcp.server
```

The server will start and listen for connections through standard I/O.

### Using with Claude Desktop

To use STeLA MCP with Claude Desktop:

1. Option 1: Using Python directly
   - Start the server using:
     ```bash
     uv run python -m src.server
     ```
   - In Claude Desktop:
     - Go to Settings
     - Under "Tools", click "Add Tool"
     - Select "MCP Server"
     - Enter the following configuration:
       - **Name**: STeLA MCP
       - **Path**: The absolute path to your Python executable (e.g., `/home/username/.venv/bin/python`)
       - **Arguments**: `-m src.server`
       - **Working Directory**: The path to your STeLA MCP project directory

2. Option 2: Using the binary
   - Copy the binary from `dist/stela-mcp` to a location in your PATH
   - In Claude Desktop:
     - Go to Settings
     - Under "Tools", click "Add Tool"
     - Select "MCP Server"
     - Enter the following configuration:
       - **Name**: STeLA MCP
       - **Path**: The absolute path to the binary (e.g., `/usr/local/bin/stela-mcp`)
       - **Arguments**: (leave empty)
       - **Working Directory**: (leave empty)

3. Once configured, you can use STeLA MCP tools in your conversations with Claude. For example:
   - "Show me the contents of my home directory"
   - "Create a new file called 'test.txt' with some content"
   - "Run the command 'ls -la' in my current directory"

4. Claude will automatically use the appropriate tools based on your requests and display the results in the conversation.

### Available Tools

#### Command Tools

##### execute_command
Executes shell commands on the local system.

**Parameters:**
* `command` (string, required): The shell command to execute
* `working_dir` (string, optional): Directory where the command should be executed

**Returns:**
* On success: Command output (stdout)
* On failure: Error message and any command output (stderr)

##### change_directory
Changes the current working directory.

**Parameters:**
* `path` (string, required): Path to change to

**Returns:**
* On success: Success message with new path
* On failure: Error message

#### File System Tools

##### read_file
Reads the contents of a file.

**Parameters:**
* `path` (string, required): Path to the file to read

**Returns:**
* On success: File contents
* On failure: Error message

##### write_file
Writes content to a file.

**Parameters:**
* `path` (string, required): Path where the file will be written
* `content` (string, required): Content to write to the file

**Returns:**
* On success: Success message
* On failure: Error message

##### list_directory
Lists contents of a directory.

**Parameters:**
* `path` (string, required): Path for the directory to list

**Returns:**
* On success: List of files and directories
* On failure: Error message

##### create_directory
Creates a new directory.

**Parameters:**
* `path` (string, required): Path for the directory to create

**Returns:**
* On success: Success message
* On failure: Error message

##### move_file
Moves or renames files and directories.

**Parameters:**
* `source` (string, required): Source path of the file or directory to move
* `destination` (string, required): Destination path where the file or directory will be moved to

**Returns:**
* On success: Success message
* On failure: Error message

##### search_files
Searches for files matching a pattern.

**Parameters:**
* `path` (string, required): Starting path for the search
* `pattern` (string, required): Search pattern to match file and directory names

**Returns:**
* On success: List of matching files
* On failure: Error message

##### directory_tree
Generates a recursive tree view of files and directories.

**Parameters:**
* `path` (string, required): Path for the directory to generate tree from

**Returns:**
* On success: JSON structure representing the directory tree
* On failure: Error message

## Security Considerations

STeLA MCP provides direct access to execute commands and file operations on the local system. Consider the following security practices:

* Run with appropriate permissions (avoid running as root/administrator)
* Use in trusted environments only
* Consider implementing additional authorization mechanisms for production use
* Be cautious about which directories you allow command execution and file operations in
* Implement path validation to prevent unauthorized access to system files

### Platform-Specific Security Notes

#### Linux/macOS
* Run with a dedicated user with limited permissions
* Consider using a chroot environment to restrict file system access
* Use `chmod` to restrict executable permissions

#### Windows
* Run as a standard user, not an administrator
* Consider using Windows Security features to restrict access
* Use folder/file permissions to limit access to sensitive directories

## Development

### Adding New Tools

To extend STeLA MCP with additional functionality, follow this pattern:

1. Add a new method to the appropriate class in `shell.py` or `filesystem.py`
2. Register the tool in `server.py` using the `@server.call_tool()` decorator
3. Implement the tool handler with proper error handling and return types

Example:
```python
@server.call_tool()
async def my_tool(request: Request[RequestParams, str], arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Description of the tool."""
    try:
        # Tool implementation
        result = await do_something(arguments)
        return {"success": True, "result": result}
    except Exception as e:
        return {"error": str(e)}
```

## License

Apache-2.0 License

## Acknowledgements

* Built with the MCP Python SDK
