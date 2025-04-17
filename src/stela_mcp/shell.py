"""Shell command execution implementation.

This module provides a secure and robust interface for executing shell commands and managing
working directories. It implements proper error handling, output capture, and security
measures to prevent command injection vulnerabilities.
"""

import os
import subprocess
from typing import Any


class ShellExecutor:
    """A class for executing shell commands with security and error handling.

    This class provides methods for executing shell commands and managing the working
    directory. It implements security measures to prevent command injection and provides
    comprehensive error handling and output capture.

    Attributes:
        working_dir (str): The current working directory for command execution.
    """

    def __init__(self, working_dir: str | None = None) -> None:
        """Initialize the ShellExecutor.

        Args:
            working_dir (str | None): Optional initial working directory. If None,
                uses the current system working directory.
        """
        # Always use the actual system working directory
        self.working_dir = os.getcwd()

    async def execute_command(
        self, command: str, args: list[str], working_dir: str | None = None
    ) -> dict:
        """Execute a shell command with proper error handling and output capture.

        This method executes a shell command with the provided arguments in the specified
        working directory. It implements security measures to prevent command injection
        and provides comprehensive error handling.

        Args:
            command (str): The command to execute.
            args (list[str]): List of arguments to pass to the command.
            working_dir (str | None): Optional working directory for command execution.
                If None, uses the current working directory.

        Returns:
            dict: A dictionary containing:
                - exit_code (int): The command's exit code
                - stdout (str): Standard output from the command
                - stderr (str): Standard error from the command
                - success (bool): Whether the command executed successfully
                - error (str, optional): Error message if execution failed
        """
        if not command:
            return {"error": "Command is required", "success": False, "exit_code": -1}

        try:
            # Combine command and args into a list and use shell=False for security
            command_list = [command] + args
            # Command and args are validated by SecurityManager before reaching here
            # shell=False prevents command injection, and the command list is pre-validated
            process = subprocess.Popen(  # noqa: S603
                command_list,  # Pass the list
                shell=False,  # Set shell=False for security
                cwd=working_dir or self.working_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate()

            return {
                "exit_code": process.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "success": process.returncode == 0,
            }
        except Exception as e:
            return {
                "error": str(e),
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False,
            }

    async def change_directory(self, path: str) -> dict[str, Any]:
        """Change the working directory with validation.

        This method changes the current working directory to the specified path,
        performing validation to ensure the path exists and is a directory.

        Args:
            path (str): The path to change to.

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Whether the directory change was successful
                - path (str, optional): The absolute path of the new working directory
                - error (str, optional): Error message if the change failed
        """
        if not path:
            return {"success": False, "error": "Path is required"}

        try:
            if not os.path.exists(path):
                return {"success": False, "error": "Path does not exist"}

            if not os.path.isdir(path):
                return {"success": False, "error": "Path is not a directory"}

            # Update both the instance variable and change the actual working directory
            os.chdir(path)
            self.working_dir = os.path.abspath(path)
            return {"success": True, "path": self.working_dir}
        except Exception as e:
            return {"success": False, "error": str(e)}
