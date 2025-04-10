"""Shell command execution implementation."""

import os
import subprocess


class ShellExecutor:
    def __init__(self, working_dir: str | None = None) -> None:
        self.working_dir = working_dir or os.getcwd()

    async def execute_command(self, command: str, working_dir: str | None = None) -> dict:
        """Execute a shell command with proper error handling and output capture."""
        if not command:
            return {"error": "Command is required"}

        try:
            process = subprocess.Popen(
                command,
                shell=True,
                cwd=working_dir or self.working_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()

            return {
                "exit_code": process.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "success": process.returncode == 0
            }
        except Exception as e:
            return {
                "error": str(e),
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }

    def change_directory(self, path: str) -> tuple[bool, str]:
        """Change the working directory with validation."""
        if not path:
            return False, "Path is required"

        try:
            if not os.path.exists(path):
                return False, "Path does not exist"

            if not os.path.isdir(path):
                return False, "Path is not a directory"

            self.working_dir = os.path.abspath(path)
            return True, self.working_dir
        except Exception as e:
            return False, str(e)
