"""Security module for Stela MCP command execution.

This module provides security controls for command execution, including:
- Command and flag validation
- Path argument validation
- Command length and timeout limits
- Configuration loading from environment variables
"""

import os
import shlex

from pydantic import BaseModel


class CommandError(Exception):
    """Base exception for command-related errors.

    This is the parent class for all command-related exceptions in the security module.
    It provides a common base for handling command execution and validation errors.
    """

    pass


class CommandSecurityError(CommandError):
    """Security violation errors.

    Raised when a command or its arguments violate security constraints,
    such as using disallowed commands, flags, or accessing restricted paths.
    """

    pass


class CommandExecutionError(CommandError):
    """Command execution errors.

    Raised when there are issues during command execution that are not
    related to security violations, such as command not found or execution failure.
    """

    pass


class CommandTimeoutError(CommandError):
    """Command timeout errors.

    Raised when a command execution exceeds the configured timeout limit.
    """

    pass


class SecurityConfig(BaseModel):
    """Security configuration for command execution.

    This class defines the security settings for command execution using Pydantic
    for validation and type safety. It includes allowed commands, flags, and limits.

    Attributes:
        allowed_commands (set[str]): Set of allowed command names
        allowed_flags (set[str]): Set of allowed command flags
        max_command_length (int): Maximum allowed command string length
        command_timeout (int): Maximum command execution time in seconds
        allow_all_commands (bool): If True, allows any command (overrides allowed_commands)
        allow_all_flags (bool): If True, allows any flag (overrides allowed_flags)
    """

    allowed_commands: set[str]
    allowed_flags: set[str]
    max_command_length: int
    command_timeout: int
    allow_all_commands: bool = False
    allow_all_flags: bool = False


class SecurityManager:
    """Manages security for shell command execution within a primary allowed directory.

    This class provides security controls for command execution, including:
    - Command and flag validation
    - Path argument validation
    - Command length and timeout limits
    - Safe working directory management

    Attributes:
        primary_allowed_dir (str): The primary directory where commands can be executed
        security_config (SecurityConfig): The security configuration settings
    """

    def __init__(self, primary_allowed_dir: str, security_config: SecurityConfig) -> None:
        """Initialize the SecurityManager.

        Args:
            primary_allowed_dir (str): The primary directory where commands can be executed.
                Must be an existing directory.
            security_config (SecurityConfig): The security configuration settings.

        Raises:
            ValueError: If primary_allowed_dir is not a valid directory.
        """
        if not primary_allowed_dir or not os.path.isdir(primary_allowed_dir):
            raise ValueError(
                f"Valid, existing primary allowed directory is required, got: {primary_allowed_dir}"
            )
        self.primary_allowed_dir = os.path.abspath(os.path.realpath(primary_allowed_dir))
        self.security_config = security_config
        print(f"SecurityManager initialized for command execution in: {self.primary_allowed_dir}")

    def _normalize_path_for_command_arg(self, path: str) -> str:
        """Normalize and validate a path provided as a command argument.

        This method ensures that path arguments in commands are:
        1. Properly normalized (absolute, resolved)
        2. Within the primary allowed directory
        3. Safe to use in command execution

        Args:
            path (str): The path argument to normalize and validate

        Returns:
            str: The normalized and validated absolute path

        Raises:
            CommandSecurityError: If the path is outside the allowed directory
                                or cannot be properly resolved
        """
        try:
            if not os.path.isabs(path):
                path = os.path.join(self.primary_allowed_dir, path)

            real_path = os.path.abspath(os.path.realpath(path))

            if not self._is_path_safe(real_path):
                raise CommandSecurityError(
                    f"Path argument '{path}' resolves outside of the allowed "
                    f"command execution directory: {self.primary_allowed_dir}"
                )

            return real_path
        except CommandSecurityError:
            raise
        except Exception as e:
            raise CommandSecurityError(f"Invalid path argument '{path}': {str(e)}") from e

    def validate_command(self, command_string: str) -> tuple[str, list[str]]:
        """Validate a command string for security compliance.

        This method performs comprehensive validation of a command string:
        1. Checks for disallowed shell operators
        2. Validates the command name against allowed commands
        3. Validates flags against allowed flags
        4. Validates path arguments
        5. Checks command length limits

        Args:
            command_string (str): The command string to validate

        Returns:
            tuple[str, list[str]]: A tuple containing:
                - The validated command name
                - The list of validated arguments

        Raises:
            CommandSecurityError: If the command violates any security constraints
        """
        shell_operators = ["&&", "||", "|", ">", ">>", "<", "<<", ";"]
        for operator in shell_operators:
            if operator in command_string:
                raise CommandSecurityError(f"Shell operator '{operator}' is not supported")

        try:
            parts = shlex.split(command_string)
            if not parts:
                raise CommandSecurityError("Empty command")

            command, args = parts[0], parts[1:]

            if (
                not self.security_config.allow_all_commands
                and command not in self.security_config.allowed_commands
            ):
                raise CommandSecurityError(f"Command '{command}' is not allowed")

            validated_args = []
            for arg in args:
                if arg.startswith("-"):
                    if (
                        not self.security_config.allow_all_flags
                        and arg not in self.security_config.allowed_flags
                    ):
                        raise CommandSecurityError(f"Flag '{arg}' is not allowed")
                    validated_args.append(arg)
                    continue

                is_potentially_path_like = (
                    "/" in arg
                    or "\\" in arg
                    or os.path.isabs(arg)
                    or arg == "."
                    or arg.startswith("~")
                    or arg.startswith("./")
                    or arg.startswith("../")
                    or any(
                        arg.endswith(ext)
                        for ext in [".txt", ".py", ".sh", ".md", ".json", ".yaml", ".yml"]
                    )
                    or arg.endswith("/")
                    or "$" in arg
                    or "%" in arg
                )

                if is_potentially_path_like:
                    try:
                        normalized_path = self._normalize_path_for_command_arg(arg)

                        if not os.path.exists(normalized_path):
                            if not any(
                                arg.endswith(ext)
                                for ext in [".txt", ".py", ".sh", ".md", ".json", ".yaml", ".yml"]
                            ):
                                print(
                                    f"Warning: Path '{normalized_path}' does not exist "
                                    "but may be created by the command"
                                )

                        if ".." in normalized_path:
                            print(
                                f"Warning: Path contains parent directory reference: "
                                f"{normalized_path}"
                            )

                        validated_args.append(normalized_path)
                    except CommandSecurityError:
                        raise
                    except Exception as e:
                        raise CommandSecurityError(
                            f"Failed to validate path argument '{arg}': {str(e)}"
                        ) from e
                else:
                    validated_args.append(arg)

            return command, validated_args

        except ValueError as e:
            raise CommandSecurityError(f"Invalid command format: {str(e)}") from e
        except CommandSecurityError:
            raise
        except Exception as e:
            raise CommandSecurityError(
                f"Unexpected error validating command '{command_string}': {e}"
            ) from e

    def _is_path_safe(self, path: str) -> bool:
        """Check if a path is within the allowed directory.

        This helper method verifies that a given path is within the primary
        allowed directory, preventing directory traversal attacks.

        Args:
            path (str): The path to check

        Returns:
            bool: True if the path is safe, False otherwise
        """
        try:
            allowed_prefix = os.path.join(self.primary_allowed_dir, "")
            return path.startswith(allowed_prefix) or path == self.primary_allowed_dir
        except Exception:
            return False


def load_security_config() -> SecurityConfig:
    """Load security configuration from environment variables.

    This function reads security settings from environment variables and creates
    a SecurityConfig instance. It handles type conversion and provides defaults
    for missing values.

    Returns:
        SecurityConfig: The loaded security configuration

    Raises:
        ValueError: If any required environment variables have invalid values
    """
    allowed_commands_str = os.getenv("ALLOWED_COMMANDS", "ls,cat,pwd,echo")
    allowed_flags_str = os.getenv("ALLOWED_FLAGS", "-l,-a,-h,--help")
    max_command_length_str = os.getenv("MAX_COMMAND_LENGTH", "1024")
    command_timeout_str = os.getenv("COMMAND_TIMEOUT", "60")

    allow_all_commands = allowed_commands_str.lower() == "all"
    allow_all_flags = allowed_flags_str.lower() == "all"

    allowed_commands_set = set()
    if not allow_all_commands:
        allowed_commands_set = {c.strip() for c in allowed_commands_str.split(",") if c.strip()}

    allowed_flags_set = set()
    if not allow_all_flags:
        allowed_flags_set = {f.strip() for f in allowed_flags_str.split(",") if f.strip()}

    try:
        max_command_length = int(max_command_length_str)
        command_timeout = int(command_timeout_str)
    except ValueError as e:
        raise ValueError(
            f"Invalid integer value in environment variable for security config: {e}"
        ) from e

    return SecurityConfig(
        allowed_commands=allowed_commands_set,
        allowed_flags=allowed_flags_set,
        max_command_length=max_command_length,
        command_timeout=command_timeout,
        allow_all_commands=allow_all_commands,
        allow_all_flags=allow_all_flags,
    )
