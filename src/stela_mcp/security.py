"""Security module for Stela MCP."""

import os
import shlex
from dataclasses import dataclass


class CommandError(Exception):
    """Base exception for command-related errors."""

    pass


class CommandSecurityError(CommandError):
    """Security violation errors."""

    pass


class CommandExecutionError(CommandError):
    """Command execution errors."""

    pass


class CommandTimeoutError(CommandError):
    """Command timeout errors."""

    pass


@dataclass
class SecurityConfig:
    """Security configuration for command execution."""

    allowed_commands: set[str]
    allowed_flags: set[str]
    max_command_length: int
    command_timeout: int
    allow_all_commands: bool = False
    allow_all_flags: bool = False


class SecurityManager:
    def __init__(self, allowed_dir: str, security_config: SecurityConfig) -> None:
        if not allowed_dir or not os.path.exists(allowed_dir):
            raise ValueError("Valid ALLOWED_DIR is required")
        self.allowed_dir = os.path.abspath(os.path.realpath(allowed_dir))
        self.security_config = security_config

    def _normalize_path(self, path: str) -> str:
        """Normalizes a path and ensures it's within allowed directory."""
        try:
            if os.path.isabs(path):
                # If absolute path, check directly
                real_path = os.path.abspath(os.path.realpath(path))
            else:
                # If relative path, combine with allowed_dir first
                real_path = os.path.abspath(os.path.realpath(os.path.join(self.allowed_dir, path)))

            if not self._is_path_safe(real_path):
                raise CommandSecurityError(
                    f"Path '{path}' is outside of allowed directory: {self.allowed_dir}"
                )

            return real_path
        except CommandSecurityError:
            raise
        except Exception as e:
            raise CommandSecurityError(f"Invalid path '{path}': {str(e)}") from e

    def validate_command(self, command_string: str) -> tuple[str, list[str]]:
        """Validates and parses a command string for security and formatting."""
        # Check for shell operators that we don't support
        shell_operators = ["&&", "||", "|", ">", ">>", "<", "<<", ";"]
        for operator in shell_operators:
            if operator in command_string:
                raise CommandSecurityError(f"Shell operator '{operator}' is not supported")

        try:
            parts = shlex.split(command_string)
            if not parts:
                raise CommandSecurityError("Empty command")

            command, args = parts[0], parts[1:]

            # Validate command if not in allow-all mode
            if (
                not self.security_config.allow_all_commands
                and command not in self.security_config.allowed_commands
            ):
                raise CommandSecurityError(f"Command '{command}' is not allowed")

            # Process and validate arguments
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

                # For any path-like argument, validate it
                if "/" in arg or "\\" in arg or os.path.isabs(arg) or arg == ".":
                    normalized_path = self._normalize_path(arg)
                    validated_args.append(normalized_path)
                else:
                    # For non-path arguments, add them as-is
                    validated_args.append(arg)

            return command, validated_args

        except ValueError as e:
            raise CommandSecurityError(f"Invalid command format: {str(e)}") from e

    def _is_path_safe(self, path: str) -> bool:
        """Checks if a given path is safe to access within allowed directory boundaries."""
        try:
            # Resolve any symlinks and get absolute path
            real_path = os.path.abspath(os.path.realpath(path))
            allowed_dir_real = os.path.abspath(os.path.realpath(self.allowed_dir))

            # Check if the path starts with allowed_dir
            return real_path.startswith(allowed_dir_real)
        except Exception:
            return False


def load_security_config() -> SecurityConfig:
    """Loads security configuration from environment variables with default fallbacks."""
    allowed_commands = os.getenv("ALLOWED_COMMANDS", "ls,cat,pwd")
    allowed_flags = os.getenv("ALLOWED_FLAGS", "-l,-a,--help")

    allow_all_commands = allowed_commands.lower() == "all"
    allow_all_flags = allowed_flags.lower() == "all"

    return SecurityConfig(
        allowed_commands=set() if allow_all_commands else set(allowed_commands.split(",")),
        allowed_flags=set() if allow_all_flags else set(allowed_flags.split(",")),
        max_command_length=int(os.getenv("MAX_COMMAND_LENGTH", "1024")),
        command_timeout=int(os.getenv("COMMAND_TIMEOUT", "30")),
        allow_all_commands=allow_all_commands,
        allow_all_flags=allow_all_flags,
    )
