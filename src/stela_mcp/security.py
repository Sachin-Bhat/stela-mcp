"""Security module for Stela MCP command execution."""

import os
import shlex
from typing import Set
from pydantic import BaseModel


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


class SecurityConfig(BaseModel):
    """Security configuration for command execution."""
    allowed_commands: Set[str]
    allowed_flags: Set[str]
    max_command_length: int
    command_timeout: int
    allow_all_commands: bool = False
    allow_all_flags: bool = False


class SecurityManager:
    """Manages security for shell command execution within a primary allowed directory."""
    def __init__(self, primary_allowed_dir: str, security_config: SecurityConfig) -> None:
        """
        Initializes the SecurityManager.

        Args:
            primary_allowed_dir: The single, primary directory context for command execution
                                 and basic path argument validation. Must be an existing directory.
            security_config: The security configuration settings.
        """
        if not primary_allowed_dir or not os.path.isdir(primary_allowed_dir): # Check if it's a directory
            raise ValueError(f"Valid, existing primary allowed directory is required, got: {primary_allowed_dir}")
        # Resolve and store the absolute real path of the primary allowed directory
        self.primary_allowed_dir = os.path.abspath(os.path.realpath(primary_allowed_dir))
        self.security_config = security_config
        print(f"SecurityManager initialized for command execution in: {self.primary_allowed_dir}") # Added log

    def _normalize_path_for_command_arg(self, path: str) -> str:
        """
        Normalizes a path *provided as a command argument* and ensures it's
        within the primary allowed directory for command execution safety.
        This is a basic check; detailed filesystem access is handled by FileSystem.
        """
        try:
            # Resolve relative paths against the primary allowed directory
            if not os.path.isabs(path):
                path = os.path.join(self.primary_allowed_dir, path)

            # Get the real, absolute path (resolves symlinks)
            real_path = os.path.abspath(os.path.realpath(path))

            # Perform the safety check against the primary directory
            if not self._is_path_safe(real_path):
                raise CommandSecurityError(
                    f"Path argument '{path}' resolves outside of the allowed command execution directory: {self.primary_allowed_dir}"
                )

            return real_path
        except CommandSecurityError:
            raise
        except Exception as e:
            # Catch potential errors during path resolution (e.g., invalid chars)
            raise CommandSecurityError(f"Invalid path argument '{path}': {str(e)}") from e

    def validate_command(self, command_string: str) -> tuple[str, list[str]]:
        """Validates a command string for allowed commands, flags, and basic path argument safety."""
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

                # Enhanced path-like argument detection
                is_potentially_path_like = (
                    # Basic path indicators
                    "/" in arg or "\\" in arg or 
                    os.path.isabs(arg) or 
                    arg == "." or 
                    arg.startswith("~") or
                    # Additional path-like patterns
                    arg.startswith("./") or
                    arg.startswith("../") or
                    # Check for common file extensions
                    any(arg.endswith(ext) for ext in [".txt", ".py", ".sh", ".md", ".json", ".yaml", ".yml"]) or
                    # Check for common directory indicators
                    arg.endswith("/") or
                    # Check for environment variable expansion
                    "$" in arg or "%" in arg
                )

                if is_potentially_path_like:
                    try:
                        # Attempt to resolve and validate the path
                        normalized_path = self._normalize_path_for_command_arg(arg)
                        
                        # Additional safety checks
                        if not os.path.exists(normalized_path):
                            # Only warn for non-existent paths if they're not clearly intended to be created
                            if not any(arg.endswith(ext) for ext in [".txt", ".py", ".sh", ".md", ".json", ".yaml", ".yml"]):
                                print(f"Warning: Path '{normalized_path}' does not exist but may be created by the command")
                        
                        # Check for common dangerous patterns
                        if ".." in normalized_path:
                            print(f"Warning: Path contains parent directory reference: {normalized_path}")
                        
                        validated_args.append(normalized_path)
                    except CommandSecurityError:
                        raise
                    except Exception as e:
                        raise CommandSecurityError(f"Failed to validate path argument '{arg}': {str(e)}") from e
                else:
                    # For non-path arguments, add them as-is (after flag checks)
                    validated_args.append(arg)

            return command, validated_args

        except ValueError as e: # Error during shlex.split
            raise CommandSecurityError(f"Invalid command format: {str(e)}") from e
        # Catch CommandSecurityError explicitly to avoid wrapping it
        except CommandSecurityError:
             raise
        # Catch other unexpected errors during validation
        except Exception as e:
            raise CommandSecurityError(f"Unexpected error validating command '{command_string}': {e}") from e

    def _is_path_safe(self, path: str) -> bool:
        """
        Checks if a given absolute path is safe (starts with the primary allowed directory).
        Assumes path is already absolute and realpath'd by the caller.
        """
        try:
            # Ensure the primary allowed dir path ends with a separator for proper prefix check
            # This prevents allowing '/allowed/dir-suffix' if '/allowed/dir' is allowed.
            allowed_prefix = os.path.join(self.primary_allowed_dir, '')
            # Check if the resolved path starts with the allowed directory prefix
            return path.startswith(allowed_prefix) or path == self.primary_allowed_dir
        except Exception:
            # Should not happen if path is already absolute, but good practice
            return False


def load_security_config() -> SecurityConfig:
    """Loads security configuration for command execution from environment variables."""
    allowed_commands_str = os.getenv("ALLOWED_COMMANDS", "ls,cat,pwd,echo")
    allowed_flags_str = os.getenv("ALLOWED_FLAGS", "-l,-a,-h,--help")
    max_command_length_str = os.getenv("MAX_COMMAND_LENGTH", "1024")
    command_timeout_str = os.getenv("COMMAND_TIMEOUT", "60")

    allow_all_commands = allowed_commands_str.lower() == "all"
    allow_all_flags = allowed_flags_str.lower() == "all"

    allowed_commands_set = set()
    if not allow_all_commands:
        allowed_commands_set = set(c.strip() for c in allowed_commands_str.split(",") if c.strip())

    allowed_flags_set = set()
    if not allow_all_flags:
        allowed_flags_set = set(f.strip() for f in allowed_flags_str.split(",") if f.strip())

    try:
        max_command_length = int(max_command_length_str)
        command_timeout = int(command_timeout_str)
    except ValueError as e:
        # Provide a more informative error if conversion fails
        raise ValueError(f"Invalid integer value in environment variable for security config: {e}") from e

    # Instantiate Pydantic model - validation happens here
    return SecurityConfig(
        allowed_commands=allowed_commands_set,
        allowed_flags=allowed_flags_set,
        max_command_length=max_command_length,
        command_timeout=command_timeout,
        allow_all_commands=allow_all_commands,
        allow_all_flags=allow_all_flags,
    )
