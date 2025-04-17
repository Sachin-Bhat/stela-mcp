"""File system operations implementation.

This module provides a secure and robust implementation of file system operations
with path validation and access control. It ensures all operations are performed
within allowed directories and handles various edge cases and error conditions.
"""

import asyncio
import difflib
import fnmatch
import mimetypes
import os
import stat as stat_module
from datetime import datetime
from pathlib import Path
from typing import Any


def normalize_path(path: str) -> str:
    """Normalize a path consistently.

    This function takes a path string and normalizes it by:
    1. Expanding user home directory (~)
    2. Resolving any symbolic links
    3. Converting to absolute path
    4. Normalizing path separators

    Args:
        path (str): The path string to normalize

    Returns:
        str: The normalized path string
    """
    return str(Path(path).expanduser().resolve())


class FileSystem:
    """A secure file system operations manager.

    This class provides a set of methods for performing file system operations
    within a set of allowed directories. It includes path validation, access control,
    and proper error handling for all operations.

    Attributes:
        allowed_directories (list[Path]): List of directories where operations are allowed
    """

    def __init__(self, allowed_directories: list[str]) -> None:
        """Initialize the FileSystem with allowed directories.

        Args:
            allowed_directories (list[str]): List of directory paths where operations are allowed.
                If empty, defaults to the current working directory.

        Raises:
            ValueError: If any of the specified directories do not exist or are not directories.
        """
        if not allowed_directories:
            self.allowed_directories = [Path(os.getcwd()).resolve()]
            print(
                "Warning: No allowed directories specified. "
                f"Defaulting to current working directory: {self.allowed_directories[0]}"
            )
        else:
            self.allowed_directories = [Path(normalize_path(d)) for d in allowed_directories]

        for d in self.allowed_directories:
            if not d.is_dir():
                print(
                    f"Error: Specified allowed directory does not exist or is not a directory: {d}"
                )
        print(
            "FileSystem initialized. Allowed directories: "
            f"{[str(d) for d in self.allowed_directories]}"
        )

    def _validate_path(
        self, requested_path_str: str, check_parent_for_creation: bool = False
    ) -> Path:
        """Validate if a requested path is within allowed directories.

        This method performs several security checks:
        1. Normalizes the requested path
        2. Verifies the path is within allowed directories
        3. Resolves symbolic links and checks their targets
        4. Validates parent directories for creation operations

        Args:
            requested_path_str (str): The path to validate
            check_parent_for_creation (bool): If True, validates parent directory
                for creation operations

        Returns:
            Path: The validated and normalized Path object

        Raises:
            PermissionError: If the path is outside allowed directories
            FileNotFoundError: If the path doesn't exist and check_parent_for_creation is False
        """
        normalized_requested = Path(normalize_path(requested_path_str))

        # Check if path is in allowed directories
        is_allowed = any(
            normalized_requested == allowed_dir or normalized_requested.is_relative_to(allowed_dir)
            for allowed_dir in self.allowed_directories
        )

        # If path is allowed, try to resolve it
        if is_allowed:
            try:
                real_path = normalized_requested.resolve(strict=True)
                is_real_path_allowed = any(
                    real_path == allowed_dir or real_path.is_relative_to(allowed_dir)
                    for allowed_dir in self.allowed_directories
                )
                if not is_real_path_allowed:
                    raise PermissionError(
                        "Access denied - path resolves to symlink target "
                        f"outside allowed directories: {normalized_requested} -> {real_path}"
                    )
                return real_path
            except FileNotFoundError:
                if not check_parent_for_creation:
                    raise
            except Exception as e:
                raise PermissionError(f"Error resolving path {normalized_requested}: {e}") from e

        # If path is not allowed or we need to check parent directory
        if not is_allowed or check_parent_for_creation:
            parent_dir = normalized_requested.parent
            try:
                real_parent_path = parent_dir.resolve(strict=True)
                is_parent_allowed = any(
                    real_parent_path == allowed_dir or real_parent_path.is_relative_to(allowed_dir)
                    for allowed_dir in self.allowed_directories
                )
                if not is_parent_allowed:
                    raise PermissionError(
                        "Access denied - parent directory resolves outside "
                        f"allowed directories: {parent_dir} -> {real_parent_path}"
                    )
                return normalized_requested
            except FileNotFoundError:
                raise FileNotFoundError(f"Parent directory does not exist: {parent_dir}") from None
            except Exception as e:
                raise PermissionError(f"Error resolving parent path {parent_dir}: {e}") from e

        # If we get here, the path is not allowed and we're not checking parent
        allowed_dirs_str = ", ".join(map(str, self.allowed_directories))
        raise PermissionError(
            f"Access denied - path is outside allowed directories: {normalized_requested} "
            f"not in [{allowed_dirs_str}]"
        )

    async def read_file(self, path: str) -> dict[str, Any]:
        """Read the complete contents of a file.

        This method reads a file's contents with proper error handling and UTF-8 encoding.
        It validates the path and ensures the file exists and is accessible.

        Args:
            path (str): The path to the file to read

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Whether the operation succeeded
                - error (str | None): Error message if operation failed
                - content (str | None): File contents if successful
        """
        try:
            full_path = self._validate_path(path)

            if not full_path.is_file():
                return {"success": False, "error": f"Path is not a file: {path}", "content": None}

            with open(full_path, encoding="utf-8") as f:
                content = f.read()
                return {
                    "success": True,
                    "error": None,
                    "content": content,
                }
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e), "content": None}
        except Exception as e:
            return {"success": False, "error": f"Failed to read file {path}: {e}", "content": None}

    async def read_multiple_files(self, paths: list[str]) -> dict[str, Any]:
        """Read multiple files simultaneously.

        This method reads multiple files concurrently using asyncio, returning
        individual results for each file. It handles errors per-file and continues
        processing other files if one fails.

        Args:
            paths (list[str]): List of file paths to read

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Whether the overall operation succeeded
                - error (str | None): Error message if operation failed
                - results (dict): Dictionary mapping paths to their contents or error messages
        """
        results = {}
        tasks = {path: asyncio.create_task(self.read_file(path)) for path in paths}
        await asyncio.gather(*tasks.values())

        for path, task in tasks.items():
            result = task.result()
            if result["success"]:
                results[path] = result["content"]
            else:
                results[path] = f"Error - {result['error']}"

        return {"success": True, "error": None, "results": results}

    async def write_file(self, path: str, content: str) -> dict[str, Any]:
        """Create a new file or overwrite an existing file.

        This method writes content to a file, creating parent directories if needed.
        It validates the path and ensures proper permissions.

        Args:
            path (str): The path where to write the file
            content (str): The content to write to the file

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Whether the operation succeeded
                - error (str | None): Error message if operation failed
                - message (str | None): Success message if operation succeeded
        """
        try:
            full_path = self._validate_path(path, check_parent_for_creation=True)
            full_path.parent.mkdir(parents=True, exist_ok=True)

            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
            return {"success": True, "error": None, "message": f"Successfully wrote to {path}"}
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e)}
        except Exception as e:
            return {"success": False, "error": f"Failed to write file {path}: {e}"}

    async def list_directory(self, path: str) -> dict[str, Any]:
        """List directory contents with file type indicators.

        This method lists the contents of a directory, prefixing each item with
        [FILE] or [DIR] to indicate its type. It validates the path and ensures
        proper permissions.

        Args:
            path (str): The path to the directory to list

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Whether the operation succeeded
                - error (str | None): Error message if operation failed
                - listing (str | None): Formatted directory listing if successful
        """
        try:
            full_path = self._validate_path(path)

            if not full_path.is_dir():
                return {
                    "success": False,
                    "error": f"Path is not a directory: {path}",
                    "listing": None,
                }

            items = []
            for item in full_path.iterdir():
                prefix = "[DIR]" if item.is_dir() else "[FILE]"
                items.append(f"{prefix} {item.name}")

            return {"success": True, "error": None, "listing": "\n".join(items)}
        except (PermissionError, FileNotFoundError) as e:
            return {
                "success": False,
                "error": f"Failed to list directory {path}: {e}",
                "listing": None,
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to list directory {path}: {e}",
                "listing": None,
            }

    async def create_directory(self, path: str) -> dict[str, Any]:
        """Create a new directory, including parents if needed.

        This method creates a new directory, creating parent directories if they
        don't exist. It validates the path and ensures proper permissions.

        Args:
            path (str): The path of the directory to create

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Whether the operation succeeded
                - error (str | None): Error message if operation failed
                - message (str | None): Success message if operation succeeded
        """
        try:
            full_path = self._validate_path(path, check_parent_for_creation=True)
            full_path.mkdir(parents=True, exist_ok=True)
            return {
                "success": True,
                "error": None,
                "message": f"Successfully created directory {path}",
            }
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e)}
        except FileExistsError:
            return {"success": False, "error": f"Path exists but is not a directory: {path}"}
        except Exception as e:
            return {"success": False, "error": f"Failed to create directory {path}: {e}"}

    async def move_file(self, source: str, destination: str) -> dict[str, Any]:
        """Move or rename a file or directory.

        This method moves a file or directory from source to destination. It
        validates both paths and ensures proper permissions. The destination
        must not exist.

        Args:
            source (str): The path of the file/directory to move
            destination (str): The destination path

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Whether the operation succeeded
                - error (str | None): Error message if operation failed
                - message (str | None): Success message if operation succeeded
        """
        try:
            src_path = self._validate_path(source)
            dst_path = self._validate_path(destination, check_parent_for_creation=True)

            if not src_path.exists():
                return {"success": False, "error": f"Source path does not exist: {source}"}

            if dst_path.exists():
                return {
                    "success": False,
                    "error": f"Destination path already exists: {destination}",
                }

            dst_path.parent.mkdir(parents=True, exist_ok=True)
            src_path.rename(dst_path)
            return {
                "success": True,
                "error": None,
                "message": f"Successfully moved {source} to {destination}",
            }
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e)}
        except Exception as e:
            return {"success": False, "error": f"Failed to move {source} to {destination}: {e}"}

    async def search_files(
        self, path: str, pattern: str, exclude_patterns: list[str] | None = None
    ) -> dict[str, Any]:
        """Recursively search for files/directories matching a pattern.

        This method searches for files and directories matching a pattern,
        optionally excluding paths matching exclude patterns. The search is
        case-insensitive and supports glob patterns.

        Args:
            path (str): The root directory to start searching from
            pattern (str): The pattern to match against (case-insensitive)
            exclude_patterns (list[str] | None): List of glob patterns to exclude

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Whether the operation succeeded
                - error (str | None): Error message if operation failed
                - matches (list[str] | str): List of matching paths or "No matches found"
        """
        if exclude_patterns is None:
            exclude_patterns = []
        try:
            root_path = self._validate_path(path)
            if not root_path.is_dir():
                return {
                    "success": False,
                    "error": f"Path is not a directory: {path}",
                    "matches": None,
                }

            matches = []
            pattern_lower = pattern.lower()

            for current_root, dirs, files in os.walk(str(root_path), topdown=True):
                current_path_obj = Path(current_root)
                dirs[:] = [
                    d
                    for d in dirs
                    if not self._should_exclude(current_path_obj / d, root_path, exclude_patterns)
                ]
                filtered_files = [
                    f
                    for f in files
                    if not self._should_exclude(current_path_obj / f, root_path, exclude_patterns)
                ]

                for d in dirs:
                    try:
                        item_path = self._validate_path(str(current_path_obj / d))
                        if pattern_lower in d.lower():
                            matches.append(str(item_path))
                    except PermissionError:
                        continue

                for f in filtered_files:
                    try:
                        item_path = self._validate_path(str(current_path_obj / f))
                        if pattern_lower in f.lower():
                            matches.append(str(item_path))
                    except PermissionError:
                        continue

            return {
                "success": True,
                "error": None,
                "matches": matches if matches else "No matches found",
            }
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e), "matches": None}
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to search files in {path}: {e}",
                "matches": None,
            }

    def _should_exclude(
        self, item_path: Path, root_path: Path, exclude_patterns: list[str]
    ) -> bool:
        """Check if a path should be excluded based on glob patterns.

        This helper method determines if a path should be excluded from search
        results based on the provided glob patterns. It handles both relative
        and absolute path patterns.

        Args:
            item_path (Path): The path to check
            root_path (Path): The root search directory
            exclude_patterns (list[str]): List of glob patterns to check against

        Returns:
            bool: True if the path should be excluded, False otherwise
        """
        if not exclude_patterns:
            return False
        try:
            relative_path_str = str(item_path.relative_to(root_path))
        except ValueError:
            absolute_path_str = str(item_path.resolve())
            for pattern in exclude_patterns:
                if fnmatch.fnmatch(absolute_path_str, pattern):
                    return True
            return False

        for pattern in exclude_patterns:
            adjusted_pattern = (
                pattern if pattern.startswith("/") or "*" in pattern else f"**/{pattern}"
            )
            if fnmatch.fnmatch(relative_path_str, adjusted_pattern):
                return True
            if "/" not in pattern and fnmatch.fnmatch(item_path.name, pattern):
                return True
        return False

    async def get_directory_tree(self, path: str) -> dict[str, Any]:
        """Generate a recursive JSON tree view of a directory.

        This method creates a hierarchical JSON representation of a directory
        structure, including file and directory information. It handles
        permission errors gracefully.

        Args:
            path (str): The root directory to generate the tree from

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Whether the operation succeeded
                - error (str | None): Error message if operation failed
                - tree (dict | None): JSON tree structure if successful
        """
        try:
            root_path = self._validate_path(path)

            if not root_path.is_dir():
                return {"success": False, "error": f"Path is not a directory: {path}", "tree": None}

            def build_tree(p: Path) -> dict:
                entry: dict[str, Any] = {
                    "name": p.name,
                    "type": "directory" if p.is_dir() else "file",
                }
                if p.is_dir():
                    children = []
                    try:
                        for child in p.iterdir():
                            if child.is_symlink() and child.resolve() == p:
                                continue
                            if os.access(child, os.R_OK):
                                children.append(build_tree(child))
                    except PermissionError:
                        entry["error"] = "Permission denied to list contents"
                    except Exception as e:
                        entry["error"] = f"Error listing contents: {e}"
                    entry["children"] = children

                return entry

            tree = build_tree(root_path)
            return {"success": True, "error": None, "tree": tree}
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e), "tree": None}
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to build directory tree for {path}: {e}",
                "tree": None,
            }

    def _get_file_info(self, path: Path) -> dict[str, Any]:
        """Get detailed information about a file or directory.

        This helper method retrieves detailed metadata about a file or directory,
        including size, timestamps, permissions, and MIME type.

        Args:
            path (Path): The path to get information about

        Returns:
            dict[str, Any]: A dictionary containing file metadata or error information
        """
        try:
            stat = path.stat()
            mode = stat.st_mode
            is_dir = stat_module.S_ISDIR(mode)
            is_file = stat_module.S_ISREG(mode)

            if is_dir:
                file_type = "directory"
                mime_type = None
            elif is_file:
                file_type = "file"
                mime_type, _ = mimetypes.guess_type(str(path))
                mime_type = mime_type or "application/octet-stream"
            else:
                file_type = "other"
                mime_type = None

            permissions = oct(mode & 0o777)

            info = {
                "name": path.name,
                "type": file_type,
                "path": str(path),
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                "permissions": permissions,
            }
            return info
        except FileNotFoundError:
            return {"error": "File not found during stat"}
        except Exception as e:
            return {"error": f"Could not get file info: {e}"}

    async def get_file_info(self, path: str) -> dict[str, Any]:
        """Get detailed file/directory metadata.

        This method retrieves comprehensive metadata about a file or directory,
        including size, timestamps, permissions, and MIME type. It formats the
        information in a human-readable string.

        Args:
            path (str): The path to get information about

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Whether the operation succeeded
                - error (str | None): Error message if operation failed
                - info (str | None): Formatted metadata string if successful
        """
        try:
            full_path = self._validate_path(path)
            info = self._get_file_info(full_path)
            if "error" in info:
                return {"success": False, "error": info["error"], "info": None}

            info_str = "\n".join(f"{k}: {v}" for k, v in info.items())

            return {"success": True, "error": None, "info": info_str}
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e), "info": None}
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get file info for {path}: {e}",
                "info": None,
            }

    async def list_allowed_directories(self) -> dict[str, Any]:
        """List all directories the server is allowed to access.

        This method returns a list of all directories that have been configured
        as allowed directories for file system operations.

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Always True
                - error (str | None): Always None
                - allowed_directories (list[str]): List of allowed directory paths
        """
        return {
            "success": True,
            "error": None,
            "allowed_directories": [str(d) for d in self.allowed_directories],
        }

    async def edit_file(
        self, path: str, edits: list[dict[str, str]], dry_run: bool = False
    ) -> dict[str, Any]:
        """Make selective edits to a file and return a diff.

        This method performs selective edits to a file based on exact line matches
        or whitespace-normalized matches. It can preview changes with dry_run
        and returns a git-style diff of the changes.

        Args:
            path (str): The path to the file to edit
            edits (list[dict[str, str]]): List of edit operations, each containing:
                - oldText: The exact lines to replace
                - newText: The new lines to insert
            dry_run (bool): If True, preview changes without applying them

        Returns:
            dict[str, Any]: A dictionary containing:
                - success (bool): Whether the operation succeeded
                - error (str | None): Error message if operation failed
                - diff (str | None): Git-style diff of changes if successful
        """
        try:
            full_path = self._validate_path(path)
            if not full_path.is_file():
                return {"success": False, "error": f"Path is not a file: {path}", "diff": None}

            with open(full_path, encoding="utf-8") as f:
                original_content = f.read()

            original_lines = original_content.splitlines(keepends=True)
            modified_lines = list(original_lines)
            applied_edit_indices: set[int] = set()

            for edit_index, edit in enumerate(edits):
                old_text = edit.get("oldText")
                new_text = edit.get("newText")

                if old_text is None or new_text is None:
                    return {
                        "success": False,
                        "error": f"Invalid edit format at index {edit_index}: {edit}",
                        "diff": None,
                    }

                old_lines_edit = old_text.splitlines(keepends=True)
                new_lines_edit = new_text.splitlines(keepends=True)

                if not old_lines_edit:
                    return {
                        "success": False,
                        "error": f"'oldText' cannot be empty for edit at index {edit_index}",
                        "diff": None,
                    }

                match_found = False
                for i in range(len(modified_lines) - len(old_lines_edit) + 1):
                    match_indices = set(range(i, i + len(old_lines_edit)))
                    if not match_indices.isdisjoint(applied_edit_indices):
                        continue

                    if modified_lines[i : i + len(old_lines_edit)] == old_lines_edit:
                        modified_lines[i : i + len(old_lines_edit)] = new_lines_edit
                        applied_edit_indices.update(range(i, i + len(new_lines_edit)))
                        match_found = True
                        break

                if not match_found:
                    normalized_original = [line.strip() for line in modified_lines]
                    normalized_old = [line.strip() for line in old_lines_edit]

                    for i in range(len(normalized_original) - len(normalized_old) + 1):
                        match_indices = set(range(i, i + len(normalized_old)))
                        if not match_indices.isdisjoint(applied_edit_indices):
                            continue

                        if normalized_original[i : i + len(normalized_old)] == normalized_old:
                            original_indent = modified_lines[i][
                                : len(modified_lines[i]) - len(modified_lines[i].lstrip())
                            ]
                            new_lines_with_indent = [
                                original_indent + line.lstrip() for line in new_lines_edit
                            ]
                            modified_lines[i : i + len(normalized_old)] = new_lines_with_indent
                            applied_edit_indices.update(range(i, i + len(new_lines_with_indent)))
                            match_found = True
                            break

                    if not match_found:
                        return {
                            "success": False,
                            "error": (
                                f"Could not find exact match for edit #{edit_index + 1} "
                                f"(with whitespace normalization):\n---\n{old_text}\n---"
                            ),
                            "diff": None,
                        }

            modified_content = "".join(modified_lines)

            diff = difflib.unified_diff(
                original_lines, modified_lines, fromfile=path, tofile=path, lineterm="\n"
            )
            diff_str = "".join(diff)

            num_backticks = 3
            while "`" * num_backticks in diff_str:
                num_backticks += 1
            formatted_diff = f"{'`' * num_backticks}diff\n{diff_str}{'`' * num_backticks}\n\n"

            if not dry_run:
                full_path_write = self._validate_path(path, check_parent_for_creation=True)
                with open(full_path_write, "w", encoding="utf-8") as f:
                    f.write(modified_content)

            return {"success": True, "error": None, "diff": formatted_diff}

        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e), "diff": None}
        except Exception as e:
            return {"success": False, "error": f"Failed to edit file {path}: {e}", "diff": None}
