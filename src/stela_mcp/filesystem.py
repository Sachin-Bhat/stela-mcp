"""File system operations implementation."""

import asyncio
import mimetypes
import os
import stat as stat_module
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional
import fnmatch
import difflib


def normalize_path(path: str) -> str:
    """Normalize a path consistently."""
    return str(Path(path).expanduser().resolve())


class FileSystem:
    def __init__(self, allowed_directories: List[str]) -> None:
        if not allowed_directories:
            self.allowed_directories = [Path(os.getcwd()).resolve()]
            print(f"Warning: No allowed directories specified. Defaulting to current working directory: {self.allowed_directories[0]}")
        else:
            self.allowed_directories = [Path(normalize_path(d)) for d in allowed_directories]

        for d in self.allowed_directories:
            if not d.is_dir():
                print(f"Error: Specified allowed directory does not exist or is not a directory: {d}")
        print(f"FileSystem initialized. Allowed directories: {[str(d) for d in self.allowed_directories]}")


    def _validate_path(self, requested_path_str: str, check_parent_for_creation: bool = False) -> Path:
        """Validate if a requested path is within allowed directories and return the resolved Path object."""
        normalized_requested = Path(normalize_path(requested_path_str))

        is_allowed = any(
            normalized_requested == allowed_dir or normalized_requested.is_relative_to(allowed_dir)
            for allowed_dir in self.allowed_directories
        )

        if is_allowed:
            try:
                real_path = normalized_requested.resolve(strict=True)
                is_real_path_allowed = any(
                    real_path == allowed_dir or real_path.is_relative_to(allowed_dir)
                    for allowed_dir in self.allowed_directories
                )
                if not is_real_path_allowed:
                    raise PermissionError(f"Access denied - path resolves to symlink target outside allowed directories: {normalized_requested} -> {real_path}")
                return real_path
            except FileNotFoundError:
                pass
            except Exception as e:
                raise PermissionError(f"Error resolving path {normalized_requested}: {e}")

        if check_parent_for_creation or not is_allowed:
            parent_dir = normalized_requested.parent
            try:
                real_parent_path = parent_dir.resolve(strict=True)
                is_parent_allowed = any(
                    real_parent_path == allowed_dir or real_parent_path.is_relative_to(allowed_dir)
                    for allowed_dir in self.allowed_directories
                )
                if not is_parent_allowed:
                    raise PermissionError(f"Access denied - parent directory resolves outside allowed directories: {parent_dir} -> {real_parent_path}")
                return normalized_requested

            except FileNotFoundError:
                raise FileNotFoundError(f"Parent directory does not exist: {parent_dir}")
            except Exception as e:
                raise PermissionError(f"Error resolving parent path {parent_dir}: {e}")

        if not is_allowed:
            allowed_dirs_str = ', '.join(map(str, self.allowed_directories))
            raise PermissionError(f"Access denied - path outside allowed directories: {normalized_requested} not in [{allowed_dirs_str}]")

        return normalized_requested


    async def read_file(self, path: str) -> dict[str, Any]:
        """Read the complete contents of a file."""
        try:
            full_path = self._validate_path(path)

            if not full_path.is_file():
                return {"success": False, "error": f"Path is not a file: {path}", "content": None}

            with open(full_path, "r", encoding="utf-8") as f:
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
        """Read multiple files simultaneously, returning results individually."""
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
        """Create a new file or overwrite an existing file."""
        try:
            full_path = self._validate_path(path, check_parent_for_creation=True)
            full_path.parent.mkdir(parents=True, exist_ok=True)

            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
            return {
                "success": True,
                "error": None,
                "message": f"Successfully wrote to {path}"
            }
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e)}
        except Exception as e:
            return {"success": False, "error": f"Failed to write file {path}: {e}"}

    async def list_directory(self, path: str) -> dict[str, Any]:
        """List directory contents with [FILE] or [DIR] prefixes."""
        try:
            full_path = self._validate_path(path)

            if not full_path.is_dir():
                return {"success": False, "error": f"Path is not a directory: {path}", "listing": None}

            items = []
            for item in full_path.iterdir():
                prefix = "[DIR]" if item.is_dir() else "[FILE]"
                items.append(f"{prefix} {item.name}")

            return {
                "success": True,
                "error": None,
                "listing": "\n".join(items)
            }
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e), "listing": None}
        except Exception as e:
            return {"success": False, "error": f"Failed to list directory {path}: {e}", "listing": None}

    async def create_directory(self, path: str) -> dict[str, Any]:
        """Create a new directory, including parents if needed."""
        try:
            full_path = self._validate_path(path, check_parent_for_creation=True)
            full_path.mkdir(parents=True, exist_ok=True)
            return {
                "success": True,
                "error": None,
                "message": f"Successfully created directory {path}"
            }
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e)}
        except FileExistsError:
            return {"success": False, "error": f"Path exists but is not a directory: {path}"}
        except Exception as e:
            return {"success": False, "error": f"Failed to create directory {path}: {e}"}

    async def move_file(self, source: str, destination: str) -> dict[str, Any]:
        """Move or rename a file or directory. Fails if destination exists."""
        try:
            src_path = self._validate_path(source)
            dst_path = self._validate_path(destination, check_parent_for_creation=True)

            if not src_path.exists():
                return {"success": False, "error": f"Source path does not exist: {source}"}

            if dst_path.exists():
                return {"success": False, "error": f"Destination path already exists: {destination}"}

            dst_path.parent.mkdir(parents=True, exist_ok=True)
            src_path.rename(dst_path)
            return {
                "success": True,
                "error": None,
                "message": f"Successfully moved {source} to {destination}"
            }
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e)}
        except Exception as e:
            return {"success": False, "error": f"Failed to move {source} to {destination}: {e}"}

    async def search_files(self, path: str, pattern: str, exclude_patterns: Optional[List[str]] = None) -> dict[str, Any]:
        """Recursively search for files/directories matching a pattern (case-insensitive), excluding specified patterns."""
        if exclude_patterns is None:
            exclude_patterns = []
        try:
            root_path = self._validate_path(path)
            if not root_path.is_dir():
                return {"success": False, "error": f"Path is not a directory: {path}", "matches": None}

            matches = []
            pattern_lower = pattern.lower()

            for current_root, dirs, files in os.walk(str(root_path), topdown=True):
                current_path_obj = Path(current_root)
                dirs[:] = [d for d in dirs if not self._should_exclude(current_path_obj / d, root_path, exclude_patterns)]
                filtered_files = [f for f in files if not self._should_exclude(current_path_obj / f, root_path, exclude_patterns)]

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
                "matches": matches if matches else "No matches found"
            }
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e), "matches": None}
        except Exception as e:
            return {"success": False, "error": f"Failed to search files in {path}: {e}", "matches": None}

    def _should_exclude(self, item_path: Path, root_path: Path, exclude_patterns: List[str]) -> bool:
        """Check if a path should be excluded based on glob patterns relative to the search root."""
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
            adjusted_pattern = pattern if pattern.startswith('/') or '*' in pattern else f"**/{pattern}"
            if fnmatch.fnmatch(relative_path_str, adjusted_pattern):
                return True
            if '/' not in pattern and fnmatch.fnmatch(item_path.name, pattern):
                return True
        return False


    async def get_directory_tree(self, path: str) -> dict[str, Any]:
        """Generate a recursive JSON tree view of a directory."""
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
            return {
                "success": True,
                "error": None,
                "tree": tree
            }
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e), "tree": None}
        except Exception as e:
            return {"success": False, "error": f"Failed to build directory tree for {path}: {e}", "tree": None}

    def _get_file_info(self, path: Path) -> dict[str, Any]:
        """Get detailed information about a file or directory."""
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
        """Get detailed file/directory metadata."""
        try:
            full_path = self._validate_path(path)
            info = self._get_file_info(full_path)
            if "error" in info:
                return {"success": False, "error": info["error"], "info": None}

            info_str = "\n".join(f"{k}: {v}" for k, v in info.items())

            return {
                "success": True,
                "error": None,
                "info": info_str
            }
        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e), "info": None}
        except Exception as e:
            return {"success": False, "error": f"Failed to get file info for {path}: {e}", "info": None}


    async def list_allowed_directories(self) -> dict[str, Any]:
        """List all directories the server is allowed to access."""
        return {
            "success": True,
            "error": None,
            "allowed_directories": [str(d) for d in self.allowed_directories]
        }


    async def edit_file(self, path: str, edits: List[dict[str, str]], dry_run: bool = False) -> dict[str, Any]:
        """Make selective edits to a file and return a diff."""
        try:
            full_path = self._validate_path(path)
            if not full_path.is_file():
                return {"success": False, "error": f"Path is not a file: {path}", "diff": None}

            with open(full_path, "r", encoding="utf-8") as f:
                original_content = f.read()

            original_lines = original_content.splitlines(keepends=True)
            modified_lines = list(original_lines)
            applied_edit_indices = set()

            for edit_index, edit in enumerate(edits):
                old_text = edit.get("oldText")
                new_text = edit.get("newText")

                if old_text is None or new_text is None:
                    return {"success": False, "error": f"Invalid edit format at index {edit_index}: {edit}", "diff": None}

                old_lines_edit = old_text.splitlines(keepends=True)
                new_lines_edit = new_text.splitlines(keepends=True)

                if not old_lines_edit:
                    return {"success": False, "error": f"'oldText' cannot be empty for edit at index {edit_index}", "diff": None}

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
                            
                        if normalized_original[i:i + len(normalized_old)] == normalized_old:
                            original_indent = modified_lines[i][:len(modified_lines[i]) - len(modified_lines[i].lstrip())]
                            new_lines_with_indent = [original_indent + line.lstrip() for line in new_lines_edit]
                            modified_lines[i:i + len(normalized_old)] = new_lines_with_indent
                            applied_edit_indices.update(range(i, i + len(new_lines_with_indent)))
                            match_found = True
                            break
                    
                    if not match_found:
                        return {"success": False, "error": f"Could not find match for edit #{edit_index+1} (with whitespace normalization):\n---\n{old_text}\n---", "diff": None}

            modified_content = "".join(modified_lines)

            diff = difflib.unified_diff(
                original_lines,
                modified_lines,
                fromfile=path,
                tofile=path,
                lineterm='\n'
            )
            diff_str = "".join(diff)

            num_backticks = 3
            while '`' * num_backticks in diff_str:
                num_backticks += 1
            formatted_diff = f"{'`' * num_backticks}diff\n{diff_str}{'`' * num_backticks}\n\n"

            if not dry_run:
                full_path_write = self._validate_path(path, check_parent_for_creation=True)
                with open(full_path_write, "w", encoding="utf-8") as f:
                    f.write(modified_content)

            return {
                "success": True,
                "error": None,
                "diff": formatted_diff
            }

        except (PermissionError, FileNotFoundError) as e:
            return {"success": False, "error": str(e), "diff": None}
        except Exception as e:
            return {"success": False, "error": f"Failed to edit file {path}: {e}", "diff": None}
