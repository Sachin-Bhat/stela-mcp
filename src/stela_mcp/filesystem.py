"""File system operations implementation."""

import asyncio
import mimetypes
import os
from datetime import datetime
from pathlib import Path
from typing import Any


def normalize_path(path: str) -> str:
    """Normalize a path consistently."""
    return str(Path(path).resolve())


def expand_home(path: str) -> str:
    """Expand ~ to home directory."""
    return str(Path(path).expanduser())


def validate_path(path: str) -> bool:
    """Validate if a path is within allowed directories."""
    # TODO: Make this configurable through a configuration file
    allowed_directories = [Path("/")]  # Currently allowing all paths
    path_obj = Path(path).resolve()

    return any(path_obj.is_relative_to(allowed_dir) for allowed_dir in allowed_directories)


class FileSystem:
    def __init__(self, root_dir: str | None = None) -> None:
        self.root_dir = Path(root_dir or os.getcwd()).resolve()

    async def read_file(self, path: str, return_metadata: bool = False) -> dict[str, Any]:
        """Read the contents of a file with optional metadata."""
        try:
            full_path = self._resolve_path(path)
            if not validate_path(str(full_path)):
                return {
                    "success": False,
                    "error": "Path not allowed",
                    "content": None,
                    "path": None,
                }

            with open(full_path, "rb") as f:
                content = f.read()
                result = {
                    "success": True,
                    "error": None,
                    "content": content.decode("utf-8"),
                    "path": str(full_path),
                }

                if return_metadata:
                    result.update(self._get_file_info(full_path))

                return result
        except Exception as e:
            return {"success": False, "error": str(e), "content": None, "path": None}

    async def read_multiple_files(self, paths: list[str]) -> list[dict[str, Any]]:
        """Read multiple files in parallel."""
        tasks = [self.read_file(path, return_metadata=True) for path in paths]
        return await asyncio.gather(*tasks)

    async def write_file(self, path: str, content: str) -> dict[str, Any]:
        """Write content to a file."""
        try:
            full_path = self._resolve_path(path)
            if not validate_path(str(full_path)):
                return {"success": False, "error": "Path not allowed", "path": None}

            # Ensure parent directory exists
            full_path.parent.mkdir(parents=True, exist_ok=True)

            with open(full_path, "w") as f:
                f.write(content)
            return {"success": True, "error": None, "path": str(full_path)}
        except Exception as e:
            return {"success": False, "error": str(e), "path": None}

    async def list_directory(self, path: str) -> dict[str, Any]:
        """List contents of a directory with enhanced metadata."""
        try:
            full_path = self._resolve_path(path)
            if not validate_path(str(full_path)):
                return {"success": False, "error": "Path not allowed", "path": None, "items": None}

            path_obj = Path(full_path)

            if not path_obj.exists():
                return {
                    "success": False,
                    "error": "Path does not exist",
                    "path": None,
                    "items": None,
                }

            if path_obj.is_file():
                return {
                    "success": True,
                    "error": None,
                    "path": str(path_obj),
                    "items": [self._get_file_info(path_obj)],
                }

            items = []
            for item in path_obj.iterdir():
                items.append(self._get_file_info(item))

            return {"success": True, "error": None, "path": str(path_obj), "items": items}
        except Exception as e:
            return {"success": False, "error": str(e), "path": None, "items": None}

    async def create_directory(self, path: str) -> dict[str, Any]:
        """Create a new directory."""
        try:
            full_path = self._resolve_path(path)
            if not validate_path(str(full_path)):
                return {"success": False, "error": "Path not allowed", "path": None}

            full_path.mkdir(parents=True, exist_ok=True)
            return {"success": True, "error": None, "path": str(full_path)}
        except Exception as e:
            return {"success": False, "error": str(e), "path": None}

    async def move_file(self, source: str, destination: str) -> dict[str, Any]:
        """Move or rename a file or directory."""
        try:
            src_path = self._resolve_path(source)
            dst_path = self._resolve_path(destination)

            if not validate_path(str(src_path)) or not validate_path(str(dst_path)):
                return {"success": False, "error": "Path not allowed", "path": None}

            src_path.rename(dst_path)
            return {"success": True, "error": None, "path": str(dst_path)}
        except Exception as e:
            return {"success": False, "error": str(e), "path": None}

    async def search_files(self, path: str, pattern: str) -> dict[str, Any]:
        """Search for files matching a pattern."""
        try:
            full_path = self._resolve_path(path)
            if not validate_path(str(full_path)):
                return {
                    "success": False,
                    "error": "Path not allowed",
                    "path": None,
                    "matches": None,
                }

            matches = []
            for root, _, files in os.walk(full_path):
                for file in files:
                    if pattern in file:
                        matches.append(str(Path(root) / file))

            return {"success": True, "error": None, "path": str(full_path), "matches": matches}
        except Exception as e:
            return {"success": False, "error": str(e), "path": None, "matches": None}

    async def get_directory_tree(self, path: str) -> dict[str, Any]:
        """Generate a recursive tree view of a directory."""
        try:
            full_path = self._resolve_path(path)
            if not validate_path(str(full_path)):
                return {"success": False, "error": "Path not allowed", "path": None, "tree": None}

            def build_tree(p: Path) -> dict:
                if p.is_file():
                    return self._get_file_info(p)

                return {
                    "name": p.name,
                    "type": "directory",
                    "path": str(p),
                    "children": [build_tree(child) for child in p.iterdir()],
                }

            tree = build_tree(full_path)
            return {"success": True, "error": None, "path": str(full_path), "tree": tree}
        except Exception as e:
            return {"success": False, "error": str(e), "path": None, "tree": None}

    def _resolve_path(self, path: str) -> Path:
        """Resolve a path relative to the root directory."""
        expanded_path = expand_home(path)
        return (self.root_dir / expanded_path).resolve()

    def _get_file_info(self, path: Path) -> dict[str, Any]:
        """Get detailed information about a file or directory."""
        stat = path.stat()
        mime_type, _ = mimetypes.guess_type(str(path))

        return {
            "name": path.name,
            "type": "file" if path.is_file() else "directory",
            "path": str(path),
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "mime_type": mime_type or "application/octet-stream",
            "is_image": mime_type.startswith("image/") if mime_type else False,
        }
