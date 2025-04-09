import os
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime

class FileSystem:
    def __init__(self, root_dir: Optional[str] = None):
        self.root_dir = root_dir or os.getcwd()

    async def read_file(self, path: str) -> Dict:
        """Read the contents of a file."""
        try:
            full_path = self._resolve_path(path)
            with open(full_path, 'r') as f:
                return {
                    "success": True,
                    "content": f.read(),
                    "path": str(full_path)
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def write_file(self, path: str, content: str) -> Dict:
        """Write content to a file."""
        try:
            full_path = self._resolve_path(path)
            with open(full_path, 'w') as f:
                f.write(content)
            return {"success": True, "path": str(full_path)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def list_directory(self, path: str) -> Dict:
        """List contents of a directory."""
        try:
            full_path = self._resolve_path(path)
            path_obj = Path(full_path)
            
            if not path_obj.exists():
                return {"success": False, "error": "Path does not exist"}
                
            if path_obj.is_file():
                return {
                    "success": True,
                    "type": "file",
                    "path": str(path_obj),
                    "info": self._get_file_info(path_obj)
                }
                
            items = []
            for item in path_obj.iterdir():
                items.append({
                    "name": item.name,
                    "type": "file" if item.is_file() else "directory",
                    "path": str(item),
                    "info": self._get_file_info(item)
                })
                
            return {
                "success": True,
                "type": "directory",
                "path": str(path_obj),
                "items": items
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def create_directory(self, path: str) -> Dict:
        """Create a new directory."""
        try:
            full_path = self._resolve_path(path)
            os.makedirs(full_path, exist_ok=True)
            return {"success": True, "path": str(full_path)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def move_file(self, source: str, destination: str) -> Dict:
        """Move or rename a file or directory."""
        try:
            src_path = self._resolve_path(source)
            dst_path = self._resolve_path(destination)
            
            if not src_path.exists():
                return {"success": False, "error": "Source path does not exist"}
                
            src_path.rename(dst_path)
            return {"success": True, "new_path": str(dst_path)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def search_files(self, path: str, pattern: str) -> Dict:
        """Search for files matching a pattern."""
        try:
            full_path = self._resolve_path(path)
            if not full_path.exists():
                return {"success": False, "error": "Path does not exist"}
                
            matches = []
            for item in full_path.rglob(pattern):
                matches.append({
                    "name": item.name,
                    "type": "file" if item.is_file() else "directory",
                    "path": str(item),
                    "info": self._get_file_info(item)
                })
                
            return {"success": True, "matches": matches}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_directory_tree(self, path: str) -> Dict:
        """Generate a recursive tree view of a directory."""
        try:
            full_path = self._resolve_path(path)
            if not full_path.exists():
                return {"success": False, "error": "Path does not exist"}
                
            def build_tree(p: Path) -> Dict:
                info = self._get_file_info(p)
                if p.is_file():
                    return info
                    
                children = []
                for child in p.iterdir():
                    children.append(build_tree(child))
                    
                return {**info, "children": children}
                
            tree = build_tree(full_path)
            return {"success": True, "tree": tree}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _resolve_path(self, path: str) -> Path:
        """Resolve a path relative to the root directory."""
        return Path(self.root_dir) / path

    def _get_file_info(self, path: Path) -> Dict:
        """Get detailed information about a file or directory."""
        stat = path.stat()
        return {
            "name": path.name,
            "path": str(path),
            "type": "file" if path.is_file() else "directory",
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "permissions": oct(stat.st_mode)[-3:]
        } 