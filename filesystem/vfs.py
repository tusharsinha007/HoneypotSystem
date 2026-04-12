"""
LLMPot — Virtual Filesystem
In-memory tree structure representing a realistic Linux filesystem.
"""

import json
import os
from pathlib import Path, PurePosixPath
from datetime import datetime
from typing import Optional


class VirtualFilesystem:
    """Simulated Linux filesystem for the honeypot."""

    def __init__(self):
        self._load_tree()
        self.cwd = "/root"
        # Runtime modifications (files created by attacker)
        self._runtime_files = {}

    def _load_tree(self):
        """Load filesystem tree from JSON definition."""
        fs_data_path = Path(__file__).parent / "fs_data.json"
        with open(fs_data_path, "r") as f:
            self.tree = json.load(f)

    def _resolve_path(self, path: str) -> str:
        """Resolve a path (handle relative paths, .., .)."""
        if not path:
            return self.cwd

        if not path.startswith("/"):
            path = self.cwd.rstrip("/") + "/" + path

        # Normalize the path
        parts = []
        for part in path.split("/"):
            if part == "" or part == ".":
                continue
            elif part == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(part)

        return "/" + "/".join(parts) if parts else "/"

    def _traverse(self, path: str) -> Optional[dict]:
        """Traverse the tree to find a node at the given path."""
        if path == "/":
            return self.tree["/"]

        # Check runtime files first
        if path in self._runtime_files:
            return self._runtime_files[path]

        parts = [p for p in path.split("/") if p]
        node = self.tree["/"]

        for part in parts:
            if node.get("type") != "dir":
                return None
            children = node.get("children", {})
            if part not in children:
                return None
            node = children[part]

        return node

    def exists(self, path: str) -> bool:
        """Check if a path exists."""
        resolved = self._resolve_path(path)
        return self._traverse(resolved) is not None

    def is_dir(self, path: str) -> bool:
        """Check if path is a directory."""
        resolved = self._resolve_path(path)
        node = self._traverse(resolved)
        return node is not None and node.get("type") == "dir"

    def is_file(self, path: str) -> bool:
        """Check if path is a file."""
        resolved = self._resolve_path(path)
        node = self._traverse(resolved)
        return node is not None and node.get("type") == "file"

    def chdir(self, path: str) -> tuple:
        """Change current working directory. Returns (success, error_msg)."""
        resolved = self._resolve_path(path)
        node = self._traverse(resolved)

        if node is None:
            return False, f"-bash: cd: {path}: No such file or directory"
        if node.get("type") != "dir":
            return False, f"-bash: cd: {path}: Not a directory"

        self.cwd = resolved
        return True, ""

    def listdir(self, path: str = None, long_format: bool = False,
                show_hidden: bool = False) -> str:
        """List directory contents."""
        resolved = self._resolve_path(path or self.cwd)
        node = self._traverse(resolved)

        if node is None:
            return f"ls: cannot access '{path}': No such file or directory"
        if node.get("type") != "dir":
            return f"ls: cannot access '{path}': Not a directory"

        children = node.get("children", {})

        # Add any runtime files in this directory
        for runtime_path, runtime_node in self._runtime_files.items():
            parent = str(PurePosixPath(runtime_path).parent)
            if parent == resolved:
                name = PurePosixPath(runtime_path).name
                children[name] = runtime_node

        if not children:
            return ""

        names = sorted(children.keys())
        if not show_hidden:
            names = [n for n in names if not n.startswith(".")]

        if not long_format:
            return "  ".join(names)

        # Long format: -rwxr-xr-x 1 root root 1234 Jan  1 00:00 filename
        lines = [f"total {len(names)}"]
        now = datetime(2024, 1, 15, 10, 30, 0)
        for name in names:
            child = children[name]
            perms = child.get("perms", "-rw-r--r--" if child["type"] == "file"
                              else "drwxr-xr-x")
            if child["type"] == "dir":
                perms = "d" + perms[1:] if not perms.startswith("d") else perms
            size = child.get("size", 4096 if child["type"] == "dir" else 0)
            date_str = now.strftime("%b %d %H:%M")
            links = 2 if child["type"] == "dir" else 1
            lines.append(
                f"{perms} {links:>2} root root {size:>8} {date_str} {name}")

        return "\n".join(lines)

    def read_file(self, path: str) -> str:
        """Read file contents. Returns fake content for known files."""
        from .fake_files import get_fake_content

        resolved = self._resolve_path(path)
        node = self._traverse(resolved)

        if node is None:
            return f"cat: {path}: No such file or directory"
        if node.get("type") == "dir":
            return f"cat: {path}: Is a directory"

        # Check runtime files
        if resolved in self._runtime_files:
            return self._runtime_files[resolved].get("content", "")

        # Get fake content for known system files
        content = get_fake_content(resolved)
        if content is not None:
            return content

        return ""

    def create_file(self, path: str, content: str = "") -> tuple:
        """Create a file (attacker-created files go to runtime storage)."""
        resolved = self._resolve_path(path)
        parent_path = str(PurePosixPath(resolved).parent)

        if not self.is_dir(parent_path):
            return False, f"touch: cannot touch '{path}': No such file or directory"

        self._runtime_files[resolved] = {
            "type": "file",
            "size": len(content),
            "perms": "-rw-r--r--",
            "content": content,
        }
        return True, ""

    def create_dir(self, path: str) -> tuple:
        """Create a directory."""
        resolved = self._resolve_path(path)
        parent_path = str(PurePosixPath(resolved).parent)

        if not self.is_dir(parent_path):
            return False, f"mkdir: cannot create directory '{path}': No such file or directory"

        self._runtime_files[resolved] = {
            "type": "dir",
            "size": 4096,
            "perms": "drwxr-xr-x",
            "children": {},
        }
        return True, ""

    def remove(self, path: str) -> tuple:
        """Remove a file or directory (only runtime files can actually be removed)."""
        resolved = self._resolve_path(path)

        if resolved in self._runtime_files:
            del self._runtime_files[resolved]
            return True, ""

        node = self._traverse(resolved)
        if node is None:
            return False, f"rm: cannot remove '{path}': No such file or directory"

        # Pretend to remove system files
        return True, ""

    def get_pwd(self) -> str:
        """Return current working directory."""
        return self.cwd
