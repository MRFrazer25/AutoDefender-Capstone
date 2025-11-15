"""Utilities for sanitizing user-supplied file system paths."""

from __future__ import annotations

import re
from pathlib import Path


def sanitize_path(path_str: str) -> Path:
    """Normalize user-supplied path strings into safe, absolute paths.

    Raises:
        ValueError: If the path is empty or contains invalid characters.
    """
    if path_str is None:
        raise ValueError("Path is required.")

    cleaned = path_str.strip().strip('"').strip("'")
    if not cleaned:
        raise ValueError("Path cannot be empty.")
    if "\x00" in cleaned:
        raise ValueError("Path contains invalid characters.")

    return Path(cleaned).expanduser().resolve(strict=False)


_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str, default: str = "export") -> str:
    """Return a filesystem-safe filename."""
    if not name:
        return default
    cleaned = _SAFE_FILENAME.sub("_", name.strip())
    return cleaned or default

