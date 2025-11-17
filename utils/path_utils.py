"""Utilities for sanitizing user-supplied file system paths."""

from __future__ import annotations

import os
import re
from pathlib import Path


def sanitize_path(path_str: str, base_dir: Path | None = None) -> Path:
    """Normalize user-supplied path strings into safe, absolute paths.
    
    Restricts paths to be within the base directory (or current working directory)
    to prevent path traversal attacks.
    
    Args:
        path_str: User-supplied path string
        base_dir: Base directory to restrict paths to (defaults to current working directory)
        
    Raises:
        ValueError: If the path is empty, contains invalid characters, or attempts traversal.
    """
    if path_str is None:
        raise ValueError("Path is required.")

    cleaned = path_str.strip().strip('"').strip("'")
    if not cleaned:
        raise ValueError("Path cannot be empty.")
    if "\x00" in cleaned:
        raise ValueError("Path contains invalid characters.")
    
    # Use base directory or current working directory as safe base
    if base_dir is None:
        base_dir = Path.cwd()
    else:
        base_dir = Path(base_dir).resolve()
    
    # Validate base directory exists and is a directory
    if not base_dir.exists():
        raise ValueError(f"Base directory does not exist: {base_dir}")
    if not base_dir.is_dir():
        raise ValueError(f"Base path is not a directory: {base_dir}")
    
    # Construct path relative to base directory using os.path operations for safety
    # This prevents direct Path construction from user input until after validation
    base_str = str(base_dir)
    base_abs = os.path.abspath(base_str)
    norm_base = os.path.normpath(base_abs)
    
    # Check if the cleaned path is absolute
    if os.path.isabs(cleaned):
        # For absolute paths, validate using os.path operations first
        # Expand user home directory if needed
        expanded = os.path.expanduser(cleaned)
        abs_cleaned = os.path.abspath(expanded)
        norm_cleaned = os.path.normpath(abs_cleaned)
        
        # Check if normalized path starts with normalized base directory
        # This ensures the path is within the base directory
        if not norm_cleaned.startswith(norm_base + os.sep) and norm_cleaned != norm_base:
            raise ValueError(f"Absolute path {cleaned} is outside allowed base directory {base_dir}")
        
        # Path is validated - now safe to construct Path object
        path_obj = Path(norm_cleaned)
    else:
        # For relative paths, safely join with base directory using os.path.join
        # Remove leading slashes and single dots to ensure it's truly relative
        cleaned_relative = cleaned
        # Remove leading ./ or .\ patterns
        if cleaned_relative.startswith('./') or cleaned_relative.startswith('.\\'):
            cleaned_relative = cleaned_relative[2:]
        # Remove leading slashes to ensure it's relative
        cleaned_relative = cleaned_relative.lstrip('/').lstrip('\\')
        # Use os.path.join to safely construct the path
        # This ensures the path stays within the base directory
        safe_path_str = os.path.join(base_str, cleaned_relative)
        # Normalize the joined path
        abs_safe = os.path.abspath(safe_path_str)
        norm_safe = os.path.normpath(abs_safe)
        
        # Verify the normalized path is still within base directory
        if not norm_safe.startswith(norm_base + os.sep) and norm_safe != norm_base:
            raise ValueError(f"Path {cleaned} resolves outside allowed base directory {base_dir}")
        
        # Path is validated - now safe to construct Path object
        path_obj = Path(norm_safe)
    
    # Check if any part of the path is ".." - this catches traversal attempts
    if ".." in path_obj.parts:
        raise ValueError("Path contains traversal sequences (..) which are not allowed.")
    
    # Resolve to absolute path
    # codeql[py/path-injection]: path_obj is constructed from validated and normalized strings
    # that have been checked to be within the base directory and free of traversal sequences
    resolved = path_obj.resolve(strict=False)
    
    # Critical security check: ensure resolved path is within base directory
    # This prevents path traversal even if other checks are bypassed
    try:
        resolved.relative_to(base_dir)
    except ValueError:
        # Path is not relative to base_dir, meaning it escaped the safe directory
        raise ValueError(f"Path traversal detected: resolved path {resolved} is outside base directory {base_dir}")
    
    return resolved


_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str, default: str = "export") -> str:
    """Return a filesystem-safe filename."""
    if not name:
        return default
    cleaned = _SAFE_FILENAME.sub("_", name.strip())
    return cleaned or default

