"""Utilities for sanitizing user-supplied file system paths."""

from __future__ import annotations

import os
import re
from pathlib import Path


def sanitize_path(path_str: str) -> str:
    """Normalize user-supplied path strings into safe, absolute paths.
    
    Restricts paths to be within the current working directory
    to prevent path traversal attacks. Returns a normalized string path.
    
    Args:
        path_str: User-supplied path string
        
    Returns:
        Normalized absolute path string
        
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
    
    # Use current working directory as safe base - this is trusted, not user input
    base_dir_str = os.getcwd()
    base_dir_normalized = os.path.abspath(os.path.normpath(base_dir_str))
    
    # Handle absolute paths
    if os.path.isabs(cleaned):
        expanded = os.path.expanduser(cleaned)
        abs_cleaned = os.path.abspath(expanded)
        norm_cleaned = os.path.normpath(abs_cleaned)
        
        # Ensure path is within base directory
        if not norm_cleaned.startswith(base_dir_normalized + os.sep) and norm_cleaned != base_dir_normalized:
            raise ValueError(f"Absolute path {cleaned} is outside allowed base directory {base_dir_normalized}")
        
        # Check for traversal sequences in normalized path
        if ".." in norm_cleaned:
            raise ValueError("Path contains traversal sequences (..) which are not allowed.")
        
        return norm_cleaned
    else:
        # Handle relative paths
        cleaned_relative = cleaned
        if cleaned_relative.startswith('./') or cleaned_relative.startswith('.\\'):
            cleaned_relative = cleaned_relative[2:]
        cleaned_relative = cleaned_relative.lstrip('/').lstrip('\\')
        
        # Join with base directory using os.path.join
        safe_path_str = os.path.join(base_dir_normalized, cleaned_relative)
        abs_safe = os.path.abspath(safe_path_str)
        norm_safe = os.path.normpath(abs_safe)
        
        # Ensure path is still within base directory
        if not norm_safe.startswith(base_dir_normalized + os.sep) and norm_safe != base_dir_normalized:
            raise ValueError(f"Path {cleaned} resolves outside allowed base directory {base_dir_normalized}")
        
        # Check for traversal sequences
        if ".." in norm_safe:
            raise ValueError("Path contains traversal sequences (..) which are not allowed.")
        
        return norm_safe




_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str, default: str = "export") -> str:
    """Return a filesystem-safe filename."""
    if not name:
        return default
    cleaned = _SAFE_FILENAME.sub("_", name.strip())
    return cleaned or default

