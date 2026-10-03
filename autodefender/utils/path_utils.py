"""Utilities for sanitizing user-supplied file system paths."""

from __future__ import annotations

import os
import re

# Where Suricata writes eve.json by default; log paths may point here
DEFAULT_SURICATA_LOG_DIRS = (
    "/var/log/suricata",
    r"C:\Program Files\Suricata\log",
)

# Extra folders the operator allows, separated by os.pathsep (";" on Windows, ":" elsewhere)
ALLOWED_DIRS_ENV = "AUTODEFENDER_ALLOWED_DIRS"


def allowed_base_dirs(include_log_dirs: bool = False) -> list[str]:
    """Return the folders user-supplied paths must stay inside.

    Always the current working directory, plus anything listed in
    AUTODEFENDER_ALLOWED_DIRS. Log paths may also use Suricata's default
    log folders.
    """
    dirs = [os.getcwd()]
    dirs += [d for d in os.getenv(ALLOWED_DIRS_ENV, "").split(os.pathsep) if d.strip()]
    if include_log_dirs:
        dirs += list(DEFAULT_SURICATA_LOG_DIRS)
    return [os.path.realpath(os.path.expanduser(d.strip())) for d in dirs]


def sanitize_path(path_str: str, include_log_dirs: bool = False) -> str:
    """Normalize a user-supplied path and make sure it stays inside an allowed folder.

    Relative paths are resolved against the current working directory.
    Symlinks are resolved first, so a link can't point outside the allowed
    folders.

    Args:
        path_str: User-supplied path string
        include_log_dirs: Also allow Suricata's default log folders

    Returns:
        Normalized absolute path string

    Raises:
        ValueError: If the path is empty, contains invalid characters, or is outside the allowed folders.
    """
    if path_str is None:
        raise ValueError("Path is required.")

    cleaned = path_str.strip().strip('"').strip("'")
    if not cleaned:
        raise ValueError("Path cannot be empty.")
    if "\x00" in cleaned:
        raise ValueError("Path contains invalid characters.")

    resolved = os.path.realpath(os.path.expanduser(cleaned))
    for base in allowed_base_dirs(include_log_dirs):
        if resolved == base:
            return base
        # Trailing separator so /data doesn't also allow /data-other
        if resolved.startswith(os.path.join(base, "")):
            return resolved

    raise ValueError(
        f"Path {cleaned} is outside the allowed folders. "
        f"Add its folder to {ALLOWED_DIRS_ENV} to allow it."
    )


_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_filename(name: str, default: str = "export") -> str:
    """Return a filesystem-safe filename."""
    if not name:
        return default
    cleaned = _SAFE_FILENAME.sub("_", name.strip()).lstrip(".")
    return cleaned[:100] or default
