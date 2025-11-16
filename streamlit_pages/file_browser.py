"""File browser component for selecting files and directories."""

import os
from pathlib import Path
from typing import Optional

import streamlit as st


def browse_file(
    current_path: str = "",
    file_types: Optional[list] = None,
    key_prefix: str = "browser",
) -> Optional[str]:
    """Display a file browser interface and return selected file path."""
    if file_types is None:
        file_types = [".json", ".db", ".txt", ".log"]

    # Initialize session state
    if f"{key_prefix}_current_dir" not in st.session_state:
        if current_path and Path(current_path).exists():
            if Path(current_path).is_file():
                st.session_state[f"{key_prefix}_current_dir"] = str(
                    Path(current_path).parent
                )
            else:
                st.session_state[f"{key_prefix}_current_dir"] = current_path
        else:
            st.session_state[f"{key_prefix}_current_dir"] = os.getcwd()

    current_dir = Path(st.session_state[f"{key_prefix}_current_dir"])

    st.markdown(f"**Current directory:** `{current_dir}`")

    # Navigation buttons
    nav_col1, nav_col2, nav_col3 = st.columns(3)
    with nav_col1:
        if st.button("Up", key=f"{key_prefix}_up"):
            if current_dir.parent != current_dir:
                st.session_state[f"{key_prefix}_current_dir"] = str(current_dir.parent)
                st.rerun()

    with nav_col2:
        if st.button("Home", key=f"{key_prefix}_home"):
            st.session_state[f"{key_prefix}_current_dir"] = os.path.expanduser("~")
            st.rerun()

    with nav_col3:
        if st.button("Current", key=f"{key_prefix}_current"):
            st.session_state[f"{key_prefix}_current_dir"] = os.getcwd()
            st.rerun()

    st.markdown("---")

    # List directories and files
    try:
        items = sorted(current_dir.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
    except PermissionError:
        st.error(f"Permission denied: {current_dir}")
        return None
    except Exception as e:
        st.error(f"Error reading directory: {e}")
        return None

    selected_path = None

    # Show directories first
    st.markdown("**Directories:**")
    dir_cols = st.columns(3)
    dir_idx = 0
    for item in items:
        if item.is_dir():
            col = dir_cols[dir_idx % 3]
            with col:
                if st.button(
                    f"[DIR] {item.name}",
                    key=f"{key_prefix}_dir_{item.name}",
                    use_container_width=True,
                ):
                    st.session_state[f"{key_prefix}_current_dir"] = str(item)
                    st.rerun()
            dir_idx += 1

    if dir_idx == 0:
        st.caption("No subdirectories")

    st.markdown("---")
    st.markdown("**Files:**")

    # Filter files by type if specified
    filtered_files = [
        item
        for item in items
        if item.is_file()
        and (not file_types or any(item.suffix.lower() == ft.lower() for ft in file_types))
    ]

    if not filtered_files:
        st.caption("No matching files in this directory")
    else:
        for item in filtered_files:
            file_col1, file_col2 = st.columns([4, 1])
            with file_col1:
                st.text(f"[FILE] {item.name}")
            with file_col2:
                if st.button("Select", key=f"{key_prefix}_file_{item.name}"):
                    selected_path = str(item)
                    st.session_state[f"{key_prefix}_selected"] = selected_path
                    st.success(f"Selected: {item.name}")

    # Return selected path if any
    if f"{key_prefix}_selected" in st.session_state:
        return st.session_state[f"{key_prefix}_selected"]

    return selected_path

