"""Helpers for showing untrusted text (log data, AI output) in Streamlit."""

import re

# Characters that Streamlit's Markdown renderer treats as formatting
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$:])")


def md_escape(value) -> str:
    """Escape text so Streamlit shows it literally instead of as Markdown.

    Log fields and model output can contain links, images, or LaTeX that
    would otherwise render (and load remote images) inside the console.
    """
    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", text)
    return _MARKDOWN_SPECIAL.sub(r"\\\1", text)
