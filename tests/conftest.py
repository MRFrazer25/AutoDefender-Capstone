"""Shared test setup."""

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.disable(logging.CRITICAL)


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Keep the audit log and env settings out of the real project files."""
    monkeypatch.setenv("AUTODEFENDER_AUDIT_DB", str(tmp_path / "audit.db"))
    for name in ("AUTODEFENDER_UI_PASSWORD", "AUTODEFENDER_DEV", "AUTODEFENDER_ALLOWED_DIRS",
                 "AUTODEFENDER_GEOIP_CITY_DB", "AUTODEFENDER_GEOIP_ASN_DB"):
        monkeypatch.delenv(name, raising=False)
    yield


@pytest.fixture
def in_tmp(tmp_path, monkeypatch):
    """Run the test with the temporary directory as the working directory."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def in_repo(monkeypatch):
    """Run the test from the repository root (for pages that use demo/ paths)."""
    monkeypatch.chdir(ROOT)
    return ROOT
