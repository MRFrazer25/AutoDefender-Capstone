"""Web console: sign-in, every page, monitoring, and approvals (Streamlit AppTest)."""

import hashlib
import shutil
import time
from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

import audit

APP_TIMEOUT = 60


@pytest.fixture
def app_env(in_repo, tmp_path, monkeypatch):
    """Run from the repo with a scratch copy of the demo database."""
    st.cache_resource.clear()  # Fresh login counters and monitor registry
    db_copy = tmp_path / "demo_copy.db"
    shutil.copyfile(in_repo / "demo" / "demo_config.db", db_copy)
    monkeypatch.setenv("AUTODEFENDER_ALLOWED_DIRS", str(tmp_path))
    monkeypatch.setenv("AUTODEFENDER_UI_PASSWORD", "test-password-for-apptest")
    return {"db": str(db_copy), "repo": in_repo}


def new_app(state=None):
    at = AppTest.from_file(str(Path(audit.__file__).with_name("streamlit_app.py")), default_timeout=APP_TIMEOUT)
    for key, value in (state or {}).items():
        at.session_state[key] = value
    return at


def signed_in_app(env, page="Setup", **extra):
    """Sign in through the real login form, then open `page` with the demo settings."""
    at = new_app().run()
    at.text_input[0].input("test-password-for-apptest")
    at.button[0].click().run()
    assert at.session_state["authenticated"], errors(at)
    state = {
        "setup_complete": True, "db_path": env["db"], "log_path": "demo/example_suricata_log.json",
        "suricata_enabled": True, "suricata_dry_run": True, "suricata_rules_dir": "./suricata_rules",
        "navigation": page,
    }
    state.update(extra)
    for key, value in state.items():
        at.session_state[key] = value
    return at.run()


def errors(at):
    return [e.value for e in at.error] + [str(x.value)[:300] for x in at.exception]


def nav_pages(at):
    return list(at.sidebar.radio[0].options) if at.sidebar.radio else []


def test_refuses_to_run_without_credentials(app_env, monkeypatch):
    monkeypatch.delenv("AUTODEFENDER_UI_PASSWORD")
    at = new_app().run()
    assert any("Refusing to run" in e.value for e in at.error)


def test_short_shared_password_refused(app_env, monkeypatch):
    monkeypatch.setenv("AUTODEFENDER_UI_PASSWORD", "short")
    at = new_app().run()
    assert any("at least 12" in e.value for e in at.error)


def test_dev_mode_on_localhost(app_env, monkeypatch):
    monkeypatch.delenv("AUTODEFENDER_UI_PASSWORD")
    monkeypatch.setenv("AUTODEFENDER_DEV", "1")
    at = new_app().run()
    assert not at.error and "Audit Log" in nav_pages(at)
    assert not any(b.label == "Sign out" for b in at.sidebar.button)


def test_shared_password_sign_in_and_idle_timeout(app_env):
    at = new_app().run()
    assert len(at.text_input) == 1 and not at.sidebar.radio  # Password only, no username
    at.text_input[0].input("wrong-password")
    at.button[0].click().run()
    assert any("Password incorrect" in e.value for e in at.error)
    at.text_input[0].input("test-password-for-apptest")
    at.button[0].click().run()
    assert at.session_state["authenticated"] and nav_pages(at)

    at.session_state["last_activity"] = time.time() - 31 * 60
    at.run()
    assert not at.sidebar.radio and any("inactivity" in i.value for i in at.info)
    actions = [e["action"] for e in audit.entries()]
    assert {"sign_in_failed", "sign_in", "session_timeout"} <= set(actions)


def test_lockout_after_five_failures(app_env):
    at = new_app().run()
    for _ in range(5):
        at.text_input[0].input("not-the-password")
        at.button[0].click().run()
    at.text_input[0].input("test-password-for-apptest")
    at.button[0].click().run()
    assert any("Too many failed attempts" in e.value for e in at.error)
    assert not at.sidebar.radio
    assert "sign_in_locked" in {e["action"] for e in audit.entries()}


def test_lockout_survives_restart(app_env):
    at = new_app().run()
    for _ in range(5):
        at.text_input[0].input("not-the-password")
        at.button[0].click().run()
    st.cache_resource.clear()  # Same as restarting the server: in-memory counters are gone
    at = new_app().run()
    at.text_input[0].input("test-password-for-apptest")
    at.button[0].click().run()
    assert any("Too many failed attempts" in e.value for e in at.error)


def test_example_password_is_refused(app_env, monkeypatch):
    monkeypatch.setenv("AUTODEFENDER_UI_PASSWORD", "replace-with-a-long-random-password")
    at = new_app().run()
    assert any("example value" in e.value for e in at.error)


def test_password_change_signs_out(app_env, monkeypatch):
    at = new_app().run()
    at.text_input[0].input("test-password-for-apptest")
    at.button[0].click().run()
    assert nav_pages(at)
    monkeypatch.setenv("AUTODEFENDER_UI_PASSWORD", "a-brand-new-password-123")
    at.run()
    assert not at.sidebar.radio and any("password changed" in i.value for i in at.info)


@pytest.mark.parametrize("page", ["Setup", "Dashboard", "Incidents", "Threat Analysis", "Action Management",
                                  "IP Management", "Playbook Editor", "Settings", "Audit Log", "Documentation"])
def test_every_page_renders(app_env, page):
    at = signed_in_app(app_env, page)
    assert not at.exception and not at.error, errors(at)


def test_dashboard_runs_real_monitoring(app_env):
    at = signed_in_app(app_env, "Dashboard")
    next(c for c in at.checkbox if "existing entries" in c.label).check()
    next(c for c in at.checkbox if c.label == "Auto-refresh").uncheck()
    next(b for b in at.button if b.label == "Start monitoring").click().run()
    deadline = time.time() + 15
    status = []
    while time.time() < deadline:
        at.run()
        status = [s.value for s in at.success if "events processed" in s.value]
        if status and "91 events processed" in status[0]:
            break
        time.sleep(0.5)
    assert status and "91 events processed" in status[0], status or errors(at)
    next(b for b in at.button if b.label == "Stop monitoring").click().run()
    assert any("Monitoring is stopped" in i.value for i in at.info)
    assert {"monitoring_started", "monitoring_stopped"} <= {e["action"] for e in audit.entries()}


def test_approving_a_rule_is_audited_and_demo_db_untouched(app_env):
    demo = app_env["repo"] / "demo" / "demo_config.db"
    before = hashlib.sha256(demo.read_bytes()).hexdigest()
    at = signed_in_app(app_env, "Action Management")
    approve = [b for b in at.button if b.label == "Approve"]
    approve[0].click().run()
    assert not at.exception, errors(at)
    assert len([b for b in at.button if b.label == "Approve"]) == len(approve) - 1
    assert "action_approved" in {e["action"] for e in audit.entries()}
    assert audit.verify() == (True, None)
    assert hashlib.sha256(demo.read_bytes()).hexdigest() == before
