"""Race-safe approvals, CLI approval failures, webhook targets, data minimization, and AI backlog."""

import threading
from datetime import datetime, timezone

from approval_handler import ApprovalHandler
from config import Config
from database import Database
from models import Action, Threat
from monitor import RealTimeMonitor
from notifications.webhook import is_valid_webhook_url
from parser import minimal_event


def action_status(db, action_id):
    return next(a.status for a in db.get_actions() if a.id == action_id)


def action_description(db, action_id):
    return next(a.description for a in db.get_actions() if a.id == action_id)


def test_only_one_approval_wins(tmp_path):
    db = Database(str(tmp_path / "race.db"))
    action_id = db.add_action(Action(threat_id=1, action_type="SURICATA_DROP_RULE", description="d",
                                     status="RECOMMENDED", timestamp=datetime.now()))
    wins = []
    barrier = threading.Barrier(8)

    def approve():
        barrier.wait()
        wins.append(db.transition_action(action_id, "RECOMMENDED", "PROCESSING"))

    threads = [threading.Thread(target=approve) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert wins.count(True) == 1
    assert action_status(db, action_id) == "PROCESSING"
    db.close()


def test_descriptions_only_change_while_pending(tmp_path):
    db = Database(str(tmp_path / "d.db"))
    action_id = db.add_action(Action(threat_id=1, action_type="SURICATA_DROP_RULE", description="old",
                                     status="EXECUTED", timestamp=datetime.now()))
    db.update_action_description(action_id, "new")
    assert action_description(db, action_id) == "old"
    db.close()


def _monitor(tmp_path):
    log = tmp_path / "eve.json"
    log.write_text("")
    config = Config()
    config.db_path = str(tmp_path / "m.db")
    config.ollama_endpoint = "http://127.0.0.1:9"
    return RealTimeMonitor(str(log), config, poll_interval=0.1)


def test_cli_prompt_failure_leaves_action_pending(tmp_path, monkeypatch):
    monitor = _monitor(tmp_path)
    action = Action(threat_id=1, action_type="SURICATA_DROP_RULE", description="x",
                    status="RECOMMENDED", timestamp=datetime.now())
    action.id = monitor.database.add_action(action)
    monitor.pending_suricata_actions.append(action)

    handler = ApprovalHandler()
    handler.set_approval_callback(monitor.approve_suricata_action)
    handler.set_rejection_callback(monitor.reject_suricata_action)
    handler.skip_callback = monitor.skip_suricata_action

    def no_terminal(*args, **kwargs):
        raise EOFError("no stdin")

    monkeypatch.setattr("approval_handler.Confirm.ask", no_terminal)
    assert handler.prompt_approval(action) is False
    assert monitor.peek_pending_suricata_action() is None  # The CLI loop can move on
    assert action_status(monitor.database, action.id) == "RECOMMENDED"  # Nothing decided
    monitor.stop()


def test_ai_backlog_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr("monitor.MAX_AI_BACKLOG", 3)
    monitor = _monitor(tmp_path)
    gate = threading.Event()
    accepted = [monitor._submit_ai_task(gate.wait, 5) for _ in range(6)]
    assert accepted == [True, True, True, False, False, False]
    gate.set()
    monitor.stop()


def test_threats_still_get_explanations_when_backlog_is_full(tmp_path, monkeypatch):
    monkeypatch.setattr("monitor.MAX_AI_BACKLOG", 0)
    monitor = _monitor(tmp_path)
    monitor.running = True
    threat = Threat(timestamp=datetime.now(timezone.utc), source_ip="203.0.113.5", dest_ip="10.0.0.5",
                    dest_port=22, event_type="alert", severity="HIGH", description="Suricata Alert: ET TEST",
                    raw_event={})
    monitor._handle_threat(threat)
    stored = monitor.database.get_threat(threat.id)
    assert stored.ai_explanation  # Built-in explanation written immediately
    monitor.stop()


def test_webhook_targets():
    assert is_valid_webhook_url("https://hooks.slack.com/services/x")
    for url in ("http://hooks.slack.com/x", "https://localhost/x", "https://127.0.0.1/x", "https://10.0.0.5/x",
                "https://169.254.169.254/latest", "https://[::1]/x", "https://user:pw@hooks.slack.com/x",
                "https://printer.local/x", "javascript:alert(1)"):
        assert not is_valid_webhook_url(url), url


def test_minimal_event_drops_browsing_data():
    event = {
        "timestamp": "t", "event_type": "alert", "src_ip": "203.0.113.9", "dest_port": 80, "proto": "TCP",
        "http": {"url": "/reset?token=secret"}, "dns": {"rrname": "private.example"}, "tls": {"sni": "x"},
        "payload": "AAAA", "alert": {"signature": "ET TEST", "severity": 1, "metadata": {"x": 1}},
    }
    kept = minimal_event(event)
    assert kept == {"timestamp": "t", "event_type": "alert", "src_ip": "203.0.113.9", "dest_port": 80,
                    "proto": "TCP", "alert": {"signature": "ET TEST", "severity": 1}}
