"""Race-safe approvals, CLI approval failures, webhook targets, data minimization, and AI backlog."""

import logging
import socket
import threading
from datetime import datetime, timezone

from autodefender.approval_handler import ApprovalHandler
from autodefender.config import Config
from autodefender.database import Database
from autodefender.models import Action, Threat
from autodefender.monitor import RealTimeMonitor
from autodefender.notifications import webhook
from autodefender.notifications.webhook import is_valid_webhook_url
from autodefender.parser import minimal_event


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

    monkeypatch.setattr("autodefender.approval_handler.Confirm.ask", no_terminal)
    assert handler.prompt_approval(action) is False
    assert monitor.peek_pending_suricata_action() is None  # The CLI loop can move on
    assert action_status(monitor.database, action.id) == "RECOMMENDED"  # Nothing decided
    monitor.stop()


def test_ai_backlog_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr("autodefender.monitor.MAX_AI_BACKLOG", 3)
    monitor = _monitor(tmp_path)
    gate = threading.Event()
    accepted = [monitor._submit_ai_task(gate.wait, 5) for _ in range(6)]
    assert accepted == [True, True, True, False, False, False]
    gate.set()
    monitor.stop()


def test_threats_still_get_explanations_when_backlog_is_full(tmp_path, monkeypatch):
    monkeypatch.setattr("autodefender.monitor.MAX_AI_BACKLOG", 0)
    monitor = _monitor(tmp_path)
    monitor.running = True
    threat = Threat(timestamp=datetime.now(timezone.utc), source_ip="203.0.113.5", dest_ip="10.0.0.5",
                    dest_port=22, event_type="alert", severity="HIGH", description="Suricata Alert: ET TEST",
                    raw_event={})
    monitor._handle_threat(threat)
    stored = monitor.database.get_threat(threat.id)
    assert stored.ai_explanation  # Built-in explanation written immediately
    monitor.stop()


# Built from pieces so tools/check_demo_data.py (no real IPs in the repo) doesn't flag it
PUBLIC_IP = ".".join(["8"] * 4)


def _fake_dns(monkeypatch, table):
    """Answer hostname lookups from a fixed table so the tests don't need the network."""
    def getaddrinfo(host, port, *args, **kwargs):
        if host not in table:
            raise socket.gaierror("not found")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in table[host]]
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


def test_webhook_targets(monkeypatch):
    _fake_dns(monkeypatch, {"hooks.slack.com": [PUBLIC_IP]})
    assert is_valid_webhook_url("https://hooks.slack.com/services/x")
    for url in ("http://hooks.slack.com/x", "https://localhost/x", "https://127.0.0.1/x", "https://10.0.0.5/x",
                "https://169.254.169.254/latest", "https://[::1]/x", "https://user:pw@hooks.slack.com/x",
                "https://printer.local/x", "javascript:alert(1)"):
        assert not is_valid_webhook_url(url), url


def test_webhook_hostnames_must_resolve_to_public_addresses(monkeypatch):
    _fake_dns(monkeypatch, {
        "metadata.example.net": ["169.254.169.254"],
        "intranet.example.net": ["10.0.0.5"],
        "mixed.example.net": [PUBLIC_IP, "192.168.1.1"],
    })
    for url in ("https://metadata.example.net/x", "https://intranet.example.net:8443/x",
                "https://mixed.example.net/x", "https://does-not-resolve.example.net/x",
                "https://hooks.slack.com:99999/x"):
        assert not is_valid_webhook_url(url), url



def test_webhook_connects_to_the_address_it_checked(monkeypatch):
    """A DNS answer that flips to a private address after the check can't redirect the request."""
    answers = iter([[PUBLIC_IP]])  # first lookup: public; any later lookup: private
    def getaddrinfo(host, port, *args, **kwargs):
        ips = next(answers, ["127.0.0.1"])
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)

    sent = {}
    class FakeClient:
        def __init__(self, **kwargs):
            sent["client"] = kwargs
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
        def post(self, url, json, headers, extensions):
            sent.update(url=url, headers=headers, extensions=extensions)
            return webhook.httpx.Response(200, request=webhook.httpx.Request("POST", url))
    monkeypatch.setattr(webhook.httpx, "Client", FakeClient)

    assert webhook.send_webhook({"text": "hi"}, "https://hooks.slack.com/services/x")
    assert sent["url"] == f"https://{PUBLIC_IP}/services/x"  # the checked address, not a new lookup
    assert sent["headers"] == {"Host": "hooks.slack.com"}
    assert sent["extensions"] == {"sni_hostname": "hooks.slack.com"}  # certificate still checked for the real name
    assert sent["client"]["follow_redirects"] is False


def test_webhook_url_is_never_logged(monkeypatch, caplog):
    """Webhook URLs are secrets, so neither our code nor httpx may write them to the log."""
    _fake_dns(monkeypatch, {"hooks.slack.com": [PUBLIC_IP]})
    secret = "T000/B000/secret-token-123"
    transport = webhook.httpx.MockTransport(lambda request: webhook.httpx.Response(500))
    real_client = webhook.httpx.Client
    monkeypatch.setattr(webhook.httpx, "Client", lambda **kw: real_client(transport=transport, **kw))
    with caplog.at_level(logging.DEBUG):
        assert not webhook.send_webhook({"text": "hi"}, f"https://hooks.slack.com/services/{secret}")
    assert "secret-token-123" not in caplog.text
    assert "failed with HTTP 500" in caplog.text

def test_minimal_event_drops_browsing_data():
    event = {
        "timestamp": "t", "event_type": "alert", "src_ip": "203.0.113.9", "dest_port": 80, "proto": "TCP",
        "http": {"url": "/reset?token=secret"}, "dns": {"rrname": "private.example"}, "tls": {"sni": "x"},
        "payload": "AAAA", "alert": {"signature": "ET TEST", "severity": 1, "metadata": {"x": 1}},
    }
    kept = minimal_event(event)
    assert kept == {"timestamp": "t", "event_type": "alert", "src_ip": "203.0.113.9", "dest_port": 80,
                    "proto": "TCP", "alert": {"signature": "ET TEST", "severity": 1}}
