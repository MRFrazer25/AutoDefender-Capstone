"""Live log tailing: partial lines, rotation, and storage."""

import json
import time
from datetime import datetime, timedelta, timezone

from autodefender.config import Config
from autodefender.database import Database
from autodefender.monitor import RealTimeMonitor
import autodefender.monitor as monitor_mod

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def alert_line(i):
    return json.dumps({
        "timestamp": (T0 + timedelta(seconds=i)).isoformat(), "event_type": "alert",
        "src_ip": "203.0.113.77", "dest_ip": "10.0.0.5", "dest_port": 80, "proto": "TCP",
        "alert": {"signature": f"ET TEST {i}", "category": "Test", "severity": 2},
    })


def wait_for(condition, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.1)
    return False


def test_tailing_partial_lines_and_rotation(tmp_path):
    log = tmp_path / "eve.json"
    log.write_text("")
    config = Config()
    config.db_path = str(tmp_path / "monitor.db")
    config.ollama_endpoint = "http://127.0.0.1:9"  # Nothing listens here; explanations fall back
    monitor = RealTimeMonitor(str(log), config, poll_interval=0.1, queue_suricata_approvals=False)
    monitor.start()
    try:
        with open(log, "a") as fh:
            fh.write(alert_line(1) + "\n" + alert_line(2)[:40])  # Second line half-written
        assert wait_for(lambda: monitor.events_processed == 1)
        time.sleep(0.5)
        assert monitor.events_processed == 1 and monitor.parser.error_count == 0

        with open(log, "a") as fh:
            fh.write(alert_line(2)[40:] + "\n")
        assert wait_for(lambda: monitor.events_processed == 2)

        log.write_text(alert_line(3) + "\n")  # Rotated / truncated
        assert wait_for(lambda: monitor.events_processed == 3)
    finally:
        monitor.stop()

    db = Database(config.db_path)
    try:
        assert len(db.get_threats()) == 3
    finally:
        db.close()


def test_chunked_read_processes_large_growth(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor_mod, "READ_CHUNK_SIZE", 80)
    log = tmp_path / "eve.json"
    log.write_text("")
    config = Config()
    config.db_path = str(tmp_path / "chunk.db")
    config.ollama_endpoint = "http://127.0.0.1:9"
    monitor = RealTimeMonitor(str(log), config, poll_interval=0.1, queue_suricata_approvals=False)
    monitor.start()
    try:
        payload = "".join(alert_line(i) + "\n" for i in range(10, 20))
        log.write_text(payload)
        assert wait_for(lambda: monitor.events_processed == 10)
    finally:
        monitor.stop()
