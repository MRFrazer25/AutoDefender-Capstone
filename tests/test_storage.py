"""Database, filtering, retention, exports, display escaping, and path checks."""

import json
import os
import threading
from datetime import datetime, timedelta, timezone

import pytest

from autodefender.analyzer import HistoricalAnalyzer
from autodefender.config import Config
from autodefender.database import Database
from autodefender.exporter import threats_to_csv, threats_to_json, write_export
from autodefender.filter import ThreatFilter
from autodefender.models import Action, Threat
from autodefender.utils.display import md_escape
from autodefender.utils.path_utils import sanitize_path

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_threat(ip, description, timestamp, severity="LOW"):
    return Threat(timestamp=timestamp, source_ip=ip, dest_ip=None, dest_port=None, event_type="alert",
                  severity=severity, description=description, raw_event={})


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "test.db"))
    yield database
    database.close()


def test_queries_timezones_and_date_filter(db):
    now = datetime.now(timezone.utc)
    for t in (make_threat("203.0.113.2", "new", now, "HIGH"),
              make_threat("203.0.113.3", "naive", datetime(2026, 1, 1, 9, 0))):
        db.add_threat(t)
    assert [t.description for t in db.get_threats(source_ip="203.0.113.2")] == ["new"]
    threats = db.get_threats()
    assert all(t.timestamp.tzinfo for t in threats)
    filtered = ThreatFilter().filter_threats(threats, start_time=datetime(2025, 12, 31), end_time=now)
    assert {t.description for t in filtered} == {"new", "naive"}


def test_retention_purge_removes_threats_and_actions(db):
    for t in (make_threat("203.0.113.1", "old", T0 - timedelta(days=400)),
              make_threat("203.0.113.2", "new", datetime.now(timezone.utc))):
        tid = db.add_threat(t)
        db.add_action(Action(threat_id=tid, action_type="LOG", description="d", status="RECOMMENDED",
                             timestamp=datetime.now()))
    assert db.purge_threats_older_than(300) == 1
    assert [t.description for t in db.get_threats()] == ["new"]
    assert len(db.get_actions()) == 1


def test_concurrent_writes(db):
    errors = []

    def writer(n):
        try:
            for i in range(50):
                db.add_threat(make_threat(f"10.9.{n}.{i}", "c", datetime.now(timezone.utc)))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and db.get_stats().total_threats == 400


def test_clear(db):
    db.add_threat(make_threat("203.0.113.1", "x", T0))
    db.clear(threats=True)
    assert db.get_stats().total_threats == 0


def test_exports_neutralize_formulas_and_stay_in_exports(in_tmp):
    evil = make_threat("=cmd|' /C calc'!A0", "@SUM(1+1)", T0)
    evil.id = 1
    text = threats_to_csv([evil])
    assert "\"'=cmd" in text and "\"'@SUM" in text
    assert json.loads(threats_to_json([evil]))["total_threats"] == 1
    path = write_export([evil], "../../evil name.csv", "csv")
    assert os.path.dirname(path) == os.path.join(os.path.realpath(in_tmp), "exports")


def test_markdown_escaping():
    assert md_escape("[x](http://e)![i](http://e)") == r"\[x\]\(http\://e\)\!\[i\]\(http\://e\)"


def test_count_threats_by_source(db):
    for ip, count in (("203.0.113.2", 3), ("203.0.113.3", 1)):
        for i in range(count):
            db.add_threat(make_threat(ip, f"{ip}-{i}", T0))
    counts = db.count_threats_by_source(["203.0.113.2", "203.0.113.3", "203.0.113.9"])
    assert counts == {"203.0.113.2": 3, "203.0.113.3": 1}
    assert db.count_threats_by_source([]) == {}


def test_sqlite_backup_round_trip(db, tmp_path):
    db.add_threat(make_threat("203.0.113.4", "kept", T0, "HIGH"))
    snapshot = db.backup_bytes()
    copy_path = tmp_path / "copy.db"
    copy_path.write_bytes(snapshot)
    copy = Database(str(copy_path))
    try:
        threats = copy.get_threats()
        assert [t.description for t in threats] == ["kept"]
    finally:
        copy.close()


def test_analyze_summary_ignores_older_database_rows(tmp_path):
    db_path = tmp_path / "hist.db"
    prior = Database(str(db_path))
    prior.add_threat(make_threat("203.0.113.50", "old-db-row", T0, "CRITICAL"))
    prior.close()
    config = Config()
    config.db_path = str(db_path)
    config.ollama_endpoint = "http://127.0.0.1:9"
    analyzer = HistoricalAnalyzer(config)
    try:
        summary = analyzer.get_summary([])
        assert "old-db-row" not in summary
        assert "Threats Detected: 0" in summary
        assert "Total: 0" in summary
    finally:
        analyzer.close()


def test_path_allow_list(in_tmp, tmp_path_factory, monkeypatch):
    outside = tmp_path_factory.mktemp("outside")
    with pytest.raises(ValueError):
        sanitize_path(str(outside / "x.db"))
    with pytest.raises(ValueError):
        sanitize_path("../../etc/passwd")
    assert sanitize_path("/var/log/suricata/eve.json", include_log_dirs=True)
    with pytest.raises(ValueError):
        sanitize_path("/var/log/suricata/x.db")
    monkeypatch.setenv("AUTODEFENDER_ALLOWED_DIRS", str(outside))
    assert sanitize_path(str(outside / "x.db"))
