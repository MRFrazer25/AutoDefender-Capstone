"""Suricata rule safety, active blocks, unblocking, and expiry."""

from datetime import datetime, timedelta, timezone

import pytest

from autodefender.ai_explainer import AIExplainer
from autodefender.config import Config
from autodefender.ip_manager import IPManager
from autodefender.models import Threat
from autodefender.suricata_manager import SuricataManager, build_drop_rule, parse_drop_rule

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def threat(ip, description="Suricata Alert: ET SCAN test"):
    return Threat(timestamp=T0, source_ip=ip, dest_ip="10.0.0.1", dest_port=22, event_type="alert",
                  severity="HIGH", description=description, raw_event={}, id=1)


@pytest.fixture
def manager(tmp_path):
    config = Config()
    config.SURICATA_ENABLED = True
    config.SURICATA_RULES_DIR = str(tmp_path / "rules")
    config.SURICATA_DRY_RUN = False
    ips = IPManager(str(tmp_path / "ips.json"))
    ips.add_whitelist("192.0.2.7")
    return SuricataManager(config, ip_manager=ips)


@pytest.mark.parametrize("rule, expected", [
    ('drop ip 203.0.113.5 any -> any any (msg:"ok"; sid:5; rev:1;)', True),
    ('drop ip any any -> any any (msg:"203.0.113.5"; sid:5; rev:1;)', False),
    ('drop ip 198.51.100.9 any -> any any (msg:"x"; sid:1; rev:1;)', False),
    ('drop ip 203.0.113.5 any -> any any (msg:"x"; sid:1; rev:1;)\npass ip any any -> any any (msg:"y"; sid:2; rev:1;)', False),
    ('pass ip 203.0.113.5 any -> any any (msg:"x"; sid:1; rev:1;)', False),
    ('drop ip 203.0.113.5 any -> any any (msg:"x"; sid:1; rev:1; threshold: type limit;)', False),
    ('drop ip 203.0.113.0/24 any -> any any (msg:"x"; sid:1; rev:1;)', False),
])
def test_ai_rules_must_block_exactly_the_threat_ip(rule, expected):
    explainer = AIExplainer.__new__(AIExplainer)
    assert explainer._validate_ai_rule(rule, threat("203.0.113.5")) is expected


def test_fallback_rule_is_safe():
    explainer = AIExplainer.__new__(AIExplainer)
    assert explainer._fallback_suricata_rule(threat(None)) is None
    assert explainer._fallback_suricata_rule(threat("127.0.0.1")) is None
    hostile = 'x"; sid:1;)\npass ip any any -> any any (msg:"y' + "\\"
    rule = explainer._fallback_suricata_rule(threat("203.0.113.5", hostile))
    assert parse_drop_rule(rule) and "\n" not in rule


def test_unique_sids_whitelist_and_backup_pruning(manager):
    for i in range(13):
        assert manager.add_custom_rule(build_drop_rule(f"203.0.113.{100 + i}", "test"))
    sids = [b["sid"] for b in manager.list_blocks()]
    assert len(sids) == len(set(sids)) == 13
    assert not manager.add_custom_rule(build_drop_rule("192.0.2.7", "whitelisted"))
    backups = list(manager.rules_dir.glob("*.backup.*"))
    assert len(backups) <= 10


def test_same_ip_is_blocked_once(manager):
    assert manager.add_custom_rule(build_drop_rule("203.0.113.50", "a"))
    assert manager.add_custom_rule(build_drop_rule("203.0.113.50", "b"))
    assert len(manager.list_blocks()) == 1


def test_unblock_removes_only_that_rule(manager):
    manager.custom_rules_file.write_text("# operator comment\nalert ip any any -> any any (msg:\"keep\"; sid:1; rev:1;)\n")
    manager.add_custom_rule(build_drop_rule("203.0.113.60", "a"))
    manager.add_custom_rule(build_drop_rule("203.0.113.61", "b"))
    assert manager.unblock_ip("203.0.113.60")
    content = manager.custom_rules_file.read_text()
    assert "203.0.113.60" not in content and "203.0.113.61" in content
    assert "# operator comment" in content and 'msg:"keep"' in content
    assert not manager.unblock_ip("203.0.113.60")


def test_blocks_expire(manager):
    manager.config.BLOCK_DURATION_HOURS = 2
    manager.add_custom_rule(build_drop_rule("203.0.113.70", "temporary"))
    manager.config.BLOCK_DURATION_HOURS = 0
    manager.add_custom_rule(build_drop_rule("203.0.113.71", "permanent"))
    blocks = {b["ip"]: b for b in manager.list_blocks()}
    assert blocks["203.0.113.70"]["expires"] and blocks["203.0.113.71"]["expires"] is None
    assert manager.expire_blocks(datetime.now(timezone.utc) + timedelta(hours=1)) == 0
    assert manager.expire_blocks(datetime.now(timezone.utc) + timedelta(hours=3)) == 1
    assert [b["ip"] for b in manager.list_blocks()] == ["203.0.113.71"]


def test_dry_run_writes_nothing(manager):
    manager.config.SURICATA_DRY_RUN = True
    assert manager.add_custom_rule(build_drop_rule("203.0.113.80", "dry"))
    assert manager.list_blocks() == []


def test_reload_without_suricatasc(manager, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    ok, message = manager.reload_rules()
    assert not ok and "not installed" in message
