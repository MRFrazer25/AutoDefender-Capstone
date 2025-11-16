"""Playbook manager for bundling recommended actions."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List

from models import Action, Threat

from utils.path_utils import sanitize_path

logger = logging.getLogger(__name__)


class PlaybookManager:
    """Load playbooks and generate suggested actions."""

    def __init__(self, playbook_path: str | None = None):
        default_path = Path("playbooks/playbooks.json")
        if playbook_path:
            try:
                default_path = sanitize_path(playbook_path)
            except ValueError as exc:
                logger.warning(f"Invalid playbook path provided: {exc}")
        self.playbook_file = default_path
        self.playbooks = self._load_playbooks()

    def _load_playbooks(self) -> list:
        if not self.playbook_file.exists():
            logger.info("Playbook file not found. Continuing without playbooks.")
            return []
        try:
            with self.playbook_file.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
                if isinstance(data, list):
                    return data
        except Exception as exc:
            logger.error(f"Failed to load playbooks: {exc}")
        return []

    def generate_actions(self, threat: Threat) -> List[Action]:
        """Return Action objects for matching playbooks."""
        matches = []
        for playbook in self.playbooks:
            if self._matches(playbook, threat):
                matches.extend(self._actions_from_playbook(playbook, threat))
        return matches

    def _matches(self, playbook: dict, threat: Threat) -> bool:
        conditions = playbook.get("conditions", {})
        severities = conditions.get("severity", [])
        keywords = [kw.lower() for kw in conditions.get("keywords", [])]
        if severities and threat.severity not in severities:
            return False
        if keywords:
            text = f"{threat.description} {threat.event_type}".lower()
            if not any(kw in text for kw in keywords):
                return False
        return True

    def _actions_from_playbook(self, playbook: dict, threat: Threat) -> List[Action]:
        steps = playbook.get("steps", [])
        actions: List[Action] = []
        for step in steps:
            action_type = step.get("type", "LOG")
            description = step.get("description", playbook.get("name", "Playbook step"))
            actions.append(
                Action(
                    threat_id=threat.id or 0,
                    action_type=action_type,
                    description=f"[{playbook.get('name','Playbook')}] {description}",
                    status="RECOMMENDED",
                    timestamp=datetime.utcnow(),
                    executed_at=None,
                )
            )
        return actions

