from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from mac_audit_agent.analyzers import parse_launchd_plist
from mac_audit_agent.models import BackgroundMonitorEvent, LaunchItemSnapshot, utc_now_iso
from mac_audit_agent.rules import correlation_id_for, evidence_hash, normalized_signal, rule_for_event


PERSISTENCE_DIRECTORIES = (
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
)

LOGIN_ITEM_SCRIPT = 'tell application "System Events" to get the name of every login item'


def _run_command(command: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.returncode, result.stdout, result.stderr
    except Exception as exc:  # pragma: no cover - environment specific
        return 1, "", str(exc)


@dataclass
class PersistenceSnapshot:
    timestamp: str = field(default_factory=utc_now_iso)
    launch_items: list[LaunchItemSnapshot] = field(default_factory=list)
    login_items: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "launch_items": [item.to_dict() for item in self.launch_items],
            "login_items": list(self.login_items),
        }


class PersistenceMonitor:
    def __init__(self, executor=_run_command) -> None:
        self.executor = executor

    def collect_snapshot(self) -> PersistenceSnapshot:
        launch_items = self._collect_launch_items()
        login_items = self._collect_login_items()
        return PersistenceSnapshot(
            launch_items=sorted(launch_items, key=lambda item: item.path),
            login_items=sorted(set(login_items)),
        )

    def evaluate(self, previous: PersistenceSnapshot | None, current: PersistenceSnapshot) -> list[BackgroundMonitorEvent]:
        if previous is None:
            return []
        previous_launch = {item.path: item for item in previous.launch_items}
        current_launch = {item.path: item for item in current.launch_items}
        previous_login = set(previous.login_items)
        current_login = set(current.login_items)

        events: list[BackgroundMonitorEvent] = []
        new_launch_items = [item for path, item in current_launch.items() if path not in previous_launch]
        new_login_items = sorted(current_login - previous_login)

        new_daemons = [item for item in new_launch_items if item.path.startswith("/Library/LaunchDaemons")]
        new_agents = [item for item in new_launch_items if "LaunchAgents" in item.path]
        if new_daemons:
            events.append(self._launch_event("launchdaemon_added", "critical", new_daemons, current.timestamp))
        if new_agents:
            events.append(self._launch_event("launchagent_added", "high", new_agents, current.timestamp))
        if new_login_items:
            events.append(self._login_event("persistence_item_created_high_risk", "critical", new_login_items, current.timestamp))
        return events

    def summarize_inventory(self, snapshot: PersistenceSnapshot) -> dict[str, object]:
        launch_items = snapshot.launch_items
        return {
            "launch_daemons": [item.to_dict() for item in launch_items if item.path.startswith("/Library/LaunchDaemons")],
            "launch_agents": [item.to_dict() for item in launch_items if "LaunchAgents" in item.path],
            "login_items": list(snapshot.login_items),
        }

    def _collect_launch_items(self) -> list[LaunchItemSnapshot]:
        snapshots: list[LaunchItemSnapshot] = []
        for root in PERSISTENCE_DIRECTORIES:
            base = Path(root).expanduser()
            if not base.exists():
                continue
            for path in sorted(base.glob("*.plist"))[:200]:
                if not path.is_file() or not os.access(path, os.R_OK):
                    continue
                try:
                    snapshots.append(parse_launchd_plist(path.read_bytes(), str(path)))
                except Exception:
                    continue
        return snapshots

    def _collect_login_items(self) -> list[str]:
        code, stdout, _stderr = self.executor(["/usr/bin/osascript", "-e", LOGIN_ITEM_SCRIPT])
        if code != 0:
            return []
        items: list[str] = []
        for token in re.split(r"[\n,]", stdout):
            cleaned = token.strip().strip('"').strip("'")
            if cleaned:
                items.append(cleaned)
        return items

    def _launch_event(self, event_type: str, severity: str, items: list[LaunchItemSnapshot], timestamp: str) -> BackgroundMonitorEvent:
        summary = self._summarize_launch_items(items)
        evidence = f"New persistence items added: {summary}."
        rule = rule_for_event(event_type)
        metadata = {
            "items": [item.to_dict() for item in items],
            "summary": summary,
            "category": event_type,
        }
        primary_path = items[0].path if items else ""
        return BackgroundMonitorEvent(
            event_id=f"{event_type}-{timestamp}-{self._fingerprint(summary)}",
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source="persistence_observer",
            evidence=evidence,
            confidence="high",
            recommendation="Review the owner, path, and purpose of the new persistence item before allowing it to remain installed.",
            metadata_json=json.dumps(metadata, sort_keys=True),
            rule_id=rule.rule_id,
            rule_name=rule.name,
            trigger_source="launchd_detector",
            trigger_subsource="launchdaemon_snapshot" if event_type == "launchdaemon_added" else "launchagent_snapshot",
            trigger_rule_id=rule.rule_id,
            trigger_rule_name=rule.name,
            raw_signal_summary=summary,
            normalized_signal=normalized_signal(event_type, summary, primary_path),
            evidence_hash=evidence_hash(event_type, summary, primary_path),
            related_path=primary_path,
            first_seen=timestamp,
            last_seen=timestamp,
            previous_state="persistence item absent",
            current_state=f"persistence item present: {summary}",
            baseline_status="new persistence",
            correlation_id=correlation_id_for(event_type, summary, primary_path, timestamp=timestamp),
            false_positive_hints=list(rule.false_positive_hints),
            recommended_verification_steps=list(rule.verification_steps),
            source_trace=f"Detector={rule.source_detector}; Rule={rule.rule_id}; Summary={summary}",
        )

    def _login_event(self, event_type: str, severity: str, items: list[str], timestamp: str) -> BackgroundMonitorEvent:
        summary = self._summarize_names(items)
        evidence = f"New login items added: {summary}."
        rule = rule_for_event(event_type)
        metadata = {
            "items": list(items),
            "summary": summary,
            "category": event_type,
        }
        return BackgroundMonitorEvent(
            event_id=f"{event_type}-{timestamp}-{self._fingerprint(summary)}",
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source="persistence_observer",
            evidence=evidence,
            confidence="high",
            recommendation="Review the new login item and confirm it is expected for the current user and workstation.",
            metadata_json=json.dumps(metadata, sort_keys=True),
            rule_id=rule.rule_id,
            rule_name=rule.name,
            trigger_source="launchd_detector",
            trigger_subsource="login_item_snapshot",
            trigger_rule_id=rule.rule_id,
            trigger_rule_name=rule.name,
            raw_signal_summary=summary,
            normalized_signal=normalized_signal(event_type, summary, ",".join(items)),
            evidence_hash=evidence_hash(event_type, summary, items),
            first_seen=timestamp,
            last_seen=timestamp,
            previous_state="login item absent",
            current_state=f"login item present: {summary}",
            baseline_status="new persistence",
            correlation_id=correlation_id_for(event_type, summary, timestamp=timestamp),
            false_positive_hints=list(rule.false_positive_hints),
            recommended_verification_steps=list(rule.verification_steps),
            source_trace=f"Detector={rule.source_detector}; Rule={rule.rule_id}; Summary={summary}",
        )

    def _summarize_launch_items(self, items: list[LaunchItemSnapshot]) -> str:
        labels = [f"{item.label} ({Path(item.path).name})" for item in items]
        return self._summarize_names(labels)

    def _summarize_names(self, items: list[str]) -> str:
        if not items:
            return "none"
        visible = items[:4]
        summary = "; ".join(visible)
        if len(items) > len(visible):
            summary += f"; and {len(items) - len(visible)} more"
        return summary

    def _fingerprint(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
