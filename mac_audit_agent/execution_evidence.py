from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.models import ScanResult


TEMP_PATH_PREFIXES = ("/tmp", "/var/tmp", "/private/tmp", "/Users/Shared")
SYSTEM_PARENT_NAMES = {
    "launchd",
    "loginwindow",
    "bash",
    "zsh",
    "sh",
    "fish",
    "ksh",
    "python",
    "python3",
    "osascript",
}


@dataclass
class ExecutionEvidenceFinding:
    title: str
    confidence: str
    evidence_items: list[str] = field(default_factory=list)
    timeline: list[dict[str, str]] = field(default_factory=list)
    explanation: str = ""
    next_steps: list[str] = field(default_factory=list)
    indicator_types: list[str] = field(default_factory=list)
    related_process: str = ""
    related_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "confidence": self.confidence,
            "evidence_items": list(self.evidence_items),
            "timeline": [dict(item) for item in self.timeline],
            "explanation": self.explanation,
            "next_steps": list(self.next_steps),
            "indicator_types": list(self.indicator_types),
            "related_process": self.related_process,
            "related_path": self.related_path,
        }


class ExecutionEvidenceEngine:
    def analyze_scan(self, scan_result: ScanResult) -> list[ExecutionEvidenceFinding]:
        artifacts = scan_result.collected_artifacts or {}
        processes = [self._as_dict(item) for item in self._as_list(artifacts.get("processes", {}).get("all", []))]
        ports = artifacts.get("ports", {}) if isinstance(artifacts.get("ports", {}), dict) else {}
        listening_ports = [self._as_dict(item) for item in self._as_list(ports.get("listening", []))]
        active_connections = [self._as_dict(item) for item in self._as_list(ports.get("active_connections", []))]
        files = [self._as_dict(item) for item in self._as_list(artifacts.get("file_issues", []))]
        launch_items = [self._as_dict(item) for item in self._as_list(artifacts.get("launch_snapshots", []))]
        login_items = self._login_items(artifacts, scan_result.baseline_diff or {})
        baseline = scan_result.baseline_diff or {}

        process_map = {
            self._safe_int(item.get("pid")): item
            for item in processes
            if self._safe_int(item.get("pid")) is not None
        }
        findings: list[ExecutionEvidenceFinding] = []

        for process in processes:
            finding = self._process_finding(scan_result, process, process_map, listening_ports, active_connections, files, launch_items, login_items, baseline)
            if finding is not None:
                findings.append(finding)

        for item in launch_items:
            finding = self._launch_item_finding(scan_result, item, baseline)
            if finding is not None:
                findings.append(finding)

        if not findings:
            return []

        findings.sort(key=lambda item: (-self._confidence_rank(item.confidence), item.related_process.lower(), item.related_path.lower(), item.title.lower()))
        return findings

    def _process_finding(
        self,
        scan_result: ScanResult,
        process: dict[str, Any],
        process_map: dict[int, dict[str, Any]],
        listening_ports: list[dict[str, Any]],
        active_connections: list[dict[str, Any]],
        files: list[dict[str, Any]],
        launch_items: list[dict[str, Any]],
        login_items: list[str],
        baseline: dict[str, Any],
    ) -> ExecutionEvidenceFinding | None:
        pid = self._safe_int(process.get("pid"))
        ppid = self._safe_int(process.get("ppid"))
        path = str(process.get("command_path") or "")
        name = str(process.get("process_name") or Path(path).name or path)
        evidence_items: list[str] = []
        timeline: list[dict[str, str]] = []
        indicator_types: set[str] = set()
        process_found = False

        if str(process.get("signed_status", "")).lower() == "unsigned":
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "process",
                "unsigned executable",
                f"{name} at {path} is unsigned.",
            )
            indicator_types.add("process")
            process_found = True
        if self._is_temp_path(path):
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "process",
                "temporary path executable",
                f"{name} executes from a temporary path: {path}.",
            )
            indicator_types.add("process")
            process_found = True
        if self._first_seen_recently(process, baseline):
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "process",
                "first seen recently",
                f"{name} appears in recent baseline changes.",
            )
            indicator_types.add("process")
            process_found = True
        if self._unexpected_parent_child(process, process_map):
            parent = process_map.get(ppid or -1)
            parent_name = str(parent.get("process_name") or Path(str(parent.get("command_path") or "")).name) if parent else f"pid {ppid}" if ppid is not None else "unknown parent"
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "process",
                "unexpected parent-child relationship",
                f"{parent_name} -> {name} ({path})",
            )
            indicator_types.add("process")
            process_found = True

        if pid is None and not process_found:
            return None

        if self._matches_launch_item(path, launch_items):
            item = self._matched_launch_item(path, launch_items)
            if item is not None:
                self._append_indicator(
                    evidence_items,
                    timeline,
                    scan_result,
                    "persistence",
                    "LaunchAgent added",
                    f"Launch item references {path}: {item.get('path', '')}.",
                )
                indicator_types.add("persistence")
        if self._matches_login_item(name, login_items):
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "persistence",
                "login item added",
                f"Login item entry is present for {name}.",
            )
            indicator_types.add("persistence")

        network_match = self._matching_port(listening_ports, pid, name)
        if network_match is not None:
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "network",
                "new listening port",
                f"{name} is associated with a listening port: {network_match.get('local_address', '')}.",
            )
            indicator_types.add("network")

        outbound = self._matching_outbound_connection(active_connections, pid, name)
        if outbound is not None:
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "network",
                "outbound connection shortly after execution",
                f"{name} matches an outbound connection: {self._connection_summary(outbound)}.",
            )
            indicator_types.add("network")

        localhost_mismatch = self._matching_localhost_mismatch(listening_ports, artifacts=scan_result.collected_artifacts or {})
        if localhost_mismatch is not None:
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "network",
                "hidden localhost mismatch",
                localhost_mismatch,
            )
            indicator_types.add("network")

        trust_match = self._matching_low_trust(process, files)
        if trust_match is not None:
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "trust",
                "low binary trust score",
                trust_match,
            )
            indicator_types.add("trust")

        hash_change = self._matching_hash_change(path, baseline)
        if hash_change is not None:
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "trust",
                "hash changed since baseline",
                hash_change,
            )
            indicator_types.add("trust")

        if not evidence_items:
            return None

        confidence = self._score_confidence(indicator_types, evidence_items)
        explanation = self._build_explanation(confidence, evidence_items, indicator_types)
        next_steps = self._next_steps(indicator_types)
        return ExecutionEvidenceFinding(
            title=f"Unexpected execution activity observed: {name}",
            confidence=confidence,
            evidence_items=evidence_items,
            timeline=timeline,
            explanation=explanation,
            next_steps=next_steps,
            indicator_types=sorted(indicator_types),
            related_process=name,
            related_path=path,
        )

    def _launch_item_finding(self, scan_result: ScanResult, item: dict[str, Any], baseline: dict[str, Any]) -> ExecutionEvidenceFinding | None:
        path = str(item.get("path") or "")
        program = str(item.get("program") or "")
        label = str(item.get("label") or Path(path).stem or "launch item")
        if not path and not program:
            return None
        evidence_items: list[str] = []
        timeline: list[dict[str, str]] = []
        indicator_types: set[str] = {"persistence"}
        if item.get("suspicious") or path in self._baseline_new_launch_items(baseline):
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "persistence",
                "LaunchAgent or LaunchDaemon added",
                f"{label} references {program or path}.",
            )
        if item.get("program_arguments") and any(self._is_temp_path(str(arg)) for arg in item.get("program_arguments", [])):
            self._append_indicator(
                evidence_items,
                timeline,
                scan_result,
                "process",
                "temporary path executable",
                f"{label} uses a temporary path in its arguments.",
            )
            indicator_types.add("process")
        if not evidence_items:
            return None
        confidence = self._score_confidence(indicator_types, evidence_items)
        explanation = self._build_explanation(confidence, evidence_items, indicator_types)
        next_steps = self._next_steps(indicator_types)
        return ExecutionEvidenceFinding(
            title=f"Unexpected execution activity observed: {label}",
            confidence=confidence,
            evidence_items=evidence_items,
            timeline=timeline,
            explanation=explanation,
            next_steps=next_steps,
            indicator_types=sorted(indicator_types),
            related_process=label,
            related_path=path or program,
        )

    def _append_indicator(
        self,
        evidence_items: list[str],
        timeline: list[dict[str, str]],
        scan_result: ScanResult,
        category: str,
        label: str,
        detail: str,
    ) -> None:
        evidence_items.append(f"{label}: {detail}")
        timeline.append(
            {
                "timestamp": self._timeline_timestamp(scan_result, category),
                "category": category,
                "event": label,
                "details": detail,
            }
        )

    def _timeline_timestamp(self, scan_result: ScanResult, category: str) -> str:
        raw_log = next((entry for entry in reversed(scan_result.raw_logs) if self._collector_matches_category(entry.collector_name, category)), None)
        if raw_log is not None:
            return raw_log.timestamp
        return scan_result.timestamp

    def _collector_matches_category(self, collector_name: str, category: str) -> bool:
        allowed = {
            "process": {"processes"},
            "persistence": {"processes"},
            "network": {"ports", "network"},
            "trust": {"processes", "ports", "files"},
        }.get(category, set())
        return collector_name in allowed

    def _matches_launch_item(self, path: str, launch_items: list[dict[str, Any]]) -> bool:
        return self._matched_launch_item(path, launch_items) is not None

    def _matched_launch_item(self, path: str, launch_items: list[dict[str, Any]]) -> dict[str, Any] | None:
        for item in launch_items:
            candidate = str(item.get("program") or "")
            candidate_path = str(item.get("path") or "")
            arguments = [str(argument) for argument in item.get("program_arguments", []) if argument]
            if path and (path == candidate or path == candidate_path or path in arguments):
                return item
        return None

    def _matches_login_item(self, name: str, login_items: list[str]) -> bool:
        normalized = name.lower()
        return any(normalized == str(item).lower() for item in login_items)

    def _matching_port(self, listening_ports: list[dict[str, Any]], pid: int | None, name: str) -> dict[str, Any] | None:
        for item in listening_ports:
            if pid is not None and self._safe_int(item.get("pid")) == pid:
                return item
            if name and str(item.get("process_name", "")).lower() == name.lower():
                return item
        return None

    def _matching_outbound_connection(self, active_connections: list[dict[str, Any]], pid: int | None, name: str) -> dict[str, Any] | None:
        for item in active_connections:
            if pid is not None and self._safe_int(item.get("pid")) == pid:
                if self._looks_outbound(item):
                    return item
            if name and str(item.get("process_name", "")).lower() == name.lower() and self._looks_outbound(item):
                return item
        return None

    def _looks_outbound(self, item: dict[str, Any]) -> bool:
        direction = str(item.get("direction", "")).lower()
        if direction in {"outbound", "egress", "remote"}:
            return True
        remote_fields = [item.get(key) for key in ["remote_address", "remote_host", "foreign_address", "destination", "dst"]]
        remote_text = " ".join(str(value) for value in remote_fields if value)
        return bool(remote_text) and not remote_text.startswith(("127.", "localhost", "::1"))

    def _connection_summary(self, item: dict[str, Any]) -> str:
        parts = []
        for key in ["direction", "local_address", "remote_address", "remote_host", "foreign_address", "destination", "protocol", "state"]:
            value = item.get(key)
            if value:
                parts.append(f"{key}={value}")
        return ", ".join(parts) if parts else json.dumps(item, sort_keys=True)

    def _matching_localhost_mismatch(self, listening_ports: list[dict[str, Any]], *, artifacts: dict[str, Any]) -> str | None:
        localhost_scan = artifacts.get("localhost_scan", {})
        if not isinstance(localhost_scan, dict):
            return None
        missing_ports = localhost_scan.get("missing_from_enumeration", []) or []
        if not missing_ports:
            return None
        for item in listening_ports:
            port = self._safe_int(item.get("port"))
            if port is not None and port in set(self._safe_int(value) for value in missing_ports if self._safe_int(value) is not None):
                return f"localhost scan saw port {port} but process enumeration did not report it."
        return f"localhost scan reported ports missing from enumeration: {', '.join(str(item) for item in missing_ports)}."

    def _matching_low_trust(self, process: dict[str, Any], files: list[dict[str, Any]]) -> str | None:
        trust_score = self._safe_int(process.get("trust_score"))
        if trust_score is not None and trust_score <= 55:
            return f"Process trust score is {trust_score}."
        path = str(process.get("command_path") or "")
        for item in files:
            if str(item.get("path") or "") == path and self._safe_int(item.get("trust_score")) is not None and self._safe_int(item.get("trust_score")) <= 55:
                return f"Binary trust score for {path} is {item.get('trust_score')}."
        return None

    def _matching_hash_change(self, path: str, baseline: dict[str, Any]) -> str | None:
        for item in baseline.get("changed_hashes", []) or []:
            if path and path in str(item.get("item_key", "")):
                return str(item.get("details", "Hash changed since baseline."))
        return None

    def _first_seen_recently(self, process: dict[str, Any], baseline: dict[str, Any]) -> bool:
        key = str((self._safe_int(process.get("pid")), str(process.get("command_path") or "")))
        for item in baseline.get("new_suspicious_processes", []) or []:
            if key in str(item.get("item_key", "")) or str(process.get("command_path") or "") in str(item.get("details", "")):
                return True
        path = str(process.get("command_path") or "")
        for item in baseline.get("new_suspicious_files", []) or []:
            if path and path in str(item.get("item_key", "")):
                return True
        return False

    def _unexpected_parent_child(self, process: dict[str, Any], process_map: dict[int, dict[str, Any]]) -> bool:
        ppid = self._safe_int(process.get("ppid"))
        if ppid is None or ppid <= 0:
            return False
        parent = process_map.get(ppid)
        if parent is None:
            return ppid not in {0, 1}
        parent_name = str(parent.get("process_name") or Path(str(parent.get("command_path") or "")).name or "").lower()
        child_path = str(process.get("command_path") or "")
        child_signed = str(process.get("signed_status", "")).lower()
        if parent_name in SYSTEM_PARENT_NAMES and (self._is_temp_path(child_path) or child_signed == "unsigned"):
            return True
        if parent_name in {"launchd", "loginwindow"} and (self._is_temp_path(child_path) or child_signed == "unsigned"):
            return True
        return False

    def _score_confidence(self, indicator_types: set[str], evidence_items: list[str]) -> str:
        process_or_execution = "process" in indicator_types or "persistence" in indicator_types
        has_persistence = "persistence" in indicator_types
        has_network = "network" in indicator_types
        has_trust = "trust" in indicator_types
        if process_or_execution and (has_persistence or has_network or has_trust):
            return "high"
        if len(evidence_items) >= 2 or len(indicator_types) >= 2:
            return "medium"
        return "low"

    def _build_explanation(self, confidence: str, evidence_items: list[str], indicator_types: set[str]) -> str:
        parts = ["Unexpected execution activity observed.", f"Confidence: {confidence}."]
        parts.append("Evidence only; no compromise claim is being made.")
        if "persistence" in indicator_types:
            parts.append("Persistence indicators are present.")
        if "network" in indicator_types:
            parts.append("Network activity is present.")
        if "trust" in indicator_types:
            parts.append("Trust anomaly indicators are present.")
        if "process" in indicator_types:
            parts.append("Process indicators are present.")
        parts.append("Review recommended.")
        return " ".join(parts)

    def _next_steps(self, indicator_types: set[str]) -> list[str]:
        next_steps = [
            "Review the executable path, code signature, and owning package.",
            "Check whether the parent process and startup item are expected for this Mac.",
            "Compare the path and hash against baseline or known-good inventory.",
        ]
        if "network" in indicator_types:
            next_steps.append("Check whether the related port or connection is expected for the current workload.")
        if "persistence" in indicator_types:
            next_steps.append("Review any added LaunchAgents, LaunchDaemons, or login items for legitimacy.")
        return next_steps

    def _baseline_new_launch_items(self, baseline: dict[str, Any]) -> set[str]:
        return {str(item.get("item_key", "")) for item in baseline.get("new_launch_items", []) or []}

    def _login_items(self, artifacts: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
        items: list[str] = []
        for candidate in [
            artifacts.get("login_items", []),
            artifacts.get("persistence", {}).get("login_items", []) if isinstance(artifacts.get("persistence", {}), dict) else [],
            baseline.get("new_login_items", []),
        ]:
            if isinstance(candidate, list):
                for item in candidate:
                    if isinstance(item, dict):
                        value = item.get("name") or item.get("label") or item.get("item_key") or item.get("title")
                        if value:
                            items.append(str(value))
                    elif item:
                        items.append(str(item))
        return sorted(set(items))

    def _is_temp_path(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in TEMP_PATH_PREFIXES)

    def _as_list(self, value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        if value is None:
            return []
        return [value]

    def _as_dict(self, value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return dict(value)
        if hasattr(value, "to_dict"):
            candidate = value.to_dict()
            if isinstance(candidate, dict):
                return dict(candidate)
        return dict(getattr(value, "__dict__", {}))

    def _safe_int(self, value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _confidence_rank(self, confidence: str) -> int:
        return {"high": 2, "medium": 1, "low": 0}.get(confidence, 0)
