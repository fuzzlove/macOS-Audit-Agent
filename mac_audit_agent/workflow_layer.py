from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from mac_audit_agent.models import (
    BackgroundMonitorEvent,
    BaselineComparison,
    Finding,
    InvestigationAuditEntry,
    ScanResult,
    ScanSummary,
)
from mac_audit_agent.storage import AuditDatabase


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}


@dataclass
class WorkflowReplayMoment:
    timestamp: str
    moment_type: str
    scan_id: str = ""
    title: str = ""
    summary: str = ""
    details: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "moment_type": self.moment_type,
            "scan_id": self.scan_id,
            "title": self.title,
            "summary": self.summary,
            "details": list(self.details),
            "evidence": list(self.evidence),
        }


@dataclass
class WorkflowReviewItem:
    finding_id: str
    title: str
    severity: str
    confidence: str
    review_state: str
    priority_score: int
    suppressed: bool
    suppression_reason: str
    explanation: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "review_state": self.review_state,
            "priority_score": self.priority_score,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "explanation": dict(self.explanation),
        }


@dataclass
class WorkflowContextMoment:
    timestamp: str
    moment_type: str
    category: str
    title: str
    summary: str
    source: str = ""
    severity: str = ""
    evidence: list[str] = field(default_factory=list)
    focus: bool = False
    related_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "moment_type": self.moment_type,
            "category": self.category,
            "title": self.title,
            "summary": self.summary,
            "source": self.source,
            "severity": self.severity,
            "evidence": list(self.evidence),
            "focus": self.focus,
            "related_id": self.related_id,
        }


@dataclass
class WorkflowContextWindow:
    anchor_timestamp: str
    window_start: str
    window_end: str
    focus_label: str
    focus_kind: str
    focus_id: str
    moments: list[WorkflowContextMoment] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor_timestamp": self.anchor_timestamp,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "focus_label": self.focus_label,
            "focus_kind": self.focus_kind,
            "focus_id": self.focus_id,
            "moments": [moment.to_dict() for moment in self.moments],
        }


class InvestigatorWorkflowLayer:
    def __init__(self, db: AuditDatabase) -> None:
        self.db = db

    def build_bundle(self, scan_id: str | None = None, *, scan_limit: int = 12, monitor_limit: int = 40) -> dict[str, Any]:
        target_scan = scan_id or self._latest_scan_id()
        return {
            "replay": self.build_security_replay(limit=scan_limit, focus_scan_id=target_scan),
            "review_queue": [item.to_dict() for item in self.build_review_queue(scan_id=target_scan)],
            "explanations": self.explain_scan(target_scan) if target_scan else [],
        }

    def build_security_replay(self, *, limit: int = 12, focus_scan_id: str | None = None) -> list[WorkflowReplayMoment]:
        moments: list[WorkflowReplayMoment] = []
        summaries = list(reversed(self.db.list_scan_summaries(limit=limit)))
        previous_scan_id: str | None = None
        for summary in summaries:
            scan = self.db.get_scan_result(summary.scan_id)
            if scan is None:
                continue
            comparison = self.db.compare_to_previous_scan(summary.scan_id)
            moments.append(self._scan_moment(summary, scan, comparison, is_focus=summary.scan_id == focus_scan_id))
            previous_scan_id = summary.scan_id
        if focus_scan_id:
            moments.extend(self._monitor_moments())
        return moments

    def build_review_queue(self, *, scan_id: str | None = None) -> list[WorkflowReviewItem]:
        scan = self._current_scan(scan_id)
        if scan is None:
            return []
        statuses = self.db.get_review_statuses(scan.scan_id)
        queue: list[WorkflowReviewItem] = []
        for finding in scan.findings:
            status = statuses.get(("finding", finding.id)) or statuses.get(("finding", getattr(finding, "finding_id", "")))
            explanation = self.explain_finding(finding, scan=scan)
            suppression = self.db.find_suppression_rule(finding)
            suppressed = bool(suppression and suppression.active)
            review_state = status.review_state if status else "not reviewed"
            priority_score = self._priority_score(finding, review_state, suppressed)
            queue.append(
                WorkflowReviewItem(
                    finding_id=finding.id,
                    title=finding.title,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    review_state=review_state,
                    priority_score=priority_score,
                    suppressed=suppressed,
                    suppression_reason=suppression.rationale if suppression else "",
                    explanation=explanation,
                )
            )
        queue.sort(key=lambda item: (-item.priority_score, -SEVERITY_RANK.get(item.severity, 0), -CONFIDENCE_RANK.get(item.confidence, 0), item.title.lower()))
        return queue

    def explain_scan(self, scan_id: str | None) -> list[dict[str, str]]:
        scan = self._current_scan(scan_id)
        if scan is None:
            return []
        return [self.explain_finding(finding, scan=scan) for finding in scan.findings]

    def explain_finding(self, finding: Finding, *, scan: ScanResult | None = None) -> dict[str, str]:
        what_happened = finding.description.strip() or finding.title.strip()
        supporting_evidence = finding.evidence_summary.strip() or finding.evidence.strip()
        why_it_matters = finding.why_this_matters.strip() or finding.business_impact.strip() or "This item is worth review because it changed the security posture or configuration."
        next_action = finding.recommended_next_steps.strip() or finding.remediation_suggestion.strip() or "Review the item in context and decide whether it is expected."
        confidence = finding.confidence
        explanation = {
            "what_happened": what_happened,
            "why_it_matters": why_it_matters,
            "confidence": confidence,
            "supporting_evidence": supporting_evidence,
            "next_action": next_action,
        }
        if scan is not None and scan.baseline_diff:
            explanation["context"] = self._baseline_context(scan.baseline_diff)
        return explanation

    def build_context_window(
        self,
        anchor_timestamp: str,
        *,
        focus_label: str = "",
        focus_kind: str = "",
        focus_category: str = "",
        focus_id: str = "",
        focus_scan_id: str = "",
        focus_event_id: str = "",
        window_minutes: int = 15,
    ) -> WorkflowContextWindow:
        anchor = self._parse_timestamp(anchor_timestamp)
        window_start = anchor - timedelta(minutes=window_minutes)
        window_end = anchor + timedelta(minutes=window_minutes)
        start_text = self._format_timestamp(window_start)
        end_text = self._format_timestamp(window_end)
        moments: list[WorkflowContextMoment] = []

        for summary in self.db.list_scan_summaries_between(start_text, end_text):
            scan = self.db.get_scan_result(summary.scan_id)
            comparison = self.db.compare_to_previous_scan(summary.scan_id)
            moments.append(
                self._scan_context_moment(
                    summary,
                    scan,
                    comparison,
                    anchor=anchor,
                    focus_scan_id=focus_scan_id,
                )
            )

        for event in self.db.background_monitor_events_between(start_text, end_text):
            moments.append(
                self._monitor_context_moment(
                    event,
                    anchor=anchor,
                    focus_event_id=focus_event_id,
                )
            )

        for entry in self.db.investigation_audit_trail_between(start_text, end_text):
            moments.append(self._audit_context_moment(entry))

        if focus_label:
            moments.append(
                WorkflowContextMoment(
                    timestamp=self._format_timestamp(anchor),
                    moment_type="focus",
                    category=self._context_category_for_focus(focus_kind, focus_category),
                    title=focus_label,
                    summary=f"Selected {focus_kind or 'item'} for context review.",
                    source="workflow_layer",
                    focus=True,
                    related_id=focus_id or focus_scan_id or focus_event_id,
                )
            )

        moments.sort(key=lambda item: (self._parse_timestamp(item.timestamp), 0 if item.focus else 1, item.title.lower()))
        return WorkflowContextWindow(
            anchor_timestamp=self._format_timestamp(anchor),
            window_start=start_text,
            window_end=end_text,
            focus_label=focus_label,
            focus_kind=focus_kind,
            focus_id=focus_id,
            moments=moments,
        )

    def mark_benign(self, scan_id: str, finding_id: str, *, notes: str = "") -> None:
        finding = self.db.get_finding_by_id(finding_id)
        if finding is None:
            return
        self.db.set_review_status(
            item_type="finding",
            item_key=finding_id,
            label=finding.title,
            review_state="false positive",
            linked_scan_id=scan_id,
            linked_finding_id=finding_id,
            notes=notes or "Marked benign in workflow layer.",
        )

    def mark_resolved(self, scan_id: str, finding_id: str, *, notes: str = "") -> None:
        finding = self.db.get_finding_by_id(finding_id)
        if finding is None:
            return
        self.db.set_review_status(
            item_type="finding",
            item_key=finding_id,
            label=finding.title,
            review_state="resolved",
            linked_scan_id=scan_id,
            linked_finding_id=finding_id,
            notes=notes or "Marked resolved in workflow layer.",
        )

    def _current_scan(self, scan_id: str | None) -> ScanResult | None:
        if scan_id:
            return self.db.get_scan_result(scan_id)
        return self.db.latest_scan_result()

    def _latest_scan_id(self) -> str:
        latest = self.db.latest_scan()
        return str(latest["scan_id"]) if latest else ""

    def _priority_score(self, finding: Finding, review_state: str, suppressed: bool) -> int:
        score = SEVERITY_RANK.get(finding.severity, 0) * 10 + CONFIDENCE_RANK.get(finding.confidence, 0) * 3
        if review_state == "not reviewed":
            score += 4
        elif review_state == "needs follow-up":
            score += 2
        elif review_state in {"false positive", "resolved"}:
            score -= 6
        if suppressed:
            score -= 8
        if finding.kev:
            score += 5
        if finding.epss_score is not None and finding.epss_score >= 0.6:
            score += 3
        return score

    def _scan_moment(
        self,
        summary: ScanSummary,
        scan: ScanResult,
        comparison: BaselineComparison,
        *,
        is_focus: bool = False,
    ) -> WorkflowReplayMoment:
        details = [
            f"Findings: {summary.findings_count}",
            f"Security score: {summary.security_score if summary.security_score is not None else 'unavailable'}",
            f"New items: {summary.new_items_count}",
            f"Score label: {summary.score_label or 'n/a'}",
        ]
        if comparison.total_changes():
            details.append(f"Baseline changes: {comparison.total_changes()} total")
            details.append(f"Replay summary: {comparison.drift_summary or 'changes detected'}")
        evidence = [finding.evidence_summary or finding.evidence for finding in scan.findings[:3]]
        title = "Current scan" if is_focus else "Previous scan"
        if comparison.total_changes():
            title = "Scan replay" if is_focus else "History point"
        return WorkflowReplayMoment(
            timestamp=summary.completed_at,
            moment_type="scan",
            scan_id=summary.scan_id,
            title=title,
            summary=summary.notes or comparison.drift_summary or "Scan completed.",
            details=details,
            evidence=[item for item in evidence if item],
        )

    def _monitor_moments(self) -> list[WorkflowReplayMoment]:
        events = self.db.recent_background_monitor_events(limit=40)
        moments: list[WorkflowReplayMoment] = []
        for event in reversed(events):
            moments.append(
                WorkflowReplayMoment(
                    timestamp=event.timestamp,
                    moment_type="monitor",
                    scan_id="",
                    title=event.event_type,
                    summary=event.evidence,
                    details=[
                        f"Severity: {event.severity}",
                        f"Confidence: {event.confidence}",
                        f"Source: {event.source}",
                    ],
                    evidence=[event.evidence],
                )
            )
        return moments

    def _baseline_context(self, baseline_diff: dict[str, Any]) -> str:
        change_count = sum(len(value) for value in baseline_diff.values() if isinstance(value, list))
        drift_score = baseline_diff.get("drift_score", 0)
        drift_label = baseline_diff.get("drift_label", "stable")
        return f"Baseline context: {change_count} changes, drift score {drift_score}/100, {drift_label}."

    def _scan_context_moment(
        self,
        summary: ScanSummary,
        scan: ScanResult | None,
        comparison: BaselineComparison,
        *,
        anchor: datetime,
        focus_scan_id: str,
    ) -> WorkflowContextMoment:
        details = [
            f"Findings: {summary.findings_count}",
            f"Security score: {summary.security_score if summary.security_score is not None else 'unavailable'}",
            f"New items: {summary.new_items_count}",
            f"Score label: {summary.score_label or 'n/a'}",
        ]
        baseline_bits = self._baseline_context_bits(comparison)
        if baseline_bits:
            details.extend(baseline_bits)
        evidence: list[str] = [summary.notes] if summary.notes else []
        if scan is not None:
            evidence.extend(
                item.evidence_summary or item.evidence
                for item in scan.findings[:3]
                if item.evidence_summary or item.evidence
            )
            if scan.baseline_diff:
                evidence.append(self._baseline_context(scan.baseline_diff))
        return WorkflowContextMoment(
            timestamp=summary.completed_at,
            moment_type="scan",
            category="scan",
            title="Current scan" if summary.scan_id == focus_scan_id else "Scan point",
            summary=summary.notes or comparison.drift_summary or "Scan completed.",
            source="scan_history",
            severity="info",
            evidence=[item for item in evidence if item],
            focus=summary.scan_id == focus_scan_id or abs((self._parse_timestamp(summary.completed_at) - anchor).total_seconds()) < 1,
            related_id=summary.scan_id,
        )

    def _monitor_context_moment(
        self,
        event: BackgroundMonitorEvent,
        *,
        anchor: datetime,
        focus_event_id: str,
    ) -> WorkflowContextMoment:
        category = self._monitor_category(event.event_type)
        summary = event.evidence.strip() or event.recommendation.strip() or event.event_type
        evidence: list[str] = [event.evidence] if event.evidence else []
        if event.recommendation:
            evidence.append(event.recommendation)
        return WorkflowContextMoment(
            timestamp=event.timestamp,
            moment_type="monitor",
            category=category,
            title=event.event_type,
            summary=summary,
            source=event.source,
            severity=event.severity,
            evidence=[item for item in evidence if item],
            focus=event.event_id == focus_event_id or abs((self._parse_timestamp(event.timestamp) - anchor).total_seconds()) < 1,
            related_id=event.event_id,
        )

    def _audit_context_moment(self, entry: InvestigationAuditEntry) -> WorkflowContextMoment:
        evidence = [entry.details] if entry.details else []
        if entry.previous_status or entry.new_status:
            evidence.append(f"{entry.previous_status or 'none'} -> {entry.new_status or 'none'}")
        return WorkflowContextMoment(
            timestamp=entry.timestamp,
            moment_type="audit",
            category="admin",
            title=f"{entry.entity_type}: {entry.action_type}",
            summary=entry.details or "Investigation state changed.",
            source="investigation_audit_trail",
            severity="info",
            evidence=[item for item in evidence if item],
            related_id=entry.entity_id,
        )

    def _baseline_context_bits(self, comparison: BaselineComparison) -> list[str]:
        bits: list[str] = []
        if comparison.new_admin_users:
            bits.append(f"New admin users: {', '.join(item.item_key for item in comparison.new_admin_users[:4])}")
        if comparison.new_launch_items:
            bits.append(f"New launch items: {', '.join(item.item_key for item in comparison.new_launch_items[:4])}")
        if comparison.changed_permissions:
            bits.append(f"Permission changes: {len(comparison.changed_permissions)}")
        if comparison.new_history_indicators:
            bits.append(f"New history indicators: {len(comparison.new_history_indicators)}")
        if comparison.drift_summary:
            bits.append(f"Drift summary: {comparison.drift_summary}")
        return bits

    def _monitor_category(self, event_type: str) -> str:
        if event_type in {"launchdaemon_added", "launchagent_added", "persistence_item_created", "persistence_item_created_high_risk"}:
            return "persistence"
        if event_type in {"network_ip_assigned", "vpn_connected"}:
            return "network"
        if event_type in {"usb_device_connected", "new_usb_device_detected"}:
            return "usb"
        if event_type in {
            "screen_locked",
            "screen_unlocked",
            "session_locked",
            "session_unlocked",
            "display_sleep",
            "display_wake",
            "system_sleep",
            "system_wake",
            "possible_lid_closed",
            "possible_lid_opened",
            "clamshell_state_changed",
            "input_activity_resumed_after_idle",
        }:
            return "session"
        if event_type == "new_admin_user_detected":
            return "admin"
        return "monitor"

    def _context_category_for_focus(self, focus_kind: str, focus_category: str) -> str:
        if focus_category:
            return focus_category
        if focus_kind == "finding":
            return "finding"
        if focus_kind == "monitor":
            return "monitor"
        if focus_kind == "scan":
            return "scan"
        return "focus"

    def _parse_timestamp(self, timestamp: str) -> datetime:
        value = str(timestamp or "").strip()
        if not value:
            return datetime.now(timezone.utc)
        value = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _format_timestamp(self, value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat()
