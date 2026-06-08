from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mac_audit_agent.app import main as gui_main
from mac_audit_agent.collectors import CollectorSuite
from mac_audit_agent.config import AuditConfig
from mac_audit_agent.cve_radar import CveRadarEngine
from mac_audit_agent.launch_agent import LaunchAgentManager, default_monitor_db_path
from mac_audit_agent.models import ScanResult, ScanSummary, utc_now_iso
from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.operational_health import OperationalHealthEngine
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json
from mac_audit_agent.runner import RunnerConfig, SafeCommandRunner
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.system_monitor_readiness import SystemMonitorReadiness


def _default_db_path() -> Path:
    return Path.home() / ".mac_audit_agent.sqlite3"


def _logs_dir_for_db(db_path: Path) -> Path:
    default_db = _default_db_path()
    if db_path.expanduser() == default_db:
        return AuditConfig().logs_dir
    return db_path.expanduser().resolve().parent / "mac_audit_agent_logs"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="macos-security-audit-agent",
        description="macOS Security Audit Agent local audit, report, and health CLI.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--safe-scan", action="store_true", help="Run a safe read-only local audit scan.")
    mode.add_argument("--aggressive-scan", action="store_true", help="Run the opt-in aggressive local audit scan.")
    parser.add_argument("--report", type=Path, help="Write an HTML report to this path. Uses the requested scan or the latest saved scan.")
    parser.add_argument("--json-report", type=Path, help="Write a JSON report to this path. Uses the requested scan or the latest saved scan.")
    parser.add_argument("--system-health", action="store_true", help="Print operational health as JSON.")
    parser.add_argument("--db", type=Path, default=_default_db_path(), help="SQLite database path. Defaults to ~/.mac_audit_agent.sqlite3.")
    parser.add_argument("--no-gui", action="store_true", help="Do not launch the GUI when no action flags are provided.")
    return parser


def _scan_summary(collectors: CollectorSuite, scan_result: ScanResult, *, started_at: str, scan_mode: str) -> ScanSummary:
    score = collectors.compute_security_score(scan_result.findings)
    return ScanSummary(
        scan_id=scan_result.scan_id,
        started_at=started_at,
        completed_at=utc_now_iso(),
        findings_count=len(scan_result.findings),
        security_score=score,
        notes=f"{scan_mode.title()} macOS audit run from CLI.",
        new_items_count=sum(len(value) for value in scan_result.baseline_diff.values() if isinstance(value, list)),
        score_label=collectors.score_label(score),
    )


def _persist_scan(db: AuditDatabase, summary: ScanSummary, scan_result: ScanResult, *, scan_mode: str, localhost_protocol: str) -> None:
    db.record_scan(summary)
    db.record_scan_result(scan_result)
    for result in scan_result.artifacts.get("command_results", []):
        db.record_command_log(scan_result.scan_id, result)
    for finding in scan_result.findings:
        db.record_finding(scan_result.scan_id, finding)
    db.record_snapshots(
        scan_result.scan_id,
        ports=scan_result.artifacts.get("ports", {}).get("listening", []),
        users=scan_result.artifacts.get("users", []),
        history_indicators=scan_result.artifacts.get("history_indicators", []),
        permissions=scan_result.artifacts.get("permission_snapshots", []),
        files=scan_result.artifacts.get("file_issues", []),
        processes=scan_result.artifacts.get("processes", {}).get("all", []),
        launch_snapshots=scan_result.artifacts.get("launch_snapshots", []),
        launch_items=set(scan_result.artifacts.get("launch_items", [])),
    )
    db.write_scan_logs(
        scan_result.scan_id,
        {
            "findings": scan_result.findings,
            "command_results": scan_result.artifacts.get("command_results", []),
            "ports": scan_result.artifacts.get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []}),
            "localhost_scan": scan_result.artifacts.get(
                "localhost_scan",
                {"target": "127.0.0.1", "mode": scan_mode, "protocol": localhost_protocol, "open_ports": [], "missing_from_enumeration": [], "errors": [], "scanned_port_count": 0},
            ),
            "processes": scan_result.artifacts.get("processes", {"all": [], "suspicious": [], "errors": []}),
            "users": scan_result.artifacts.get("users", []),
            "history_indicators": scan_result.artifacts.get("history_indicators", []),
            "permission_snapshots": scan_result.artifacts.get("permission_snapshots", []),
            "file_issues": scan_result.artifacts.get("file_issues", []),
            "launch_snapshots": scan_result.artifacts.get("launch_snapshots", []),
            "comparison": type("BaselineHolder", (), {"to_dict": lambda self_: scan_result.baseline_diff})(),
            "raw_logs": scan_result.raw_logs,
        },
    )


def _run_scan(db: AuditDatabase, *, aggressive: bool) -> tuple[ScanSummary, ScanResult]:
    scan_mode = "aggressive" if aggressive else "safe"
    localhost_protocol = "both" if aggressive else "tcp"
    config = AuditConfig(logs_dir=db.logs_dir, dry_run=False, disable_aggressive_scan=False)
    runner = SafeCommandRunner(RunnerConfig(dry_run=False))
    collectors = CollectorSuite(runner, config)
    started_at = utc_now_iso()
    scan_result = collectors.run_scan(
        previous_result=db.latest_scan_result(),
        scan_mode=scan_mode,
        localhost_scan_protocol=localhost_protocol,
    )
    summary = _scan_summary(collectors, scan_result, started_at=started_at, scan_mode=scan_mode)
    _persist_scan(db, summary, scan_result, scan_mode=scan_mode, localhost_protocol=localhost_protocol)
    return summary, scan_result


def _latest_or_safe_scan(db: AuditDatabase, *, requested_scan: ScanResult | None) -> ScanResult:
    if requested_scan is not None:
        return requested_scan
    latest = db.latest_scan_result()
    if latest is not None:
        return latest
    return _run_scan(db, aggressive=False)[1]


def _system_health(db: AuditDatabase) -> dict:
    config = AuditConfig(logs_dir=db.logs_dir)
    engine = OperationalHealthEngine(
        db,
        user_launch_agent=LaunchAgentManager(db.path),
        system_launch_agent=LaunchAgentManager(default_monitor_db_path("system"), scope="system"),
        notification_manager=NotificationManager(db),
        system_readiness=SystemMonitorReadiness(default_monitor_db_path("system")),
        cve_radar_engine=CveRadarEngine(db, config),
    )
    return engine.build_report().to_dict()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    action_requested = any([args.safe_scan, args.aggressive_scan, args.report, args.json_report, args.system_health])
    if not action_requested:
        if args.no_gui:
            parser.print_help()
            return 0
        return gui_main()

    db = AuditDatabase(args.db, _logs_dir_for_db(args.db))
    scan_result: ScanResult | None = None
    if args.safe_scan or args.aggressive_scan:
        summary, scan_result = _run_scan(db, aggressive=bool(args.aggressive_scan))
        print(
            json.dumps(
                {
                    "scan_id": summary.scan_id,
                    "findings_count": summary.findings_count,
                    "security_score": summary.security_score,
                    "score_label": summary.score_label,
                    "database": str(args.db),
                },
                indent=2,
            )
        )
    if args.report:
        report_scan = _latest_or_safe_scan(db, requested_scan=scan_result)
        path = export_scan_result_html(report_scan, args.report)
        print(f"HTML report written: {path}")
    if args.json_report:
        report_scan = _latest_or_safe_scan(db, requested_scan=scan_result)
        path = export_scan_result_json(report_scan, args.json_report)
        print(f"JSON report written: {path}")
    if args.system_health:
        print(json.dumps(_system_health(db), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
