from pathlib import Path
import plistlib

from mac_audit_agent.collectors import CollectorSuite
from mac_audit_agent.config import AuditConfig
from mac_audit_agent.intrusion_methods import analyze_launch_item_for_persistence, analyze_vmmap_line
from mac_audit_agent.intrusion_methods import scan_persistence_methods
from mac_audit_agent.models import CommandExecutionResult, LaunchItemSnapshot, ProcessSnapshot
from mac_audit_agent.rules import rule_for_finding


class FakeRunner:
    def execute(self, command):
        if command.id.startswith("runtime.memory.vmmap."):
            return CommandExecutionResult(
                command_id=command.id,
                command_preview=command.preview,
                executed_at="2026-06-04T00:00:00Z",
                stdout="MALLOC_SMALL  0000000123400000-0000000123500000 [ 1024K] rwx/rwx SM=PRV\n",
                stderr="",
                exit_code=0,
                timed_out=False,
                truncated=False,
                dry_run=False,
            )
        return CommandExecutionResult(
            command_id=command.id,
            command_preview=command.preview,
            executed_at="2026-06-04T00:00:00Z",
            stdout="",
            stderr="",
            exit_code=0,
            timed_out=False,
            truncated=False,
            dry_run=False,
        )


def test_launchdaemon_temp_path_persistence_scores_critical() -> None:
    item = LaunchItemSnapshot(
        path="/Library/LaunchDaemons/com.apple.softwareupdate.plist",
        label="com.apple.softwareupdate",
        program="/tmp/.update",
        program_arguments=["/tmp/.update", "--beacon"],
        run_at_load=True,
        keep_alive=True,
        suspicious=True,
        reasons=["launch_program_in_writable_path"],
    )
    finding = analyze_launch_item_for_persistence(item)
    assert finding is not None
    assert finding.severity == "critical"
    assert finding.mitre == "T1543.004"
    assert "launchd_program_from_writable_path" in finding.reasons


def test_vmmap_writable_executable_region_is_shellcode_review_signal() -> None:
    finding = analyze_vmmap_line(
        4321,
        "unknown",
        "/private/tmp/.x",
        "MALLOC_SMALL  0000000123400000-0000000123500000 [ 1024K] rwx/rwx SM=PRV",
    )
    assert finding is not None
    assert finding.severity == "critical"
    assert "writable_executable_memory" in finding.reasons
    rule = rule_for_finding("Execution", finding.title, finding.evidence, "/usr/bin/vmmap -interleaved 4321")
    assert rule.rule_id == "possible_shellcode_memory_detected"


def test_intrusion_methods_collector_adds_memory_and_persistence_findings(monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.collectors.scan_persistence_methods", lambda: [])
    original_exists = Path.exists
    monkeypatch.setattr("mac_audit_agent.collectors.Path.exists", lambda self: True if str(self) == "/usr/bin/vmmap" else original_exists(self))
    suite = CollectorSuite(FakeRunner(), AuditConfig(dry_run=False))
    process = ProcessSnapshot(
        pid=4321,
        ppid=1,
        user="m",
        command_path="/private/tmp/.x",
        process_name=".x",
        signed_status="unsigned",
        trust_level="untrusted",
        reasons=["unsigned_process_binary", "process_in_writable_path"],
        trust_score=10,
    )
    launch_item = LaunchItemSnapshot(
        path="/Library/LaunchDaemons/com.bad.plist",
        label="com.bad",
        program="/tmp/.agent",
        program_arguments=["/tmp/.agent"],
        run_at_load=True,
        keep_alive=True,
        suspicious=True,
        reasons=["launch_program_in_writable_path"],
    )
    result = suite._collect_intrusion_methods_result([process], [launch_item])
    findings = suite._findings_for_intrusion_methods(result.artifacts["intrusion_methods"])
    titles = [item.title for item in findings]
    assert any("ATT&CK Persistence" in title for title in titles)
    assert any("Possible In-Memory Code Execution" in title for title in titles)
    assert result.artifacts["intrusion_methods"]["memory"]


def test_normal_loginwindow_plist_without_hooks_is_not_flagged(tmp_path: Path) -> None:
    plist_path = tmp_path / "com.apple.loginwindow.plist"
    plist_path.write_bytes(plistlib.dumps({"AutoLaunchedApplicationDictionary": []}))
    assert scan_persistence_methods([plist_path]) == []
