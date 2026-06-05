from __future__ import annotations

import plistlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


WRITABLE_EXECUTION_PREFIXES = ("/tmp", "/var/tmp", "/private/tmp", "/Users/Shared")
USER_EXECUTION_MARKERS = ("/Users/", "/.Trash/", "/Downloads/")
PERSISTENCE_REVIEW_PATHS = [
    "/Library/StartupItems",
    "/Library/Preferences/com.apple.loginwindow.plist",
    "/private/etc/periodic",
    "/etc/periodic",
    "/etc/crontab",
    "/usr/lib/cron/tabs",
    "/var/at/tabs",
    "/Library/ScriptingAdditions",
]
VM_REGION_RE = re.compile(
    r"^(?P<region>[A-Za-z0-9_.:/()\[\] -]+?)\s+"
    r"(?P<address>[0-9A-Fa-fx`-]+)\s+\[\s*(?P<size>[^\]]+)\]\s+"
    r"(?P<prot>[rwx\-/]+)(?:/(?P<maxprot>[rwx\-/]+))?",
)
SHELLCODE_REGION_TERMS = ("MALLOC", "STACK", "VM_ALLOCATE", "anonymous", "mapped file")


@dataclass
class PersistenceMethodFinding:
    title: str
    severity: str
    confidence: str
    path: str
    method: str
    evidence: str
    reasons: list[str] = field(default_factory=list)
    mitre: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MemoryRegionFinding:
    title: str
    severity: str
    confidence: str
    pid: int | None
    process_name: str
    process_path: str
    evidence: str
    reasons: list[str] = field(default_factory=list)
    mitre: str = "T1055/T1620"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def scan_persistence_methods(paths: list[Path] | None = None) -> list[PersistenceMethodFinding]:
    findings: list[PersistenceMethodFinding] = []
    for path in paths or [Path(item) for item in PERSISTENCE_REVIEW_PATHS]:
        if not path.exists():
            continue
        if path.is_dir():
            findings.extend(_scan_persistence_directory(path))
        elif path.is_file():
            finding = _scan_persistence_file(path)
            if finding is not None:
                findings.append(finding)
    return findings


def analyze_launch_item_for_persistence(item: Any) -> PersistenceMethodFinding | None:
    path = str(getattr(item, "path", "") or _get(item, "path"))
    label = str(getattr(item, "label", "") or _get(item, "label"))
    program = str(getattr(item, "program", "") or _get(item, "program"))
    arguments = list(getattr(item, "program_arguments", []) or _get(item, "program_arguments", []) or [])
    run_at_load = bool(getattr(item, "run_at_load", False) or _get(item, "run_at_load", False))
    keep_alive = bool(getattr(item, "keep_alive", False) or _get(item, "keep_alive", False))
    suspicious = bool(getattr(item, "suspicious", False) or _get(item, "suspicious", False))
    reasons = list(getattr(item, "reasons", []) or _get(item, "reasons", []) or [])
    joined = " ".join([program, *[str(arg) for arg in arguments]])
    if _path_is_writable_execution(program):
        reasons.append("launchd_program_from_writable_path")
    if _path_is_user_execution(program):
        reasons.append("launchd_program_from_user_space")
    if run_at_load:
        reasons.append("run_at_load")
    if keep_alive:
        reasons.append("keep_alive")
    if any(term in joined.lower() for term in ("curl ", "bash -c", "sh -c", "osascript", "python -c", "python3 -c", "base64", "chmod +x")):
        reasons.append("script_or_download_execution")
    high_risk = suspicious or any(reason in reasons for reason in {"launchd_program_from_writable_path", "script_or_download_execution"})
    if not high_risk and len(reasons) < 2:
        return None
    is_daemon = "/LaunchDaemons/" in path
    severity = "critical" if is_daemon and high_risk else "high" if high_risk else "medium"
    return PersistenceMethodFinding(
        title=f"ATT&CK Persistence Review: {label or Path(path).name}",
        severity=severity,
        confidence="high" if high_risk else "medium",
        path=path,
        method="LaunchDaemon" if is_daemon else "LaunchAgent",
        evidence=f"{path} launches {program or joined}; reasons={','.join(sorted(set(reasons)))}",
        reasons=sorted(set(reasons)),
        mitre="T1543.004" if is_daemon else "T1543.001",
    )


def analyze_vmmap_output(pid: int | None, process_name: str, process_path: str, vmmap_output: str) -> list[MemoryRegionFinding]:
    findings: list[MemoryRegionFinding] = []
    for line in vmmap_output.splitlines():
        finding = analyze_vmmap_line(pid, process_name, process_path, line)
        if finding is not None:
            findings.append(finding)
    return findings


def analyze_vmmap_line(pid: int | None, process_name: str, process_path: str, line: str) -> MemoryRegionFinding | None:
    match = VM_REGION_RE.match(line.strip())
    if not match:
        return None
    region = match.group("region").strip()
    prot = (match.group("prot") or "").lower()
    maxprot = (match.group("maxprot") or "").lower()
    combined_prot = f"{prot}/{maxprot}"
    reasons: list[str] = []
    if "x" in prot and "w" in prot:
        reasons.append("writable_executable_memory")
    if "x" in prot and any(term.lower() in region.lower() for term in SHELLCODE_REGION_TERMS):
        reasons.append("executable_anonymous_or_heap_region")
    if "x" in maxprot and "w" in maxprot and "x" in prot:
        reasons.append("max_protection_allows_write_execute")
    if not reasons:
        return None
    severity = "critical" if "writable_executable_memory" in reasons else "high"
    return MemoryRegionFinding(
        title=f"Possible In-Memory Code Execution: {process_name or pid}",
        severity=severity,
        confidence="medium",
        pid=pid,
        process_name=process_name,
        process_path=process_path,
        evidence=f"vmmap region '{region}' has protections {combined_prot}: {line.strip()}",
        reasons=reasons,
    )


def _scan_persistence_directory(path: Path) -> list[PersistenceMethodFinding]:
    findings: list[PersistenceMethodFinding] = []
    for child in sorted(path.rglob("*"))[:300]:
        if not child.is_file():
            continue
        finding = _scan_persistence_file(child)
        if finding is not None:
            findings.append(finding)
    return findings


def _scan_persistence_file(path: Path) -> PersistenceMethodFinding | None:
    reasons: list[str] = []
    method = _persistence_method_for_path(path)
    try:
        stat_result = path.stat()
    except OSError:
        return None
    if stat_result.st_mode & 0o002:
        reasons.append("world_writable_persistence_file")
    content_preview = ""
    if path.suffix == ".plist":
        try:
            payload = plistlib.loads(path.read_bytes())
            for key in ("LoginHook", "LogoutHook", "Program", "ProgramArguments"):
                value = payload.get(key)
                if value:
                    content_preview += f" {key}={value}"
            if payload.get("LoginHook") or payload.get("LogoutHook"):
                reasons.append("login_hook_configured")
            if payload.get("RunAtLoad"):
                reasons.append("run_at_load")
            if payload.get("KeepAlive"):
                reasons.append("keep_alive")
        except Exception:
            reasons.append("plist_parse_failed")
    else:
        try:
            content_preview = path.read_text(encoding="utf-8", errors="replace")[:500]
        except OSError:
            content_preview = ""
    lowered = f"{path} {content_preview}".lower()
    if any(term in lowered for term in ("curl ", "bash -c", "sh -c", "osascript", "base64", "chmod +x", "python -c", "python3 -c")):
        reasons.append("script_or_download_execution")
    if any(prefix in str(path) for prefix in WRITABLE_EXECUTION_PREFIXES):
        reasons.append("persistence_from_writable_path")
    if not reasons and method != "StartupItems":
        return None
    high_risk = any(reason in reasons for reason in {"world_writable_persistence_file", "script_or_download_execution", "login_hook_configured", "persistence_from_writable_path"})
    return PersistenceMethodFinding(
        title=f"ATT&CK Persistence Method Observed: {method}",
        severity="high" if high_risk else "medium",
        confidence="medium" if high_risk else "low",
        path=str(path),
        method=method,
        evidence=f"{path}; reasons={','.join(sorted(set(reasons))) or 'legacy persistence surface present'}",
        reasons=sorted(set(reasons)),
        mitre=_mitre_for_method(method),
    )


def _persistence_method_for_path(path: Path) -> str:
    text = str(path)
    if "StartupItems" in text:
        return "StartupItems"
    if "loginwindow.plist" in text:
        return "LoginHook"
    if "/periodic" in text:
        return "PeriodicScript"
    if "cron" in text or "/tabs" in text or "crontab" in text:
        return "CronOrAt"
    if "ScriptingAdditions" in text:
        return "ScriptingAddition"
    return "PersistenceFile"


def _mitre_for_method(method: str) -> str:
    return {
        "StartupItems": "T1037.005",
        "LoginHook": "T1037.002",
        "LaunchAgent": "T1543.001",
        "LaunchDaemon": "T1543.004",
        "PeriodicScript": "T1037",
        "CronOrAt": "T1053",
        "ScriptingAddition": "T1546",
    }.get(method, "T1547")


def _path_is_writable_execution(path: str) -> bool:
    return str(path).startswith(WRITABLE_EXECUTION_PREFIXES)


def _path_is_user_execution(path: str) -> bool:
    return any(marker in str(path) for marker in USER_EXECUTION_MARKERS)


def _get(item: Any, key: str, default: Any = "") -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return default
