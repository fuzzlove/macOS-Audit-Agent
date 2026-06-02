from __future__ import annotations

import os
import plistlib
import pwd
import grp
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from mac_audit_agent.models import BackgroundMonitorStatus


LAUNCH_AGENT_LABEL = "com.mac-audit-agent.monitor"
LAUNCHCTL_BIN = "/bin/launchctl"
PLUTIL_BIN = "/usr/bin/plutil"
LOG_BIN = "/usr/bin/log"
MAC_AUDIT_AGENT_ENV_SCOPE = "MAC_AUDIT_AGENT_LAUNCH_SCOPE"
MAC_AUDIT_AGENT_ENV_RUNTIME_ROOT = "MAC_AUDIT_AGENT_RUNTIME_ROOT"
MAC_AUDIT_AGENT_ENV_LOG_ROOT = "MAC_AUDIT_AGENT_LOG_ROOT"
MAC_AUDIT_AGENT_ENV_DB_PATH = "MAC_AUDIT_AGENT_DB_PATH"
SYSTEM_RUNTIME_ROOT = Path("/Library/Application Support/MacAuditAgent/runtime")
SYSTEM_LOG_ROOT = Path("/Library/Logs/MacAuditAgent")
SYSTEM_DB_PATH = Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3")


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def monitor_script_path() -> Path:
    return project_root() / "mac_audit_agent" / "monitor.py"


def launch_scope(default: str = "user") -> str:
    scope = os.environ.get(MAC_AUDIT_AGENT_ENV_SCOPE, default).strip().lower()
    return "system" if scope == "system" else "user"


def runtime_root(scope: str | None = None) -> Path:
    scope = launch_scope() if scope is None else launch_scope(scope)
    if scope == "system":
        return Path(os.environ.get(MAC_AUDIT_AGENT_ENV_RUNTIME_ROOT, str(SYSTEM_RUNTIME_ROOT))).expanduser()
    return Path.home() / ".mac_audit_agent" / "runtime"


def runtime_package_root(scope: str | None = None) -> Path:
    if scope is None:
        return runtime_root() / "mac_audit_agent"
    return runtime_root(scope) / "mac_audit_agent"


def runtime_monitor_script_path(scope: str | None = None) -> Path:
    if scope is None:
        return runtime_package_root() / "monitor.py"
    return runtime_package_root(scope) / "monitor.py"


def monitor_log_root(scope: str | None = None) -> Path:
    scope = launch_scope() if scope is None else launch_scope(scope)
    if scope == "system":
        return Path(os.environ.get(MAC_AUDIT_AGENT_ENV_LOG_ROOT, str(SYSTEM_LOG_ROOT))).expanduser()
    return Path.home() / ".mac_audit_agent" / "logs"


def default_monitor_db_path(scope: str | None = None) -> Path:
    scope = launch_scope() if scope is None else launch_scope(scope)
    if scope == "system":
        return Path(os.environ.get(MAC_AUDIT_AGENT_ENV_DB_PATH, str(SYSTEM_DB_PATH))).expanduser()
    return Path.home() / ".mac_audit_agent.sqlite3"


@dataclass
class LaunchAgentPaths:
    plist_path: Path
    stdout_path: Path
    stderr_path: Path


def default_launch_agent_paths(scope: str | None = None) -> LaunchAgentPaths:
    scope = launch_scope() if scope is None else launch_scope(scope)
    logs_dir = monitor_log_root(scope)
    launch_agents_dir = Path("/Library/LaunchDaemons") if scope == "system" else Path.home() / "Library" / "LaunchAgents"
    return LaunchAgentPaths(
        plist_path=launch_agents_dir / f"{LAUNCH_AGENT_LABEL}.plist",
        stdout_path=logs_dir / "background_monitor.stdout.log",
        stderr_path=logs_dir / "background_monitor.stderr.log",
    )


def launchctl_target(scope: str | None = None) -> str:
    scope = launch_scope() if scope is None else launch_scope(scope)
    if scope == "system":
        return "system"
    return f"gui/{os.getuid()}"


def build_launch_agent_plist(*, db_path: Path, poll_interval_seconds: int = 15, python_executable: str | None = None, scope: str = "user") -> dict:
    scope = launch_scope(scope)
    paths = default_launch_agent_paths(scope)
    root = runtime_root("system") if scope == "system" else runtime_root()
    monitor_path = runtime_monitor_script_path("system") if scope == "system" else runtime_monitor_script_path()
    payload = {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": [
            python_executable or "/usr/bin/python3",
            str(monitor_path),
            "--run",
        ],
        "RunAtLoad": True,
        "KeepAlive": True,
        "WorkingDirectory": str(root),
        "EnvironmentVariables": {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            MAC_AUDIT_AGENT_ENV_SCOPE: scope,
            MAC_AUDIT_AGENT_ENV_RUNTIME_ROOT: str(root),
            MAC_AUDIT_AGENT_ENV_LOG_ROOT: str(monitor_log_root(scope)),
            MAC_AUDIT_AGENT_ENV_DB_PATH: str(db_path),
        },
        "StandardOutPath": str(paths.stdout_path),
        "StandardErrorPath": str(paths.stderr_path),
    }
    if scope == "user":
        payload["ProcessType"] = "Interactive"
    return payload


def _format_command(command: list[str]) -> str:
    return " ".join(command)


PID_RE = re.compile(r"\bpid = (\d+)\b")


class LaunchAgentManager:
    def __init__(self, db_path: Path, runner=None, scope: str = "user") -> None:
        self.db_path = db_path
        self.scope = launch_scope(scope)
        self.paths = default_launch_agent_paths(self.scope)
        self.runner = runner or subprocess.run

    def _runtime_root(self) -> Path:
        return runtime_root("system") if self.scope == "system" else runtime_root()

    def _runtime_package_root(self) -> Path:
        return runtime_package_root("system") if self.scope == "system" else runtime_package_root()

    def _runtime_monitor_script_path(self) -> Path:
        return runtime_monitor_script_path("system") if self.scope == "system" else runtime_monitor_script_path()

    def _launchctl_target(self) -> str:
        return launchctl_target("system") if self.scope == "system" else launchctl_target()

    def install(self, poll_interval_seconds: int = 15) -> Path:
        if self.scope == "system" and os.geteuid() != 0:
            raise RuntimeError("System LaunchDaemon installation requires root privileges.")
        payload = build_launch_agent_plist(db_path=self.db_path, poll_interval_seconds=poll_interval_seconds, scope=self.scope)
        if payload.get("Label") != LAUNCH_AGENT_LABEL:
            raise RuntimeError(f"Invalid LaunchAgent Label: expected {LAUNCH_AGENT_LABEL}, got {payload.get('Label')}")
        self._ensure_install_paths()
        self._install_runtime_files()
        self.paths.plist_path.write_bytes(plistlib.dumps(payload))
        os.chmod(self.paths.plist_path, 0o644)
        current_user = pwd.getpwuid(os.getuid())
        target_group = "wheel" if self.scope == "system" else "staff"
        target_uid = 0 if self.scope == "system" else current_user.pw_uid
        target_gid = grp.getgrnam(target_group).gr_gid
        os.chown(self.paths.plist_path, target_uid, target_gid)
        self._run([PLUTIL_BIN, "-lint", str(self.paths.plist_path)])
        return self.paths.plist_path

    def uninstall(self) -> None:
        if self.paths.plist_path.exists():
            self.paths.plist_path.unlink()

    def repair(self, poll_interval_seconds: int = 15) -> tuple[Path, list[str]]:
        notes: list[str] = []
        for command in self._bootout_commands():
            try:
                self._run(command, tolerate=self._bootout_tolerate())
                notes.append(f"ok: {_format_command(command)}")
            except Exception as exc:
                notes.append(str(exc))
        for candidate in [
            self.paths.plist_path,
            Path("/Library/LaunchAgents") / f"{LAUNCH_AGENT_LABEL}.plist",
            Path("/Library/LaunchDaemons") / f"{LAUNCH_AGENT_LABEL}.plist",
        ]:
            try:
                if candidate.exists():
                    candidate.unlink()
                    notes.append(f"removed: {candidate}")
            except OSError as exc:
                notes.append(f"remove failed: {candidate} | {exc}")
        plist_path = self.install(poll_interval_seconds=poll_interval_seconds)
        self.start()
        verify = self.status()
        notes.append(f"verify: loaded={verify.loaded} running={verify.running} pid={verify.process_pid}")
        return plist_path, notes

    def force_reinstall(self, poll_interval_seconds: int = 15) -> tuple[Path, list[str]]:
        notes: list[str] = []
        for command in self._bootout_commands():
            try:
                self._run(command, tolerate=self._bootout_tolerate())
                notes.append(f"ok: {_format_command(command)}")
            except Exception as exc:
                notes.append(str(exc))
        try:
            if self.paths.plist_path.exists():
                self.paths.plist_path.unlink()
                notes.append(f"removed: {self.paths.plist_path}")
        except OSError as exc:
            notes.append(f"remove failed: {self.paths.plist_path} | {exc}")
        plist_path = self.install(poll_interval_seconds=poll_interval_seconds)
        notes.append(f"recreated: {plist_path}")
        self.start()
        verify = self.status()
        notes.append(f"verify: loaded={verify.loaded} running={verify.running} pid={verify.process_pid}")
        return plist_path, notes

    def start(self) -> None:
        self._bootstrap_preflight()
        for command in self._bootout_commands():
            self._run(
                command,
                tolerate=self._bootout_tolerate(),
            )
        try:
            self._run([LAUNCHCTL_BIN, "bootstrap", self._launchctl_target(), str(self.paths.plist_path)], tolerate={"already bootstrapped"})
        except Exception as exc:
            launchd_tail = self._launchd_log_tail()
            message = str(exc)
            if launchd_tail:
                message = f"{message}\nlaunchd log tail:\n{launchd_tail}"
            raise RuntimeError(message) from exc
        self._run([LAUNCHCTL_BIN, "kickstart", "-k", f"{self._launchctl_target()}/{LAUNCH_AGENT_LABEL}"])

    def stop(self) -> None:
        self._run([LAUNCHCTL_BIN, "bootout", self._launchctl_target(), str(self.paths.plist_path)], tolerate={"could not find specified service"})

    def status(self) -> BackgroundMonitorStatus:
        installed = self.paths.plist_path.exists()
        loaded = False
        running = False
        last_error = ""
        process_pid = None
        if installed:
            command = [LAUNCHCTL_BIN, "print", f"{self._launchctl_target()}/{LAUNCH_AGENT_LABEL}"]
            result = self._run(command, check=False)
            stdout = (result.stdout or "").lower()
            loaded = result.returncode == 0
            running = result.returncode == 0 and ("state = running" in stdout or "state = waiting" in stdout)
            pid_match = PID_RE.search(result.stdout or "")
            if pid_match:
                process_pid = int(pid_match.group(1))
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "command failed").strip()
                last_error = f"Command failed: {_format_command(command)}\nstderr:\n{detail}"
        return BackgroundMonitorStatus(
            installed=installed,
            loaded=loaded,
            running=running,
            enabled=installed,
            plist_path=str(self.paths.plist_path),
            label=LAUNCH_AGENT_LABEL,
            log_path=str(self.paths.stdout_path),
            db_path=str(self.db_path),
            process_pid=process_pid,
            last_error=last_error,
            current_launchctl_domain=self._launchctl_target(),
        )

    def show_logs(self) -> str:
        return str(self.paths.stdout_path)

    def _bootstrap_preflight(self) -> None:
        self._run([PLUTIL_BIN, "-lint", str(self.paths.plist_path)])
        payload = plistlib.loads(self.paths.plist_path.read_bytes())
        program_arguments = list(payload.get("ProgramArguments", []))
        expected_program_arguments = ["/usr/bin/python3", str(self._runtime_monitor_script_path()), "--run"]
        if program_arguments != expected_program_arguments:
            raise RuntimeError(
                "LaunchAgent preflight failed: ProgramArguments must be "
                f"{expected_program_arguments}, got {program_arguments}"
            )
        working_directory = Path(str(payload.get("WorkingDirectory", ""))).expanduser()
        if "Documents" in str(working_directory) or "Desktop" in str(working_directory) or "Downloads" in str(working_directory):
            raise RuntimeError(f"LaunchAgent preflight failed: WorkingDirectory must not be inside a protected folder: {working_directory}")
        if not working_directory.exists():
            raise RuntimeError(f"LaunchAgent preflight failed: WorkingDirectory does not exist: {working_directory}")
        if working_directory != self._runtime_root():
            raise RuntimeError(
                f"LaunchAgent preflight failed: WorkingDirectory must be {self._runtime_root()}, got {working_directory}"
            )
        if self.scope == "system" and self.paths.plist_path.parent != Path("/Library/LaunchDaemons"):
            raise RuntimeError(
                f"LaunchAgent preflight failed: system LaunchDaemon plist must live in /Library/LaunchDaemons, got {self.paths.plist_path.parent}"
            )
        for log_parent in [self.paths.stdout_path.parent, self.paths.stderr_path.parent]:
            if not log_parent.exists():
                raise RuntimeError(f"LaunchAgent preflight failed: log directory does not exist: {log_parent}")
        current_uid = os.getuid()
        plist_stat = self.paths.plist_path.stat()
        mode = stat.S_IMODE(plist_stat.st_mode)
        expected_uid = 0 if self.scope == "system" else current_uid
        if plist_stat.st_uid != expected_uid:
            owner_name = pwd.getpwuid(plist_stat.st_uid).pw_name
            expected_name = "root" if self.scope == "system" else pwd.getpwuid(current_uid).pw_name
            expected_group = "wheel" if self.scope == "system" else "staff"
            raise RuntimeError(
                f"LaunchAgent preflight failed: plist owner is {owner_name}, expected {expected_name}. "
                f"Repair: sudo chown {expected_name}:{expected_group} {self.paths.plist_path}"
            )
        if mode != 0o644:
            raise RuntimeError(
                f"LaunchAgent preflight failed: plist mode is {oct(mode)}, expected 0o644. "
                f"Repair: chmod 644 {self.paths.plist_path}"
            )

    def _ensure_install_paths(self) -> None:
        current_uid = os.getuid()
        current_user = pwd.getpwuid(current_uid)
        target_group = "wheel" if self.scope == "system" else "staff"
        target_gid = grp.getgrnam(target_group).gr_gid
        target_uid = 0 if self.scope == "system" else current_uid
        for directory in [self.paths.stdout_path.parent, self.paths.plist_path.parent, self._runtime_root(), self._runtime_package_root()]:
            directory.mkdir(parents=True, exist_ok=True)
            try:
                directory.chmod(0o755)
            except OSError:
                pass
            try:
                os.chown(directory, target_uid, target_gid)
            except OSError:
                pass
            if not os.access(directory, os.W_OK):
                raise RuntimeError(
                    f"LaunchAgent path is not writable: {directory}. "
                    f"Repair: sudo chown -R {('root' if self.scope == 'system' else current_user.pw_name)}:{target_group} {directory}"
                )

    def _install_runtime_files(self) -> None:
        source_root = project_root() / "mac_audit_agent"
        target_root = self._runtime_package_root()
        current_uid = os.getuid()
        target_group = "wheel" if self.scope == "system" else "staff"
        target_gid = grp.getgrnam(target_group).gr_gid
        target_uid = 0 if self.scope == "system" else current_uid
        shutil.copytree(
            source_root,
            target_root,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tests"),
            copy_function=shutil.copyfile,
        )
        for path in sorted(target_root.rglob("*")):
            try:
                if path.is_dir():
                    path.chmod(0o755)
                else:
                    path.chmod(0o755 if path.name == "monitor.py" else 0o644)
            except OSError:
                pass
            try:
                os.chown(path, target_uid, target_gid)
            except OSError:
                pass
        try:
            os.chown(target_root, target_uid, target_gid)
            os.chown(self._runtime_root(), target_uid, target_gid)
        except OSError:
            pass

    def _bootout_commands(self) -> list[list[str]]:
        return [
            [LAUNCHCTL_BIN, "bootout", f"{self._launchctl_target()}/{LAUNCH_AGENT_LABEL}"],
            [LAUNCHCTL_BIN, "bootout", self._launchctl_target(), str(self.paths.plist_path)],
        ]

    def _bootout_tolerate(self) -> set[str]:
        return {
            "could not find specified service",
            "service cannot load in requested session",
            "no such process",
            "not loaded",
            "domain does not support the specified action",
            "input/output error",
        }

    def _launchd_log_tail(self) -> str:
        if not Path(LOG_BIN).exists():
            return ""
        result = self._run(
            [
                LOG_BIN,
                "show",
                "--style",
                "compact",
                "--last",
                "5m",
                "--predicate",
                'process == "launchd"',
            ],
            check=False,
        )
        content = (result.stdout or result.stderr or "").strip()
        if not content:
            return ""
        lines = content.splitlines()
        return "\n".join(lines[-30:])

    def _run(self, command: list[str], *, check: bool = True, tolerate: set[str] | None = None):
        result = self.runner(command, capture_output=True, text=True)
        tolerate = tolerate or set()
        stderr = (result.stderr or "").lower()
        stdout = (result.stdout or "").lower()
        if check and result.returncode != 0 and not any(item in stderr or item in stdout for item in tolerate):
            detail = (result.stderr or result.stdout or "command failed").strip()
            raise RuntimeError(f"Command failed: {_format_command(command)}\nstderr:\n{detail}")
        return result
