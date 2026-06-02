from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    category: str
    description: str
    severity: str
    confidence_default: str
    source_detector: str
    false_positive_hints: list[str]
    verification_steps: list[str]
    mitre_mapping: str = ""
    enabled_by_default: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _rule(
    rule_id: str,
    name: str,
    category: str,
    description: str,
    severity: str,
    confidence_default: str,
    source_detector: str,
    false_positive_hints: list[str],
    verification_steps: list[str],
    mitre_mapping: str = "",
    enabled_by_default: bool = True,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        name=name,
        category=category,
        description=description,
        severity=severity,
        confidence_default=confidence_default,
        source_detector=source_detector,
        false_positive_hints=false_positive_hints,
        verification_steps=verification_steps,
        mitre_mapping=mitre_mapping,
        enabled_by_default=enabled_by_default,
    )


RULES: dict[str, Rule] = {
    "launchdaemon_added": _rule(
        "launchdaemon_added",
        "LaunchDaemon Added",
        "persistence",
        "A new system LaunchDaemon plist appeared under /Library/LaunchDaemons.",
        "critical",
        "high",
        "persistence_monitor",
        ["software install or update", "managed endpoint tooling", "approved service deployment"],
        ["Inspect the plist target, owner, code signature, and package receipt.", "Confirm whether the change matches an approved installation or admin action."],
        "T1543.001",
    ),
    "launchagent_added": _rule(
        "launchagent_added",
        "LaunchAgent Added",
        "persistence",
        "A new LaunchAgent plist appeared in a LaunchAgents directory.",
        "high",
        "high",
        "persistence_monitor",
        ["user-installed app", "helper app update", "managed software deployment"],
        ["Inspect the plist target and ownership.", "Confirm whether the agent belongs to an approved application."],
        "T1543.001",
    ),
    "persistence_item_created_high_risk": _rule(
        "persistence_item_created_high_risk",
        "Login Item Added",
        "persistence",
        "A new login item was added for the current user.",
        "critical",
        "high",
        "persistence_monitor",
        ["user preference change", "new app install", "managed profile"],
        ["Inspect the login item name and source application.", "Confirm whether the item was added intentionally."],
        "T1547.015",
    ),
    "network_ip_assigned": _rule(
        "network_ip_assigned",
        "Network IP Assigned",
        "network",
        "An interface received a new IP address assignment.",
        "info",
        "high",
        "network_detector",
        ["expected DHCP lease renewal", "interface reconnect", "network switch change"],
        ["Confirm the interface, subnet, and gateway match the expected environment.", "Verify whether the change aligns with a known network transition."],
    ),
    "vpn_connected": _rule(
        "vpn_connected",
        "VPN Connected",
        "network",
        "A VPN interface appeared or changed state.",
        "info",
        "high",
        "network_detector",
        ["user initiated VPN", "managed always-on VPN", "profile refresh"],
        ["Confirm the profile and endpoint are expected.", "Check whether the VPN change matches user activity or policy."],
    ),
    "display_sleep": _rule(
        "display_sleep",
        "Display Sleep",
        "session",
        "The display transitioned to sleep.",
        "info",
        "high",
        "session_monitor",
        ["normal idle sleep", "user-initiated sleep", "power management"],
        ["Confirm the transition matches expected user or power-state activity."],
    ),
    "display_wake": _rule(
        "display_wake",
        "Display Wake",
        "session",
        "The display transitioned back to awake.",
        "info",
        "high",
        "session_monitor",
        ["normal wake", "lid open", "user returning to desk"],
        ["Confirm the wake matches expected user activity."],
    ),
    "possible_lid_opened": _rule(
        "possible_lid_opened",
        "Possible Lid Opened",
        "session",
        "A lid-open transition was observed.",
        "high",
        "high",
        "session_monitor",
        ["normal lid open", "dock reconnect", "power state transition"],
        ["Confirm the lid transition matches expected user activity."],
    ),
    "possible_lid_closed": _rule(
        "possible_lid_closed",
        "Possible Lid Closed",
        "session",
        "A lid-closed transition was observed.",
        "high",
        "high",
        "session_monitor",
        ["normal lid close", "closing a laptop", "travel or docking"],
        ["Confirm the lid transition matches expected user activity."],
    ),
    "usb_device_connected": _rule(
        "usb_device_connected",
        "USB Connected",
        "hardware",
        "A previously seen USB device was recognized again.",
        "info",
        "high",
        "hardware_detector",
        ["physical reconnect", "dock reconnect", "USB hub topology change"],
        ["Confirm the USB device is expected.", "Compare vendor, product, serial, and port identity."],
    ),
    "new_usb_device_detected": _rule(
        "new_usb_device_detected",
        "New USB Device Detected",
        "hardware",
        "A new USB device identity was observed.",
        "critical",
        "high",
        "hardware_detector",
        ["new accessory", "dock replacement", "vendor firmware update"],
        ["Inspect the vendor, product, serial, and attachment location.", "Confirm whether the device is approved for use."],
    ),
    "system_moisture_detected": _rule(
        "system_moisture_detected",
        "Moisture Detected",
        "hardware",
        "A moisture or liquid warning marker was observed.",
        "critical",
        "high",
        "hardware_detector",
        ["transient sensor text", "environmental warning", "hardware log artifact"],
        ["Disconnect external power and inspect the affected port or device.", "Confirm whether the signal was a real hardware warning."],
    ),
    "suspicious_process_observed": _rule(
        "suspicious_process_observed",
        "Suspicious Process Observed",
        "execution",
        "A process started from an unexpected path or with a risky command line.",
        "high",
        "medium",
        "process_detector",
        ["developer tooling", "temporary build output", "admin maintenance task"],
        ["Inspect the binary path, parent process, and code signature.", "Compare the process hash against baseline if available."],
        "T1059",
    ),
    "capture_capable_process_observed": _rule(
        "capture_capable_process_observed",
        "Capture-Capable Process Observed",
        "privacy",
        "A capture-capable application was observed running.",
        "medium",
        "low",
        "privacy_monitor",
        ["normal conferencing app", "screen recording app", "browser media helper"],
        ["Confirm the app is expected to be open.", "Correlate with nearby session or privacy events."],
    ),
    "camera_activity_confirmed": _rule(
        "camera_activity_confirmed",
        "Camera Activity Confirmed",
        "privacy",
        "A camera-active signal was observed from public APIs.",
        "high",
        "high",
        "privacy_monitor",
        ["legitimate video call", "camera test", "photobooth session"],
        ["Confirm whether camera use is expected.", "Check the active application and nearby events."],
    ),
    "input_activity_resumed_after_idle": _rule(
        "input_activity_resumed_after_idle",
        "Input Resumed After Idle",
        "session",
        "Keyboard, mouse, and trackpad input resumed after a sustained idle period.",
        "medium",
        "high",
        "session_monitor",
        ["user returned to desk", "remote session wake", "touchpad movement while docked"],
        ["Confirm the input resume was expected.", "Review surrounding session and display events."],
    ),
    "alert_storm_detected": _rule(
        "alert_storm_detected",
        "Alert Storm Detected",
        "provenance",
        "Many alerts with the same shape appeared in a short window.",
        "high",
        "medium",
        "alert_storm_detector",
        ["benign noisy app", "broken detector", "automation or install churn"],
        ["Review the top event types and sources.", "Check whether the detector itself is noisy or the activity is expected."],
    ),
    "new_admin_user_detected": _rule(
        "new_admin_user_detected",
        "New Admin User Detected",
        "identity",
        "A new administrative user was observed.",
        "critical",
        "high",
        "baseline_drift",
        ["normal account creation", "managed user onboarding", "directory service sync"],
        ["Confirm the account owner and whether the admin grant was approved."],
    ),
    "heartbeat": _rule(
        "heartbeat",
        "Heartbeat",
        "monitoring",
        "Monitor heartbeat event.",
        "info",
        "high",
        "monitor",
        ["routine monitor activity"],
        ["No action needed unless the monitor is unhealthy."],
    ),
}


def rule_for_event(event_type: str) -> Rule:
    return RULES.get(
        event_type,
        _rule(
            event_type or "unknown",
            event_type.replace("_", " ").title() if event_type else "Unknown Event",
            "provenance",
            "No explicit rule mapping exists for this event type.",
            "low",
            "low",
            "unknown_detector",
            ["limited context", "legacy event payload", "rule registry incomplete"],
            ["Inspect the detector and surrounding events.", "Add or update a rule mapping before relying on the popup."],
            enabled_by_default=False,
        ),
    )


def rule_for_finding(category: str, title: str, evidence: str = "", command_used: str = "") -> Rule:
    normalized = f"{category} {title} {evidence} {command_used}".lower()
    if "launchdaemon" in normalized:
        return RULES["launchdaemon_added"]
    if "launchagent" in normalized:
        return RULES["launchagent_added"]
    if "login item" in normalized:
        return RULES["persistence_item_created_high_risk"]
    if "port" in normalized:
        return _rule(
            "localhost_hidden_port_detected",
            "Hidden Localhost Port",
            "network",
            "A localhost-bound listening port was observed.",
            "critical",
            "high",
            "network_detector",
            ["developer service", "debug server", "local proxy"],
            ["Inspect the listening process and confirm whether the port should be open."],
        )
    if "process" in normalized or "execution" in normalized:
        return RULES["suspicious_process_observed"]
    if "history" in normalized:
        return _rule(
            "shell_history_pattern",
            "Shell History Pattern",
            "process",
            "A shell history pattern matched a risky command line.",
            "medium",
            "low",
            "history_detector",
            ["legitimate admin work", "training commands", "documentation snippets"],
            ["Review the surrounding history entries and confirm the command intent."],
        )
    return _rule(
        re.sub(r"[^a-z0-9_]+", "_", title.lower()).strip("_") or "finding_rule",
        title,
        category,
        "A finding was created from scan evidence.",
        str("high" if category.lower() in {"baseline comparison", "persistence"} else "medium"),
        "medium",
        "scan_collector",
        ["benign maintenance", "software updates", "approved administrative activity"],
        ["Inspect the source artifact.", "Compare the item against baseline and surrounding events."],
    )


def sanitize_signal_text(value: str) -> str:
    text = str(value or "")
    text = re.sub(r"(?i)(authorization=)([^\s&]+(?:\s+[^\s&]+)?)", r"\1[redacted]", text)
    text = re.sub(r"(?i)(token|cookie|password)=([^\s&]+)", r"\1=[redacted]", text)
    text = re.sub(r"(?i)(bearer\s+)[^\s&]+", r"\1[redacted]", text)
    return text


def evidence_hash(*parts: Any) -> str:
    material = json.dumps([sanitize_signal_text(str(part)) for part in parts], sort_keys=True)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def normalized_signal(*parts: Any) -> str:
    return sanitize_signal_text(" | ".join(str(part) for part in parts if str(part)))


def correlation_id_for(*parts: Any, timestamp: str | None = None, bucket_seconds: int = 300) -> str:
    bucket = ""
    if timestamp:
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            epoch = int(dt.timestamp())
            bucket = str(epoch - (epoch % max(1, bucket_seconds)))
        except ValueError:
            bucket = timestamp[:16]
    material = normalized_signal(*parts, bucket)
    return f"corr-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"
