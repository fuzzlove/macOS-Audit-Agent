from __future__ import annotations

import hashlib
import json
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field

from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.rules import correlation_id_for, evidence_hash, normalized_signal, rule_for_event
from mac_audit_agent.network_discovery import (
    _parse_ifconfig_interface,
    detect_network_scope,
    detect_preferred_interface,
    parse_active_interfaces,
)


VPN_INTERFACE_PREFIXES = ("utun", "ppp", "ipsec", "tun", "tap")


def _run_command(command: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.returncode, result.stdout, result.stderr
    except Exception as exc:  # pragma: no cover - command failures are environment specific
        return 1, "", str(exc)


@dataclass
class NetworkMonitorSnapshot:
    timestamp: str = field(default_factory=utc_now_iso)
    interface: str = ""
    ip_address: str = ""
    netmask: str = ""
    gateway: str = ""
    subnet: str = ""
    scope: str = ""
    wifi_ssid: str = ""
    active_interfaces: list[dict[str, str]] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    vpn_interfaces: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "interface": self.interface,
            "ip_address": self.ip_address,
            "netmask": self.netmask,
            "gateway": self.gateway,
            "subnet": self.subnet,
            "scope": self.scope,
            "wifi_ssid": self.wifi_ssid,
            "active_interfaces": [dict(item) for item in self.active_interfaces],
            "dns_servers": list(self.dns_servers),
            "vpn_interfaces": [dict(item) for item in self.vpn_interfaces],
        }


class NetworkMonitor:
    def __init__(self, executor=_run_command) -> None:
        self.executor = executor

    def collect_snapshot(self) -> NetworkMonitorSnapshot:
        interface = detect_preferred_interface()
        try:
            scope = detect_network_scope(interface)
        except Exception:
            scope = {
                "interface": interface,
                "ip_address": "",
                "netmask": "",
                "broadcast": "",
                "subnet": "",
                "gateway": "",
                "scope": "",
            }
        ifconfig_code, ifconfig_stdout, _ = self.executor(["/sbin/ifconfig"])
        if ifconfig_code != 0:
            ifconfig_stdout = ""
        active_interfaces = parse_active_interfaces(ifconfig_stdout)
        interface_details: list[dict[str, str]] = []
        vpn_interfaces: list[dict[str, str]] = []
        for candidate in active_interfaces:
            if not self._should_track_interface(candidate):
                continue
            details = _parse_ifconfig_interface(ifconfig_stdout, candidate)
            if not details or not details.get("ip_address"):
                continue
            interface_record = {
                "interface": candidate,
                "kind": self._interface_kind(candidate),
                "ip_address": details.get("ip_address", ""),
                "netmask": details.get("netmask", ""),
                "broadcast": details.get("broadcast", ""),
            }
            interface_details.append(interface_record)
            if not candidate.startswith(VPN_INTERFACE_PREFIXES):
                continue
            vpn_interfaces.append(dict(interface_record))
        return NetworkMonitorSnapshot(
            interface=str(scope.get("interface", interface)),
            ip_address=str(scope.get("ip_address", "")),
            netmask=str(scope.get("netmask", "")),
            gateway=str(scope.get("gateway", "")),
            subnet=str(scope.get("subnet", "")),
            scope=str(scope.get("scope", "")),
            wifi_ssid=self._collect_wifi_ssid(active_interfaces),
            active_interfaces=sorted(interface_details, key=lambda item: item.get("interface", "")),
            dns_servers=self._collect_dns_servers(),
            vpn_interfaces=sorted(vpn_interfaces, key=lambda item: item.get("interface", "")),
        )

    def evaluate(
        self,
        previous: NetworkMonitorSnapshot | None,
        current: NetworkMonitorSnapshot,
    ) -> list[BackgroundMonitorEvent]:
        if previous is None:
            return []
        timestamp = utc_now_iso()
        events: list[BackgroundMonitorEvent] = []
        events.extend(self._interface_change_events(previous, current, timestamp=timestamp))
        previous_primary = (previous.interface, previous.ip_address, previous.netmask, previous.gateway, previous.subnet)
        current_primary = (current.interface, current.ip_address, current.netmask, current.gateway, current.subnet)
        if current.ip_address and current_primary != previous_primary and not current.interface.startswith("lo"):
            evidence = (
                f"IP address assigned on {current.interface}: {current.ip_address} "
                f"(subnet {current.subnet or 'unknown'}, gateway {current.gateway or 'unknown'}). "
                f"Detected at {timestamp}."
            )
            rule = rule_for_event("network_ip_assigned")
            connection_rule = rule_for_event("new_network_connection_detected")
            outbound_rule = rule_for_event("new_outbound_connection_detected")
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="network_ip_assigned",
                    severity="medium",
                    source="network_state_observer",
                    evidence=evidence,
                    confidence="high",
                    recommendation="Confirm the new network connection is expected before relying on it for work.",
                    metadata={
                        "interface": current.interface,
                        "ip_address": current.ip_address,
                        "netmask": current.netmask,
                        "gateway": current.gateway,
                        "subnet": current.subnet,
                        "scope": current.scope,
                    },
                    rule=rule,
                    previous_state=f"{previous.interface or 'no interface'} had {previous.ip_address or 'no IP'}",
                    current_state=f"{current.interface} assigned {current.ip_address}",
                )
            )
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="new_network_connection_detected",
                    severity="high",
                    source="network_state_observer",
                    evidence=f"New active network connection observed on {current.interface}: {current.ip_address} (gateway {current.gateway or 'unknown'}). Detected at {timestamp}.",
                    confidence="high",
                    recommendation="Confirm the new connection matches expected network activity.",
                    metadata={
                        "interface": current.interface,
                        "ip_address": current.ip_address,
                        "netmask": current.netmask,
                        "gateway": current.gateway,
                        "subnet": current.subnet,
                        "scope": current.scope,
                    },
                    rule=connection_rule,
                    previous_state=f"{previous.interface or 'no interface'} had {previous.ip_address or 'no IP'}",
                    current_state=f"{current.interface} assigned {current.ip_address}",
                )
            )
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="new_outbound_connection_detected",
                    severity="high",
                    source="network_state_observer",
                    evidence=f"New outbound network path observed on {current.interface}: {current.ip_address} (gateway {current.gateway or 'unknown'}). Detected at {timestamp}.",
                    confidence="high",
                    recommendation="Confirm the outbound path matches expected host and network activity.",
                    metadata={
                        "interface": current.interface,
                        "ip_address": current.ip_address,
                        "netmask": current.netmask,
                        "gateway": current.gateway,
                        "subnet": current.subnet,
                        "scope": current.scope,
                    },
                    rule=outbound_rule,
                    previous_state=f"{previous.interface or 'no interface'} had {previous.ip_address or 'no IP'}",
                    current_state=f"{current.interface} outbound path active",
                )
            )
        if current.wifi_ssid and current.wifi_ssid != previous.wifi_ssid:
            rule = rule_for_event("new_network_connection_detected")
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="new_network_connection_detected",
                    severity="high",
                    source="network_state_observer",
                    evidence=f"Wi-Fi network changed from {previous.wifi_ssid or 'none'} to {current.wifi_ssid}. Detected at {timestamp}.",
                    confidence="high",
                    recommendation="Confirm the Wi-Fi network is trusted before continuing sensitive work.",
                    metadata={
                        "interface": current.interface,
                        "wifi_ssid": current.wifi_ssid,
                        "previous_wifi_ssid": previous.wifi_ssid,
                        "ip_address": current.ip_address,
                        "gateway": current.gateway,
                    },
                    rule=rule,
                    previous_state=previous.wifi_ssid or "no wifi network",
                    current_state=current.wifi_ssid,
                )
            )
        previous_vpn = {self._vpn_signature(item) for item in previous.vpn_interfaces}
        current_vpn = [item for item in current.vpn_interfaces if self._vpn_signature(item) not in previous_vpn]
        if current_vpn:
            summary = "; ".join(
                f"{item.get('interface', '')} {item.get('ip_address', '')}".strip()
                for item in current_vpn[:3]
            )
            if len(current_vpn) > 3:
                summary += f"; and {len(current_vpn) - 3} more"
            rule = rule_for_event("vpn_connected")
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="vpn_connected",
                    severity="medium",
                    source="network_state_observer",
                    evidence=f"VPN connection assigned: {summary}. Detected at {timestamp}.",
                    confidence="high",
                    recommendation="Confirm the VPN connection is expected and matches the intended profile.",
                    metadata={
                        "vpn_interfaces": current_vpn,
                    },
                    rule=rule,
                    previous_state="no new vpn interface observed",
                    current_state=f"vpn interfaces present: {summary}",
                )
            )
        removed_vpn = [item for item in previous.vpn_interfaces if self._vpn_signature(item) not in {self._vpn_signature(v) for v in current.vpn_interfaces}]
        if removed_vpn:
            summary = "; ".join(
                f"{item.get('interface', '')} {item.get('ip_address', '')}".strip()
                for item in removed_vpn[:3]
            )
            if len(removed_vpn) > 3:
                summary += f"; and {len(removed_vpn) - 3} more"
            rule = rule_for_event("vpn_disconnected")
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="vpn_disconnected",
                    severity="medium",
                    source="network_state_observer",
                    evidence=f"VPN connection removed: {summary}. Detected at {timestamp}.",
                    confidence="high",
                    recommendation="Confirm the VPN disconnect is expected and review nearby session events.",
                    metadata={
                        "vpn_interfaces": removed_vpn,
                    },
                    rule=rule,
                    previous_state=f"vpn interfaces present: {summary}",
                    current_state="no vpn interface observed",
                )
            )
        if current.gateway and current.gateway != previous.gateway:
            rule = rule_for_event("new_gateway_detected")
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="new_gateway_detected",
                    severity="high",
                    source="network_state_observer",
                    evidence=f"Default gateway changed from {previous.gateway or 'none'} to {current.gateway} on {current.interface or 'unknown interface'}. Detected at {timestamp}.",
                    confidence="high",
                    recommendation="Confirm the gateway belongs to the expected network before continuing sensitive work.",
                    metadata={
                        "interface": current.interface,
                        "previous_gateway": previous.gateway,
                        "gateway": current.gateway,
                        "ip_address": current.ip_address,
                        "subnet": current.subnet,
                    },
                    rule=rule,
                    previous_state=previous.gateway or "no gateway",
                    current_state=current.gateway,
                )
            )
        previous_dns = set(previous.dns_servers)
        current_dns = set(current.dns_servers)
        if current_dns and current_dns != previous_dns:
            added = sorted(current_dns - previous_dns)
            removed = sorted(previous_dns - current_dns)
            rule = rule_for_event("new_dns_server_detected")
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="new_dns_server_detected",
                    severity="high",
                    source="network_state_observer",
                    evidence=(
                        "DNS server configuration changed; "
                        f"added={', '.join(added) if added else 'none'}; "
                        f"removed={', '.join(removed) if removed else 'none'}. Detected at {timestamp}."
                    ),
                    confidence="high",
                    recommendation="Confirm DNS servers are expected for this network, VPN, or managed profile.",
                    metadata={
                        "dns_servers": sorted(current_dns),
                        "previous_dns_servers": sorted(previous_dns),
                        "added": added,
                        "removed": removed,
                    },
                    rule=rule,
                    previous_state=", ".join(sorted(previous_dns)) or "no dns servers",
                    current_state=", ".join(sorted(current_dns)),
                )
            )
        return events

    def _vpn_signature(self, item: dict[str, str]) -> str:
        return "|".join(str(item.get(key, "")).strip() for key in ["interface", "ip_address", "netmask", "broadcast"])

    def _interface_signature(self, item: dict[str, str]) -> str:
        return "|".join(str(item.get(key, "")).strip() for key in ["interface", "ip_address", "netmask", "broadcast", "kind"])

    def _interface_kind(self, interface: str) -> str:
        if interface.startswith(VPN_INTERFACE_PREFIXES):
            return "vpn"
        if interface.startswith("en"):
            return "ethernet_or_wifi"
        if interface.startswith("bridge"):
            return "bridge"
        if interface.startswith("awdl") or interface.startswith("llw"):
            return "apple_wireless_direct"
        if interface.startswith("ap"):
            return "wireless_access_point"
        if interface.startswith("thunderbolt"):
            return "thunderbolt"
        return "network"

    def _should_track_interface(self, interface: str) -> bool:
        if interface.startswith("lo"):
            return False
        if interface.startswith("awdl") or interface.startswith("llw"):
            return False
        return True

    def _collect_dns_servers(self) -> list[str]:
        code, stdout, _ = self.executor(["/usr/sbin/scutil", "--dns"])
        if code != 0:
            return []
        servers: set[str] = set()
        for line in stdout.splitlines():
            if "nameserver[" not in line or ":" not in line:
                continue
            value = line.split(":", 1)[1].strip()
            if value:
                servers.add(value)
        return sorted(servers)

    def _collect_wifi_ssid(self, active_interfaces: list[str]) -> str:
        for interface in [item for item in active_interfaces if item.startswith("en")]:
            code, stdout, _ = self.executor(["/usr/sbin/networksetup", "-getairportnetwork", interface])
            if code != 0:
                continue
            text = stdout.strip()
            if not text or "not associated" in text.lower():
                continue
            if ":" in text:
                ssid = text.split(":", 1)[1].strip()
                if ssid:
                    return ssid
        return ""

    def _interface_change_events(
        self,
        previous: NetworkMonitorSnapshot,
        current: NetworkMonitorSnapshot,
        *,
        timestamp: str,
    ) -> list[BackgroundMonitorEvent]:
        events: list[BackgroundMonitorEvent] = []
        previous_by_signature = {self._interface_signature(item): item for item in previous.active_interfaces}
        current_by_signature = {self._interface_signature(item): item for item in current.active_interfaces}
        previous_by_name = {item.get("interface", ""): item for item in previous.active_interfaces}
        current_by_name = {item.get("interface", ""): item for item in current.active_interfaces}
        added = [item for signature, item in current_by_signature.items() if signature not in previous_by_signature]
        removed = [item for signature, item in previous_by_signature.items() if signature not in current_by_signature]
        for item in sorted(added, key=lambda value: value.get("interface", "")):
            interface = item.get("interface", "")
            if interface in previous_by_name:
                continue
            rule = rule_for_event("network_interface_connected")
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="network_interface_connected",
                    severity="medium",
                    source="network_state_observer",
                    evidence=(
                        f"Network interface connected: {interface or 'unknown'} "
                        f"({item.get('kind', 'network')}) assigned {item.get('ip_address', 'unknown IP')}. "
                        f"Detected at {timestamp}."
                    ),
                    confidence="high",
                    recommendation="Confirm the new interface is expected for this workstation, dock, VPN, or managed network.",
                    metadata=item,
                    rule=rule,
                    previous_state="interface not active",
                    current_state=f"{interface} {item.get('ip_address', '')}".strip(),
                )
            )
        for item in sorted(removed, key=lambda value: value.get("interface", "")):
            interface = item.get("interface", "")
            if interface in current_by_name:
                continue
            rule = rule_for_event("network_interface_disconnected")
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="network_interface_disconnected",
                    severity="medium",
                    source="network_state_observer",
                    evidence=(
                        f"Network interface disconnected: {interface or 'unknown'} "
                        f"({item.get('kind', 'network')}) previously had {item.get('ip_address', 'unknown IP')}. "
                        f"Detected at {timestamp}."
                    ),
                    confidence="high",
                    recommendation="Confirm the interface disconnect was expected and review nearby session/device activity.",
                    metadata=item,
                    rule=rule,
                    previous_state=f"{interface} {item.get('ip_address', '')}".strip(),
                    current_state="interface not active",
                )
            )
        for interface, current_item in sorted(current_by_name.items()):
            previous_item = previous_by_name.get(interface)
            if not previous_item:
                continue
            if self._interface_signature(previous_item) == self._interface_signature(current_item):
                continue
            rule = rule_for_event("network_ip_assigned")
            events.append(
                self._event(
                    timestamp=timestamp,
                    event_type="network_ip_assigned",
                    severity="medium",
                    source="network_state_observer",
                    evidence=(
                        f"Network interface changed: {interface} ({current_item.get('kind', 'network')}) "
                        f"moved from {previous_item.get('ip_address', 'unknown IP')} to {current_item.get('ip_address', 'unknown IP')}. "
                        f"Detected at {timestamp}."
                    ),
                    confidence="high",
                    recommendation="Confirm the interface IP change matches expected network activity.",
                    metadata={"previous": previous_item, "current": current_item, **current_item},
                    rule=rule,
                    previous_state=f"{interface} {previous_item.get('ip_address', '')}".strip(),
                    current_state=f"{interface} {current_item.get('ip_address', '')}".strip(),
                )
            )
        return events

    def _event(
        self,
        *,
        timestamp: str,
        event_type: str,
        severity: str,
        source: str,
        evidence: str,
        confidence: str,
        recommendation: str,
        metadata: dict,
        rule=None,
        previous_state: str = "",
        current_state: str = "",
    ) -> BackgroundMonitorEvent:
        fingerprint = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode("utf-8")).hexdigest()[:12]
        rule = rule or rule_for_event(event_type)
        raw_summary = evidence
        return BackgroundMonitorEvent(
            event_id=f"{event_type}-{timestamp}-{fingerprint}",
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source=source,
            evidence=evidence,
            confidence=confidence,
            recommendation=recommendation,
            metadata_json=json.dumps(metadata, sort_keys=True),
            rule_id=rule.rule_id,
            rule_name=rule.name,
            trigger_source="network_detector",
            trigger_subsource=self._trigger_subsource_for(event_type),
            trigger_rule_id=rule.rule_id,
            trigger_rule_name=rule.name,
            raw_signal_summary=raw_summary,
            normalized_signal=normalized_signal(event_type, raw_summary, metadata),
            evidence_hash=evidence_hash(event_type, raw_summary, metadata),
            first_seen=timestamp,
            last_seen=timestamp,
            previous_state=previous_state,
            current_state=current_state,
            baseline_status=self._baseline_status_for(event_type),
            correlation_id=correlation_id_for(event_type, source, metadata.get("interface", ""), timestamp=timestamp),
            false_positive_hints=list(rule.false_positive_hints),
            recommended_verification_steps=list(rule.verification_steps),
            source_trace=f"Detector={rule.source_detector}; Rule={rule.rule_id}; Evidence={raw_summary}",
        )

    def _trigger_subsource_for(self, event_type: str) -> str:
        if event_type in {"network_ip_assigned", "network_interface_connected", "network_interface_disconnected", "new_network_connection_detected", "new_gateway_detected", "new_dns_server_detected"}:
            return "ifconfig_route_dns_state"
        if event_type in {"vpn_connected", "vpn_disconnected"}:
            return "vpn_interface_state"
        return "network_state_observer"

    def _baseline_status_for(self, event_type: str) -> str:
        if event_type == "network_ip_assigned":
            return "new network assignment"
        if event_type in {"network_interface_connected", "network_interface_disconnected"}:
            return "network interface inventory changed"
        if event_type in {"new_gateway_detected", "new_dns_server_detected"}:
            return "network resolver or route changed"
        if event_type in {"vpn_connected", "vpn_disconnected"}:
            return "vpn interface changed"
        return "network connection changed"


class NetworkStateObserver:
    def __init__(self, monitor: NetworkMonitor, poll_seconds: float = 2.0, quiet_window_seconds: float = 4.0) -> None:
        self.monitor = monitor
        self.poll_seconds = max(0.5, poll_seconds)
        self.quiet_window_seconds = max(self.poll_seconds, quiet_window_seconds)
        self.events: queue.Queue[BackgroundMonitorEvent] = queue.Queue()
        self.current_snapshot: NetworkMonitorSnapshot | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="mac-audit-network-observer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.poll_seconds * 2))

    def drain(self) -> list[BackgroundMonitorEvent]:
        drained: list[BackgroundMonitorEvent] = []
        while True:
            try:
                drained.append(self.events.get_nowait())
            except queue.Empty:
                return drained

    def _run(self) -> None:
        previous = self.monitor.collect_snapshot()
        self.current_snapshot = previous
        pending: list[BackgroundMonitorEvent] = []
        last_change = 0.0
        while not self._stop.wait(self.poll_seconds):
            current = self.monitor.collect_snapshot()
            self.current_snapshot = current
            events = self.monitor.evaluate(previous, current)
            if events:
                pending.extend(events)
                last_change = time.monotonic()
            if pending and time.monotonic() - last_change >= self.quiet_window_seconds:
                for event in pending:
                    self.events.put(event)
                pending.clear()
            previous = current
