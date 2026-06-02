# Background Monitor UAT

## Preconditions

- Run the desktop app as the logged-in macOS user.
- Do not use `sudo` for the user LaunchAgent workflow.
- Expected plist path:
  `~/Library/LaunchAgents/com.mac-audit-agent.monitor.plist`
- Expected launchctl domain:
  `gui/<uid>`

For system-daemon validation, run the install flow with `MAC_AUDIT_AGENT_LAUNCH_SCOPE=system` from an elevated shell. The expected plist path becomes `/Library/LaunchDaemons/com.mac-audit-agent.monitor.plist` and the launchctl domain becomes `system`.

## Test Cases

### 1. Install LaunchAgent

Action:
- Open `Background Monitor`.
- Click `Install Background Monitor`.

Expected:
- `~/Library/LaunchAgents/com.mac-audit-agent.monitor.plist` exists.
- `launchctl print gui/<uid>/com.mac-audit-agent.monitor` works.
- Monitor health shows `LaunchAgent installed: yes`.

### 2. Start monitor

Action:
- Click `Start Monitor`.

Expected:
- No `sudo` prompt is required.
- Monitor health shows `LaunchAgent loaded: yes`.
- Monitor PID is visible.
- Heartbeat updates within 60 seconds.

### 3. Generate test event

Action:
- Click `Generate Test Event`.

Expected:
- Event appears in the recent events table.
- Event is saved in SQLite immediately.
- A user notification appears.
- Event appears in exported JSON and HTML when monitor logs are included.

### 4. Display sleep/wake

Action:
- Lock the screen or sleep and wake the display.

Expected:
- A screen or system wake/sleep or lock/unlock event is logged when detectable.
- A user notification appears.

### 5. Camera/process simulation

Action:
- Open FaceTime, Photo Booth, Zoom, Teams, or QuickTime Player.

Expected:
- `camera_activity_suspected` or `capture_process_observed` is logged.
- A notification appears.
- Confidence remains `low` or `medium` unless a public API confirms active use.

### 6. Screen sharing posture

Action:
- Enable or disable Screen Sharing in System Settings.

Expected:
- `screen_sharing_enabled` or `screen_sharing_disabled` is logged.
- A notification appears.

### 7. Stop monitor

Action:
- Click `Stop Monitor`.

Expected:
- Monitor process stops.
- Heartbeat stops advancing.
- UI shows `stopped`.

### 8. Restart after logout/login

Action:
- Log out and back in.

Expected:
- LaunchAgent starts automatically.
- A new heartbeat appears.

### 9. Export logs

Action:
- Export JSON or HTML with background monitor logs included.

Expected:
- Monitor events are present in the export.
- Camera video, microphone audio, screen contents, keystrokes, and packet contents are not included.

### 10. USB reconnect recognition

Action:
- Unplug and reconnect a previously trusted USB device.

Expected:
- One grouped `usb_device_connected` event is recorded after the quiet window.
- The Notification Center banner uses the `Pop` sound.
- The event remains informational and does not activate the persistent overlay.

### 11. First-seen USB device

Action:
- Connect a USB device that has not been seen before by the current trusted inventory.

Expected:
- `new_usb_device_detected` is recorded at critical severity.
- The `Pop` sound is used.
- The persistent bottom-right overlay becomes active until acknowledged.
- The event is saved locally and appears in exports.

### 12. New network IP assignment

Action:
- Join a new Wi-Fi or Ethernet network so the active interface receives a new IP assignment.

Expected:
- `network_ip_assigned` is recorded at informational severity.
- A subtle grey bottom-right overlay appears.
- The event remains logged locally and appears in exports.

### 13. New VPN connection

Action:
- Connect a VPN profile that creates a new tunnel interface.

Expected:
- `vpn_connected` is recorded at informational severity.
- A subtle grey bottom-right overlay appears.
- The event remains logged locally and appears in exports.

### 14. Permission denied / notification denied

Action:
- Simulate a notification or database write failure.

Expected:
- UI shows a clear warning.
- `~/Library/Logs/MacAuditAgent/monitor.log` contains the fallback error entry.
- The app does not crash.

### 15. New startup daemon or persistence item

Action:
- Add a new LaunchDaemon, LaunchAgent, or login item on a test machine.

Expected:
- New `/Library/LaunchDaemons` entries trigger a critical `launchdaemon_added` alert.
- New LaunchAgents or login items trigger a critical persistence alert.
- The monitor log records the previous and current persistence inventories.
- The event is saved locally and appears in exports.

### 16. System daemon install

Action:
- Install the monitor with `MAC_AUDIT_AGENT_LAUNCH_SCOPE=system`.

Expected:
- The plist is written to `/Library/LaunchDaemons/com.mac-audit-agent.monitor.plist`.
- The runtime root is shared under `/Library/Application Support/MacAuditAgent/runtime`.
- Logs are written under `/Library/Logs/MacAuditAgent`.
- The daemon reports `system` as its launchctl domain.

### 17. Input resumes after idle

Action:
- Leave the keyboard, mouse, and trackpad untouched for 2 minutes, then resume input.

Expected:
- `input_activity_resumed_after_idle` is recorded at medium severity.
- The authorized-use CFAA reminder dialog appears again after the idle period.
- The event is stored locally and appears in the recent events table.

### 18. Show Context timeline

Action:
- Select a finding in Results and click `Show Context`, or select a monitor event and click `Show Context`.

Expected:
- A timeline opens showing activity 15 minutes before and 15 minutes after the selected item.
- The context view includes scan summaries, monitor events, persistence changes, network changes, USB changes, session events, and admin-related changes that fall inside the window.
- The dialog shows evidence only and does not infer compromise.
