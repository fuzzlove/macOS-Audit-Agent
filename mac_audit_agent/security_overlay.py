from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QVBoxLayout, QWidget


POLL_MILLISECONDS = 750
SEVERITY_STYLES = {
    "info": {
        "background": "rgba(112, 112, 112, 185)",
        "border": "rgba(230, 230, 230, 80)",
        "opacity": 0.88,
    },
    "medium": {
        "background": "rgba(138, 91, 52, 205)",
        "border": "rgba(255, 214, 153, 110)",
        "opacity": 0.92,
    },
    "high": {
        "background": "rgba(122, 64, 8, 220)",
        "border": "rgba(255, 200, 120, 140)",
        "opacity": 0.95,
    },
    "critical": {
        "background": "rgba(107, 0, 0, 225)",
        "border": "rgba(255, 190, 190, 160)",
        "opacity": 0.97,
    },
}


class SecurityOverlay(QWidget):
    def __init__(self, state_path: Path) -> None:
        super().__init__()
        self.state_path = state_path
        self._last_payload = ""
        self.setWindowTitle("Mac Audit Agent Security Notice")
        self.setWindowFlags(
            Qt.WindowType.Tool
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.FramelessWindowHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.setFixedWidth(390)
        self.setObjectName("securityOverlayRoot")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        self.title = QLabel()
        self.title.setStyleSheet("font-size: 15px; font-weight: bold;")
        self.details = QLabel()
        self.details.setWordWrap(True)
        self.notice = QLabel(
            "Authorized use only. Activity is logged. This indicator is not a legal determination."
        )
        self.notice.setWordWrap(True)
        self.notice.setStyleSheet("font-size: 11px;")
        self.acknowledge = QPushButton("Acknowledge")
        self.acknowledge.clicked.connect(self._acknowledge)
        for widget in [self.title, self.details, self.notice, self.acknowledge]:
            widget.setStyleSheet("color: #FFFFFF;")
            layout.addWidget(widget)
        timer = QTimer(self)
        timer.timeout.connect(self.refresh)
        timer.start(POLL_MILLISECONDS)
        self.refresh()

    def refresh(self) -> None:
        try:
            raw = self.state_path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            self.hide()
            return
        if raw == self._last_payload:
            return
        self._last_payload = raw
        if not payload.get("active", False):
            self.hide()
            return
        severity = str(payload.get("severity", "info")).lower()
        count = int(payload.get("count", 1) or 1)
        self.title.setText(f"{severity.upper()} security indicator")
        self.details.setText(
            f"{payload.get('event_type', 'security_event')}\n"
            f"{payload.get('summary', '')}\n"
            f"Detected: {payload.get('timestamp', '')}\n"
            f"Grouped events: {count}"
        )
        style = SEVERITY_STYLES.get(severity, SEVERITY_STYLES["info"])
        self.setWindowOpacity(style["opacity"])
        self.setStyleSheet(
            "#securityOverlayRoot {"
            f"background-color: {style['background']};"
            f"border: 1px solid {style['border']};"
            "border-radius: 14px;"
            "}"
            "QPushButton {"
            "background-color: rgba(255, 255, 255, 28);"
            "border: 1px solid rgba(255, 255, 255, 60);"
            "border-radius: 8px;"
            "padding: 6px 10px;"
            "color: #FFFFFF;"
            "}"
            "QPushButton:hover {"
            "background-color: rgba(255, 255, 255, 40);"
            "}"
        )
        self.adjustSize()
        self._move_to_bottom_right()
        self.show()
        self.raise_()

    def _move_to_bottom_right(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        available = screen.availableGeometry()
        margin = 18
        self.move(available.right() - self.width() - margin, available.bottom() - self.height() - margin)

    def _acknowledge(self) -> None:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            payload["active"] = False
            payload["acknowledged_by_pid"] = os.getpid()
            self.state_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        except (OSError, json.JSONDecodeError):
            pass
        self.hide()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mac Audit Agent persistent security overlay")
    parser.add_argument("--state-path", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    app = QApplication(sys.argv[:1])
    overlay = SecurityOverlay(args.state_path)
    overlay.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
