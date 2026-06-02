from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


RECOVERY_BUTTON_STYLES = {
    "primary": """
        QPushButton[recoveryButtonRole="primary"] {
            background: #1F6FEB;
            color: #FFFFFF;
            border: 1px solid #58A6FF;
            border-radius: 6px;
            min-height: 36px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
        }
        QPushButton[recoveryButtonRole="primary"]:hover { background: #256ADF; }
        QPushButton[recoveryButtonRole="primary"]:pressed { background: #195BB8; }
        QPushButton[recoveryButtonRole="primary"]:focus { border: 2px solid #F0F6FC; }
    """,
    "secondary": """
        QPushButton[recoveryButtonRole="secondary"] {
            background: #30363D;
            color: #F0F6FC;
            border: 1px solid #8B949E;
            border-radius: 6px;
            min-height: 36px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
        }
        QPushButton[recoveryButtonRole="secondary"]:hover { background: #3A4047; }
        QPushButton[recoveryButtonRole="secondary"]:pressed { background: #262B31; }
        QPushButton[recoveryButtonRole="secondary"]:focus { border: 2px solid #F0F6FC; }
    """,
    "warning": """
        QPushButton[recoveryButtonRole="warning"] {
            background: #9A6700;
            color: #FFFFFF;
            border: 1px solid #D29922;
            border-radius: 6px;
            min-height: 36px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
        }
        QPushButton[recoveryButtonRole="warning"]:hover { background: #B07800; }
        QPushButton[recoveryButtonRole="warning"]:pressed { background: #7F5600; }
        QPushButton[recoveryButtonRole="warning"]:focus { border: 2px solid #F0F6FC; }
    """,
    "urgent": """
        QPushButton[recoveryButtonRole="urgent"] {
            background: #7A1F5C;
            color: #FFFFFF;
            border: 1px solid #D2A8FF;
            border-radius: 6px;
            min-height: 36px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
        }
        QPushButton[recoveryButtonRole="urgent"]:hover { background: #8A2468; }
        QPushButton[recoveryButtonRole="urgent"]:pressed { background: #65184B; }
        QPushButton[recoveryButtonRole="urgent"]:focus { border: 2px solid #F0F6FC; }
    """,
    "disabled": """
        QPushButton:disabled {
            background: #484F58;
            color: #8B949E;
            border: 1px solid #6E7681;
            border-radius: 6px;
            min-height: 36px;
            padding: 6px 10px;
            font-size: 12px;
            font-weight: 600;
        }
    """,
}


def make_recovery_button(text: str, tooltip: str, style: str = "primary", min_width: int | None = None) -> QPushButton:
    button = QPushButton(text)
    button.setToolTip(tooltip)
    button.setMinimumHeight(36)
    button.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
    button.setProperty("recoveryButtonRole", style)
    button.setCursor(Qt.PointingHandCursor)
    button.setStyleSheet(RECOVERY_BUTTON_STYLES.get(style, RECOVERY_BUTTON_STYLES["secondary"]) + RECOVERY_BUTTON_STYLES["disabled"])
    button.setMinimumWidth(max(110, len(text) * 8 + 28) if min_width is None else min_width)
    return button


class RecoveryEvidenceWarningDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Potential Evidence Preservation Risk")
        self._choice = "cancel"
        layout = QVBoxLayout(self)
        warning = QLabel(
            "This system may contain logs, caches, temporary files, browser data, or application artifacts that could assist future troubleshooting or incident investigation.\n\n"
            "Cleanup may permanently remove evidence.\n\n"
            "Continue only if you understand the impact."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)
        button_row = QHBoxLayout()
        self.cancel_button = make_recovery_button("Cancel", "Close this dialog and cancel cleanup.", "secondary")
        self.snapshot_button = make_recovery_button("Create Evidence Snapshot First", "Create an evidence snapshot before cleanup.", "primary", min_width=240)
        self.continue_button = make_recovery_button("Continue Cleanup", "Proceed with cleanup after reviewing the preservation warning.", "urgent", min_width=180)
        self.snapshot_button.setDefault(True)
        self.snapshot_button.setAutoDefault(True)
        self.cancel_button.clicked.connect(lambda: self._finish("cancel"))
        self.snapshot_button.clicked.connect(lambda: self._finish("snapshot"))
        self.continue_button.clicked.connect(lambda: self._finish("continue"))
        for button in [self.cancel_button, self.snapshot_button, self.continue_button]:
            button_row.addWidget(button)
        layout.addLayout(button_row)

    def _finish(self, choice: str) -> None:
        self._choice = choice
        if choice == "cancel":
            self.reject()
        else:
            self.accept()

    def choice(self) -> str:
        return self._choice


class SystemRecoveryPanel(QFrame):
    incident_check_requested = Signal()
    snapshot_requested = Signal()
    preview_requested = Signal()
    cleanup_requested = Signal()
    open_snapshots_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("systemRecoveryPanel")
        self.setFrameShape(QFrame.StyledPanel)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._recovery_data: dict[str, Any] = {}
        self._build_ui()
        self.set_recovery_data(
            {
                "assessment": {
                    "title": "Recovery not checked yet",
                    "level": "safe",
                    "reasons": ["No recovery assessment has been generated yet."],
                    "recommendation": "Open the tab or run an incident check to inspect cleanup risk.",
                },
                "preview": {
                    "generated_at": "",
                    "summary": "No cleanup preview has been generated yet.",
                    "recovery_score": 0,
                    "opportunities": 0,
                    "total_recoverable_bytes": 0,
                    "performance_improvement": "Low",
                    "risk_level": "safe",
                    "candidates": [],
                    "growth_summary": [],
                    "protected_paths": [],
                },
                "snapshot_history": [],
                "cleanup_history": [],
                "cache_age": "unknown",
                "generated_at": "",
                "last_error": "",
            }
        )

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header_row = QHBoxLayout()
        title_block = QVBoxLayout()
        self.title_label = QLabel("System Recovery")
        self.title_label.setStyleSheet("font-size: 18px; font-weight: 700; color: #F0F6FC;")
        self.subtitle_label = QLabel("Storage, cleanup, snapshots, performance, and recommendations.")
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setStyleSheet("color: #9DB0C9;")
        title_block.addWidget(self.title_label)
        title_block.addWidget(self.subtitle_label)
        header_row.addLayout(title_block)
        header_row.addStretch(1)
        self.recovery_state_label = QLabel("Recovery not checked yet")
        self.recovery_state_label.setStyleSheet("font-size: 14px; font-weight: 700; color: #D6E4FF;")
        header_row.addWidget(self.recovery_state_label)
        layout.addLayout(header_row)

        summary_row = QHBoxLayout()
        self.recovery_score_label = QLabel("Recovery Score: --")
        self.space_recovery_label = QLabel("Potential Space Recovery: --")
        self.last_checked_label = QLabel("Last checked: not yet")
        self.cache_age_label = QLabel("Cache age: unknown")
        for label in [self.recovery_score_label, self.space_recovery_label, self.last_checked_label, self.cache_age_label]:
            label.setStyleSheet("color: #D6E4FF;")
            summary_row.addWidget(label)
        summary_row.addStretch(1)
        layout.addLayout(summary_row)

        toolbar = QHBoxLayout()
        self.incident_check_button = make_recovery_button("Run Incident Check", "Evaluate cleanup risk before any cleanup operation.", "warning")
        self.snapshot_button = make_recovery_button("Create Evidence Snapshot", "Create a forensic snapshot before cleanup.", "primary")
        self.preview_button = make_recovery_button("Preview Cleanup", "Preview candidate files and estimated space recovery without deleting anything.", "secondary")
        self.cleanup_button = make_recovery_button("Run Cleanup", "Run cleanup only after review and a preservation warning.", "urgent")
        self.open_snapshots_button = make_recovery_button("Open Snapshots Folder", "Open the local evidence snapshot folder.", "secondary")
        for button in [
            self.incident_check_button,
            self.snapshot_button,
            self.preview_button,
            self.cleanup_button,
            self.open_snapshots_button,
        ]:
            toolbar.addWidget(button)
        layout.addLayout(toolbar)

        self.incident_check_button.clicked.connect(self.incident_check_requested.emit)
        self.snapshot_button.clicked.connect(self.snapshot_requested.emit)
        self.preview_button.clicked.connect(self.preview_requested.emit)
        self.cleanup_button.clicked.connect(self.cleanup_requested.emit)
        self.open_snapshots_button.clicked.connect(self.open_snapshots_requested.emit)

        self.tabs = QTabWidget()
        self.storage_tab = QWidget()
        self.cleanup_tab = QWidget()
        self.snapshots_tab = QWidget()
        self.performance_tab = QWidget()
        self.recommendations_tab = QWidget()
        self._build_storage_tab()
        self._build_cleanup_tab()
        self._build_snapshots_tab()
        self._build_performance_tab()
        self._build_recommendations_tab()
        self.tabs.addTab(self.storage_tab, "Storage")
        self.tabs.addTab(self.cleanup_tab, "Cleanup")
        self.tabs.addTab(self.snapshots_tab, "Snapshots")
        self.tabs.addTab(self.performance_tab, "Performance")
        self.tabs.addTab(self.recommendations_tab, "Recommendations")
        layout.addWidget(self.tabs, 1)

        self.setStyleSheet(
            """
            QFrame#systemRecoveryPanel {
                background: rgba(18, 24, 34, 210);
                border: 1px solid rgba(127, 139, 166, 90);
                border-radius: 16px;
            }
            QTabWidget::pane {
                border: 1px solid rgba(127, 139, 166, 70);
                border-radius: 10px;
            }
            QTableWidget {
                background: rgba(10, 14, 24, 110);
                border: 1px solid rgba(127, 139, 166, 60);
                border-radius: 8px;
                color: #ECF4FF;
            }
            QTextEdit, QLineEdit {
                background: rgba(10, 14, 24, 100);
                border: 1px solid rgba(127, 139, 166, 60);
                border-radius: 8px;
                color: #ECF4FF;
            }
            QCheckBox {
                color: #D6E4FF;
            }
            """
        )

    def _build_storage_tab(self) -> None:
        layout = QVBoxLayout(self.storage_tab)
        layout.addWidget(QLabel("Largest cache consumers and recent growth compared to local baselines."))
        self.storage_summary_label = QLabel("No storage preview yet.")
        self.storage_summary_label.setWordWrap(True)
        layout.addWidget(self.storage_summary_label)
        self.storage_table = self._make_table(["Category", "Kind", "Path", "Current", "Baseline", "Recoverable", "Recommendation", "Risk"])
        layout.addWidget(self.storage_table, 1)

    def _build_cleanup_tab(self) -> None:
        layout = QVBoxLayout(self.cleanup_tab)
        layout.addWidget(QLabel("Review cleanup candidates before deleting anything. Protected artifacts are never cleaned automatically."))
        self.cleanup_scope_label = QLabel("No cleanup preview yet.")
        self.cleanup_scope_label.setWordWrap(True)
        layout.addWidget(self.cleanup_scope_label)
        root_row = QHBoxLayout()
        root_row.addWidget(QLabel("Optional user-selected log folder"))
        self.custom_cleanup_root = QLineEdit()
        self.custom_cleanup_root.setPlaceholderText("Choose a log folder to include in preview")
        self.custom_cleanup_root.textChanged.connect(self._update_custom_root_hint)
        root_row.addWidget(self.custom_cleanup_root, 1)
        self.browse_root_button = make_recovery_button("Browse", "Select a custom log folder to add to preview.", "secondary", min_width=110)
        self.browse_root_button.clicked.connect(self._browse_cleanup_root)
        root_row.addWidget(self.browse_root_button)
        layout.addLayout(root_row)
        self.custom_root_hint = QLabel("No custom cleanup folder selected.")
        self.custom_root_hint.setWordWrap(True)
        layout.addWidget(self.custom_root_hint)
        self.cleanup_table = self._make_table(["Category", "Kind", "Path", "Current", "Baseline", "Recoverable", "Recommendation", "Risk"])
        self.cleanup_table.itemSelectionChanged.connect(self._update_cleanup_selection_label)
        self.cleanup_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.cleanup_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.cleanup_table, 1)
        self.cleanup_selection_label = QLabel("Selected cleanup paths: none")
        self.cleanup_selection_label.setWordWrap(True)
        layout.addWidget(self.cleanup_selection_label)

    def _build_snapshots_tab(self) -> None:
        layout = QVBoxLayout(self.snapshots_tab)
        layout.addWidget(QLabel("Snapshots and cleanup actions are stored locally for forensic preservation."))
        self.snapshot_history_table = self._make_table(["Created At", "Snapshot ID", "Reason", "Assessment", "Path"])
        self.cleanup_history_table = self._make_table(["Created At", "Action", "Risk", "Result", "Snapshot ID"])
        layout.addWidget(QLabel("Snapshot History"))
        layout.addWidget(self.snapshot_history_table, 1)
        layout.addWidget(QLabel("Cleanup History"))
        layout.addWidget(self.cleanup_history_table, 1)

    def _build_performance_tab(self) -> None:
        layout = QVBoxLayout(self.performance_tab)
        self.performance_summary_label = QLabel("No performance estimate yet.")
        self.performance_summary_label.setWordWrap(True)
        layout.addWidget(self.performance_summary_label)
        self.recovery_metrics_table = self._make_table(["Field", "Value"])
        layout.addWidget(self.recovery_metrics_table, 1)
        self.growth_table = self._make_table(["Path", "Category", "Baseline", "Current", "Growth"])
        layout.addWidget(self.growth_table, 1)

    def _build_recommendations_tab(self) -> None:
        layout = QVBoxLayout(self.recommendations_tab)
        self.incident_title_label = QLabel("Incident awareness has not run yet.")
        self.incident_title_label.setWordWrap(True)
        self.incident_title_label.setStyleSheet("font-weight: 700; color: #F0F6FC;")
        layout.addWidget(self.incident_title_label)
        self.incident_reasons = QTextEdit()
        self.incident_reasons.setReadOnly(True)
        layout.addWidget(self.incident_reasons, 1)
        self.no_alerts_label = QLabel("Why no alerts? No recovery assessment has been generated yet.")
        self.no_alerts_label.setWordWrap(True)
        layout.addWidget(self.no_alerts_label)
        self.protected_paths_label = QTextEdit()
        self.protected_paths_label.setReadOnly(True)
        layout.addWidget(self.protected_paths_label, 1)

    def _make_table(self, headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setStretchLastSection(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setWordWrap(True)
        return table

    def _populate_table(self, table: QTableWidget, rows: list[list[str]]) -> None:
        table.setRowCount(0)
        for row_data in rows:
            row = table.rowCount()
            table.insertRow(row)
            for column, value in enumerate(row_data):
                table.setItem(row, column, QTableWidgetItem(value))
        table.resizeRowsToContents()

    def _browse_cleanup_root(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Cleanup Log Folder")
        if path:
            self.custom_cleanup_root.setText(path)

    def _update_custom_root_hint(self, *_args) -> None:
        value = self.custom_cleanup_root.text().strip()
        if value:
            self.custom_root_hint.setText(f"User-selected cleanup folder: {value}")
        else:
            self.custom_root_hint.setText("No custom cleanup folder selected.")

    def _update_cleanup_selection_label(self) -> None:
        self.cleanup_selection_label.setText(
            "Selected cleanup paths: " + (", ".join(self.selected_cleanup_paths()) if self.selected_cleanup_paths() else "none")
        )

    def extra_cleanup_roots(self) -> list[str]:
        value = self.custom_cleanup_root.text().strip()
        return [value] if value else []

    def selected_cleanup_paths(self) -> list[str]:
        paths: list[str] = []
        for row in sorted({index.row() for index in self.cleanup_table.selectedIndexes()}):
            item = self.cleanup_table.item(row, 2)
            if item and item.text().strip():
                paths.append(item.text().strip())
        return paths

    def set_status(self, text: str) -> None:
        self.recovery_state_label.setText(text or "Recovery not checked yet")

    def set_recovery_data(self, payload: dict[str, Any]) -> None:
        self._recovery_data = dict(payload or {})
        assessment = self._recovery_data.get("assessment", {}) if isinstance(self._recovery_data.get("assessment", {}), dict) else {}
        preview = self._recovery_data.get("preview", {}) if isinstance(self._recovery_data.get("preview", {}), dict) else {}
        snapshot_history = self._recovery_data.get("snapshot_history", []) if isinstance(self._recovery_data.get("snapshot_history", []), list) else []
        cleanup_history = self._recovery_data.get("cleanup_history", []) if isinstance(self._recovery_data.get("cleanup_history", []), list) else []
        self.set_status(str(assessment.get("title", "Recovery not checked yet")))
        self.last_checked_label.setText(f"Last checked: {self._recovery_data.get('generated_at', 'not yet') or 'not yet'}")
        self.cache_age_label.setText(f"Cache age: {self._recovery_data.get('cache_age', 'unknown') or 'unknown'}")
        self.recovery_score_label.setText(f"Recovery Score: {preview.get('recovery_score', '--')}/100")
        self.space_recovery_label.setText(f"Potential Space Recovery: {preview.get('summary', 'No cleanup preview available.')}")
        reasons = assessment.get("reasons", []) if isinstance(assessment.get("reasons", []), list) else []
        reason_text = "\n".join(f"- {str(reason)}" for reason in reasons) or "- No recent incident indicators were found."
        self.incident_title_label.setText(str(assessment.get("title", "Incident awareness")))
        self.incident_reasons.setPlainText(reason_text)
        self.no_alerts_label.setText(self._why_no_alerts(assessment, preview))
        self.protected_paths_label.setPlainText(
            "Protected paths:\n" + "\n".join(f"- {str(path)}" for path in preview.get("protected_paths", []))
            if preview.get("protected_paths")
            else "Protected paths:\n- Mac Audit Agent evidence, snapshots, reports, notes, and monitor database are never cleaned automatically."
        )
        rows = []
        for candidate in preview.get("candidates", []):
            if not isinstance(candidate, dict):
                continue
            rows.append(
                [
                    str(candidate.get("category", "")),
                    str(candidate.get("kind", "")),
                    str(candidate.get("path", "")),
                    str(candidate.get("current_bytes", "")),
                    str(candidate.get("baseline_bytes", "")),
                    str(candidate.get("recoverable_bytes", "")),
                    str(candidate.get("recommendation", "")),
                    str(candidate.get("risk", "")),
                ]
            )
        if not rows:
            rows = [["No cleanup candidates yet", "", "", "", "", "", "Run Preview Cleanup to inspect candidates.", "safe"]]
        self._populate_table(self.cleanup_table, rows)
        self._populate_table(self.storage_table, rows)
        self.cleanup_scope_label.setText(
            f"Recovery opportunities: {preview.get('opportunities', 0)} | Potential space recovery: {preview.get('summary', 'No cleanup preview available.')}"
        )
        self._update_cleanup_selection_label()
        self.performance_summary_label.setText(
            f"Recovery opportunities: {preview.get('opportunities', 0)} | Potential space recovery: {preview.get('summary', 'No cleanup preview available.')} | Risk: {preview.get('risk_level', 'safe')} | Improvement: {preview.get('performance_improvement', 'Low')}"
        )
        metrics_rows = [
            ["Recovery Score", f"{preview.get('recovery_score', 0)}/100"],
            ["Potential Space Recovery", preview.get("summary", "0 B")],
            ["Performance Improvement", preview.get("performance_improvement", "Low")],
            ["Risk Level", preview.get("risk_level", "safe")],
            ["Opportunities", str(preview.get("opportunities", 0))],
            ["Protected Paths", str(len(preview.get("protected_paths", [])))],
        ]
        self._populate_table(self.recovery_metrics_table, metrics_rows)
        growth_rows = []
        for item in preview.get("growth_summary", []):
            if not isinstance(item, dict):
                continue
            growth_rows.append(
                [
                    str(item.get("path", "")),
                    str(item.get("category", "")),
                    str(item.get("baseline_bytes", "")),
                    str(item.get("current_bytes", "")),
                    str(item.get("growth_bytes", "")),
                ]
            )
        if not growth_rows:
            growth_rows = [["No anomalous growth detected", "", "", "", ""]]
        self._populate_table(self.growth_table, growth_rows)
        snapshot_rows = [
            [
                str(item.get("created_at", "")),
                str(item.get("snapshot_id", "")),
                str(item.get("reason", "")),
                str(item.get("assessment_level", "")),
                str(item.get("snapshot_path", "")),
            ]
            for item in snapshot_history
        ] or [["No snapshots yet", "", "", "", ""]]
        self._populate_table(self.snapshot_history_table, snapshot_rows)
        cleanup_rows = [
            [
                str(item.get("created_at", "")),
                str(item.get("action_type", "")),
                str(item.get("risk_level", "")),
                str(item.get("result_text", "")),
                str(item.get("snapshot_id", "")),
            ]
            for item in cleanup_history
        ] or [["No cleanup actions yet", "", "", "", ""]]
        self._populate_table(self.cleanup_history_table, cleanup_rows)

    def _why_no_alerts(self, assessment: dict[str, Any], preview: dict[str, Any]) -> str:
        level = str(assessment.get("level", "safe"))
        reasons = assessment.get("reasons", []) if isinstance(assessment.get("reasons", []), list) else []
        if not preview.get("candidates"):
            if level == "safe":
                return "Why no alerts? No recovery candidates were identified in the whitelisted cleanup areas."
            return "Why no alerts? Cleanup should be reviewed first, and the preview currently has no deletable candidates."
        if level == "incident_response_recommended":
            return "Why no alerts? Incident response is recommended before cleanup."
        if reasons:
            return "Why no alerts? " + "; ".join(str(reason) for reason in reasons)
        return "Why no alerts? The current preview is informational and no cleanup has been requested."
