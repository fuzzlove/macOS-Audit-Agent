from __future__ import annotations

from typing import Any

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


PROFILE_OPTIONS = [
    "Young Child",
    "Teen",
    "Adult",
    "Senior",
    "Shared Family Computer",
    "Special Needs User",
    "School Device",
]


def _make_table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setAlternatingRowColors(True)
    table.setWordWrap(True)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setStretchLastSection(True)
    return table


class FamilySafetyPanel(QFrame):
    audit_requested = Signal(str)
    export_html_requested = Signal()
    export_json_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("familySafetyPanel")
        self.setFrameShape(QFrame.StyledPanel)
        self._report: dict[str, Any] = {}
        self._build_ui()
        self.set_report({})

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title = QLabel("Family & Safety Center")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #F0F6FC;")
        subtitle = QLabel("Guided, local checks for making this Mac safer for children, families, schools, caregivers, seniors, and users with special needs.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #9DB0C9;")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        privacy = QLabel("Privacy-first: no messages, screenshots, keystrokes, browsing history, microphone data, camera data, or uploads.")
        privacy.setWordWrap(True)
        privacy.setStyleSheet("color: #D6E4FF; font-weight: 600;")
        layout.addWidget(privacy)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Who uses this Mac?"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(PROFILE_OPTIONS)
        self.profile_combo.setMinimumHeight(34)
        controls.addWidget(self.profile_combo)
        self.audit_button = QPushButton("Run Safety Audit")
        self.audit_button.setProperty("role", "primary")
        self.audit_button.clicked.connect(lambda: self.audit_requested.emit(self.profile_combo.currentText()))
        controls.addWidget(self.audit_button)
        self.export_html_button = QPushButton("Export HTML")
        self.export_html_button.clicked.connect(self.export_html_requested.emit)
        controls.addWidget(self.export_html_button)
        self.export_json_button = QPushButton("Export JSON")
        self.export_json_button.clicked.connect(self.export_json_requested.emit)
        controls.addWidget(self.export_json_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        score_frame = QFrame()
        score_frame.setProperty("themeCard", True)
        score_layout = QGridLayout(score_frame)
        score_layout.setContentsMargins(12, 12, 12, 12)
        self.score_label = QLabel("Safety Score: --")
        self.score_label.setStyleSheet("font-size: 24px; font-weight: 700;")
        self.score_bar = QProgressBar()
        self.score_bar.setRange(0, 100)
        self.score_bar.setValue(0)
        self.improvements_label = QLabel("Recommended improvements will appear after an audit.")
        self.improvements_label.setWordWrap(True)
        self.completed_label = QLabel("Completed actions will appear after an audit.")
        self.completed_label.setWordWrap(True)
        score_layout.addWidget(self.score_label, 0, 0)
        score_layout.addWidget(self.score_bar, 0, 1)
        score_layout.addWidget(self.improvements_label, 1, 0, 1, 2)
        score_layout.addWidget(self.completed_label, 2, 0, 1, 2)
        layout.addWidget(score_frame)

        self.tabs = QTabWidget()
        self.audit_table = _make_table(["Category", "Check", "Status", "Plain-language guidance"])
        self.checklist_table = _make_table(["Checklist Item", "Status", "Next Step"])
        self.accessibility_table = _make_table(["Accessibility Item", "Status", "Guidance"])
        self.safe_browsing_table = _make_table(["Protection", "Status", "Guidance"])
        self.app_review_table = _make_table(["App", "Status", "Guidance", "Evidence"])
        self.education_view = QTextEdit()
        self.education_view.setReadOnly(True)
        self.wizard_view = QTextEdit()
        self.wizard_view.setReadOnly(True)
        self.caregiver_view = QTextEdit()
        self.caregiver_view.setReadOnly(True)
        self._add_table_tab(self.audit_table, "Safety Audit")
        self._add_table_tab(self.checklist_table, "Parent Checklist")
        self._add_table_tab(self.accessibility_table, "Accessibility")
        self._add_table_tab(self.safe_browsing_table, "Safe Browsing")
        self._add_text_tab(self.wizard_view, "Wizard")
        self._add_table_tab(self.app_review_table, "Apps")
        self._add_text_tab(self.caregiver_view, "Caregiver")
        self._add_text_tab(self.education_view, "Guidance")
        layout.addWidget(self.tabs, 1)

    def _add_table_tab(self, table: QTableWidget, title: str) -> None:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(6, 6, 6, 6)
        page_layout.addWidget(table)
        self.tabs.addTab(page, title)

    def _add_text_tab(self, text: QTextEdit, title: str) -> None:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(6, 6, 6, 6)
        page_layout.addWidget(text)
        self.tabs.addTab(page, title)

    def set_report(self, report: dict[str, Any]) -> None:
        self._report = report or {}
        score = self._report.get("score", {}) if isinstance(self._report.get("score", {}), dict) else {}
        score_value = int(score.get("score", 0) or 0)
        self.score_label.setText(f"Safety Score: {score_value if self._report else '--'}")
        self.score_bar.setValue(score_value)
        improvements = list(score.get("recommended_improvements", []))[:5]
        completed = list(score.get("completed_actions", []))[:5]
        self.improvements_label.setText("Recommended Improvements: " + ("; ".join(improvements) if improvements else "Run an audit to see next steps."))
        self.completed_label.setText("Completed Actions: " + ("; ".join(completed) if completed else "Run an audit to see configured protections."))
        self._set_rows(self.audit_table, list(self._report.get("findings", [])), ["category", "title", "status", "recommendation"])
        self._set_rows(self.checklist_table, list(self._report.get("parent_checklist", [])), ["title", "status", "recommendation"])
        self._set_rows(self.accessibility_table, list(self._report.get("accessibility_checklist", [])), ["title", "status", "recommendation"])
        self._set_rows(self.safe_browsing_table, list(self._report.get("safe_browsing_status", [])), ["title", "status", "recommendation"])
        self._set_rows(self.app_review_table, list(self._report.get("app_review", [])), ["title", "status", "recommendation", "evidence"])
        self.wizard_view.setPlainText(self._wizard_text())
        self.caregiver_view.setPlainText(self._caregiver_text())
        self.education_view.setPlainText(self._education_text())

    def _set_rows(self, table: QTableWidget, rows: list[dict[str, Any]], keys: list[str]) -> None:
        table.setRowCount(0)
        for row_index, row in enumerate(rows):
            table.insertRow(row_index)
            for column, key in enumerate(keys):
                table.setItem(row_index, column, QTableWidgetItem(str(row.get(key, ""))))
        table.resizeRowsToContents()

    def _wizard_text(self) -> str:
        wizard = self._report.get("wizard_recommendations", {})
        if not isinstance(wizard, dict) or not wizard:
            return "Choose who uses this Mac, then run the Safety Audit to generate recommendations."
        profile = ", ".join(str(item) for item in wizard.get("profile", []))
        recs = "\n".join(f"- {item}" for item in wizard.get("recommendations", []))
        return f"Profile: {profile}\n\nRecommended setup:\n{recs}"

    def _caregiver_text(self) -> str:
        dashboard = self._report.get("caregiver_dashboard", {})
        forecast = self._report.get("family_security_forecast", [])
        if not isinstance(dashboard, dict) or not dashboard:
            return "Run the Safety Audit to see a simple caregiver dashboard."
        lines = [
            f"Safety score: {dashboard.get('safety_score', '--')}",
            f"Recent changes: {dashboard.get('recent_changes', '')}",
            "New apps to review: " + ", ".join(str(item) for item in dashboard.get("new_apps", [])[:8]),
            "Safety recommendations:",
        ]
        lines.extend(f"- {item}" for item in dashboard.get("safety_recommendations", []))
        lines.append("\nFamily Security Forecast:")
        for card in forecast:
            lines.append(f"- {card.get('topic', '')}: {card.get('guidance', '')} Action: {card.get('action', '')}")
        return "\n".join(lines)

    def _education_text(self) -> str:
        cards = list(self._report.get("education_cards", []))
        notice = list(self._report.get("privacy_notice", []))
        if not cards:
            return "Plain-language online safety cards will appear after an audit."
        lines = ["Online Safety Guidance:"]
        for card in cards:
            lines.append(f"\n{card.get('topic', '')}\n{card.get('guidance', '')}\nAction: {card.get('action', '')}")
        lines.append("\nPrivacy Requirements:")
        lines.extend(f"- {item}" for item in notice)
        return "\n".join(lines)
