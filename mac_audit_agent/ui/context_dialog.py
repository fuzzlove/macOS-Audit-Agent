from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from mac_audit_agent.workflow_layer import WorkflowContextWindow


class ContextDialog(QDialog):
    def __init__(self, window: WorkflowContextWindow, parent=None) -> None:
        super().__init__(parent)
        self.window = window
        self.setWindowTitle("Show Context")
        self.resize(1100, 650)
        layout = QVBoxLayout(self)

        summary = QLabel(
            f"Timeline of surrounding activity for {window.focus_label or 'selected item'} "
            f"from {window.window_start} to {window.window_end}."
        )
        summary.setWordWrap(True)
        layout.addWidget(summary)

        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Type", "Category", "Source", "Severity", "Focus", "Summary", "Evidence"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

        self._populate()

    def _populate(self) -> None:
        self.table.setRowCount(0)
        if not self.window.moments:
            self.table.setRowCount(1)
            self.table.setItem(0, 0, QTableWidgetItem("No surrounding activity recorded"))
            for column in range(1, self.table.columnCount()):
                self.table.setItem(0, column, QTableWidgetItem(""))
            self.table.resizeRowsToContents()
            return

        for moment in self.window.moments:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [
                moment.timestamp,
                moment.moment_type,
                moment.category,
                moment.source,
                moment.severity,
                "yes" if moment.focus else "",
                moment.summary,
                " | ".join(moment.evidence),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if moment.focus:
                    item.setFont(self._bold_font(item.font()))
                    item.setBackground(QBrush(QColor(240, 244, 255)))
                self.table.setItem(row, column, item)
        self.table.resizeRowsToContents()

    def _bold_font(self, font) -> QFont:
        result = QFont(font)
        result.setBold(True)
        return result
