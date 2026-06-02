from __future__ import annotations

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QTextEdit, QVBoxLayout


class AlertProvenanceDialog(QDialog):
    def __init__(self, title: str, body: str, context_window: dict | None = None, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        layout = QVBoxLayout(self)
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setPlainText(self._compose_text(body, context_window or {}))
        layout.addWidget(self.text)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _compose_text(self, body: str, context_window: dict) -> str:
        lines = [body.strip()]
        if context_window:
            lines.append("")
            lines.append("Surrounding timeline:")
            for moment in context_window.get("moments", []):
                timestamp = str(moment.get("timestamp", ""))
                title = str(moment.get("title", ""))
                summary = str(moment.get("summary", ""))
                source = str(moment.get("source", ""))
                focus = " [focus]" if moment.get("focus") else ""
                lines.append(f"- {timestamp} | {title}{focus} | {source} | {summary}")
        return "\n".join(lines).strip()
