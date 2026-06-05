from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.family_safety import FamilySafetyAuditor, export_family_safety_html, export_family_safety_json
from mac_audit_agent.ui.main_window import MainWindow


def test_family_safety_report_is_privacy_first_and_scored(tmp_path: Path, monkeypatch) -> None:
    auditor = FamilySafetyAuditor(home=tmp_path)
    monkeypatch.setattr(auditor, "_run", lambda command: "FileVault is On." if "fdesetup" in command else "")
    monkeypatch.setattr(auditor, "_app_review", lambda: [])

    report = auditor.build_report("Young Child")
    payload = report.to_dict()

    assert 0 <= payload["score"]["score"] <= 100
    assert payload["wizard_recommendations"]["profile"] == ["Young Child"]
    assert any("browsing history" in item for item in payload["privacy_notice"])
    assert any(item["title"] == "Screen Time enabled" for item in payload["findings"])
    assert any(card["topic"] == "Cyberbullying" for card in payload["education_cards"])


def test_family_safety_exports_html_and_json(tmp_path: Path, monkeypatch) -> None:
    auditor = FamilySafetyAuditor(home=tmp_path)
    monkeypatch.setattr(auditor, "_run", lambda command: "")
    monkeypatch.setattr(auditor, "_app_review", lambda: [])
    report = auditor.build_report("School Device")

    html_path = export_family_safety_html(report, tmp_path / "family.html")
    json_path = export_family_safety_json(report, tmp_path / "family.json")

    assert "Family Safety Report" in html_path.read_text(encoding="utf-8")
    assert "Privacy-first report" in html_path.read_text(encoding="utf-8")
    assert '"wizard_recommendations"' in json_path.read_text(encoding="utf-8")


def test_main_navigation_includes_family_safety(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    items = [window.sidebar.item(index).text() for index in range(window.sidebar.count())]
    assert "Family & Safety" in items
    assert hasattr(window, "family_safety_panel")
    window.show_family_safety_page()
    assert window.sidebar.currentItem().text() == "Family & Safety"

    window.close()
    app.processEvents()
