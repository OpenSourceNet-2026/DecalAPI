# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
Search page — the landing view.

Layout:
    [ hash input                         ] [ Scan ]
    ─────────────────────────────────────────────────
    table: Hash | Type | Detections | Tags | Sources | Scanned At
    (or a placeholder string when no VT key is configured)

History is loaded from scan_history.json on every refresh() call so
it stays consistent if the user edits the file externally.

Double-clicking a row reopens that scan's generated comment so the user
can copy it to VirusTotal without re-scanning.
"""

from datetime import datetime

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QDialog, QDialogButtonBox, QTextEdit, QFrame,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor

from src.env_io        import read_key, key_is_set
from src.history_store import load_scan_history, record_scan
from src.scan_worker   import HashScanner


# ── Stylesheet ────────────────────────────────────────────────────────────────
# Edge-inspired: white surface, #0078d4 accent, Segoe UI throughout.
# border-radius on the search bar matches Edge's address bar pill shape.

_QSS = """
QWidget#search_root { background: #f3f3f3; }

QLineEdit#hash_input {
    border: 1px solid #ccc;
    border-radius: 22px;
    padding: 0 18px;
    font-family: 'Segoe UI'; font-size: 14px;
    background: #fff; color: #1a1a1a;
    selection-background-color: #0078d4;
}
QLineEdit#hash_input:focus { border: 2px solid #0078d4; }

QPushButton#scan_btn {
    background: #0078d4; color: #fff;
    border: none; border-radius: 22px;
    font-family: 'Segoe UI'; font-size: 14px; font-weight: 600;
    padding: 0 24px;
}
QPushButton#scan_btn:hover   { background: #106ebe; }
QPushButton#scan_btn:pressed { background: #005a9e; }
QPushButton#scan_btn:disabled { background: #aaa; }

QTableWidget#hit_table {
    background: #fff;
    border: 1px solid #e0e0e0; border-radius: 8px;
    font-family: 'Segoe UI'; font-size: 13px; color: #1a1a1a;
    gridline-color: #f0f0f0; outline: 0;
}
QTableWidget#hit_table::item          { padding: 7px 12px; border: none; }
QTableWidget#hit_table::item:selected { background: #e5f1fb; color: #1a1a1a; }
QTableWidget#hit_table::item:alternate { background: #fafafa; }

QHeaderView::section {
    background: #f7f7f7;
    border: none; border-bottom: 1px solid #e0e0e0;
    padding: 8px 12px;
    font-family: 'Segoe UI'; font-size: 12px; font-weight: 600; color: #555;
}

QLabel#no_results_hint {
    color: #999; font-family: 'Segoe UI'; font-size: 15px;
}
QLabel#scan_status {
    color: #666; font-family: 'Segoe UI'; font-size: 13px;
}
"""


class SearchPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("search_root")
        self.setStyleSheet(_QSS)

        # Keep a reference to the active worker so it isn't GC'd mid-scan
        self._active_scanner: HashScanner | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(52, 36, 52, 36)
        outer.setSpacing(16)

        # ── Hash input row ────────────────────────────────────────────────────
        bar = QHBoxLayout()
        bar.setSpacing(10)

        self.hash_input = QLineEdit()
        self.hash_input.setObjectName("hash_input")
        self.hash_input.setPlaceholderText("Paste an MD5, SHA1, or SHA256 hash…")
        self.hash_input.setFixedHeight(44)
        self.hash_input.returnPressed.connect(self._begin_scan)

        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setObjectName("scan_btn")
        self.scan_btn.setFixedSize(100, 44)
        self.scan_btn.clicked.connect(self._begin_scan)

        bar.addWidget(self.hash_input)
        bar.addWidget(self.scan_btn)
        outer.addLayout(bar)

        # Status line below the bar ("Scanning…" / error messages)
        self.status_lbl = QLabel("")
        self.status_lbl.setObjectName("scan_status")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(self.status_lbl)

        # ── Results table ─────────────────────────────────────────────────────
        self.hit_table = self._make_table()
        outer.addWidget(self.hit_table)
        self.hit_table.doubleClicked.connect(self._reopen_comment)

        # Shown when there's nothing in the table yet
        self.hint_lbl = QLabel("Nothing here yet, put your API on settings.")
        self.hint_lbl.setObjectName("no_results_hint")
        self.hint_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.addWidget(self.hint_lbl)

        self.refresh()

    # ── Table ─────────────────────────────────────────────────────────────────

    def _make_table(self) -> QTableWidget:
        tbl = QTableWidget()
        tbl.setObjectName("hit_table")
        tbl.setColumnCount(6)
        tbl.setHorizontalHeaderLabels(
            ["Hash", "Type", "Detections", "Tags", "Sources", "Scanned At"]
        )
        # Hash and Tags columns should stretch; the rest stay fixed-ish
        tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tbl.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tbl.verticalHeader().setVisible(False)
        tbl.setAlternatingRowColors(True)
        tbl.setShowGrid(False)
        tbl.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        return tbl

    # ── Page lifecycle ────────────────────────────────────────────────────────

    def refresh(self):
        """
        Called each time we navigate back to this page.
        Gates the scan controls behind the VT key check so the user
        can't fire a scan with no credentials configured.
        """
        has_key = key_is_set("VT_API_KEY")
        self.hash_input.setEnabled(has_key)
        self.scan_btn.setEnabled(has_key)

        if not has_key:
            self.hit_table.hide()
            self.hint_lbl.setText("Nothing here yet, put your API on settings.")
            self.hint_lbl.show()
            return

        self.hint_lbl.hide()
        self.hit_table.show()
        self._repopulate_table()

    def _repopulate_table(self):
        """Rebuild the table from scan_history.json, newest entries first."""
        records = load_scan_history()
        self.hit_table.setRowCount(0)

        for rec in reversed(records):
            row = self.hit_table.rowCount()
            self.hit_table.insertRow(row)

            hits = rec.get("hit_count", 0)
            det_cell = QTableWidgetItem(str(hits))
            # Red for anything flagged, green for clean — quick visual triage
            det_cell.setForeground(
                QColor("#c0392b") if isinstance(hits, int) and hits > 0
                else QColor("#27ae60")
            )

            # Which intel sources actually returned a result for this hash
            src_parts = []
            if rec.get("vt_found"):     src_parts.append("VT")
            if rec.get("mb_found"):     src_parts.append("MB")
            if rec.get("anyrun_found"): src_parts.append("any.run")

            self.hit_table.setItem(row, 0, QTableWidgetItem(rec.get("hash", "")))
            self.hit_table.setItem(row, 1, QTableWidgetItem(rec.get("hash_type", "")))
            self.hit_table.setItem(row, 2, det_cell)
            self.hit_table.setItem(row, 3, QTableWidgetItem(", ".join(rec.get("tags", []))))
            self.hit_table.setItem(row, 4, QTableWidgetItem(", ".join(src_parts) or "VT"))
            self.hit_table.setItem(row, 5, QTableWidgetItem(rec.get("scanned_at", "")))

            # Stash the saved comment on the hash cell for the double-click handler
            self.hit_table.item(row, 0).setData(
                Qt.ItemDataRole.UserRole, rec.get("comment", "")
            )

        if self.hit_table.rowCount() == 0:
            self.hint_lbl.setText("No scans yet — paste a hash above to get started.")
            self.hint_lbl.show()

    # ── Scan flow ─────────────────────────────────────────────────────────────

    def _begin_scan(self):
        raw_hash = self.hash_input.text().strip()
        if not raw_hash:
            return

        vt_key     = read_key("VT_API_KEY")     or ""
        mb_key     = read_key("MB_API_KEY")     or ""
        anyrun_key = read_key("ANYRUN_API_KEY") or ""

        if not vt_key:
            self.status_lbl.setText("⚠  No VT API key — open Settings first.")
            return

        self._lock_controls(True)

        self._active_scanner = HashScanner(raw_hash, vt_key, mb_key, anyrun_key)
        self._active_scanner.scan_done.connect(self._handle_result)
        self._active_scanner.scan_failed.connect(self._handle_error)
        self._active_scanner.start()

    def _handle_result(self, result: dict):
        self._lock_controls(False)

        vt      = result["vt"]
        mb      = result["mb"]
        ar      = result["anyrun"]
        tags    = result["tags"]
        fhash   = result["hash"]

        # The worker now builds the comment and optionally posts it to VT.
        comment        = result.get("comment_text", "")
        comment_result = result.get("comment_result", {})

        record_scan({
            "hash":         fhash,
            "hash_type":    vt.get("hash_type", _id_hash_type(fhash)),
            "hit_count":    vt.get("hit_count",    0),
            "engine_count": vt.get("engine_count", 0),
            "tags":         tags,
            "scanned_at":   datetime.now().strftime("%Y-%m-%d %H:%M"),
            "comment":      comment,
            "vt_found":     vt.get("found",  False),
            "mb_found":     mb.get("found",  False),
            "anyrun_found": ar.get("found",  False),
        })

        self._repopulate_table()
        self.hint_lbl.hide()
        self._show_result_popup(vt, mb, ar, tags, comment, comment_result)

    def _handle_error(self, msg: str):
        self._lock_controls(False)
        self.status_lbl.setText(f"Error: {msg}")

    def _lock_controls(self, locked: bool):
        self.scan_btn.setEnabled(not locked)
        self.hash_input.setEnabled(not locked)
        self.status_lbl.setText("Scanning…" if locked else "")

    # ── Dialogs ───────────────────────────────────────────────────────────────

    def _show_result_popup(self, vt, mb, ar, tags, comment, comment_result):
        dlg = QDialog(self)
        dlg.setWindowTitle("Scan Result")
        dlg.setMinimumWidth(560)
        dlg.setStyleSheet("""
            QDialog  { background: #f9f9f9; }
            QLabel   { font-family: 'Segoe UI'; font-size: 13px; color: #1a1a1a; }
            QTextEdit {
                font-family: 'Consolas'; font-size: 12px;
                border: 1px solid #ddd; border-radius: 6px; background: #fff;
            }
            QPushButton {
                background: #0078d4; color: #fff; border: none;
                border-radius: 6px; padding: 8px 20px;
                font-family: 'Segoe UI'; font-size: 13px; font-weight: 600;
            }
            QPushButton:hover { background: #106ebe; }
        """)

        layout = QVBoxLayout(dlg)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        hits  = vt.get("hit_count",    0)
        total = vt.get("engine_count", 0)
        color = "#c0392b" if hits > 0 else "#27ae60"

        layout.addWidget(QLabel(
            f"<b>Detections:</b> <span style='color:{color}'>{hits}</span> / {total}"
        ))
        if tags:
            layout.addWidget(QLabel(f"<b>Tags:</b> {', '.join(tags)}"))
        if mb.get("signature"):
            layout.addWidget(QLabel(f"<b>Signature (MB):</b> {mb['signature']}"))
        if ar.get("verdict"):
            layout.addWidget(QLabel(f"<b>any.run verdict:</b> {ar['verdict']}"))

        # ── Auto-comment status ───────────────────────────────────────────────
        if comment_result.get("ok"):
            layout.addWidget(QLabel(
                "<b>Comment:</b> <span style='color:#27ae60'>posted to VirusTotal</span>"
            ))
        elif comment_result.get("status", 0) > 0:
            detail = comment_result.get("detail", "unknown error")
            layout.addWidget(QLabel(
                f"<b>Comment:</b> <span style='color:#c0392b'>failed — {detail}</span>"
            ))

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #e0e0e0;")
        layout.addWidget(line)

        layout.addWidget(QLabel("<b>Generated comment</b> (copy → paste to VirusTotal):"))
        box = QTextEdit()
        box.setPlainText(comment)
        box.setFixedHeight(140)
        layout.addWidget(box)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        btns.accepted.connect(dlg.accept)
        layout.addWidget(btns)

        dlg.exec()

    def _reopen_comment(self, index):
        """Double-click a row to view/edit its saved comment without re-scanning."""
        item = self.hit_table.item(index.row(), 0)
        if not item:
            return
        saved = item.data(Qt.ItemDataRole.UserRole) or "(no comment saved for this entry)"

        dlg = QDialog(self)
        dlg.setWindowTitle("Saved Comment")
        dlg.setMinimumWidth(480)
        layout = QVBoxLayout(dlg)

        box = QTextEdit()
        box.setPlainText(saved)
        layout.addWidget(box)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(dlg.reject)
        layout.addWidget(btns)

        dlg.exec()


def _id_hash_type(h: str) -> str:
    return {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(h), "Unknown")
