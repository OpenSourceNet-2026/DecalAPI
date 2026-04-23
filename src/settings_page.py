# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
Settings page.

Four sections:
    1. API Keys         — VT (required), MB (optional), any.run (optional)
    2. Comment Template — textarea with placeholder hint below it
    3. Auto Comment     — toggle to post comments to VT after each scan
    4. Save / Cancel buttons

Keys are written to .env via env_io.write_keys().
The comment template goes to config.json via config_store.store_comment_tpl().
The auto-comment flag goes to config.json via config_store.store_auto_comment().

Hitting Cancel discards in-memory edits and fires the on_done callback;
no writes happen.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QTextEdit, QPushButton, QFrame, QScrollArea, QCheckBox,
)
from PyQt6.QtCore import Qt

from src.env_io       import read_key, write_keys
from src.config_store import (
    pull_comment_tpl, store_comment_tpl, DEFAULT_TEMPLATE,
    pull_auto_comment, store_auto_comment,
)


_QSS = """
QWidget#settings_root  { background: #f3f3f3; }
QScrollArea, QWidget#inner { background: transparent; border: none; }

QLabel#pg_title   { font-family:'Segoe UI'; font-size:22px; font-weight:bold; color:#1a1a1a; }
QLabel#sec_head   { font-family:'Segoe UI'; font-size:14px; font-weight:600; color:#1a1a1a; }
QLabel#fld_label  { font-family:'Segoe UI'; font-size:13px; font-weight:600; color:#333; }
QLabel#fld_hint   { font-family:'Segoe UI'; font-size:11px; color:#888; }

QLineEdit#key_field {
    border:1px solid #ccc; border-radius:6px;
    padding:0 12px; height:38px;
    font-family:'Consolas'; font-size:13px;
    background:#fff; color:#1a1a1a;
}
QLineEdit#key_field:focus { border:2px solid #0078d4; }

QTextEdit#tpl_field {
    border:1px solid #ccc; border-radius:6px;
    padding:8px 12px;
    font-family:'Consolas'; font-size:13px;
    background:#fff; color:#1a1a1a;
}
QTextEdit#tpl_field:focus { border:2px solid #0078d4; }

QCheckBox#auto_comment_cb {
    font-family:'Segoe UI'; font-size:13px; color:#1a1a1a;
    spacing: 8px;
}
QCheckBox#auto_comment_cb::indicator {
    width: 18px; height: 18px;
    border: 2px solid #999; border-radius: 4px;
    background: #fff;
}
QCheckBox#auto_comment_cb::indicator:checked {
    background: #0078d4; border-color: #0078d4;
    image: none;
}
QCheckBox#auto_comment_cb::indicator:hover {
    border-color: #0078d4;
}

QPushButton#save_btn {
    background:#0078d4; color:#fff; border:none;
    border-radius:6px; padding:9px 28px;
    font-family:'Segoe UI'; font-size:14px; font-weight:600;
}
QPushButton#save_btn:hover   { background:#106ebe; }
QPushButton#save_btn:pressed { background:#005a9e; }

QPushButton#cancel_btn {
    background:transparent; color:#555;
    border:1px solid #ccc; border-radius:6px;
    padding:9px 28px;
    font-family:'Segoe UI'; font-size:14px;
}
QPushButton#cancel_btn:hover { background:#e8e8e8; }

QPushButton#reset_tpl_btn {
    background:transparent; border:none;
    color:#888; font-family:'Segoe UI'; font-size:12px;
    text-decoration:underline; padding:0;
}
QPushButton#reset_tpl_btn:hover { color:#0078d4; }
"""


class SettingsPage(QWidget):
    def __init__(self, parent=None, on_done=None):
        super().__init__(parent)
        self.setObjectName("settings_root")
        self.setStyleSheet(_QSS)
        self._on_done = on_done   # fired after Save or Cancel — returns to search

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        inner = QWidget()
        inner.setObjectName("inner")
        form = QVBoxLayout(inner)
        form.setContentsMargins(64, 40, 64, 40)
        form.setSpacing(20)

        # Title
        title = QLabel("Settings")
        title.setObjectName("pg_title")
        form.addWidget(title)
        form.addWidget(self._rule())

        # ── API Keys ──────────────────────────────────────────────────────────
        form.addWidget(self._sec("API Keys"))

        form.addWidget(self._lbl("VirusTotal API Key"))
        form.addWidget(self._hint("virustotal.com  →  Profile  →  API Key"))
        self.vt_field = self._key_input(read_key("VT_API_KEY") or "")
        form.addWidget(self.vt_field)

        form.addSpacing(4)

        form.addWidget(self._lbl("MalwareBazaar API Key"))
        form.addWidget(self._hint("bazaar.abuse.ch  →  Account  →  API key   (optional)"))
        self.mb_field = self._key_input(read_key("MB_API_KEY") or "")
        form.addWidget(self.mb_field)

        form.addSpacing(4)

        form.addWidget(self._lbl("any.run API Key"))
        form.addWidget(self._hint("app.any.run  →  Profile  →  API key   (Hunter plan+, optional)"))
        self.ar_field = self._key_input(read_key("ANYRUN_API_KEY") or "")
        form.addWidget(self.ar_field)

        form.addWidget(self._rule())

        # ── Comment template ──────────────────────────────────────────────────
        form.addWidget(self._sec("Average VirusTotal Comment"))
        form.addWidget(self._hint(
            "Placeholders:  {HASH}  {tags}  {detections}  {total}  {date}  {names}  {family}  {verdict}"
        ))

        self.tpl_box = QTextEdit()
        self.tpl_box.setObjectName("tpl_field")
        self.tpl_box.setFixedHeight(160)
        self.tpl_box.setPlainText(pull_comment_tpl())
        form.addWidget(self.tpl_box)

        # "Reset to default" sits flush-right below the textarea
        reset_row = QHBoxLayout()
        reset_row.addStretch()
        reset_btn = QPushButton("Reset to default")
        reset_btn.setObjectName("reset_tpl_btn")
        reset_btn.clicked.connect(lambda: self.tpl_box.setPlainText(DEFAULT_TEMPLATE))
        reset_row.addWidget(reset_btn)
        form.addLayout(reset_row)

        form.addWidget(self._rule())

        # ── Auto Comment ──────────────────────────────────────────────────────
        form.addWidget(self._sec("Auto Comment"))
        form.addWidget(self._hint(
            "When enabled, DecalAPI posts your generated comment to VirusTotal "
            "automatically after each scan.  Uses the same VT API key."
        ))

        self.auto_comment_cb = QCheckBox("Post comment to VirusTotal after scan")
        self.auto_comment_cb.setObjectName("auto_comment_cb")
        self.auto_comment_cb.setChecked(pull_auto_comment())
        form.addWidget(self.auto_comment_cb)

        form.addWidget(self._rule())

        # ── Buttons ───────────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        btn_row.addStretch()

        cancel = QPushButton("Cancel")
        cancel.setObjectName("cancel_btn")
        cancel.clicked.connect(self._cancel)

        save = QPushButton("Save")
        save.setObjectName("save_btn")
        save.clicked.connect(self._save)

        btn_row.addWidget(cancel)
        btn_row.addWidget(save)
        form.addLayout(btn_row)
        form.addStretch()

        scroll.setWidget(inner)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(scroll)

    # ── Widget helpers ────────────────────────────────────────────────────────

    def _key_input(self, prefill: str) -> QLineEdit:
        f = QLineEdit()
        f.setObjectName("key_field")
        f.setFixedHeight(38)
        f.setText(prefill)
        f.setEchoMode(QLineEdit.EchoMode.Password)
        return f

    def _lbl(self, text: str) -> QLabel:
        w = QLabel(text); w.setObjectName("fld_label"); return w

    def _hint(self, text: str) -> QLabel:
        w = QLabel(text); w.setObjectName("fld_hint")
        w.setWordWrap(True); return w

    def _sec(self, text: str) -> QLabel:
        w = QLabel(text); w.setObjectName("sec_head"); return w

    def _rule(self) -> QFrame:
        ln = QFrame()
        ln.setFrameShape(QFrame.Shape.HLine)
        ln.setStyleSheet("background:#e0e0e0; border:none;")
        ln.setFixedHeight(1)
        return ln

    # ── Actions ───────────────────────────────────────────────────────────────

    def _save(self):
        write_keys({
            "VT_API_KEY":     self.vt_field.text().strip(),
            "MB_API_KEY":     self.mb_field.text().strip(),
            "ANYRUN_API_KEY": self.ar_field.text().strip(),
        })
        store_comment_tpl(self.tpl_box.toPlainText())
        store_auto_comment(self.auto_comment_cb.isChecked())
        if self._on_done:
            self._on_done()

    def _cancel(self):
        if self._on_done:
            self._on_done()