# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
Top-level application window.

Shell layout:
    ┌─────────────────────────────────────────┐
    │  DecalAPI                           [⚙] │  48px top bar
    ├─────────────────────────────────────────┤
    │  QStackedWidget                         │
    │    page 0 — SearchPage                  │
    │    page 1 — SettingsPage                │
    └─────────────────────────────────────────┘

The gear button in the top-right corner is the only navigation control.
When on the Settings page it morphs into a ← back arrow so intent is obvious.
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QSizePolicy,
)

from src.search_page   import SearchPage
from src.settings_page import SettingsPage


_WIN_QSS = """
QMainWindow, QWidget#root { background: #f3f3f3; }

QWidget#topbar {
    background: #fff;
    border-bottom: 1px solid #e0e0e0;
}

QLabel#brand {
    font-family: 'Segoe UI'; font-size: 16px; font-weight: bold;
    color: #1a1a1a; letter-spacing: 0.3px;
}

QPushButton#nav_btn {
    background: transparent; border: none;
    font-size: 19px; color: #444;
    border-radius: 6px; padding: 2px 8px;
}
QPushButton#nav_btn:hover   { background: #ebebeb; }
QPushButton#nav_btn:pressed { background: #d8d8d8; }
"""

_PAGE_SEARCH   = 0
_PAGE_SETTINGS = 1


class DecalWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DecalAPI")
        self.setMinimumSize(880, 580)
        self.resize(1080, 680)
        self.setStyleSheet(_WIN_QSS)

        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)

        shell = QVBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        shell.addWidget(self._build_topbar())

        self.stack = QStackedWidget()
        self.search_pg   = SearchPage(self)
        self.settings_pg = SettingsPage(self, on_done=self._back_to_search)

        self.stack.addWidget(self.search_pg)    # _PAGE_SEARCH
        self.stack.addWidget(self.settings_pg)  # _PAGE_SETTINGS
        shell.addWidget(self.stack)

        self._go_search()

    def _build_topbar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("topbar")
        bar.setFixedHeight(48)

        row = QHBoxLayout(bar)
        row.setContentsMargins(18, 0, 14, 0)

        brand = QLabel("DecalAPI")
        brand.setObjectName("brand")

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        self.nav_btn = QPushButton("⚙")
        self.nav_btn.setObjectName("nav_btn")
        self.nav_btn.setFixedSize(38, 38)
        self.nav_btn.setToolTip("Settings")
        self.nav_btn.clicked.connect(self._toggle_page)

        row.addWidget(brand)
        row.addWidget(spacer)
        row.addWidget(self.nav_btn)
        return bar

    def _toggle_page(self):
        if self.stack.currentIndex() == _PAGE_SETTINGS:
            self._go_search()
        else:
            self._go_settings()

    def _go_search(self):
        self.stack.setCurrentIndex(_PAGE_SEARCH)
        self.nav_btn.setText("⚙")
        self.nav_btn.setToolTip("Settings")
        self.search_pg.refresh()   # re-check API key, reload history

    def _go_settings(self):
        self.stack.setCurrentIndex(_PAGE_SETTINGS)
        self.nav_btn.setText("←")
        self.nav_btn.setToolTip("Back")

    def _back_to_search(self):
        """Callback wired into SettingsPage — called on Save and Cancel."""
        self._go_search()
