# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT
#
# Source: https://github.com/OpenSourceNet-2026/DecalAPI

import sys
from PyQt6.QtWidgets import QApplication
from src.window import DecalWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("DecalAPI")
    app.setStyle("Fusion")   # neutral canvas — our QSS takes over from here

    win = DecalWindow()
    win.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
