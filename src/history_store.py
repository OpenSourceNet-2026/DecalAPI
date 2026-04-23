# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
Local scan history (scan_history.json).

Deliberately flat JSON — no SQLite, no ORM.  The dataset is small
(one entry per unique hash, capped by how many hashes a user realistically
scans) and JSON is human-readable so users can inspect / edit it directly.

Each record shape:
    {
        "hash":         str,
        "hash_type":    "MD5" | "SHA1" | "SHA256" | "Unknown",
        "hit_count":    int,      # malicious + suspicious engines
        "engine_count": int,      # total engines that checked
        "tags":         [str],    # merged from VT + MB + any.run
        "scanned_at":   str,      # "YYYY-MM-DD HH:MM"
        "comment":      str,      # filled template at time of scan
        "vt_found":     bool,
        "mb_found":     bool,
        "anyrun_found": bool,
    }
"""

import json
from pathlib import Path


_HIST_PATH = Path(__file__).resolve().parent.parent / "scan_history.json"


def load_scan_history() -> list[dict]:
    """Return all stored records, oldest first.  Safe to call at any time."""
    if not _HIST_PATH.exists():
        return []
    try:
        raw = _HIST_PATH.read_text("utf-8").strip()
        return json.loads(raw) if raw else []
    except (json.JSONDecodeError, OSError):
        # Don't crash on startup just because the history file is corrupt.
        # User loses old records but the app stays usable.
        return []


def record_scan(entry: dict):
    """
    Add *entry* to history, replacing any previous record for the same hash.
    This means re-scanning a hash always gives you the freshest data at the
    top of the table without accumulating duplicates.
    """
    history = load_scan_history()
    # Strip old record for this hash if it exists
    history = [r for r in history if r.get("hash") != entry.get("hash")]
    history.append(entry)
    _write_history(history)


def wipe_history():
    """Clear everything.  Exposed for a future 'Clear History' button."""
    _write_history([])


def _write_history(records: list[dict]):
    _HIST_PATH.write_text(
        json.dumps(records, indent=2, ensure_ascii=False), "utf-8"
    )
