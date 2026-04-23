# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
On-disk config store (config.json).

Deliberately NOT folded into .env — multiline strings in dotenv are handled
differently by every parser on the planet and it's not worth the headache.
JSON is unambiguous, so the comment template lives here.

Keys managed:
    comment_tpl    str   — the user's comment template (multiline)
    auto_comment   bool  — post the generated comment to VT after each scan

File is created lazily on first Save; we don't create it at startup.
"""

import json
from pathlib import Path


_CFG_PATH = Path(__file__).resolve().parent.parent / "config.json"

# Ships out of the box.  {}-tokens are documented in README.md and shown
# as textarea hints in SettingsPage so users know what they can drop in.
_BUILTIN_TPL = (
    "CHANGE ME\n"
    "{HASH}\n"
    "Detected by DecalAPI\n"
    "Common tags: {tags}"
)


def pull_cfg() -> dict:
    """
    Read config.json and hand back its contents.
    Gives {} on first run (file doesn't exist yet) or on a corrupt file —
    callers always get something they can work with.
    """
    if not _CFG_PATH.exists():
        return {}
    try:
        return json.loads(_CFG_PATH.read_text("utf-8"))
    except (json.JSONDecodeError, PermissionError, OSError):
        # Corrupted or locked (antivirus, etc.).  App keeps running,
        # user sees defaults until they hit Save and we overwrite it cleanly.
        return {}


def flush_cfg(blob: dict):
    """Overwrite config.json with blob.  Callers own the merge step."""
    _CFG_PATH.write_text(
        json.dumps(blob, indent=2, ensure_ascii=False), "utf-8"
    )


# ── comment template ----------------------------------------------------------

def pull_comment_tpl() -> str:
    return pull_cfg().get("comment_tpl", _BUILTIN_TPL)


def store_comment_tpl(raw_text: str):
    """Merge-write so we don't stomp unrelated keys that might be added later."""
    blob = pull_cfg()
    blob["comment_tpl"] = raw_text
    flush_cfg(blob)


# ── auto-comment toggle ─────────────────────────────────────────────────────

def pull_auto_comment() -> bool:
    """Return the current auto-comment preference.  Off by default."""
    return bool(pull_cfg().get("auto_comment", False))


def store_auto_comment(enabled: bool):
    """Merge-write the auto_comment flag without touching other keys."""
    blob = pull_cfg()
    blob["auto_comment"] = enabled
    flush_cfg(blob)


# Re-exported so SettingsPage can pre-fill the textarea without reaching into
# this module's private namespace.
DEFAULT_TEMPLATE = _BUILTIN_TPL