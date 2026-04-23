# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
.env reader / writer.

We roll our own parser instead of pulling in python-dotenv because:
  a) fewer dependencies to pin
  b) we need runtime write-back from the Settings page, which dotenv
     doesn't support cleanly without re-loading the process environment

Keys managed here:
    VT_API_KEY      VirusTotal v3
    MB_API_KEY      MalwareBazaar   (optional)
    ANYRUN_API_KEY  any.run sandbox (optional, Hunter plan+)
"""

from pathlib import Path


_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def _parse_dotenv() -> dict:
    """
    Minimal .env parser — handles KEY=value, KEY="value", KEY='value'.
    Skips blank lines and # comments.  No multiline support intentionally;
    multiline config lives in config.json instead.
    """
    if not _ENV_PATH.exists():
        return {}

    out = {}
    for raw in _ENV_PATH.read_text("utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        # Strip surrounding quotes that editors / CI sometimes add
        out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def read_key(name: str) -> str | None:
    """Return the value for *name*, or None if it's absent or empty."""
    return _parse_dotenv().get(name) or None


def key_is_set(name: str) -> bool:
    """True when the key exists and is non-empty — used to gate the UI."""
    return bool(read_key(name))


def write_keys(pairs: dict):
    """
    Upsert a batch of key=value pairs into .env.

    Strategy:
      - Load the file line-by-line and track which line each key occupies.
      - For keys already present: overwrite that line in-place (preserves comments
        and ordering that the user may have set up manually).
      - For new keys: append at the bottom.
      - Empty values in *pairs* are skipped — we don't want a Save click that
        leaves a field blank to silently erase a key that was previously valid.
    """
    existing_lines: list[str] = []
    line_idx_for_key: dict[str, int] = {}

    if _ENV_PATH.exists():
        existing_lines = _ENV_PATH.read_text("utf-8").splitlines()
        for idx, raw in enumerate(existing_lines):
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, _ = line.partition("=")
                line_idx_for_key[k.strip()] = idx

    for key, val in pairs.items():
        if not val:
            continue   # don't erase — user probably just left the field alone
        entry = f'{key}="{val}"'
        if key in line_idx_for_key:
            existing_lines[line_idx_for_key[key]] = entry
        else:
            existing_lines.append(entry)

    _ENV_PATH.write_text("\n".join(existing_lines) + "\n", "utf-8")
