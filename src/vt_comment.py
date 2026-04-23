# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
VirusTotal v3 file-comment posting.

API docs: https://developers.virustotal.com/reference/files-comments

We touch exactly one endpoint:
    POST /api/v3/files/{hash}/comments

Request body shape:
    {
        "data": {
            "type": "comment",
            "attributes": { "text": "<comment body>" }
        }
    }

The free VT tier shares the same 4 req/min budget across all endpoints,
so auto-commenting eats into the lookup allowance.  DecalAPI posts at
most one comment per scan, which is fine for normal usage.
"""

import requests


_VT_COMMENTS = "https://www.virustotal.com/api/v3/files/{}/comments"
_TIMEOUT     = 15


# ── Public API ────────────────────────────────────────────────────────────────

def post_comment(file_hash: str, text: str, api_key: str) -> dict:
    """
    Post *text* as a community comment on *file_hash*.

    Returns a dict with at least:
        ok      bool   — True when VT accepted the comment (HTTP 200)
        status  int    — raw HTTP status code for diagnostics
        detail  str    — human-readable one-liner for the UI status label

    Does NOT raise on HTTP errors — callers check the 'ok' flag instead.
    This keeps the scan flow from blowing up when commenting fails for
    quota or permission reasons.
    """
    if not text.strip():
        return {"ok": False, "status": 0, "detail": "empty comment, skipped"}

    payload = {
        "data": {
            "type": "comment",
            "attributes": {"text": text},
        }
    }

    try:
        resp = requests.post(
            _VT_COMMENTS.format(file_hash),
            headers={
                "x-apikey":     api_key,
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"ok": False, "status": 0, "detail": str(exc)}

    if resp.status_code == 200:
        return {"ok": True, "status": 200, "detail": "comment posted"}

    # VT returns structured errors — pull the message if available
    err_msg = _extract_error(resp)
    return {"ok": False, "status": resp.status_code, "detail": err_msg}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_error(resp: requests.Response) -> str:
    """Best-effort extraction of VT's error message."""
    try:
        body = resp.json()
        err  = body.get("error", {})
        msg  = err.get("message", "") if isinstance(err, dict) else str(err)
        if msg:
            return f"{resp.status_code} — {msg}"
    except (ValueError, KeyError):
        pass
    return f"HTTP {resp.status_code}"
