# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
MalwareBazaar (abuse.ch) hash query.

API docs: https://bazaar.abuse.ch/api/

Endpoint:
    POST https://mb-api.abuse.ch/api/v1/
    Body: query=get_info&hash={hash}

No authentication required for basic lookups — the public endpoint is
rate-limited by IP rather than key.  We keep timeout short (10s) because
MB is supplemental; if it times out we just show VT data on its own.

The signature field is usually the malware family name as labelled by the
submitter (e.g. "AsyncRAT", "Formbook").  We fold it into the tag list so
comment_gen can include it without callers needing to handle it specially.
"""

import requests


_MB_ENDPOINT = "https://mb-api.abuse.ch/api/v1/"
_TIMEOUT     = 10


def query_mb(file_hash: str) -> dict:
    """
    Look up *file_hash* in MalwareBazaar.

    Never raises — network failures and "not found" both return the same
    empty-result dict so the caller (scan_worker) doesn't need to branch.
    """
    try:
        resp = requests.post(
            _MB_ENDPOINT,
            data={"query": "get_info", "hash": file_hash},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()

        if body.get("query_status") != "ok":
            # "no_results", "illegal_hash", etc. — all mean "not found for us"
            return _empty_result()

        # MB returns a list; each item is one submission.  We only care about
        # the first (most recent) entry.
        entry = body.get("data", [{}])[0]
        return _extract_mb_fields(entry)

    except Exception:
        # Timeout, DNS failure, bad JSON — doesn't matter, fall through
        return _empty_result()


def _extract_mb_fields(entry: dict) -> dict:
    raw_tags  = entry.get("tags") or []
    signature = entry.get("signature") or ""

    # Dedupe and lowercase everything so merging with VT tags later is clean
    tag_set = list(dict.fromkeys(
        [t.lower() for t in raw_tags]
        + ([signature.lower()] if signature else [])
    ))

    return {
        "found":      True,
        "tags":       tag_set,
        "signature":  signature,         # original casing for display
        "file_type":  entry.get("file_type", ""),
        "file_name":  entry.get("file_name", ""),
        "origin":     entry.get("origin_country", ""),
        "first_seen": entry.get("first_seen", ""),
        "reporter":   entry.get("reporter", ""),
    }


def _empty_result() -> dict:
    return {
        "found": False, "tags": [], "signature": "",
        "file_type": "", "file_name": "", "origin": "",
        "first_seen": "", "reporter": "",
    }
