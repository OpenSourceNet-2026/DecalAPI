# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
VirusTotal v3 file-hash lookup.

API docs: https://developers.virustotal.com/reference/file-info

We touch exactly one endpoint:
    GET /api/v3/files/{hash}

Fields we actually care about (the response has a lot of noise):
    last_analysis_stats         — engine verdict breakdown
    popular_threat_classification — category labels + dominant family name
    tags                        — VT's own internal tag list
    names                       — filenames this sample has been seen as

The free VT tier allows 4 req/min and 500/day.  DecalAPI does one lookup
per Scan click so you'd have to be very determined to hit the cap, (changes made to auto-comment, so you might hit earlier.)
"""

import requests


_VT_FILES = "https://www.virustotal.com/api/v3/files/{}"
_TIMEOUT   = 15   # VT can be sluggish; give it some room


def lookup_hash(file_hash: str, api_key: str) -> dict:
    """
    Look up *file_hash* on VirusTotal.

    Returns a normalised dict (see _parse_vt_attrs for the full shape).
    Raises requests.HTTPError for anything that isn't 200 or 404.
    A 404 just means VT hasn't seen the file — that's a valid result, not
    an error, so we return a "not found" dict instead of raising.
    """
    resp = requests.get(
        _VT_FILES.format(file_hash),
        headers={"x-apikey": api_key},
        timeout=_TIMEOUT,
    )

    if resp.status_code == 404:
        # Not in VT's corpus.  Could be a novel sample or a benign internal tool.
        return _not_found(file_hash)

    resp.raise_for_status()

    attrs = resp.json().get("data", {}).get("attributes", {})
    return _parse_vt_attrs(file_hash, attrs)


def _parse_vt_attrs(file_hash: str, attrs: dict) -> dict:
    # ── Detection counts ────────────────────────────────────────────────────
    stats = attrs.get("last_analysis_stats", {})
    # "suspicious" counts as a hit for our purposes — some engines flag PUAs
    # as suspicious rather than malicious, and we want those surfaced too.
    hit_count   = stats.get("malicious", 0) + stats.get("suspicious", 0)
    engine_count = sum(stats.values()) if stats else 0

    # ── Threat classification ───────────────────────────────────────────────
    classification = attrs.get("popular_threat_classification", {})

    # Category labels like "trojan", "ransomware", "stealer" — shown as tags
    raw_cats  = classification.get("popular_threat_category", [])
    cat_labels = [c["value"].lower() for c in raw_cats if c.get("value")]

    # VT's own tag list (more technical: "peexe", "overlay", "signed", etc.)
    vt_tags = [t.lower() for t in attrs.get("tags", [])]

    # Merge and dedupe, category labels go first (more human-readable)
    merged_tags = list(dict.fromkeys(cat_labels + vt_tags))

    # Dominant family name — first entry if present, e.g. "RedLine", "Amadey"
    name_entries = classification.get("popular_threat_name", [])
    family = name_entries[0].get("value", "") if name_entries else ""

    # Real-world filenames this sample has been submitted under.
    # Cap at 5 — some samples have hundreds of names, no need to show all.
    seen_as = list(attrs.get("names", []))[:5]

    return {
        "found":        True,
        "hash":         file_hash,
        "hash_type":    _identify_hash_type(file_hash),
        "hit_count":    hit_count,
        "engine_count": engine_count,
        "tags":         merged_tags,
        "seen_as":      seen_as,
        "family":       family,
        "report_url":   f"https://www.virustotal.com/gui/file/{file_hash}",
    }


def _not_found(file_hash: str) -> dict:
    return {
        "found": False, "hash": file_hash,
        "hash_type": _identify_hash_type(file_hash),
        "hit_count": 0, "engine_count": 0,
        "tags": [], "seen_as": [], "family": "",
        "report_url": f"https://www.virustotal.com/gui/file/{file_hash}",
    }


def _identify_hash_type(h: str) -> str:
    # Length is the only reliable discriminator for raw hex hashes
    return {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(h), "Unknown")
