# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
Fills the user's comment template with real scan data.

Template tokens (documented in README.md and shown as hints in Settings):
    {HASH}        the hash string that was submitted
    {tags}        comma-separated tag list merged from VT + MB + any.run
    {detections}  hit_count  (engines that flagged it malicious/suspicious)
    {total}       engine_count (total engines that checked the file)
    {date}        YYYY-MM-DD of the scan
    {names}       up to 5 filenames VT has seen this sample submitted as
    {family}      dominant malware family from VT classification
    {verdict}     any.run sandbox verdict if available, else "n/a"

All substitution is plain str.replace so users can put the tokens anywhere
in the template including inside URLs, code blocks, whatever they want.
"""

from datetime import datetime
from src.config_store import pull_comment_tpl


def render_comment(
    file_hash:    str,
    tags:         list,
    hit_count:    int  = 0,
    engine_count: int  = 0,
    seen_as:      list = None,
    family:       str  = "",
    ar_verdict:   str  = "",
) -> str:
    """
    Load the saved template and substitute every known placeholder.
    Falls back to the built-in default if nothing has been saved yet.
    """
    tpl = pull_comment_tpl()

    tag_str    = ", ".join(tags)         if tags     else "none"
    names_str  = ", ".join(seen_as or []) if seen_as else "unknown"
    today      = datetime.now().strftime("%Y-%m-%d")

    # fmt: off  — keep replacements vertically aligned; easier to diff
    filled = (tpl
        .replace("{HASH}",        file_hash)
        .replace("{tags}",        tag_str)
        .replace("{detections}",  str(hit_count))
        .replace("{total}",       str(engine_count))
        .replace("{date}",        today)
        .replace("{names}",       names_str)
        .replace("{family}",      family    or "unknown")
        .replace("{verdict}",     ar_verdict or "n/a")
    )
    # fmt: on

    return filled
