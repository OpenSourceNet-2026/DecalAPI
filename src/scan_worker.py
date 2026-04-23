# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
Background QThread that fires all three API lookups off the main thread.

PyQt6 keeps the UI responsive while the network calls are in flight.
All three lookups run sequentially (VT → MB → any.run) rather than in
parallel — the bottleneck is almost always VT's rate limit, so threading
the other two wouldn't meaningfully improve wall-clock time.

When auto_comment is enabled in config.json the worker will also POST
the generated comment back to VT after the lookups finish.  A comment
failure never blocks the scan result from reaching the UI.

Signals:
    scan_done(dict)   emitted with the merged result on success
    scan_failed(str)  emitted with an error message on VT failure
                      (MB and any.run failures are swallowed internally)
"""

from PyQt6.QtCore import QThread, pyqtSignal

from src.vt_fetch      import lookup_hash
from src.mb_fetch      import query_mb
from src.anyrun_fetch  import query_anyrun
from src.vt_comment    import post_comment
from src.comment_gen   import render_comment
from src.config_store  import pull_auto_comment


class HashScanner(QThread):
    scan_done   = pyqtSignal(dict)
    scan_failed = pyqtSignal(str)

    def __init__(self, file_hash: str, vt_key: str, mb_key: str = "", anyrun_key: str = ""):
        super().__init__()
        self.file_hash   = file_hash
        self.vt_key      = vt_key
        self.mb_key      = mb_key       # not actually used by query_mb (public endpoint)
        self.anyrun_key  = anyrun_key   # empty → any.run step is skipped silently

    def run(self):
        try:
            vt_data  = lookup_hash(self.file_hash, self.vt_key)
            mb_data  = query_mb(self.file_hash)
            ar_data  = query_anyrun(self.file_hash, self.anyrun_key)

            # Merge tag lists from all three sources.  dict.fromkeys preserves
            # insertion order and dedupes — VT tags come first since they're
            # generally the most reliable classification signal.
            merged_tags = list(dict.fromkeys(
                vt_data.get("tags", [])
                + mb_data.get("tags", [])
                + ar_data.get("tags",  [])
            ))

            # ── Auto-comment ─────────────────────────────────────────────────
            # Build the comment text regardless — the UI needs it for the
            # result popup.  Only POST it to VT when the toggle is on.
            comment_text = render_comment(
                file_hash    = self.file_hash,
                tags         = merged_tags,
                hit_count    = vt_data.get("hit_count",    0),
                engine_count = vt_data.get("engine_count", 0),
                seen_as      = vt_data.get("seen_as",      []),
                family       = vt_data.get("family",       ""),
                ar_verdict   = ar_data.get("verdict",      ""),
            )

            comment_result = {"ok": False, "status": 0, "detail": "auto-comment off"}
            if pull_auto_comment() and self.vt_key:
                comment_result = post_comment(
                    self.file_hash, comment_text, self.vt_key,
                )

            self.scan_done.emit({
                "hash":    self.file_hash,
                "vt":      vt_data,
                "mb":      mb_data,
                "anyrun":  ar_data,
                "tags":    merged_tags,
                "comment_text":   comment_text,
                "comment_result": comment_result,
            })

        except Exception as exc:
            # VT raised — propagate so the UI can show the error
            self.scan_failed.emit(str(exc))