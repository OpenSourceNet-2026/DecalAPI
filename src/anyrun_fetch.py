# DecalAPI — hash-based threat intelligence front-end
# Copyright (c) 2024 DecalAPI contributors
# SPDX-License-Identifier: MIT

"""
any.run sandbox integration — optional.

API docs: https://any.run/api-documentation/

NOTE: The REST API is gated behind a Hunter subscription or higher.
      Free accounts get the web UI only.  If ANYRUN_API_KEY is blank,
      this module returns an empty dict and nothing breaks — the rest of
      the scan still completes normally via VT + MB.

Endpoint used:
    GET /v1/analysis/?hash={hash}

We surface:
    verdict   — worst verdict across all tasks ("malicious" > "suspicious" > "no threats")
    tags      — sandbox-assigned tags from each task
    threats   — process/threat names flagged during execution
"""

import requests


_AR_BASE    = "https://api.any.run/v1"
_TIMEOUT    = 12


def query_anyrun(file_hash: str, api_key: str) -> dict:
    """
    Pull sandbox results for *file_hash* from any.run.

    Returns an empty dict when no key is provided or the request fails.
    Raises nothing — any.run is best-effort enrichment.
    """
    if not api_key:
        return _empty_result()

    try:
        resp = requests.get(
            f"{_AR_BASE}/analysis/",
            params={"hash": file_hash},
            headers={"Authorization": f"API-Key {api_key}"},
            timeout=_TIMEOUT,
        )

        if resp.status_code == 403:
            # Key is valid but the plan doesn't include API access
            # TODO: surface this to the user as a warning in the status bar
            return _empty_result()

        resp.raise_for_status()
        tasks = resp.json().get("data", {}).get("tasks", [])

        if not tasks:
            return _empty_result()

        return _reduce_tasks(tasks)

    except Exception:
        return _empty_result()


def _reduce_tasks(tasks: list) -> dict:
    """
    Flatten a list of sandbox task objects down to one combined result.
    We pick the most severe verdict found across all tasks rather than
    just looking at the first one — a sample might have benign and
    malicious tasks depending on the sandbox environment used.
    """
    all_verdicts = []
    all_tags     = []
    all_threats  = []

    for task in tasks:
        v = task.get("verdict", "").lower()
        if v:
            all_verdicts.append(v)

        for tag in task.get("tags", []):
            key = tag.lower()
            if key not in all_tags:
                all_tags.append(key)

        for threat in task.get("threats", []):
            # any.run uses either processName or name depending on the task type
            name = threat.get("processName") or threat.get("name", "")
            if name and name not in all_threats:
                all_threats.append(name)

    # Severity order: malicious > suspicious > no threats
    if "malicious" in all_verdicts:
        top = "malicious"
    elif "suspicious" in all_verdicts:
        top = "suspicious"
    else:
        top = "no threats"

    return {"found": True, "verdict": top, "tags": all_tags, "threats": all_threats}


def _empty_result() -> dict:
    return {"found": False, "verdict": "", "tags": [], "threats": []}
