"""Change Detector Module

Compares registry scan results against a known baseline to detect changes.
Generates structured events for new, modified, deleted, and error conditions.

IMPORTANT: Polling-based monitoring cannot detect changes that occur and
reverse between polling intervals. This is a known limitation.
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Severity levels
SEVERITY_INFORMATIONAL = "informational"
SEVERITY_SUSPICIOUS = "suspicious"
SEVERITY_INVESTIGATION = "investigation_required"

# Change types
CHANGE_ADDED = "ADDED"
CHANGE_DELETED = "DELETED"
CHANGE_MODIFIED = "MODIFIED"
CHANGE_TYPE_CHANGED = "TYPE_CHANGED"
CHANGE_ERROR = "ERROR"

# Suspicious value patterns (case-insensitive substrings)
SUSPICIOUS_PATTERNS = [
    "powershell", "cmd.exe /c", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32", "certutil",
    "bitsadmin", ".vbs", ".js", ".ps1", ".bat",
    "temp\\", "tmp\\", "appdata\\local\\temp",
    "downloadedinstaller",
]

# Sensitive registry categories that raise severity
SENSITIVE_CATEGORIES = [
    "Windows Defender", "Windows Firewall",
    "Security Policy & UAC", "Services & Drivers",
]


def generate_event_id() -> str:
    """Generate a unique event ID."""
    return str(uuid.uuid4())


def _compute_fingerprint(change_type: str, full_path: str,
                          value_name: str, view: str) -> str:
    """Compute a stable fingerprint for deduplication."""
    return f"{change_type}|{full_path}|{value_name}|{view}"


def assess_severity(change_type: str, value_name: str, value_data: Any,
                     category: str = "", old_data: Any = None) -> tuple[str, str]:
    """Assess the severity of a detected change.
    
    Returns (severity, reason) tuple.
    
    NOTE: Not every registry modification is malicious. This provides
    a heuristic classification, not a definitive security verdict.
    """
    data_str = str(value_data).lower() if value_data else ""
    old_str = str(old_data).lower() if old_data else ""

    # Deletions in sensitive areas
    if change_type == CHANGE_DELETED and category in SENSITIVE_CATEGORIES:
        return (
            SEVERITY_INVESTIGATION,
            f"Security-related registry value deleted in {category}",
        )

    # Check suspicious patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in data_str:
            return (
                SEVERITY_SUSPICIOUS,
                f"Value contains suspicious pattern: {pattern}",
            )

    # New entries in startup locations
    if change_type == CHANGE_ADDED and "run" in category.lower():
        return (
            SEVERITY_SUSPICIOUS,
            "New startup entry added",
        )

    # Modifications in sensitive categories
    if change_type in (CHANGE_MODIFIED, CHANGE_TYPE_CHANGED) and category in SENSITIVE_CATEGORIES:
        return (
            SEVERITY_SUSPICIOUS,
            f"Security-related value modified in {category}",
        )

    # Deletions in startup locations
    if change_type == CHANGE_DELETED and "run" in category.lower():
        return (
            SEVERITY_INFORMATIONAL,
            "Startup entry removed (may be normal uninstall behavior)",
        )

    # Default: informational
    return (
        SEVERITY_INFORMATIONAL,
        "Registry value changed",
    )


def _build_value_map(scan_result: dict) -> dict:
    """Build a name -> value dict from a scan result's values list."""
    vmap = {}
    for v in scan_result.get("values", []):
        vmap[v["name"]] = v
    return vmap


def _build_scan_index(scan_results: list) -> dict:
    """Build an index of (full_path, view) -> scan_result."""
    index = {}
    for result in scan_results:
        key = (result["full_path"], result.get("view", "default"))
        index[key] = result
    return index


def detect_changes(baseline_results: list, current_results: list,
                   file_resolver=None) -> list[dict]:
    """Compare current scan results against baseline and generate change events.
    
    Args:
        baseline_results: List of scan results from baseline
        current_results: List of scan results from current scan
        file_resolver: Optional file_resolver module for path resolution
    
    Returns:
        List of change event dicts
    """
    events = []
    baseline_index = _build_scan_index(baseline_results)
    current_index = _build_scan_index(current_results)
    now = datetime.now(timezone.utc).isoformat()

    all_keys = set(list(baseline_index.keys()) + list(current_index.keys()))

    for scan_key in sorted(all_keys):
        full_path, view = scan_key
        baseline_entry = baseline_index.get(scan_key)
        current_entry = current_index.get(scan_key)

        # Handle error states - do NOT treat access_denied as deletion
        if current_entry and current_entry["status"] in ("access_denied", "error"):
            if baseline_entry and baseline_entry["status"] == "ok":
                events.append({
                    "event_id": generate_event_id(),
                    "timestamp": now,
                    "hive": current_entry.get("hive", ""),
                    "full_path": full_path,
                    "value_name": "(key-level)",
                    "change_type": CHANGE_ERROR,
                    "previous_value": None,
                    "current_value": None,
                    "previous_type": None,
                    "current_type": None,
                    "category": current_entry.get("category", ""),
                    "view": view,
                    "severity": SEVERITY_INFORMATIONAL,
                    "reason": (
                        f"Key was readable in baseline but is now {current_entry['status']}. "
                        "This is NOT a confirmed deletion. The key may still exist but "
                        "access permissions may have changed."
                    ),
                    "fingerprint": _compute_fingerprint(
                        CHANGE_ERROR, full_path, "(key-level)", view
                    ),
                    "resolved_file": None,
                    "status": current_entry["status"],
                })
            continue

        # Key exists in current but not baseline (new key entirely)
        if current_entry and not baseline_entry:
            if current_entry["status"] == "ok":
                for val in current_entry.get("values", []):
                    severity, reason = assess_severity(
                        CHANGE_ADDED, val["name"], val["data"],
                        current_entry.get("category", "")
                    )
                    resolved = None
                    if file_resolver:
                        try:
                            resolved = file_resolver.resolve_registry_value(
                                val["name"], val["data"], val["type"]
                            )
                        except Exception as e:
                            logger.debug("File resolution failed: %s", e)
                    events.append({
                        "event_id": generate_event_id(),
                        "timestamp": now,
                        "hive": current_entry.get("hive", ""),
                        "full_path": full_path,
                        "value_name": val["name"],
                        "change_type": CHANGE_ADDED,
                        "previous_value": None,
                        "current_value": val["data"],
                        "previous_type": None,
                        "current_type": val["type"],
                        "category": current_entry.get("category", ""),
                        "view": view,
                        "severity": severity,
                        "reason": reason,
                        "fingerprint": _compute_fingerprint(
                            CHANGE_ADDED, full_path, val["name"], view
                        ),
                        "resolved_file": resolved,
                        "status": "detected",
                    })
            continue

        # Key in baseline but not in current - only if current was not scanned at all
        if baseline_entry and not current_entry:
            if baseline_entry["status"] == "ok":
                for val in baseline_entry.get("values", []):
                    severity, reason = assess_severity(
                        CHANGE_DELETED, val["name"], val["data"],
                        baseline_entry.get("category", "")
                    )
                    events.append({
                        "event_id": generate_event_id(),
                        "timestamp": now,
                        "hive": baseline_entry.get("hive", ""),
                        "full_path": full_path,
                        "value_name": val["name"],
                        "change_type": CHANGE_DELETED,
                        "previous_value": val["data"],
                        "current_value": None,
                        "previous_type": val["type"],
                        "current_type": None,
                        "category": baseline_entry.get("category", ""),
                        "view": view,
                        "severity": severity,
                        "reason": reason,
                        "fingerprint": _compute_fingerprint(
                            CHANGE_DELETED, full_path, val["name"], view
                        ),
                        "resolved_file": None,
                        "status": "detected",
                    })
            continue

        # Both exist and both are OK - compare values
        if (baseline_entry and current_entry and
                baseline_entry["status"] == "ok" and current_entry["status"] == "ok"):
            
            base_values = _build_value_map(baseline_entry)
            curr_values = _build_value_map(current_entry)
            category = current_entry.get("category", "")

            all_value_names = set(list(base_values.keys()) + list(curr_values.keys()))

            for vname in sorted(all_value_names):
                base_val = base_values.get(vname)
                curr_val = curr_values.get(vname)

                if curr_val and not base_val:
                    # New value
                    severity, reason = assess_severity(
                        CHANGE_ADDED, vname, curr_val["data"], category
                    )
                    resolved = None
                    if file_resolver:
                        try:
                            resolved = file_resolver.resolve_registry_value(
                                vname, curr_val["data"], curr_val["type"]
                            )
                        except Exception as e:
                            logger.debug("File resolution failed: %s", e)
                    events.append({
                        "event_id": generate_event_id(),
                        "timestamp": now,
                        "hive": current_entry.get("hive", ""),
                        "full_path": full_path,
                        "value_name": vname,
                        "change_type": CHANGE_ADDED,
                        "previous_value": None,
                        "current_value": curr_val["data"],
                        "previous_type": None,
                        "current_type": curr_val["type"],
                        "category": category,
                        "view": view,
                        "severity": severity,
                        "reason": reason,
                        "fingerprint": _compute_fingerprint(
                            CHANGE_ADDED, full_path, vname, view
                        ),
                        "resolved_file": resolved,
                        "status": "detected",
                    })

                elif base_val and not curr_val:
                    # Deleted value
                    severity, reason = assess_severity(
                        CHANGE_DELETED, vname, base_val["data"], category
                    )
                    events.append({
                        "event_id": generate_event_id(),
                        "timestamp": now,
                        "hive": current_entry.get("hive", ""),
                        "full_path": full_path,
                        "value_name": vname,
                        "change_type": CHANGE_DELETED,
                        "previous_value": base_val["data"],
                        "current_value": None,
                        "previous_type": base_val["type"],
                        "current_type": None,
                        "category": category,
                        "view": view,
                        "severity": severity,
                        "reason": reason,
                        "fingerprint": _compute_fingerprint(
                            CHANGE_DELETED, full_path, vname, view
                        ),
                        "resolved_file": None,
                        "status": "detected",
                    })

                elif base_val and curr_val:
                    # Check for modifications
                    data_changed = base_val["data"] != curr_val["data"]
                    type_changed = base_val["type"] != curr_val["type"]

                    if type_changed:
                        change_type = CHANGE_TYPE_CHANGED
                        severity, reason = assess_severity(
                            change_type, vname, curr_val["data"],
                            category, base_val["data"]
                        )
                    elif data_changed:
                        change_type = CHANGE_MODIFIED
                        severity, reason = assess_severity(
                            change_type, vname, curr_val["data"],
                            category, base_val["data"]
                        )
                        # Check if referenced executable path changed
                        if file_resolver:
                            try:
                                base_res = base_val.get("resolved_file") or file_resolver.resolve_registry_value(
                                    vname, base_val["data"], base_val["type"], check_exists=False, compute_hash=False
                                )
                                curr_res = curr_val.get("resolved_file") or file_resolver.resolve_registry_value(
                                    vname, curr_val["data"], curr_val["type"], check_exists=False, compute_hash=False
                                )
                                base_exe = (base_res or {}).get("command_info", {}).get("executable_path")
                                curr_exe = (curr_res or {}).get("command_info", {}).get("executable_path")
                                if base_exe and curr_exe and base_exe.lower() != curr_exe.lower():
                                    reason = f"Referenced executable path changed: '{base_exe}' -> '{curr_exe}'"
                                    if "run" in category.lower() or category in SENSITIVE_CATEGORIES:
                                        severity = SEVERITY_SUSPICIOUS
                            except Exception as e:
                                logger.debug("Exe path comparison failed: %s", e)
                    else:
                        # Registry value unchanged - check if referenced file on disk changed
                        base_meta = (base_val.get("resolved_file") or {}).get("file_metadata") or {}
                        curr_meta = (curr_val.get("resolved_file") or {}).get("file_metadata") or {}

                        if base_meta and curr_meta:
                            base_hash = base_meta.get("sha256")
                            curr_hash = curr_meta.get("sha256")
                            if base_hash and curr_hash and base_hash != curr_hash:
                                events.append({
                                    "event_id": generate_event_id(),
                                    "timestamp": now,
                                    "hive": current_entry.get("hive", ""),
                                    "full_path": full_path,
                                    "value_name": vname,
                                    "change_type": "FILE_MODIFIED",
                                    "previous_value": f"SHA256:{base_hash[:16]}...",
                                    "current_value": f"SHA256:{curr_hash[:16]}...",
                                    "previous_type": base_val["type"],
                                    "current_type": curr_val["type"],
                                    "category": category,
                                    "view": view,
                                    "severity": SEVERITY_INVESTIGATION if category in SENSITIVE_CATEGORIES else SEVERITY_SUSPICIOUS,
                                    "reason": f"Referenced executable '{curr_meta.get('path')}' was modified on disk (SHA-256 hash changed)",
                                    "fingerprint": _compute_fingerprint("FILE_MODIFIED", full_path, vname, view),
                                    "resolved_file": curr_val.get("resolved_file"),
                                    "status": "detected",
                                })
                            elif base_meta.get("exists") is True and curr_meta.get("exists") is False:
                                events.append({
                                    "event_id": generate_event_id(),
                                    "timestamp": now,
                                    "hive": current_entry.get("hive", ""),
                                    "full_path": full_path,
                                    "value_name": vname,
                                    "change_type": "FILE_DELETED",
                                    "previous_value": base_val["data"],
                                    "current_value": None,
                                    "previous_type": base_val["type"],
                                    "current_type": curr_val["type"],
                                    "category": category,
                                    "view": view,
                                    "severity": SEVERITY_SUSPICIOUS,
                                    "reason": f"Referenced executable '{curr_meta.get('path')}' was deleted or is missing from disk",
                                    "fingerprint": _compute_fingerprint("FILE_DELETED", full_path, vname, view),
                                    "resolved_file": curr_val.get("resolved_file"),
                                    "status": "detected",
                                })
                        continue  # Finished checking unchanged value

                    resolved = curr_val.get("resolved_file")
                    if resolved is None and file_resolver:
                        try:
                            resolved = file_resolver.resolve_registry_value(
                                vname, curr_val["data"], curr_val["type"]
                            )
                        except Exception as e:
                            logger.debug("File resolution failed: %s", e)
                    events.append({
                        "event_id": generate_event_id(),
                        "timestamp": now,
                        "hive": current_entry.get("hive", ""),
                        "full_path": full_path,
                        "value_name": vname,
                        "change_type": change_type,
                        "previous_value": base_val["data"],
                        "current_value": curr_val["data"],
                        "previous_type": base_val["type"],
                        "current_type": curr_val["type"],
                        "category": category,
                        "view": view,
                        "severity": severity,
                        "reason": reason,
                        "fingerprint": _compute_fingerprint(
                            change_type, full_path, vname, view
                        ),
                        "resolved_file": resolved,
                        "status": "detected",
                    })

    return events
