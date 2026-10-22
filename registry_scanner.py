"""Registry Scanner Module

Performs read-only scanning of configured Windows Registry locations.
Captures key paths, value names, value data, and registry data types.
This is a selected-path scanner, NOT a full registry backup tool.
"""

import winreg
import json
import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Map string hive names to winreg constants
HIVE_MAP = {
    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKEY_USERS": winreg.HKEY_USERS,
    "HKU": winreg.HKEY_USERS,
    "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
    "HKCC": winreg.HKEY_CURRENT_CONFIG,
}

# Map winreg type constants to human-readable names
TYPE_NAMES = {
    winreg.REG_NONE: "REG_NONE",
    winreg.REG_SZ: "REG_SZ",
    winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
    winreg.REG_BINARY: "REG_BINARY",
    winreg.REG_DWORD: "REG_DWORD",
    winreg.REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    winreg.REG_LINK: "REG_LINK",
    winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
    winreg.REG_RESOURCE_LIST: "REG_RESOURCE_LIST",
    winreg.REG_FULL_RESOURCE_DESCRIPTOR: "REG_FULL_RESOURCE_DESCRIPTOR",
    winreg.REG_RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
    winreg.REG_QWORD: "REG_QWORD",
}


def _serialize_value(value: Any, reg_type: int) -> Any:
    """Convert a registry value to a JSON-serializable form."""
    if value is None:
        return None
    if reg_type == winreg.REG_BINARY:
        if isinstance(value, (bytes, bytearray)):
            return value.hex()
        return str(value)
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return value.hex()
    return value


def _get_access_flags(scan_64bit: bool = True, scan_32bit: bool = False):
    """Return list of access flag tuples (label, flags) to try."""
    flags = []
    if scan_64bit:
        flags.append(("64bit", winreg.KEY_READ | winreg.KEY_WOW64_64KEY))
    if scan_32bit:
        flags.append(("32bit", winreg.KEY_READ | winreg.KEY_WOW64_32KEY))
    if not flags:
        flags.append(("default", winreg.KEY_READ))
    return flags


def scan_registry_key(hive_name: str, subkey: str,
                       scan_64bit: bool = True, scan_32bit: bool = True):
    """Scan a single registry key and return its values.
    
    Returns a dict with:
        - full_path: str
        - hive: str
        - subkey: str
        - status: 'ok' | 'access_denied' | 'not_found' | 'error'
        - values: list of value dicts
        - error_message: str or None
        - view: str ('64bit', '32bit', or 'default')
        - scan_timestamp: str
    """
    hive_const = HIVE_MAP.get(hive_name)
    if hive_const is None:
        return {
            "full_path": f"{hive_name}\\{subkey}",
            "hive": hive_name,
            "subkey": subkey,
            "status": "error",
            "values": [],
            "error_message": f"Unsupported registry hive: {hive_name}",
            "view": "unknown",
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        }

    access_list = _get_access_flags(scan_64bit, scan_32bit)
    results = []

    for view_label, access_flag in access_list:
        result = {
            "full_path": f"{hive_name}\\{subkey}",
            "hive": hive_name,
            "subkey": subkey,
            "status": "ok",
            "values": [],
            "error_message": None,
            "view": view_label,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            with winreg.OpenKey(hive_const, subkey, 0, access_flag) as key:
                index = 0
                while True:
                    try:
                        name, data, reg_type = winreg.EnumValue(key, index)
                        type_name = TYPE_NAMES.get(reg_type, f"UNKNOWN({reg_type})")
                        result["values"].append({
                            "name": name,
                            "data": _serialize_value(data, reg_type),
                            "type": type_name,
                            "type_id": reg_type,
                        })
                        index += 1
                    except OSError:
                        break
        except PermissionError:
            result["status"] = "access_denied"
            result["error_message"] = (
                f"Access denied reading {hive_name}\\{subkey} ({view_label} view). "
                "Administrator privileges may be required."
            )
            logger.warning("Access denied: %s\\%s (%s)", hive_name, subkey, view_label)
        except FileNotFoundError:
            result["status"] = "not_found"
            result["error_message"] = (
                f"Registry key not found: {hive_name}\\{subkey} ({view_label} view). "
                "The key may not exist on this system."
            )
            logger.info("Key not found: %s\\%s (%s)", hive_name, subkey, view_label)
        except OSError as e:
            result["status"] = "error"
            result["error_message"] = f"OS error reading {hive_name}\\{subkey}: {e}"
            logger.error("OS error: %s\\%s: %s", hive_name, subkey, e)

        results.append(result)

    return results


def perform_full_scan(config: dict, file_resolver=None) -> dict:
    """Perform a full scan of all configured registry paths.

    This is a SELECTED-PATH scan based on explicitly configured locations.
    It is NOT a complete backup of the Windows Registry.

    Args:
        config: Application configuration dict
        file_resolver: Optional file_resolver module for path resolution

    Returns:
        Baseline dict containing scan results, metadata, and status.
    """
    scan_64 = config.get("registry_views", {}).get("scan_64bit", True)
    scan_32 = config.get("registry_views", {}).get("scan_32bit", True)
    monitored = config.get("monitored_paths", [])

    # Auto-import file_resolver if enabled and not explicitly passed
    if file_resolver is None and config.get("file_checks", {}).get("resolve_paths", True):
        try:
            import file_resolver as fr_mod
            file_resolver = fr_mod
        except ImportError:
            file_resolver = None

    check_exists = config.get("file_checks", {}).get("check_file_exists", True)
    compute_hash = config.get("file_checks", {}).get("compute_sha256", True)

    scan_start = datetime.now(timezone.utc)
    all_results = []
    total_values = 0
    total_errors = 0
    total_access_denied = 0
    total_not_found = 0
    categories_scanned = []

    for category_block in monitored:
        category = category_block.get("category", "Unknown")
        categories_scanned.append(category)
        paths = category_block.get("paths", [])

        for path_entry in paths:
            hive = path_entry.get("hive", "")
            subkey = path_entry.get("subkey", "")

            scan_results = scan_registry_key(hive, subkey, scan_64, scan_32)
            if isinstance(scan_results, dict):
                scan_results = [scan_results]

            for result in scan_results:
                result["category"] = category
                values = result.get("values", [])
                total_values += len(values)

                # Attach file metadata to string values if resolver available
                if file_resolver:
                    for val in values:
                        if val.get("type") in ("REG_SZ", "REG_EXPAND_SZ"):
                            try:
                                resolved = file_resolver.resolve_registry_value(
                                    val["name"], val["data"], val["type"],
                                    check_exists=check_exists,
                                    compute_hash=compute_hash,
                                )
                                val["resolved_file"] = resolved
                            except Exception as e:
                                logger.debug("File resolution failed for %s: %s", val.get("name"), e)

                if result["status"] == "access_denied":
                    total_access_denied += 1
                elif result["status"] == "error":
                    total_errors += 1
                elif result["status"] == "not_found":
                    total_not_found += 1
                all_results.append(result)

    scan_end = datetime.now(timezone.utc)

    baseline = {
        "metadata": {
            "description": (
                "Windows Registry selected-path baseline. "
                "This is NOT a complete registry backup. "
                "Only explicitly configured paths are scanned."
            ),
            "created_at": scan_start.isoformat(),
            "completed_at": scan_end.isoformat(),
            "duration_seconds": (scan_end - scan_start).total_seconds(),
            "scan_type": "selected_paths",
            "total_keys_scanned": len(all_results),
            "total_values_captured": total_values,
            "total_errors": total_errors,
            "total_access_denied": total_access_denied,
            "total_not_found": total_not_found,
            "categories_scanned": categories_scanned,
            "registry_views": {
                "64bit": scan_64,
                "32bit": scan_32,
            },
        },
        "scan_results": all_results,
    }

    return baseline


def save_baseline(baseline: dict, file_path: str) -> None:
    """Save baseline to a JSON file.
    
    Writes to a temporary file first, then renames for atomicity.
    """
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Compute integrity hash
    content = json.dumps(baseline, indent=2, ensure_ascii=False)
    integrity_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    baseline["metadata"]["integrity_sha256"] = integrity_hash
    content = json.dumps(baseline, indent=2, ensure_ascii=False)

    tmp_path = path.with_suffix(".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
        # Atomic-ish rename (on Windows, need to remove target first if exists)
        if path.exists():
            path.unlink()
        tmp_path.rename(path)
        logger.info("Baseline saved to %s (%d bytes)", path, len(content))
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def load_baseline(file_path: str) -> dict | None:
    """Load a baseline from disk. Returns None if not found or invalid."""
    path = Path(file_path)
    if not path.exists():
        logger.info("No baseline file found at %s", path)
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        if "metadata" not in baseline or "scan_results" not in baseline:
            logger.warning("Baseline file is missing required fields.")
            return None
        logger.info("Baseline loaded from %s", path)
        return baseline
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load baseline: %s", e)
        return None


def verify_baseline_integrity(baseline: dict) -> bool:
    """Verify the SHA-256 integrity hash of a loaded baseline."""
    stored_hash = baseline.get("metadata", {}).get("integrity_sha256")
    if not stored_hash:
        return True  # No hash stored, skip verification
    
    # Recompute without the hash field
    baseline_copy = json.loads(json.dumps(baseline))
    baseline_copy["metadata"].pop("integrity_sha256", None)
    content = json.dumps(baseline_copy, indent=2, ensure_ascii=False)
    computed = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return computed == stored_hash


def delete_registry_value(hive_name: str, subkey: str, value_name: str, view: str = "64bit") -> tuple[bool, str]:
    """Safely delete a suspicious or malicious registry value.
    
    Args:
        hive_name: Hive identifier (e.g. 'HKEY_CURRENT_USER' or 'HKCU')
        subkey: Registry path under hive (e.g. 'Software\\Microsoft\\Windows\\CurrentVersion\\Run')
        value_name: Name of the registry value to delete
        view: Architecture view ('64bit' or '32bit')
        
    Returns:
        (success: bool, message: str)
    """
    hive_const = HIVE_MAP.get(hive_name)
    if hive_const is None:
        return False, f"Unsupported registry hive: {hive_name}"

    access_flag = winreg.KEY_SET_VALUE
    if view == "64bit":
        access_flag |= winreg.KEY_WOW64_64KEY
    elif view == "32bit":
        access_flag |= winreg.KEY_WOW64_32KEY

    try:
        with winreg.OpenKey(hive_const, subkey, 0, access_flag) as key:
            winreg.DeleteValue(key, value_name)
        logger.info("Successfully deleted registry value: %s\\%s [%s]", hive_name, subkey, value_name)
        return True, f"Registry value '{value_name}' was successfully deleted from {hive_name}\\{subkey}."
    except PermissionError:
        err_msg = f"Access denied deleting {hive_name}\\{subkey}\\{value_name}. Administrator privileges are required."
        logger.warning(err_msg)
        return False, err_msg
    except FileNotFoundError:
        return True, f"Value '{value_name}' was already removed or does not exist."
    except Exception as e:
        err_msg = f"Failed to delete registry value: {e}"
        logger.error(err_msg)
        return False, err_msg
