"""File Resolver Module

Identifies and analyzes executable file paths referenced by registry values.
Parses command lines, expands environment variables, resolves quoted paths,
and collects file metadata. Never executes, modifies, or deletes any files.
"""

import os
import re
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Known executable extensions
EXECUTABLE_EXTENSIONS = {
    ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msc",
    ".scr", ".pif",
}

# Known library/module extensions
LIBRARY_EXTENSIONS = {
    ".dll", ".sys", ".drv", ".ocx", ".cpl",
}

# rundll32 pattern
RUNDLL32_PATTERN = re.compile(
    r'(?:.*[\\/])?rundll32(?:\.exe)?\s+["\']?(.+?)["\']?\s*,',
    re.IGNORECASE,
)


def classify_file_type(path_str: str) -> str:
    """Classify a file path by its extension."""
    if not path_str:
        return "unknown"
    ext = Path(path_str).suffix.lower()
    if ext in EXECUTABLE_EXTENSIONS:
        return "executable"
    if ext in LIBRARY_EXTENSIONS:
        return "library"
    if ext:
        return f"file({ext})"
    return "unknown"


def expand_env_variables(value: str) -> str:
    """Expand Windows environment variables in a string.
    
    Handles %VAR% style variables. Returns original if expansion fails.
    """
    if not value or "%" not in value:
        return value
    try:
        return os.path.expandvars(value)
    except Exception as e:
        logger.debug("Environment variable expansion failed for '%s': %s", value, e)
        return value


def _extract_quoted_path(value: str) -> tuple[str | None, str]:
    """Extract a quoted path from the beginning of a string.
    
    Returns (extracted_path, remainder) or (None, original).
    """
    value = value.strip()
    if value.startswith('"'):
        end = value.find('"', 1)
        if end != -1:
            return value[1:end], value[end + 1:].strip()
    if value.startswith("'"):
        end = value.find("'", 1)
        if end != -1:
            return value[1:end], value[end + 1:].strip()
    return None, value


def _looks_like_path(value: str) -> bool:
    """Check if a string looks like it could contain a file path."""
    if not value or not isinstance(value, str):
        return False
    # Drive letter path
    if len(value) >= 3 and value[1] == ":" and value[2] in ("\\", "/"):
        return True
    # UNC path
    if value.startswith("\\\\"):
        return True
    # Environment variable path
    if "%" in value and ("\\" in value or "/" in value):
        return True
    # Relative path with backslash
    if "\\" in value and "." in value:
        return True
    return False


def _parse_unquoted_command(value: str) -> tuple[str | None, str]:
    """Parse an unquoted command line to extract the executable path.
    
    Tries progressively shorter prefixes to find an existing file.
    Falls back to splitting on spaces if no file is found.
    """
    expanded = expand_env_variables(value)
    
    # Try progressively shorter space-delimited prefixes
    parts = expanded.split()
    for i in range(len(parts), 0, -1):
        candidate = " ".join(parts[:i])
        if os.path.isfile(candidate):
            args = " ".join(parts[i:])
            return candidate, args
    
    # If no existing file found, use first token
    if parts:
        return parts[0], " ".join(parts[1:])
    
    return None, value


def parse_command_line(value: str) -> dict:
    """Parse a registry value to extract executable path and arguments.
    
    Returns a dict with:
        - original_value: str
        - expanded_value: str
        - executable_path: str or None
        - arguments: str
        - parse_method: str
        - file_type: str
    """
    if not value or not isinstance(value, str):
        return {
            "original_value": str(value) if value is not None else "",
            "expanded_value": "",
            "executable_path": None,
            "arguments": "",
            "parse_method": "empty_or_invalid",
            "file_type": "unknown",
        }

    original = value
    expanded = expand_env_variables(value.strip())
    
    # Check for rundll32 pattern
    rundll_match = RUNDLL32_PATTERN.match(expanded)
    if rundll_match:
        dll_path = rundll_match.group(1).strip().strip('"\'')
        dll_expanded = expand_env_variables(dll_path)
        return {
            "original_value": original,
            "expanded_value": expanded,
            "executable_path": dll_expanded,
            "arguments": expanded[rundll_match.end()-1:].strip(),
            "parse_method": "rundll32",
            "file_type": classify_file_type(dll_expanded),
        }

    # Try quoted path extraction
    quoted_path, remainder = _extract_quoted_path(expanded)
    if quoted_path:
        return {
            "original_value": original,
            "expanded_value": expanded,
            "executable_path": quoted_path,
            "arguments": remainder,
            "parse_method": "quoted",
            "file_type": classify_file_type(quoted_path),
        }

    # Try unquoted command parsing
    if _looks_like_path(expanded):
        exe_path, arguments = _parse_unquoted_command(expanded)
        if exe_path:
            return {
                "original_value": original,
                "expanded_value": expanded,
                "executable_path": exe_path,
                "arguments": arguments,
                "parse_method": "unquoted",
                "file_type": classify_file_type(exe_path),
            }

    # Fallback: treat entire value as unresolved
    return {
        "original_value": original,
        "expanded_value": expanded,
        "executable_path": None,
        "arguments": "",
        "parse_method": "unresolved",
        "file_type": "unknown",
    }


def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str | None:
    """Compute the hash of a file. Returns None on failure."""
    try:
        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError, ValueError) as e:
        logger.debug("Hash computation failed for '%s': %s", file_path, e)
        return None


def get_file_metadata(file_path: str, compute_hash: bool = True) -> dict:
    """Collect metadata for a file path.
    
    Returns dict with existence, size, modification time, and optional hash.
    Never executes or modifies the file.
    """
    result = {
        "path": file_path,
        "exists": False,
        "size_bytes": None,
        "modified_time": None,
        "sha256": None,
        "error": None,
    }

    if not file_path:
        result["error"] = "No file path provided"
        return result

    try:
        p = Path(file_path)
        if p.exists():
            result["exists"] = True
            stat = p.stat()
            result["size_bytes"] = stat.st_size
            result["modified_time"] = datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).isoformat()
            if compute_hash:
                result["sha256"] = compute_file_hash(file_path)
        else:
            result["error"] = "File not found"
    except PermissionError:
        result["error"] = "Access denied"
    except OSError as e:
        result["error"] = f"OS error: {e}"

    return result


def resolve_registry_value(value_name: str, value_data: Any, value_type: str,
                            check_exists: bool = True, compute_hash: bool = True) -> dict:
    """Resolve file information from a registry value.
    
    Args:
        value_name: Registry value name
        value_data: Registry value data
        value_type: Registry value type string (e.g., 'REG_SZ')
        check_exists: Whether to check if the file exists
        compute_hash: Whether to compute SHA-256 hash
    
    Returns:
        Resolution dict with parsed command, file metadata, and status.
    """
    result = {
        "value_name": value_name,
        "value_data": value_data,
        "value_type": value_type,
        "resolution_status": "unresolved",
        "command_info": None,
        "file_metadata": None,
    }

    # Only attempt resolution for string-type values
    if value_type not in ("REG_SZ", "REG_EXPAND_SZ"):
        result["resolution_status"] = "non_string_type"
        return result

    if not isinstance(value_data, str) or not value_data.strip():
        result["resolution_status"] = "empty_value"
        return result

    # Parse the command line
    cmd_info = parse_command_line(value_data)
    result["command_info"] = cmd_info

    exe_path = cmd_info.get("executable_path")
    if not exe_path:
        result["resolution_status"] = "unresolved"
        return result

    result["resolution_status"] = "resolved"

    # Get file metadata if requested
    if check_exists:
        file_meta = get_file_metadata(exe_path, compute_hash=compute_hash)
        result["file_metadata"] = file_meta
        if not file_meta["exists"]:
            result["resolution_status"] = "file_not_found"

    return result


def assess_file_risk(file_path: str, exists: bool, command_line: str, category: str = "") -> tuple[str, str]:
    """Assess the security risk of a file referenced by registry values.

    Returns (risk_level, explanation) tuple.
    risk_level: 'BENIGN' | 'INFO' | 'WARNING' | 'SUSPICIOUS' | 'CRITICAL'
    """
    if not file_path:
        return ("INFO", "No file path specified")

    norm_path = file_path.lower()
    ext = Path(file_path).suffix.lower()

    # Missing file check
    if not exists:
        return ("WARNING", "Referenced file does not exist on disk (orphaned or broken registry reference)")

    # Temporary directory check
    temp_indicators = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\"]
    for ind in temp_indicators:
        if ind in norm_path:
            return ("SUSPICIOUS", f"File is located in a temporary directory ({ind.strip('\\')})")

    # Script files
    script_exts = {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1"}
    if ext in script_exts:
        return ("SUSPICIOUS", f"Script file execution configured in registry ({ext})")

    # AppData directory check
    if "\\appdata\\" in norm_path and "\\programs\\" not in norm_path:
        if "run" in category.lower():
            return ("WARNING", "Startup executable located in user AppData folder")

    # Unquoted path vulnerability
    if " " in file_path and not command_line.strip().startswith('"'):
        return ("WARNING", "Unquoted path with spaces (potential unquoted search path elevation vector)")

    # System binaries
    if norm_path.startswith("c:\\windows\\system32\\") or norm_path.startswith("c:\\windows\\syswow64\\"):
        return ("BENIGN", "Standard Windows system binary")

    if norm_path.startswith("c:\\program files") or norm_path.startswith("c:\\programdata\\"):
        return ("BENIGN", "Standard application directory binary")

    return ("INFO", "Accessible file reference")


def analyze_all_monitored_files(config: dict, scan_results: list = None) -> dict:
    """Perform an advanced system monitoring scan analyzing all files referenced across registry keys.

    Returns a comprehensive dictionary with summary statistics and per-file analysis.
    """
    import registry_scanner
    if not scan_results:
        scan_data = registry_scanner.perform_full_scan(config)
        scan_results = scan_data.get("scan_results", [])

    analyzed_files = []
    total_size_bytes = 0
    existing_count = 0
    missing_count = 0
    suspicious_count = 0
    hashes_computed = 0

    for key_res in scan_results:
        category = key_res.get("category", "General")
        full_path = key_res.get("full_path", "")
        view = key_res.get("view", "default")

        for val in key_res.get("values", []):
            vname = val.get("name", "")
            vdata = val.get("data")
            vtype = val.get("type", "")

            if vtype not in ("REG_SZ", "REG_EXPAND_SZ") or not isinstance(vdata, str) or not vdata.strip():
                continue

            res = resolve_registry_value(vname, vdata, vtype, check_exists=True, compute_hash=True)
            cmd_info = res.get("command_info") or {}
            exe_path = cmd_info.get("executable_path")

            if not exe_path:
                continue

            file_meta = res.get("file_metadata") or {}
            exists = file_meta.get("exists", False)
            size = file_meta.get("size_bytes")
            sha256 = file_meta.get("sha256")
            mtime = file_meta.get("modified_time")
            file_type = cmd_info.get("file_type", "unknown")

            risk_level, explanation = assess_file_risk(
                exe_path, exists, str(vdata), category
            )

            if exists:
                existing_count += 1
                if size:
                    total_size_bytes += size
                if sha256:
                    hashes_computed += 1
            else:
                missing_count += 1

            if risk_level in ("WARNING", "SUSPICIOUS", "CRITICAL"):
                suspicious_count += 1

            analyzed_files.append({
                "file_path": exe_path,
                "file_name": Path(exe_path).name if exe_path else "Unknown",
                "exists": exists,
                "size_bytes": size,
                "sha256": sha256,
                "modified_time": mtime,
                "file_type": file_type,
                "risk_level": risk_level,
                "finding": explanation,
                "category": category,
                "registry_path": full_path,
                "value_name": vname,
                "value_data": str(vdata),
                "arguments": cmd_info.get("arguments", ""),
                "view": view,
            })

    return {
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_files_analyzed": len(analyzed_files),
            "existing_files": existing_count,
            "missing_files": missing_count,
            "suspicious_or_warning_files": suspicious_count,
            "hashes_computed": hashes_computed,
            "total_size_bytes": total_size_bytes,
        },
        "files": analyzed_files,
    }

