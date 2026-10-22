"""Report Generator Module

Generates structured logs and reports for registry monitoring events.
Supports JSONL event logs, CSV exports, and summary reports.
Uses UTF-8 encoding and safe file handling throughout.
"""

import csv
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler

logger = logging.getLogger(__name__)


def setup_logging(config: dict, app_dir: str) -> logging.Logger:
    """Configure application logging with rotation."""
    log_config = config.get("logging", {})
    log_dir = os.path.join(app_dir, log_config.get("log_directory", "data/logs"))
    os.makedirs(log_dir, exist_ok=True)

    app_log_file = os.path.join(log_dir, log_config.get("app_log_file", "app.log"))
    max_bytes = log_config.get("max_log_size_mb", 10) * 1024 * 1024

    root_logger = logging.getLogger()
    # Only add handlers if none exist yet
    if not root_logger.handlers:
        root_logger.setLevel(logging.DEBUG)

        # File handler with rotation
        fh = RotatingFileHandler(
            app_log_file, maxBytes=max_bytes, backupCount=5,
            encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        root_logger.addHandler(fh)

        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%H:%M:%S"
        ))
        root_logger.addHandler(ch)

    return root_logger


class EventLogger:
    """Logs events to a JSONL file."""

    def __init__(self, config: dict, app_dir: str):
        log_config = config.get("logging", {})
        log_dir = os.path.join(app_dir, log_config.get("log_directory", "data/logs"))
        os.makedirs(log_dir, exist_ok=True)
        self._event_file = os.path.join(
            log_dir, log_config.get("event_log_file", "events.jsonl")
        )
        self._max_bytes = log_config.get("max_log_size_mb", 10) * 1024 * 1024

    def log_event(self, event: dict):
        """Append an event to the JSONL log file."""
        try:
            # Check file size for basic rotation
            if os.path.exists(self._event_file):
                size = os.path.getsize(self._event_file)
                if size > self._max_bytes:
                    rotated = self._event_file + ".1"
                    if os.path.exists(rotated):
                        os.remove(rotated)
                    os.rename(self._event_file, rotated)

            with open(self._event_file, "a", encoding="utf-8") as f:
                line = json.dumps(event, ensure_ascii=False, default=str)
                f.write(line + "\n")
        except OSError as e:
            logger.error("Failed to write event to JSONL log: %s", e)

    def log_events(self, events: list[dict]):
        """Append multiple events to the JSONL log file."""
        for event in events:
            self.log_event(event)

    def read_events(self, max_events: int = 1000) -> list[dict]:
        """Read events from the JSONL log file.
        
        Returns the most recent events up to max_events.
        """
        events = []
        if not os.path.exists(self._event_file):
            return events
        try:
            with open(self._event_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except OSError as e:
            logger.error("Failed to read event log: %s", e)
        # Return most recent events
        if len(events) > max_events:
            events = events[-max_events:]
        return events


class ReportGenerator:
    """Generates CSV and summary reports from events."""

    def __init__(self, config: dict, app_dir: str):
        report_config = config.get("reporting", {})
        self._output_dir = os.path.join(
            app_dir, report_config.get("output_directory", "data/reports")
        )
        self._csv_enabled = report_config.get("csv_export_enabled", True)
        os.makedirs(self._output_dir, exist_ok=True)

    def export_events_to_csv(self, events: list[dict],
                              filename: str | None = None) -> str | None:
        """Export events to a CSV file.
        
        Args:
            events: List of event dicts to export
            filename: Optional filename (auto-generated if None)
            
        Returns:
            Path to the generated CSV file, or None on failure.
        """
        if not self._csv_enabled:
            logger.info("CSV export is disabled in configuration.")
            return None

        if not events:
            logger.info("No events to export.")
            return None

        if filename is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"registry_changes_{timestamp}.csv"

        filepath = os.path.join(self._output_dir, filename)

        # Define CSV columns
        columns = [
            "event_id", "timestamp", "change_type", "severity",
            "category", "hive", "full_path", "value_name",
            "previous_value", "current_value", "previous_type",
            "current_type", "view", "reason", "status",
            "resolved_executable", "file_exists", "file_sha256",
        ]

        try:
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
                writer.writeheader()

                for event in events:
                    row = {col: event.get(col, "") for col in columns}

                    # Flatten resolved file info
                    resolved = event.get("resolved_file") or {}
                    cmd_info = resolved.get("command_info") or {}
                    file_meta = resolved.get("file_metadata") or {}

                    row["resolved_executable"] = cmd_info.get("executable_path", "")
                    row["file_exists"] = str(file_meta.get("exists", "")) if file_meta else ""
                    row["file_sha256"] = file_meta.get("sha256", "") if file_meta else ""

                    # Truncate long values for CSV readability
                    for key in ("previous_value", "current_value"):
                        val = str(row.get(key, ""))
                        if len(val) > 500:
                            row[key] = val[:497] + "..."

                    writer.writerow(row)

            logger.info("CSV report exported: %s (%d events)", filepath, len(events))
            return filepath

        except OSError as e:
            logger.error("Failed to export CSV: %s", e)
            return None

    def generate_summary_report(self, events: list[dict],
                                 baseline_metadata: dict | None = None) -> dict:
        """Generate a summary report from events.
        
        Returns a structured summary dict with counts and breakdowns.
        """
        summary = {
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(events),
            "by_change_type": {},
            "by_severity": {},
            "by_category": {},
            "by_hive": {},
            "notable_events": [],
        }

        if baseline_metadata:
            summary["baseline_info"] = {
                "created_at": baseline_metadata.get("created_at", "Unknown"),
                "total_keys": baseline_metadata.get("total_keys_scanned", 0),
                "total_values": baseline_metadata.get("total_values_captured", 0),
            }

        for event in events:
            # Count by change type
            ct = event.get("change_type", "UNKNOWN")
            summary["by_change_type"][ct] = summary["by_change_type"].get(ct, 0) + 1

            # Count by severity
            sev = event.get("severity", "informational")
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

            # Count by category
            cat = event.get("category", "Unknown")
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

            # Count by hive
            hive = event.get("hive", "Unknown")
            summary["by_hive"][hive] = summary["by_hive"].get(hive, 0) + 1

            # Collect notable events (suspicious or investigation_required)
            if sev in ("suspicious", "investigation_required"):
                summary["notable_events"].append({
                    "event_id": event.get("event_id"),
                    "change_type": ct,
                    "severity": sev,
                    "full_path": event.get("full_path"),
                    "value_name": event.get("value_name"),
                    "reason": event.get("reason"),
                })

        return summary

    def save_summary_report(self, summary: dict,
                             filename: str | None = None) -> str | None:
        """Save a summary report to a JSON file.
        
        Args:
            summary: Summary dict to save
            filename: Optional filename (auto-generated if None)
            
        Returns:
            Path to the saved report, or None on failure.
        """
        if filename is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"summary_report_{timestamp}.json"

        filepath = os.path.join(self._output_dir, filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
            logger.info("Summary report saved: %s", filepath)
            return filepath
        except OSError as e:
            logger.error("Failed to save summary report: %s", e)
            return None

    def export_baseline_snapshot(self, baseline: dict,
                                  filename: str | None = None) -> str | None:
        """Export a human-readable baseline snapshot.
        
        Args:
            baseline: Baseline dict to export
            filename: Optional filename (auto-generated if None)
            
        Returns:
            Path to the exported snapshot, or None on failure.
        """
        if filename is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"baseline_snapshot_{timestamp}.json"

        filepath = os.path.join(self._output_dir, filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(baseline, f, indent=2, ensure_ascii=False, default=str)
            logger.info("Baseline snapshot exported: %s", filepath)
            return filepath
        except OSError as e:
            logger.error("Failed to export baseline snapshot: %s", e)
            return None


def export_events_csv(events: list[dict], output_path: str) -> str:
    """Export events directly to the specified CSV file path."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    columns = [
        "event_id", "timestamp", "change_type", "severity",
        "category", "hive", "full_path", "value_name",
        "previous_value", "current_value", "previous_type",
        "current_type", "view", "reason", "status",
        "resolved_executable", "file_exists", "file_sha256",
    ]
    try:
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for event in events:
                row = {col: event.get(col, "") for col in columns}
                resolved = event.get("resolved_file") or {}
                cmd_info = resolved.get("command_info") or {}
                file_meta = resolved.get("file_metadata") or {}
                row["resolved_executable"] = cmd_info.get("executable_path", "")
                row["file_exists"] = str(file_meta.get("exists", "")) if file_meta else ""
                row["file_sha256"] = file_meta.get("sha256", "") if file_meta else ""
                for key in ("previous_value", "current_value"):
                    val = str(row.get(key, ""))
                    if len(val) > 500:
                        row[key] = val[:497] + "..."
                writer.writerow(row)
        logger.info("CSV exported: %s (%d events)", output_path, len(events))
        return output_path
    except OSError as e:
        logger.error("Failed to export CSV: %s", e)
        raise


def generate_summary_report(events: list[dict],
                            baseline_metadata: dict | None = None,
                            config: dict | None = None) -> dict:
    """Generate a summary report from events and metadata."""
    generator = ReportGenerator(config or {}, ".")
    summary = generator.generate_summary_report(events, baseline_metadata)
    if config:
        summary["polling_interval_seconds"] = config.get("polling_interval_seconds", 5)
        monitored_paths = []
        for cat_block in config.get("monitored_paths", []):
            for p in cat_block.get("paths", []):
                monitored_paths.append(f"{p.get('hive', '')}\\{p.get('subkey', '')}")
        summary["total_monitored_paths"] = len(monitored_paths)
        summary["monitored_paths"] = monitored_paths
    return summary


def save_summary_report(summary: dict, output_path: str) -> str:
    """Save a summary report to the specified file path."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=str)
        logger.info("Summary report saved: %s", output_path)
        return output_path
    except OSError as e:
        logger.error("Failed to save summary report: %s", e)
        raise


def export_advanced_analysis_csv(files: list[dict], output_path: str) -> str:
    """Export advanced file analysis results to CSV."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    columns = [
        "risk_level", "file_name", "exists", "file_type", "size_bytes",
        "sha256", "finding", "file_path", "category", "registry_path",
        "value_name", "value_data", "arguments", "modified_time", "view",
    ]
    try:
        with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for row in files:
                r = dict(row)
                if len(str(r.get("value_data", ""))) > 500:
                    r["value_data"] = str(r["value_data"])[:497] + "..."
                writer.writerow(r)
        logger.info("Advanced analysis CSV saved: %s (%d files)", output_path, len(files))
        return output_path
    except OSError as e:
        logger.error("Failed to export advanced analysis CSV: %s", e)
        raise


def export_advanced_analysis_json(report_data: dict, output_path: str) -> str:
    """Export advanced file analysis results to JSON."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        logger.info("Advanced analysis JSON saved: %s", output_path)
        return output_path
    except OSError as e:
        logger.error("Failed to export advanced analysis JSON: %s", e)
        raise


def export_events_visual_report(events: list[dict],
                                baseline_metadata: dict | None,
                                output_path: str) -> str:
    """Generate and save a publication-quality visual image report (PNG) of events."""
    import visual_reporter
    return visual_reporter.generate_events_visual_report(events, baseline_metadata, output_path)


def export_advanced_analysis_visual_report(report_data: dict, output_path: str) -> str:
    """Generate and save a publication-quality visual image report (PNG) of file analysis."""
    import visual_reporter
    return visual_reporter.generate_advanced_file_visual_report(report_data, output_path)



