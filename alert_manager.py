"""Alert Manager Module

Manages desktop pop-up alerts for registry change events.
Uses a thread-safe queue and Tkinter's after() mechanism to
display alerts on the GUI thread without blocking monitoring.
"""

import logging
import time
import tkinter as tk
from tkinter import messagebox
from collections import deque
from threading import Lock
from typing import Callable

logger = logging.getLogger(__name__)


class AlertManager:
    """Manages alert display, deduplication, rate limiting, and muting."""

    def __init__(self, config: dict):
        self._config = config.get("alert_settings", {})
        self._popup_enabled = self._config.get("popup_enabled", True)
        self._muted = self._config.get("mute_popups", False)
        self._severity_threshold = self._config.get(
            "popup_severity_threshold", "informational"
        )
        self._rate_limit_seconds = self._config.get("popup_rate_limit_seconds", 3)
        self._max_queued = self._config.get("max_queued_alerts", 50)

        self._seen_fingerprints: set[str] = set()
        self._alert_history: deque[dict] = deque(maxlen=1000)
        self._last_alert_time: float = 0.0
        self._lock = Lock()
        self._suppressed_count: int = 0
        self._pending_alerts: deque[dict] = deque(maxlen=self._max_queued)

        # Severity ordering for threshold comparison
        self._severity_order = {
            "informational": 0,
            "suspicious": 1,
            "investigation_required": 2,
        }

    @property
    def muted(self) -> bool:
        return self._muted

    @muted.setter
    def muted(self, value: bool):
        self._muted = value

    @property
    def popup_enabled(self) -> bool:
        return self._popup_enabled

    @popup_enabled.setter
    def popup_enabled(self, value: bool):
        self._popup_enabled = value

    @property
    def suppressed_count(self) -> int:
        return self._suppressed_count

    @property
    def alert_history(self) -> list[dict]:
        with self._lock:
            return list(self._alert_history)

    def _meets_threshold(self, severity: str) -> bool:
        """Check if an event's severity meets the alert threshold."""
        event_level = self._severity_order.get(severity, 0)
        threshold_level = self._severity_order.get(self._severity_threshold, 0)
        return event_level >= threshold_level

    def should_alert(self, event: dict) -> bool:
        """Determine whether an event should trigger a pop-up alert."""
        if not self._popup_enabled:
            return False
        if self._muted:
            return False

        severity = event.get("severity", "informational")
        if not self._meets_threshold(severity):
            return False

        # Check deduplication
        fingerprint = event.get("fingerprint", "")
        if fingerprint and fingerprint in self._seen_fingerprints:
            with self._lock:
                self._suppressed_count += 1
            return False

        # Check rate limiting
        now = time.time()
        if now - self._last_alert_time < self._rate_limit_seconds:
            # Queue for later instead of dropping
            with self._lock:
                if len(self._pending_alerts) < self._max_queued:
                    self._pending_alerts.append(event)
            return False

        return True

    def record_alert(self, event: dict):
        """Record that an alert was shown for this event."""
        with self._lock:
            fingerprint = event.get("fingerprint", "")
            if fingerprint:
                self._seen_fingerprints.add(fingerprint)
            self._alert_history.append(event)
            self._last_alert_time = time.time()

    def get_pending_alert(self) -> dict | None:
        """Get next pending alert, respecting rate limiting."""
        now = time.time()
        if now - self._last_alert_time < self._rate_limit_seconds:
            return None
        with self._lock:
            if self._pending_alerts:
                event = self._pending_alerts.popleft()
                # Re-check dedup for queued alerts
                fp = event.get("fingerprint", "")
                if fp and fp in self._seen_fingerprints:
                    self._suppressed_count += 1
                    return None
                return event
        return None

    def format_alert_message(self, event: dict) -> str:
        """Format an event into a human-readable alert message."""
        resolved = event.get("resolved_file") or {}
        cmd_info = resolved.get("command_info") or {}
        file_meta = resolved.get("file_metadata") or {}

        exe_path = cmd_info.get("executable_path", "Unknown")
        file_exists = "Unknown"
        if file_meta:
            file_exists = "Yes" if file_meta.get("exists") else "No"

        lines = [
            f"Change Type: {event.get('change_type', 'UNKNOWN')}",
            f"Registry Location: {event.get('full_path', 'Unknown')}",
            f"Value Name: {event.get('value_name', 'Unknown')}",
            f"Referenced File: {exe_path}",
            f"File Exists: {file_exists}",
            f"Severity: {event.get('severity', 'Unknown').title()}",
            f"Reason: {event.get('reason', 'No details')}",
        ]

        if event.get("current_value") is not None:
            cv = str(event["current_value"])
            if len(cv) > 120:
                cv = cv[:117] + "..."
            lines.append(f"Current Value: {cv}")

        if event.get("previous_value") is not None:
            pv = str(event["previous_value"])
            if len(pv) > 120:
                pv = pv[:117] + "..."
            lines.append(f"Previous Value: {pv}")

        return "\n".join(lines)

    def reset_fingerprints(self):
        """Clear seen fingerprints (e.g., after baseline reset)."""
        with self._lock:
            self._seen_fingerprints.clear()
            self._suppressed_count = 0
            self._pending_alerts.clear()

    def update_config(self, config: dict):
        """Update alert settings from config."""
        settings = config.get("alert_settings", {})
        self._popup_enabled = settings.get("popup_enabled", True)
        self._muted = settings.get("mute_popups", False)
        self._severity_threshold = settings.get(
            "popup_severity_threshold", "informational"
        )
        self._rate_limit_seconds = settings.get("popup_rate_limit_seconds", 3)
        self._max_queued = settings.get("max_queued_alerts", 50)
