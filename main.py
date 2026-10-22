"""Windows Registry Change Monitoring System - Main Application

A defensive, read-only registry auditing tool that monitors selected
Windows Registry locations for changes and provides desktop alerts.

This application:
- Never modifies or deletes registry values
- Never disables Windows security protections
- Never executes registry-referenced programs
- Never automatically terminates processes
- Does not guarantee malware detection or complete system protection
"""

import json
import logging
import os
import sys
import threading
import time
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue, Empty
from tkinter import ttk, messagebox, filedialog

# Verify Windows platform
if sys.platform != "win32":
    print("ERROR: This application requires Windows.")
    print("The Windows Registry is not available on this platform.")
    sys.exit(1)

import registry_scanner
import change_detector
import file_resolver
import alert_manager
import report_generator
import visual_reporter
import database
import autostart
import theme_manager
from settings_window import AppSettingsWindow
from PIL import Image, ImageTk

logger = logging.getLogger(__name__)

if getattr(sys, "frozen", False):
    exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    parent_dir = os.path.dirname(exe_dir)
    # If running from a build 'dist' directory inside project root, use the parent project root
    if os.path.basename(exe_dir).lower() == "dist" and os.path.exists(os.path.join(parent_dir, "config.json")):
        APP_DIR = parent_dir
    else:
        APP_DIR = exe_dir

    # If config.json doesn't exist in the target folder, copy default bundled config if present
    bundled_dir = getattr(sys, "_MEIPASS", APP_DIR)
    bundled_config = os.path.join(bundled_dir, "config.json")
    target_config = os.path.join(APP_DIR, "config.json")
    if not os.path.exists(target_config) and os.path.exists(bundled_config):
        try:
            import shutil
            shutil.copy2(bundled_config, target_config)
        except Exception:
            pass
    # If app_icon.ico is in bundled_dir, copy to target data folder if needed
    bundled_icon = os.path.join(bundled_dir, "data", "app_icon.ico")
    target_icon = os.path.join(APP_DIR, "data", "app_icon.ico")
    if not os.path.exists(target_icon) and os.path.exists(bundled_icon):
        try:
            import shutil
            os.makedirs(os.path.dirname(target_icon), exist_ok=True)
            shutil.copy2(bundled_icon, target_icon)
        except Exception:
            pass
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_FILE = os.path.join(APP_DIR, "config.json")
DEFAULT_BASELINE_PATH = os.path.join(APP_DIR, "data", "baseline.json")


def hide_console_window():
    """Hide the Windows console/terminal window so it runs silently in the background."""
    if sys.platform == "win32":
        try:
            import ctypes
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE = 0
        except Exception as e:
            logger.debug("Failed to hide console window: %s", e)


# Automatically hide the black console window when running on Windows
hide_console_window()


def load_config(config_path: str = CONFIG_FILE) -> dict:
    """Load and validate configuration file."""
    defaults = {
        "polling_interval_seconds": 5,
        "monitored_paths": [],
        "alert_settings": {
            "popup_enabled": True,
            "popup_severity_threshold": "informational",
            "popup_rate_limit_seconds": 3,
            "max_queued_alerts": 50,
            "mute_popups": False,
        },
        "file_checks": {
            "resolve_paths": True,
            "compute_sha256": True,
            "check_file_exists": True,
            "collect_file_metadata": True,
        },
        "logging": {
            "log_directory": "data/logs",
            "app_log_file": "app.log",
            "event_log_file": "events.jsonl",
            "max_log_size_mb": 10,
            "log_retention_days": 90,
        },
        "reporting": {
            "output_directory": "data/reports",
            "csv_export_enabled": True,
        },
        "baseline": {
            "file_path": "data/baseline.json",
            "auto_create_on_first_run": False,
        },
        "hide_taskbar_icon": True,
        "minimize_to_floating_icon": True,
        "registry_views": {
            "scan_64bit": True,
            "scan_32bit": True,
        },
    }

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        logger.info("Configuration loaded from %s", config_path)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("Config load failed (%s), using defaults.", e)
        config = defaults

    # Validate polling interval
    interval = config.get("polling_interval_seconds", 5)
    if not isinstance(interval, (int, float)) or interval < 1:
        config["polling_interval_seconds"] = 5

    # Ensure required sections exist
    for key, default_val in defaults.items():
        if key not in config:
            config[key] = default_val

    return config


def set_taskbar_visibility(widget, show: bool = True):
    """Toggle appearance of a window on the Windows Taskbar.

    When show is False:
    - Sets '-toolwindow' True (WS_EX_TOOLWINDOW)
    - Removes window entry from the Windows Taskbar.

    When show is True:
    - Sets '-toolwindow' False
    - Window appears normally on the Windows Taskbar.
    """
    try:
        widget.wm_attributes("-toolwindow", not show)
    except Exception:
        try:
            import ctypes
            widget.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(widget.winfo_id()) or widget.winfo_id()
            GWL_EXSTYLE = -20
            WS_EX_TOOLWINDOW = 0x00000080
            WS_EX_APPWINDOW = 0x00040000

            style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
            if show:
                style = (style & ~WS_EX_TOOLWINDOW) | WS_EX_APPWINDOW
            else:
                style = (style | WS_EX_TOOLWINDOW) & ~WS_EX_APPWINDOW

            is_withdrawn = (widget.state() == "withdrawn")
            if not is_withdrawn:
                ctypes.windll.user32.ShowWindow(hwnd, 0)
            ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)
            if not is_withdrawn:
                ctypes.windll.user32.ShowWindow(hwnd, 5)
        except Exception as e:
            logger.debug("Failed to set taskbar visibility: %s", e)


class MonitoringThread(threading.Thread):
    """Background thread for continuous registry monitoring."""

    def __init__(self, config: dict, event_queue: Queue,
                 baseline: dict, file_resolver_mod):
        super().__init__(daemon=True)
        self._config = config
        self._event_queue = event_queue
        self._baseline = baseline
        self._file_resolver = file_resolver_mod
        self._stop_event = threading.Event()
        self._interval = config.get("polling_interval_seconds", 5)
        # Track last known state for detecting inter-scan changes
        self._last_state = baseline.get("scan_results", [])

    def stop(self):
        """Signal the monitoring thread to stop."""
        self._stop_event.set()

    def is_stopping(self) -> bool:
        return self._stop_event.is_set()

    def update_baseline(self, baseline: dict):
        """Update the reference baseline."""
        self._baseline = baseline
        self._last_state = baseline.get("scan_results", [])

    def update_interval(self, new_interval: int):
        """Update polling interval dynamically."""
        self._interval = max(1, int(new_interval))
        self._config["polling_interval_seconds"] = self._interval
        logger.info("Monitoring thread polling interval updated to %ds", self._interval)

    def run(self):
        logger.info("Monitoring thread started (interval=%ds)", self._interval)
        self._event_queue.put({"type": "status", "status": "MONITORING"})

        while not self._stop_event.is_set():
            try:
                current_scan = registry_scanner.perform_full_scan(self._config)
                current_results = current_scan.get("scan_results", [])

                # Determine file resolver module usage
                fr = self._file_resolver if self._config.get(
                    "file_checks", {}).get("resolve_paths", True) else None

                events = change_detector.detect_changes(
                    self._last_state, current_results, fr
                )

                if events:
                    self._event_queue.put({
                        "type": "events",
                        "events": events,
                        "scan_timestamp": current_scan["metadata"]["completed_at"],
                    })
                    # Update last known state after detecting changes
                    self._last_state = current_results

                else:
                    self._last_state = current_results

                # Send scan stats
                self._event_queue.put({
                    "type": "scan_complete",
                    "timestamp": current_scan["metadata"]["completed_at"],
                    "keys_scanned": current_scan["metadata"]["total_keys_scanned"],
                    "errors": current_scan["metadata"]["total_errors"],
                    "access_denied": current_scan["metadata"]["total_access_denied"],
                })

            except Exception as e:
                logger.error("Monitoring scan error: %s", e, exc_info=True)
                self._event_queue.put({
                    "type": "error",
                    "message": str(e),
                })

            # Wait for interval or stop signal
            self._stop_event.wait(self._interval)

        self._event_queue.put({"type": "status", "status": "STOPPED"})
        logger.info("Monitoring thread stopped.")


class NonBlockingAlertWindow(tk.Toplevel):
    """A floating, non-blocking desktop alert notification window.

    Displays detected registry changes on top of other windows without
    pausing background monitoring or blocking the Tkinter event loop.
    """

    _active_popups = []

    def __init__(self, parent, event: dict, on_view_event=None, on_mute=None):
        super().__init__(parent)
        self.event = event
        self.on_view_event = on_view_event
        self.on_mute = on_mute

        severity = event.get("severity", "informational")
        if severity == "investigation_required":
            bg_color = "#b71c1c"
            title_text = "⚠ INVESTIGATION REQUIRED: Registry Change"
        elif severity == "suspicious":
            bg_color = "#e65100"
            title_text = "⚠ SUSPICIOUS: Registry Change Detected"
        else:
            bg_color = "#1565c0"
            title_text = "ℹ Registry Change Detected"

        self.title("Registry Change Alert")
        self.attributes("-topmost", True)
        self.resizable(False, False)
        self.configure(bg="#f8f9fa")

        # Position window near bottom-right of screen, stacked
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        offset = (len(NonBlockingAlertWindow._active_popups) % 5) * 35
        pos_x = max(20, screen_w - 560 - offset)
        pos_y = max(20, screen_h - 430 - offset)
        self.geometry(f"530x340+{pos_x}+{pos_y}")
        NonBlockingAlertWindow._active_popups.append(self)
        set_taskbar_visibility(self, False)

        # Header banner
        header = tk.Frame(self, bg=bg_color, padx=12, pady=10)
        header.pack(fill=tk.X)
        tk.Label(
            header, text=title_text, fg="white", bg=bg_color,
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w")

        # Content body
        body = tk.Frame(self, bg="#f8f9fa", padx=14, pady=10)
        body.pack(fill=tk.BOTH, expand=True)

        resolved = event.get("resolved_file") or {}
        cmd_info = resolved.get("command_info") or {}
        file_meta = resolved.get("file_metadata") or {}
        exe_path = cmd_info.get("executable_path", "Unknown")
        file_exists = "Yes" if file_meta.get("exists") else ("No" if file_meta else "Unknown")

        details = [
            ("Change Type:", event.get("change_type", "UNKNOWN")),
            ("Registry Location:", event.get("full_path", "Unknown")),
            ("Value Name:", event.get("value_name", "Unknown")),
            ("Referenced File:", exe_path),
            ("File Exists:", file_exists),
            ("Severity:", severity.title()),
            ("Reason:", event.get("reason", "No details")),
        ]

        for i, (label, val) in enumerate(details):
            tk.Label(
                body, text=label, bg="#f8f9fa", fg="#555555",
                font=("Segoe UI", 9, "bold"), anchor="w"
            ).grid(row=i, column=0, sticky="nw", pady=2, padx=(0, 8))
            val_lbl = tk.Label(
                body, text=str(val)[:85] + ("..." if len(str(val)) > 85 else ""),
                bg="#f8f9fa", fg="#111111", font=("Segoe UI", 9),
                anchor="w", justify="left", wraplength=380
            )
            val_lbl.grid(row=i, column=1, sticky="w", pady=2)

        # Button frame
        btn_frame = tk.Frame(self, bg="#eeeeee", padx=10, pady=8)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        dismiss_btn = ttk.Button(btn_frame, text="Dismiss", command=self._dismiss)
        dismiss_btn.pack(side=tk.RIGHT, padx=4)

        if self.on_view_event:
            view_btn = ttk.Button(btn_frame, text="View in Table", command=self._view_in_table)
            view_btn.pack(side=tk.RIGHT, padx=4)

        if self.on_mute:
            mute_btn = ttk.Button(btn_frame, text="Mute Pop-ups", command=self._mute)
            mute_btn.pack(side=tk.LEFT, padx=4)

        self.protocol("WM_DELETE_WINDOW", self._dismiss)

    def _dismiss(self):
        if self in NonBlockingAlertWindow._active_popups:
            NonBlockingAlertWindow._active_popups.remove(self)
        self.destroy()

    def _view_in_table(self):
        if self.on_view_event:
            self.on_view_event(self.event)
        self._dismiss()

    def _mute(self):
        if self.on_mute:
            self.on_mute()
        self._dismiss()


def _format_size(size_bytes):
    """Format byte size into human-readable string."""
    if size_bytes is None:
        return "N/A"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


class FloatingDesktopWidget(tk.Toplevel):
    """Movable floating desktop widget/icon that stays on screen when app runs in background.

    Features:
    - Draggable anywhere on desktop using mouse drag (<B1-Motion>)
    - Click or double-click restores the main frontend visual app
    - Displays live monitoring status (MONITORING / STOPPED) and change counter
    - Right-click context menu with quick actions
    - Keeps app running in background without taskbar clutter
    """

    def __init__(self, app):
        super().__init__(app.root)
        self.app = app
        self.title("Registry Monitor Floating Icon")

        # Frameless, topmost floating widget
        self.overrideredirect(True)
        self.wm_attributes("-topmost", True)

        # Track dragging state
        self._drag_start_x = 0
        self._drag_start_y = 0
        self._is_dragging = False

        # Position at bottom-right of screen initially
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        init_x = max(50, screen_w - 250)
        init_y = max(50, screen_h - 150)
        self.geometry(f"220x64+{init_x}+{init_y}")

        self.configure(bg="#0f172a")  # Dark slate background
        self._build_ui()

        # Ensure floating widget NEVER creates an entry on the Windows taskbar
        set_taskbar_visibility(self, False)

        # Start hidden until user sends to background
        self.withdraw()

    def _build_ui(self):
        # Outer container frame with border
        self.container = tk.Frame(self, bg="#0f172a", bd=2, relief=tk.RIDGE, cursor="fleur")
        self.container.pack(fill=tk.BOTH, expand=True)

        # Left Icon Canvas
        self.icon_canvas = tk.Canvas(self.container, width=40, height=40, bg="#0f172a", highlightthickness=0, cursor="fleur")
        self.icon_canvas.pack(side=tk.LEFT, padx=(8, 4), pady=10)
        # Draw shield badge
        self.icon_canvas.create_polygon([20, 4, 36, 10, 36, 26, 20, 36, 4, 26, 4, 10], fill="#1e40af", outline="#60a5fa", width=2)
        self.icon_canvas.create_polygon([20, 8, 32, 13, 32, 24, 20, 32, 8, 24, 8, 13], fill="#2563eb")
        self.icon_canvas.create_text(20, 20, text="🛡️", font=("Segoe UI Emoji", 11))

        # Center Info Frame
        info_frame = tk.Frame(self.container, bg="#0f172a", cursor="fleur")
        info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=10)

        self.title_label = tk.Label(
            info_frame, text="Registry Monitor", font=("Segoe UI", 9, "bold"),
            bg="#0f172a", fg="#ffffff", cursor="fleur"
        )
        self.title_label.pack(anchor="w")

        self.status_pill = tk.Label(
            info_frame, text="● STOPPED", font=("Segoe UI", 8, "bold"),
            bg="#0f172a", fg="#ef4444", cursor="fleur"
        )
        self.status_pill.pack(anchor="w")

        # Right Counter Badge Frame
        badge_frame = tk.Frame(self.container, bg="#0f172a", cursor="fleur")
        badge_frame.pack(side=tk.RIGHT, padx=(4, 10), pady=10)

        self.counter_badge = tk.Label(
            badge_frame, text="0", font=("Segoe UI", 9, "bold"),
            bg="#1e293b", fg="#38bdf8", padx=6, pady=2, relief=tk.FLAT
        )
        self.counter_badge.pack(anchor="center")

        # Context Menu (Right Click)
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="🖥️ Open Frontend Visual App", command=self.restore_frontend_app)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="▶ Start Monitoring", command=self.app._start_monitoring)
        self.context_menu.add_command(label="⏹ Stop Monitoring", command=self.app._stop_monitoring)
        self.context_menu.add_command(label="📊 Graphical Report", command=self.app._show_visual_report)
        self.context_menu.add_command(label="🛡️ Advanced System Monitoring", command=self.app._advanced_system_monitoring)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="❌ Exit Application", command=self.app._on_close)

        # Bind mouse events to ALL widgets so clicking or dragging anywhere works
        for w in (self, self.container, self.icon_canvas, info_frame, self.title_label, self.status_pill, badge_frame, self.counter_badge):
            w.bind("<ButtonPress-1>", self._on_mouse_down)
            w.bind("<B1-Motion>", self._on_mouse_drag)
            w.bind("<ButtonRelease-1>", self._on_mouse_up)
            w.bind("<Double-Button-1>", lambda e: self.restore_frontend_app())
            w.bind("<Button-3>", self._show_context_menu)

    def _on_mouse_down(self, event):
        self._drag_start_x = event.x_root - self.winfo_x()
        self._drag_start_y = event.y_root - self.winfo_y()
        self._is_dragging = False

    def _on_mouse_drag(self, event):
        self._is_dragging = True
        new_x = event.x_root - self._drag_start_x
        new_y = event.y_root - self._drag_start_y
        self.geometry(f"+{new_x}+{new_y}")

    def _on_mouse_up(self, event):
        if not self._is_dragging:
            self.restore_frontend_app()
        self._is_dragging = False

    def _show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def update_status(self, status: str, changes_count: int = 0, suspicious_count: int = 0):
        """Update live status pill and badge counter."""
        if status == "MONITORING":
            self.status_pill.configure(text="● MONITORING", fg="#22c55e")
            self.container.configure(bd=2, relief=tk.RIDGE)
        elif status == "STARTING":
            self.status_pill.configure(text="● STARTING...", fg="#f59e0b")
        else:
            self.status_pill.configure(text="● STOPPED", fg="#ef4444")

        # Counter badge
        if suspicious_count > 0:
            self.counter_badge.configure(text=f"⚠ {changes_count}", bg="#7f1d1d", fg="#fca5a5")
        elif changes_count > 0:
            self.counter_badge.configure(text=str(changes_count), bg="#1e3a8a", fg="#93c5fd")
        else:
            self.counter_badge.configure(text="0", bg="#1e293b", fg="#94a3b8")

    def show_floating_widget(self):
        """Display the floating widget on desktop and hide main app from taskbar."""
        self.update_status(self.app.status, self.app.total_changes, self.app.suspicious_count)
        self.deiconify()
        set_taskbar_visibility(self, False)
        self.lift()
        self.wm_attributes("-topmost", True)

    def restore_frontend_app(self):
        """Hide the floating widget and restore main frontend app on screen."""
        self.withdraw()
        self.app.root.deiconify()
        self.app.root.state("normal")
        # Restore on taskbar only if user has not checked 'Hide from Taskbar'
        if not self.app.hide_taskbar_var.get():
            set_taskbar_visibility(self.app.root, show=True)
        else:
            set_taskbar_visibility(self.app.root, show=False)
        self.app.root.lift()
        self.app.root.focus_force()


class VisualReportViewerDialog(tk.Toplevel):
    """Interactive Graphical Image Report Viewer using Pillow and Tkinter."""

    def __init__(self, parent, image_path: str, title: str = "Graphical Visual Report"):
        super().__init__(parent)
        self.title(title)
        self.geometry("1180x820")
        self.minsize(850, 600)
        self.image_path = image_path
        self.zoom_level = 1.0

        try:
            self.pil_image = Image.open(image_path)
        except Exception as e:
            logger.error("Failed to open image %s: %s", image_path, e)
            messagebox.showerror("Image Error", f"Failed to load image:\n{e}", parent=parent)
            self.destroy()
            return

        self.tk_photo = None
        self._build_ui()
        self._render_image()

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding=8)
        main_frame.pack(fill=tk.BOTH, expand=True)

        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 6))

        ttk.Button(toolbar, text="🔍 Zoom In (+)", command=self._zoom_in).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="🔍 Zoom Out (-)", command=self._zoom_out).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="📐 100% (Reset)", command=self._zoom_reset).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="↔ Fit Width", command=self._zoom_fit_width).pack(side=tk.LEFT, padx=3)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=3)

        ttk.Button(toolbar, text="💾 Save Image As...", command=self._save_as).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="🖼️ Open in System Viewer", command=self._open_system_viewer).pack(side=tk.LEFT, padx=3)

        ttk.Button(toolbar, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=3)

        self.zoom_label = ttk.Label(toolbar, text="Zoom: 100%", font=("Segoe UI", 9))
        self.zoom_label.pack(side=tk.RIGHT, padx=12)

        canvas_frame = ttk.Frame(main_frame, relief=tk.SUNKEN, borderwidth=1)
        canvas_frame.pack(fill=tk.BOTH, expand=True)

        self.canvas = tk.Canvas(canvas_frame, bg="#2d3748", highlightthickness=0)
        self.h_scroll = ttk.Scrollbar(canvas_frame, orient=tk.HORIZONTAL, command=self.canvas.xview)
        self.v_scroll = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL, command=self.canvas.yview)
        self.canvas.configure(xscrollcommand=self.h_scroll.set, yscrollcommand=self.v_scroll.set)

        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.v_scroll.grid(row=0, column=1, sticky="ns")
        self.h_scroll.grid(row=1, column=0, sticky="ew")
        canvas_frame.grid_rowconfigure(0, weight=1)
        canvas_frame.grid_columnconfigure(0, weight=1)

        self.canvas.bind("<MouseWheel>", self._on_mousewheel)

        dim_str = f"{self.pil_image.width} × {self.pil_image.height} px"
        self.status_bar = ttk.Label(
            main_frame,
            text=f"Resolution: {dim_str} | File: {self.image_path}",
            relief=tk.SUNKEN,
            padding=(4, 2),
            font=("Segoe UI", 9)
        )
        self.status_bar.pack(fill=tk.X, pady=(4, 0))

    def _render_image(self):
        w = max(100, int(self.pil_image.width * self.zoom_level))
        h = max(100, int(self.pil_image.height * self.zoom_level))

        if self.zoom_level == 1.0:
            display_img = self.pil_image
        else:
            display_img = self.pil_image.resize((w, h), Image.Resampling.LANCZOS)

        self.tk_photo = ImageTk.PhotoImage(display_img)
        self.canvas.delete("all")
        self.canvas.create_image(10, 10, anchor="nw", image=self.tk_photo)
        self.canvas.configure(scrollregion=(0, 0, w + 20, h + 20))
        self.zoom_label.configure(text=f"Zoom: {int(self.zoom_level * 100)}%")

    def _zoom_in(self):
        if self.zoom_level < 3.0:
            self.zoom_level = round(self.zoom_level * 1.25, 2)
            self._render_image()

    def _zoom_out(self):
        if self.zoom_level > 0.2:
            self.zoom_level = round(self.zoom_level / 1.25, 2)
            self._render_image()

    def _zoom_reset(self):
        self.zoom_level = 1.0
        self._render_image()

    def _zoom_fit_width(self):
        self.update_idletasks()
        cw = self.canvas.winfo_width() - 40
        if cw > 100 and self.pil_image.width > 0:
            self.zoom_level = round(cw / self.pil_image.width, 2)
            self._render_image()

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _save_as(self):
        dest = filedialog.asksaveasfilename(
            parent=self,
            title="Save Graphical Report Image",
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")],
            initialfile=os.path.basename(self.image_path)
        )
        if dest:
            try:
                self.pil_image.save(dest, "PNG")
                messagebox.showinfo("Saved", f"Report image saved to:\n{dest}", parent=self)
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save image:\n{e}", parent=self)

    def _open_system_viewer(self):
        try:
            os.startfile(self.image_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open system viewer:\n{e}", parent=self)


class AdvancedAnalysisReportWindow(tk.Toplevel):
    """Interactive report window for Advanced System Monitoring file analysis."""

    def __init__(self, parent, report_data: dict, default_csv: str = "", default_json: str = "", default_visual: str = ""):
        super().__init__(parent)
        self.title("Advanced System Monitoring - Comprehensive File Analysis Report")
        self.geometry("1120x740")
        self.minsize(950, 560)

        self.report_data = report_data
        self.all_files = report_data.get("files", [])
        self.filtered_files = list(self.all_files)
        self.default_csv = default_csv
        self.default_json = default_json
        self.default_visual = default_visual

        self._build_ui()
        self._populate_tree()

    def _build_ui(self):
        card_bg = "#f5f7fa"
        main_pad = ttk.Frame(self, padding=12)
        main_pad.pack(fill=tk.BOTH, expand=True)

        # Header Title
        header_frame = ttk.Frame(main_pad)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            header_frame,
            text="🛡️ Advanced System Monitoring & File Analysis Report",
            font=("Segoe UI", 15, "bold")
        ).pack(anchor="w")

        ttk.Label(
            header_frame,
            text="Deep forensic inspection of all binaries, scripts, and libraries referenced in monitored registry locations.",
            font=("Segoe UI", 9),
            foreground="#555555"
        ).pack(anchor="w", pady=(2, 0))

        # Metrics summary cards
        summary = self.report_data.get("summary", {})
        metrics_frame = ttk.LabelFrame(main_pad, text="Analysis Summary", padding=10)
        metrics_frame.pack(fill=tk.X, pady=(0, 10))

        metrics = [
            ("Total Files Referenced", str(summary.get("total_files_analyzed", 0)), "#1565c0"),
            ("Existing on Disk", str(summary.get("existing_files", 0)), "#2e7d32"),
            ("Missing / Orphaned", str(summary.get("missing_files", 0)), "#c62828" if summary.get("missing_files", 0) > 0 else "#555555"),
            ("Security Warnings", str(summary.get("suspicious_or_warning_files", 0)), "#e65100" if summary.get("suspicious_or_warning_files", 0) > 0 else "#2e7d32"),
            ("SHA-256 Hashes Computed", str(summary.get("hashes_computed", 0)), "#4527a0"),
        ]

        for title, val, color in metrics:
            card = tk.Frame(metrics_frame, bg=card_bg, padx=12, pady=6, relief=tk.GROOVE, bd=1)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            tk.Label(card, text=title, font=("Segoe UI", 8), bg=card_bg, fg="#555555").pack(anchor="center")
            tk.Label(card, text=val, font=("Segoe UI", 13, "bold"), bg=card_bg, fg=color).pack(anchor="center")

        # Filters toolbar
        filter_frame = ttk.Frame(main_pad)
        filter_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(filter_frame, text="Filter:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar(value="All Files")
        filter_combo = ttk.Combobox(
            filter_frame, textvariable=self.filter_var, state="readonly", width=25,
            values=["All Files", "Only Warnings / Suspicious", "Only Missing Files", "Only Existing Files"]
        )
        filter_combo.pack(side=tk.LEFT, padx=(0, 15))
        filter_combo.bind("<<ComboboxSelected>>", self._on_filter_changed)

        ttk.Label(filter_frame, text="Search:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._on_filter_changed())
        search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=32)
        search_entry.pack(side=tk.LEFT, padx=(0, 10))

        self.count_label = ttk.Label(filter_frame, text="", font=("Segoe UI", 9))
        self.count_label.pack(side=tk.RIGHT)

        # Table Frame
        table_frame = ttk.Frame(main_pad)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        cols = ("risk", "filename", "exists", "size", "type", "hash", "category", "finding")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")

        self.tree.heading("risk", text="Risk")
        self.tree.heading("filename", text="File Name")
        self.tree.heading("exists", text="Exists")
        self.tree.heading("size", text="Size")
        self.tree.heading("type", text="Type")
        self.tree.heading("hash", text="SHA-256")
        self.tree.heading("category", text="Registry Category")
        self.tree.heading("finding", text="Security Finding")

        self.tree.column("risk", width=95, minwidth=75, anchor="center")
        self.tree.column("filename", width=180, minwidth=120)
        self.tree.column("exists", width=65, minwidth=50, anchor="center")
        self.tree.column("size", width=85, minwidth=65, anchor="e")
        self.tree.column("type", width=95, minwidth=75, anchor="center")
        self.tree.column("hash", width=140, minwidth=100)
        self.tree.column("category", width=160, minwidth=120)
        self.tree.column("finding", width=310, minwidth=180)

        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select_file)
        self.tree.bind("<Double-1>", self._on_select_file)

        # Tags
        self.tree.tag_configure("tag_SUSPICIOUS", background="#ffebee", foreground="#b71c1c")
        self.tree.tag_configure("tag_WARNING", background="#fff8e1", foreground="#e65100")
        self.tree.tag_configure("tag_BENIGN", background="#f1f8e9")
        self.tree.tag_configure("tag_INFO", background="#ffffff")

        # Bottom Inspector Details
        details_frame = ttk.LabelFrame(main_pad, text="Selected File Security Details", padding=6)
        details_frame.pack(fill=tk.X, pady=(0, 8))

        self.details_box = tk.Text(
            details_frame, height=5, wrap=tk.WORD, font=("Consolas", 9),
            bg="#f9f9f9", state=tk.DISABLED
        )
        d_vsb = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.details_box.yview)
        self.details_box.configure(yscrollcommand=d_vsb.set)
        self.details_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Action Buttons
        btn_bar = ttk.Frame(main_pad)
        btn_bar.pack(fill=tk.X)

        ttk.Button(btn_bar, text="📁 Export JSON Report", command=self._export_json).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_bar, text="📊 Export CSV", command=self._export_csv).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_bar, text="🖼️ View Graphical Report", command=self._view_visual_report).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_bar, text="💾 Save Image...", command=self._save_image_report).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_bar, text="Close", command=self.destroy).pack(side=tk.RIGHT, padx=3)

    def _on_filter_changed(self, event=None):
        self._populate_tree()

    def _populate_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        filter_mode = self.filter_var.get()
        query = self.search_var.get().strip().lower()

        filtered = []
        for f in self.all_files:
            risk = f.get("risk_level", "INFO")
            exists = f.get("exists", False)

            if filter_mode == "Only Warnings / Suspicious" and risk not in ("WARNING", "SUSPICIOUS", "CRITICAL"):
                continue
            if filter_mode == "Only Missing Files" and exists:
                continue
            if filter_mode == "Only Existing Files" and not exists:
                continue

            if query:
                haystack = f"{f.get('file_name', '')} {f.get('file_path', '')} {f.get('finding', '')} {f.get('sha256', '')} {f.get('category', '')}".lower()
                if query not in haystack:
                    continue

            filtered.append(f)

        self.filtered_files = filtered
        self.count_label.configure(text=f"Showing {len(filtered)} of {len(self.all_files)} files")

        for f in filtered:
            risk = f.get("risk_level", "INFO")
            tag = f"tag_{risk}"
            sha_display = (f.get("sha256")[:16] + "...") if f.get("sha256") else "N/A"
            size_str = _format_size(f.get("size_bytes"))

            self.tree.insert(
                "", tk.END,
                values=(
                    risk,
                    f.get("file_name", "Unknown"),
                    "Yes" if f.get("exists") else "No",
                    size_str,
                    f.get("file_type", "unknown"),
                    sha_display,
                    f.get("category", ""),
                    f.get("finding", ""),
                ),
                tags=(tag,)
            )

        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self._on_select_file()
        else:
            self.details_box.configure(state=tk.NORMAL)
            self.details_box.delete("1.0", tk.END)
            self.details_box.insert("1.0", "No files match the selected filter criteria.")
            self.details_box.configure(state=tk.DISABLED)

    def _on_select_file(self, event=None):
        selection = self.tree.selection()
        if not selection:
            return
        idx = self.tree.index(selection[0])
        if idx >= len(self.filtered_files):
            return
        f = self.filtered_files[idx]

        size_line = f"File Size:        {_format_size(f.get('size_bytes'))} ({f.get('size_bytes')} bytes)" if f.get('size_bytes') is not None else "File Size:        N/A"
        lines = [
            f"File Name:        {f.get('file_name', 'N/A')}",
            f"Full Path:        {f.get('file_path', 'N/A')}",
            f"File Exists:      {'Yes' if f.get('exists') else 'No (Missing or unreachable on disk)'}",
            size_line,
            f"File Type:        {f.get('file_type', 'N/A')}",
            f"Modified Time:    {f.get('modified_time', 'N/A')}",
            f"SHA-256 Hash:     {f.get('sha256', 'N/A')}",
            f"Security Risk:    {f.get('risk_level', 'N/A')}",
            f"Security Finding: {f.get('finding', 'N/A')}",
            "",
            f"Registry Key:     {f.get('registry_path', 'N/A')} ({f.get('view', 'default')} view)",
            f"Registry Value:   {f.get('value_name', 'N/A')}",
            f"Command Line:     {f.get('value_data', 'N/A')}",
        ]
        if f.get("arguments"):
            lines.append(f"Arguments:        {f.get('arguments')}")

        self.details_box.configure(state=tk.NORMAL)
        self.details_box.delete("1.0", tk.END)
        self.details_box.insert("1.0", "\n".join(lines))
        self.details_box.configure(state=tk.DISABLED)

    def _export_json(self):
        filepath = filedialog.asksaveasfilename(
            parent=self,
            title="Export Advanced Analysis (JSON)",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=os.path.basename(self.default_json) if self.default_json else "advanced_analysis.json"
        )
        if filepath:
            try:
                report_generator.export_advanced_analysis_json(self.report_data, filepath)
                messagebox.showinfo("Export Successful", f"Analysis report saved to:\n{filepath}", parent=self)
            except Exception as e:
                messagebox.showerror("Export Failed", f"Failed to save JSON report:\n{e}", parent=self)

    def _export_csv(self):
        filepath = filedialog.asksaveasfilename(
            parent=self,
            title="Export Advanced Analysis (CSV)",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=os.path.basename(self.default_csv) if self.default_csv else "advanced_analysis.csv"
        )
        if filepath:
            try:
                report_generator.export_advanced_analysis_csv(self.all_files, filepath)
                messagebox.showinfo("Export Successful", f"CSV report saved to:\n{filepath}", parent=self)
            except Exception as e:
                messagebox.showerror("Export Failed", f"Failed to save CSV report:\n{e}", parent=self)

    def _view_visual_report(self):
        """Open the graphical visual report dialog."""
        if not self.default_visual or not os.path.exists(self.default_visual):
            report_dir = os.path.join(APP_DIR, "data", "reports")
            os.makedirs(report_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.default_visual = os.path.join(report_dir, f"advanced_file_visual_{ts}.png")
            report_generator.export_advanced_analysis_visual_report(self.report_data, self.default_visual)
        VisualReportViewerDialog(self, self.default_visual, "Advanced System Monitoring - Graphical Visual Report")

    def _save_image_report(self):
        """Prompt user to save the graphical report image to a chosen path."""
        if not self.default_visual or not os.path.exists(self.default_visual):
            report_dir = os.path.join(APP_DIR, "data", "reports")
            os.makedirs(report_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.default_visual = os.path.join(report_dir, f"advanced_file_visual_{ts}.png")
            report_generator.export_advanced_analysis_visual_report(self.report_data, self.default_visual)
        dest = filedialog.asksaveasfilename(
            parent=self,
            title="Save Graphical Report Image",
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")],
            initialfile=os.path.basename(self.default_visual)
        )
        if dest:
            import shutil
            shutil.copy2(self.default_visual, dest)
            messagebox.showinfo("Saved", f"Image report saved to:\n{dest}", parent=self)


class RegistryMonitorApp:
    """Main Tkinter application for the Registry Change Monitor."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Windows Registry Change Monitoring System")
        self.root.geometry("1260x840")
        self.root.minsize(980, 650)
        self.root.configure(bg="#0b0f19")

        # Application state
        self.app_dir = APP_DIR
        self.config = load_config()
        self.baseline = None
        self.events: list[dict] = []
        self.monitoring_thread: MonitoringThread | None = None
        self.event_queue = Queue()
        self.status = "STOPPED"
        self.last_scan_time = "Never"
        self.scan_errors = 0
        self.total_changes = 0
        self.suspicious_count = 0

        # Encrypted Database Manager
        self.db = database.get_db(APP_DIR)

        # Dynamic Cyber Theme
        self.current_theme_name = self.config.get("appearance", {}).get("theme", theme_manager.DEFAULT_THEME_NAME)
        self.theme = theme_manager.get_theme(self.current_theme_name)
        self.root.configure(bg=self.theme["bg"])

        # Track themed frames and widgets for live theme switching
        self._themed_bg_frames = []
        self._themed_card_frames = []
        self._themed_labels = []

        # Search, filter, and inspector telemetry state
        self.search_var = tk.StringVar()
        self.severity_filter_var = tk.StringVar(value="All Severities")
        self.selected_event_sha256 = ""
        self.selected_event_path = ""
        self.selected_event_full_text = ""

        # Setup logging
        report_generator.setup_logging(self.config, APP_DIR)
        self.event_logger = report_generator.EventLogger(self.config, APP_DIR)

        # Setup alert manager
        self.alert_mgr = alert_manager.AlertManager(self.config)

        # Baseline path
        self.baseline_path = os.path.join(
            APP_DIR,
            self.config.get("baseline", {}).get("file_path", "data/baseline.json")
        )

        # Taskbar visibility toggle (defaults to True: taskbar icon hidden, frontend displayed on screen)
        self.hide_taskbar_var = tk.BooleanVar(
            value=self.config.get("hide_taskbar_icon", True)
        )

        # Minimize to floating desktop icon toggle
        self.minimize_to_icon_var = tk.BooleanVar(
            value=self.config.get("minimize_to_floating_icon", True)
        )

        # Set application icon if available
        icon_path = os.path.join(APP_DIR, "data", "app_icon.ico")
        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception:
                pass

        # Build GUI
        self._build_gui()

        # Initialize draggable floating desktop widget
        self.floating_widget = FloatingDesktopWidget(self)

        # Apply initial taskbar visibility
        if self.hide_taskbar_var.get():
            set_taskbar_visibility(self.root, False)
            self._taskbar_after_id = self.root.after(50, self._apply_initial_taskbar)

        # Try loading existing baseline
        self._load_existing_baseline()

        # Start queue processing
        self._process_queue()

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Bind window minimize event (<Unmap>)
        self.root.bind("<Unmap>", self._on_window_unmap)

    def _build_gui(self):
        """Build the spacious, modern cybersecurity Blue Team dashboard layout."""
        theme = self.theme
        BG = theme["bg"]
        CARD_BG = theme["card_bg"]
        BORDER = theme["card_border"]
        BORDER_ACCENT = theme["card_border_accent"]
        ACCENT = theme["accent_primary"]
        FG = theme["fg_primary"]
        FG_MUTED = theme["fg_secondary"]

        # Track themed widgets for dynamic theme changes
        self._themed_bg_frames = []
        self._themed_card_frames = []
        self._themed_labels = []

        # Configure styles
        style = ttk.Style()
        style.theme_use("clam")

        # Global element styles
        style.configure(".", background=BG, foreground=FG, font=("Segoe UI", 9))
        style.configure("Dark.TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD_BG)
        style.configure("Dark.TLabelframe", background=CARD_BG, foreground=FG_MUTED, bordercolor=BORDER, relief=tk.SOLID, borderwidth=1)
        style.configure("Dark.TLabelframe.Label", background=CARD_BG, foreground=ACCENT, font=("Segoe UI", 9, "bold"))

        # Treeview styling
        style.configure(
            "Dark.Treeview",
            background=theme["tree_bg"],
            foreground=theme["tree_fg"],
            fieldbackground=theme["tree_bg"],
            rowheight=26,
            bordercolor=BORDER,
            font=("Segoe UI", 9)
        )
        style.configure(
            "Dark.Treeview.Heading",
            background=theme["tree_heading_bg"],
            foreground=theme["tree_heading_fg"],
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padding=[4, 4]
        )
        style.map("Dark.Treeview", background=[("selected", theme["tree_select_bg"])], foreground=[("selected", theme["tree_select_fg"])])

        # Notebook tabs styling
        style.configure("Dark.TNotebook", background=CARD_BG, borderwidth=0)
        style.configure("Dark.TNotebook.Tab", background=theme["tree_heading_bg"], foreground=FG_MUTED, padding=[16, 6], font=("Segoe UI", 9, "bold"))
        style.map("Dark.TNotebook.Tab", background=[("selected", CARD_BG)], foreground=[("selected", ACCENT)])

        # Button variants
        style.configure("Dark.TButton", background=theme["btn_normal_bg"], foreground=theme["btn_normal_fg"], bordercolor=BORDER_ACCENT, borderwidth=1, focusthickness=0, font=("Segoe UI", 9))
        style.map("Dark.TButton", background=[("active", theme["btn_active_bg"]), ("disabled", theme["tree_bg"])], foreground=[("disabled", "#64748b")])

        style.configure("Green.TButton", background="#059669", foreground="#ffffff", bordercolor="#10b981", borderwidth=1, focusthickness=0, font=("Segoe UI", 9, "bold"))
        style.map("Green.TButton", background=[("active", "#047857"), ("disabled", "#1e293b")], foreground=[("disabled", "#64748b")])

        style.configure("Red.TButton", background="#b91c1c", foreground="#ffffff", bordercolor="#ef4444", borderwidth=1, focusthickness=0, font=("Segoe UI", 9, "bold"))
        style.map("Red.TButton", background=[("active", "#991b1b"), ("disabled", "#1e293b")], foreground=[("disabled", "#64748b")])

        style.configure("Orange.TButton", background="#c2410c", foreground="#ffffff", bordercolor="#f97316", borderwidth=1, focusthickness=0, font=("Segoe UI", 9, "bold"))
        style.map("Orange.TButton", background=[("active", "#ea580c"), ("disabled", "#1e293b")], foreground=[("disabled", "#64748b")])

        style.configure("Cyan.TButton", background="#0369a1", foreground="#ffffff", bordercolor=ACCENT, borderwidth=1, focusthickness=0, font=("Segoe UI", 9, "bold"))
        style.map("Cyan.TButton", background=[("active", "#0284c7")])

        style.configure("Purple.TButton", background="#6d28d9", foreground="#ffffff", bordercolor="#a855f7", borderwidth=1, focusthickness=0, font=("Segoe UI", 9, "bold"))
        style.map("Purple.TButton", background=[("active", "#7c3aed")])

        # Checkbutton and Entry styling
        style.configure("Dark.TCheckbutton", background=CARD_BG, foreground=FG_MUTED, font=("Segoe UI", 9))
        style.map("Dark.TCheckbutton", background=[("active", CARD_BG)], foreground=[("active", FG)])
        style.configure("Dark.TEntry", fieldbackground=theme["entry_bg"], foreground=theme["entry_fg"], insertcolor=ACCENT, bordercolor=BORDER_ACCENT)

        # Label styles for KPI cards
        style.configure("Header.TLabel", background=BG, foreground=FG, font=("Segoe UI", 15, "bold"))
        style.configure("Status.TLabel", background=CARD_BG, font=("Segoe UI", 11))
        style.configure("Stat.TLabel", background=CARD_BG, foreground=FG_MUTED, font=("Segoe UI", 9))
        style.configure("Green.TLabel", background=CARD_BG, foreground="#10b981", font=("Segoe UI", 14, "bold"))
        style.configure("Red.TLabel", background=CARD_BG, foreground="#ef4444", font=("Segoe UI", 14, "bold"))
        style.configure("Orange.TLabel", background=CARD_BG, foreground="#f59e0b", font=("Segoe UI", 14, "bold"))
        style.configure("Blue.TLabel", background=CARD_BG, foreground=ACCENT, font=("Segoe UI", 14, "bold"))
        style.configure("Purple.TLabel", background=CARD_BG, foreground="#c084fc", font=("Segoe UI", 14, "bold"))

        # Main root wrapper
        main_frame = ttk.Frame(self.root, style="Dark.TFrame", padding=12)
        main_frame.pack(fill=tk.BOTH, expand=True)
        self.main_frame = main_frame

        # ========================================================
        # 1. TOP HEADER & TELEMETRY BADGES
        # ========================================================
        header_frame = tk.Frame(main_frame, bg=BG)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        self._themed_bg_frames.append(header_frame)

        header_left = tk.Frame(header_frame, bg=BG)
        header_left.pack(side=tk.LEFT, fill=tk.Y)
        self._themed_bg_frames.append(header_left)

        # Shield badge canvas
        self.icon_canvas = tk.Canvas(header_left, width=38, height=38, bg=BG, highlightthickness=0)
        self.icon_canvas.pack(side=tk.LEFT, padx=(0, 10))
        self.icon_canvas.create_polygon([19, 3, 35, 9, 35, 24, 19, 35, 3, 24, 3, 9], fill="#1e3a8a", outline=ACCENT, width=2)
        self.icon_canvas.create_polygon([19, 7, 30, 12, 30, 22, 19, 31, 8, 22, 8, 12], fill="#0284c7")
        self.icon_canvas.create_text(19, 19, text="🛡️", font=("Segoe UI Emoji", 11))

        # Title block
        title_block = tk.Frame(header_left, bg=BG)
        title_block.pack(side=tk.LEFT)
        self._themed_bg_frames.append(title_block)

        self.lbl_main_title = tk.Label(
            title_block, text="WINDOWS REGISTRY MONITORING SYSTEM",
            font=("Segoe UI", 13, "bold"), fg=FG, bg=BG
        )
        self.lbl_main_title.pack(anchor="w")
        self.lbl_sub_title = tk.Label(
            title_block,
            text="Defensive Registry Telemetry • Real-Time Integrity Auditing • MITRE ATT&CK Tracking",
            font=("Segoe UI", 8), fg=FG_MUTED, bg=BG
        )
        self.lbl_sub_title.pack(anchor="w")

        # Telemetry Badges & Settings Trigger (Right side)
        header_right = tk.Frame(header_frame, bg=BG)
        header_right.pack(side=tk.RIGHT, fill=tk.Y)
        self._themed_bg_frames.append(header_right)

        self.header_status_badge = tk.Label(
            header_right, text="● STOPPED", bg="#450a0a", fg="#f87171",
            font=("Segoe UI", 8, "bold"), padx=10, pady=3, relief=tk.FLAT
        )
        self.header_status_badge.pack(side=tk.LEFT, padx=3)

        poll_s = self.config.get("polling_interval_seconds", 5)
        self.header_polling_badge = tk.Label(
            header_right, text=f"⏱ {poll_s}s Polling", bg="#1e293b", fg=FG_MUTED,
            font=("Segoe UI", 8, "bold"), padx=8, pady=3, cursor="hand2"
        )
        self.header_polling_badge.pack(side=tk.LEFT, padx=3)
        self.header_polling_badge.bind("<Button-1>", self._show_quick_polling_menu)

        self.header_db_badge = tk.Label(
            header_right, text="🔒 AES-256 DB", bg="#064e3b", fg="#34d399",
            font=("Segoe UI", 8, "bold"), padx=8, pady=3
        )
        self.header_db_badge.pack(side=tk.LEFT, padx=3)

        self.header_last_scan_badge = tk.Label(
            header_right, text="🕒 Last: Never", bg="#082f49", fg=ACCENT,
            font=("Segoe UI", 8, "bold"), padx=8, pady=3
        )
        self.header_last_scan_badge.pack(side=tk.LEFT, padx=3)

        # Header Settings Button
        self.btn_header_settings = tk.Button(
            header_right, text="⚙️ App Settings",
            bg="#1e293b", fg="#ffffff", activebackground="#334155", activeforeground="#ffffff",
            font=("Segoe UI", 8, "bold"), padx=10, pady=3, bd=1, relief=tk.SOLID,
            highlightbackground=ACCENT, highlightthickness=1, cursor="hand2",
            command=self._open_settings
        )
        self.btn_header_settings.pack(side=tk.LEFT, padx=(6, 0))

        # ========================================================
        # 2. SPACIOUS 5 KPI SCORECARDS (WITH ACCENT COLOR BARS)
        # ========================================================
        cards_frame = tk.Frame(main_frame, bg=BG)
        cards_frame.pack(fill=tk.X, pady=(0, 10))
        self._themed_bg_frames.append(cards_frame)

        def make_card(parent, title_text, sub_text, accent_color):
            card = tk.Frame(
                parent, bg=CARD_BG, bd=1, relief=tk.SOLID,
                highlightbackground=BORDER, highlightthickness=1
            )
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            self._themed_card_frames.append(card)

            # Top accent colored bar
            top_bar = tk.Frame(card, bg=accent_color, height=3)
            top_bar.pack(fill=tk.X)

            inner = tk.Frame(card, bg=CARD_BG, padx=12, pady=7)
            inner.pack(fill=tk.BOTH, expand=True)
            self._themed_card_frames.append(inner)

            lbl_title = tk.Label(inner, text=title_text, bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"))
            lbl_title.pack(anchor="w")
            self._themed_labels.append(lbl_title)

            val_frame = tk.Frame(inner, bg=CARD_BG)
            val_frame.pack(anchor="w", pady=2)
            self._themed_card_frames.append(val_frame)

            lbl_sub = tk.Label(inner, text=sub_text, bg=CARD_BG, fg="#64748b", font=("Segoe UI", 8))
            lbl_sub.pack(anchor="w")
            self._themed_labels.append(lbl_sub)

            return card, val_frame

        # Card 1: System Status
        _, val_f1 = make_card(cards_frame, "SYSTEM STATUS", "Continuous Polling Engine", "#ef4444")
        self.status_label = ttk.Label(val_f1, text="STOPPED", style="Red.TLabel")
        self.status_label.pack(anchor="w")

        # Card 2: Detected Changes
        _, val_f2 = make_card(cards_frame, "DETECTED CHANGES", "Audited Registry Deltas", ACCENT)
        self.changes_label = ttk.Label(val_f2, text="0", style="Blue.TLabel")
        self.changes_label.pack(anchor="w")

        # Card 3: Suspicious Findings
        _, val_f3 = make_card(cards_frame, "SUSPICIOUS FINDINGS", "Heuristic & ATT&CK Flags", "#f59e0b")
        self.suspicious_label = ttk.Label(val_f3, text="0", style="Orange.TLabel")
        self.suspicious_label.pack(anchor="w")

        # Card 4: Scan Exceptions
        _, val_f4 = make_card(cards_frame, "SCAN EXCEPTIONS", "Access Denied / Errors", "#a855f7")
        self.errors_label = ttk.Label(val_f4, text="0", style="Purple.TLabel")
        self.errors_label.pack(anchor="w")

        # Card 5: Baseline Snapshot
        _, val_f5 = make_card(cards_frame, "REGISTRY BASELINE", "Encrypted & SHA-256 Verified", "#10b981")
        self.baseline_label = ttk.Label(val_f5, text="Not loaded", style="Stat.TLabel", font=("Segoe UI", 9, "bold"))
        self.baseline_label.pack(anchor="w")
        self.scan_time_label = ttk.Label(val_f5, text="Never", style="Stat.TLabel")

        # ========================================================
        # 3. OPERATIONS & CONTROL CENTER (PROPERLY SEGMENTED)
        # ========================================================
        controls = ttk.LabelFrame(main_frame, text="Operations & Control Center", style="Dark.TLabelframe", padding=8)
        controls.pack(fill=tk.X, pady=(0, 10))

        # Row 1: Segmented Action Toolbar
        btn_row = tk.Frame(controls, bg=CARD_BG)
        btn_row.pack(fill=tk.X, pady=(0, 8))
        self._themed_card_frames.append(btn_row)

        # Left Ribbon: Core Engine Actions
        left_ribbon = tk.Frame(btn_row, bg=CARD_BG)
        left_ribbon.pack(side=tk.LEFT, fill=tk.Y)
        self._themed_card_frames.append(left_ribbon)

        self.btn_start = ttk.Button(left_ribbon, text="▶ Start Monitoring", style="Green.TButton", command=self._start_monitoring)
        self.btn_start.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_stop = ttk.Button(left_ribbon, text="⏹ Stop Monitoring", style="Red.TButton", command=self._stop_monitoring, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=3)

        self.btn_rescan = ttk.Button(left_ribbon, text="🔄 Rescan Registry", style="Cyan.TButton", command=self._rescan_registry)
        self.btn_rescan.pack(side=tk.LEFT, padx=3)

        ttk.Separator(left_ribbon, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        self.btn_create_baseline = ttk.Button(left_ribbon, text="📋 Create Baseline", style="Dark.TButton", command=self._create_baseline)
        self.btn_create_baseline.pack(side=tk.LEFT, padx=3)

        self.btn_reset = ttk.Button(left_ribbon, text="🗑 Reset Baseline", style="Dark.TButton", command=self._reset_baseline)
        self.btn_reset.pack(side=tk.LEFT, padx=3)

        ttk.Separator(left_ribbon, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)

        self.btn_remediate = ttk.Button(
            left_ribbon, text="🛡️ Remediate Threat", style="Red.TButton",
            command=self._remediate_selected_threat
        )
        self.btn_remediate.pack(side=tk.LEFT, padx=3)

        self.btn_auto_clean = ttk.Button(
            left_ribbon, text="⚡ Auto-Clean Threats", style="Orange.TButton",
            command=self._auto_clean_all_threats
        )
        self.btn_auto_clean.pack(side=tk.LEFT, padx=3)

        # Right Ribbon: Forensics, Intelligence & Settings
        right_ribbon = tk.Frame(btn_row, bg=CARD_BG)
        right_ribbon.pack(side=tk.RIGHT, fill=tk.Y)
        self._themed_card_frames.append(right_ribbon)

        self.btn_advanced_monitor = ttk.Button(right_ribbon, text="🛡️ Advanced System Monitoring", style="Purple.TButton", command=self._advanced_system_monitoring)
        self.btn_advanced_monitor.pack(side=tk.LEFT, padx=3)

        self.btn_visual_report = ttk.Button(right_ribbon, text="📊 Graphical Report", style="Dark.TButton", command=self._show_visual_report)
        self.btn_visual_report.pack(side=tk.LEFT, padx=3)

        self.btn_export = ttk.Button(right_ribbon, text="📁 Export Reports", style="Dark.TButton", command=self._export_report)
        self.btn_export.pack(side=tk.LEFT, padx=3)

        ttk.Separator(right_ribbon, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        self.btn_settings = ttk.Button(right_ribbon, text="⚙️ App Settings", style="Dark.TButton", command=self._open_settings)
        self.btn_settings.pack(side=tk.LEFT, padx=3)

        self.btn_run_backend = ttk.Button(right_ribbon, text="👻 Run in Background", style="Dark.TButton", command=self._run_in_background)
        self.btn_run_backend.pack(side=tk.LEFT, padx=(3, 0))

        # Compatibility alias
        self.btn_view_events = self.btn_visual_report

        # Row 2: Live Search & Filter Bar + Stealth Controls
        filter_row = tk.Frame(controls, bg=CARD_BG)
        filter_row.pack(fill=tk.X, pady=(2, 0))
        self._themed_card_frames.append(filter_row)

        lbl_s = tk.Label(filter_row, text="Search Telemetry:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"))
        lbl_s.pack(side=tk.LEFT, padx=(0, 5))
        self._themed_labels.append(lbl_s)

        self.search_entry = ttk.Entry(filter_row, textvariable=self.search_var, width=24, style="Dark.TEntry")
        self.search_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.search_var.trace_add("write", lambda *args: self._on_search_filter_changed())

        lbl_sev = tk.Label(filter_row, text="Severity Filter:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"))
        lbl_sev.pack(side=tk.LEFT, padx=(0, 5))
        self._themed_labels.append(lbl_sev)

        self.severity_combo = ttk.Combobox(
            filter_row, textvariable=self.severity_filter_var, state="readonly", width=18,
            values=["All Severities", "Suspicious / Critical", "Investigation Required", "Informational", "Errors Only"]
        )
        self.severity_combo.pack(side=tk.LEFT, padx=(0, 8))
        self.severity_combo.bind("<<ComboboxSelected>>", self._on_search_filter_changed)

        ttk.Button(filter_row, text="✕ Clear", style="Dark.TButton", command=self._clear_filters).pack(side=tk.LEFT, padx=(0, 14))

        self.event_filter_count_label = tk.Label(filter_row, text="Showing all 0 events", bg=CARD_BG, fg=ACCENT, font=("Segoe UI", 8, "bold"))
        self.event_filter_count_label.pack(side=tk.LEFT)
        self._themed_labels.append(self.event_filter_count_label)

        # Stealth controls on the right
        self.mute_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(filter_row, text="Mute Pop-ups", variable=self.mute_var, command=self._toggle_mute, style="Dark.TCheckbutton").pack(side=tk.RIGHT, padx=4)

        ttk.Checkbutton(filter_row, text="Hide Taskbar Icon", variable=self.hide_taskbar_var, command=self._toggle_hide_taskbar, style="Dark.TCheckbutton").pack(side=tk.RIGHT, padx=4)

        ttk.Checkbutton(filter_row, text="Minimize to Desktop Icon", variable=self.minimize_to_icon_var, style="Dark.TCheckbutton").pack(side=tk.RIGHT, padx=4)

        # ========================================================
        # 4. EVENT TABLE (LIVE TELEMETRY STREAM)
        # ========================================================
        table_frame = ttk.LabelFrame(main_frame, text="Live Telemetry Event Stream", style="Dark.TLabelframe", padding=6)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        tree_container = tk.Frame(table_frame, bg=theme["tree_bg"])
        tree_container.pack(fill=tk.BOTH, expand=True)

        columns = ("timestamp", "severity", "change_type", "registry_path", "value_name", "file_path", "status")
        self.event_tree = ttk.Treeview(tree_container, columns=columns, show="headings", selectmode="browse", style="Dark.Treeview")

        self.event_tree.heading("timestamp", text="Timestamp")
        self.event_tree.heading("severity", text="Severity")
        self.event_tree.heading("change_type", text="Change Type")
        self.event_tree.heading("registry_path", text="Registry Location")
        self.event_tree.heading("value_name", text="Value Name")
        self.event_tree.heading("file_path", text="Referenced Binary / Command")
        self.event_tree.heading("status", text="Audit Status")

        self.event_tree.column("timestamp", width=145, minwidth=125)
        self.event_tree.column("severity", width=105, minwidth=85, anchor="center")
        self.event_tree.column("change_type", width=95, minwidth=75, anchor="center")
        self.event_tree.column("registry_path", width=340, minwidth=180)
        self.event_tree.column("value_name", width=160, minwidth=100)
        self.event_tree.column("file_path", width=240, minwidth=120)
        self.event_tree.column("status", width=90, minwidth=70, anchor="center")

        vsb = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.event_tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=self.event_tree.xview)
        self.event_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.event_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)

        # Bind events for details
        self.event_tree.bind("<Double-1>", self._show_event_details)
        self.event_tree.bind("<<TreeviewSelect>>", self._show_event_details)
        self.event_tree.bind("<Button-3>", self._show_tree_context_menu)

        # Tag configurations for colors
        self._refresh_tree_tags()

        # ========================================================
        # 5. SPLIT FORENSIC INVESTIGATOR (NOTEBOOK TABS)
        # ========================================================
        inspector_frame = ttk.LabelFrame(main_frame, text="Forensic Investigation & Artifact Inspector", style="Dark.TLabelframe", padding=6)
        inspector_frame.pack(fill=tk.X, pady=(0, 4))

        self.inspector_notebook = ttk.Notebook(inspector_frame, style="Dark.TNotebook")
        self.inspector_notebook.pack(fill=tk.BOTH, expand=True)

        # --- TAB 1: Structured Telemetry Cards ---
        tab_cards = tk.Frame(self.inspector_notebook, bg=theme["tree_bg"], padx=8, pady=6)
        self.inspector_notebook.add(tab_cards, text="🛡️ Structured Forensic Telemetry")
        self._themed_card_frames.append(tab_cards)

        # Left Card: Registry Telemetry
        left_card = tk.Frame(tab_cards, bg=CARD_BG, bd=1, relief=tk.SOLID, highlightbackground=BORDER, highlightthickness=1, padx=10, pady=6)
        left_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 4))
        self._themed_card_frames.append(left_card)

        tk.Label(left_card, text="REGISTRY TELEMETRY", bg=CARD_BG, fg=ACCENT, font=("Segoe UI", 9, "bold")).pack(anchor="w")

        p_frame = tk.Frame(left_card, bg=CARD_BG)
        p_frame.pack(fill=tk.X, pady=1)
        self._themed_card_frames.append(p_frame)
        tk.Label(p_frame, text="Path:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"), width=7, anchor="w").pack(side=tk.LEFT)
        self.insp_path_val = tk.Label(p_frame, text="No event selected", bg=CARD_BG, fg="#ffffff", font=("Segoe UI", 8, "bold"), anchor="w")
        self.insp_path_val.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(p_frame, text="📋", font=("Segoe UI", 7), bg="#1e293b", fg="#ffffff", bd=0, padx=4, command=self._copy_selected_path).pack(side=tk.RIGHT)

        n_frame = tk.Frame(left_card, bg=CARD_BG)
        n_frame.pack(fill=tk.X, pady=1)
        self._themed_card_frames.append(n_frame)
        tk.Label(n_frame, text="Value:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"), width=7, anchor="w").pack(side=tk.LEFT)
        self.insp_name_val = tk.Label(n_frame, text="—", bg=CARD_BG, fg="#ffffff", font=("Segoe UI", 8), anchor="w")
        self.insp_name_val.pack(side=tk.LEFT)

        t_frame = tk.Frame(left_card, bg=CARD_BG)
        t_frame.pack(fill=tk.X, pady=1)
        self._themed_card_frames.append(t_frame)
        tk.Label(t_frame, text="Delta:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"), width=7, anchor="w").pack(side=tk.LEFT)
        self.insp_type_val = tk.Label(t_frame, text="—", bg=CARD_BG, fg="#fbbf24", font=("Segoe UI", 8, "bold"), anchor="w")
        self.insp_type_val.pack(side=tk.LEFT)

        v_frame = tk.Frame(left_card, bg=CARD_BG)
        v_frame.pack(fill=tk.X, pady=1)
        self._themed_card_frames.append(v_frame)
        tk.Label(v_frame, text="Old Val:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"), width=7, anchor="w").pack(side=tk.LEFT)
        self.insp_prev_val = tk.Label(v_frame, text="—", bg=CARD_BG, fg="#f87171", font=("Consolas", 8), anchor="w")
        self.insp_prev_val.pack(side=tk.LEFT)

        c_frame = tk.Frame(left_card, bg=CARD_BG)
        c_frame.pack(fill=tk.X, pady=1)
        self._themed_card_frames.append(c_frame)
        tk.Label(c_frame, text="New Val:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"), width=7, anchor="w").pack(side=tk.LEFT)
        self.insp_curr_val = tk.Label(c_frame, text="—", bg=CARD_BG, fg="#34d399", font=("Consolas", 8), anchor="w")
        self.insp_curr_val.pack(side=tk.LEFT)

        r_frame = tk.Frame(left_card, bg=CARD_BG)
        r_frame.pack(fill=tk.X, pady=1)
        self._themed_card_frames.append(r_frame)
        tk.Label(r_frame, text="Reason:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"), width=7, anchor="w").pack(side=tk.LEFT)
        self.insp_reason_val = tk.Label(r_frame, text="Select an event from the telemetry stream above.", bg=CARD_BG, fg="#fde047", font=("Segoe UI", 8), anchor="w", wraplength=480, justify="left")
        self.insp_reason_val.pack(side=tk.LEFT)

        act_frame = tk.Frame(left_card, bg=CARD_BG)
        act_frame.pack(fill=tk.X, pady=(6, 0))
        self._themed_card_frames.append(act_frame)

        self.btn_insp_remediate = tk.Button(
            act_frame, text="🗑️ Neutralize & Delete Registry Threat",
            bg="#dc2626", fg="#ffffff", activebackground="#b91c1c", activeforeground="#ffffff",
            font=("Segoe UI", 8, "bold"), bd=0, padx=8, pady=4, cursor="hand2",
            command=self._remediate_selected_threat
        )
        self.btn_insp_remediate.pack(side=tk.LEFT)

        # Right Card: Binary & Artifact Telemetry
        right_card = tk.Frame(tab_cards, bg=CARD_BG, bd=1, relief=tk.SOLID, highlightbackground=BORDER, highlightthickness=1, padx=10, pady=6)
        right_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0))
        self._themed_card_frames.append(right_card)

        tk.Label(right_card, text="REFERENCED BINARY & ON-DISK ARTIFACT", bg=CARD_BG, fg="#a855f7", font=("Segoe UI", 9, "bold")).pack(anchor="w")

        e_frame = tk.Frame(right_card, bg=CARD_BG)
        e_frame.pack(fill=tk.X, pady=1)
        self._themed_card_frames.append(e_frame)
        tk.Label(e_frame, text="Binary:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"), width=8, anchor="w").pack(side=tk.LEFT)
        self.insp_exe_val = tk.Label(e_frame, text="—", bg=CARD_BG, fg="#ffffff", font=("Segoe UI", 8, "bold"), anchor="w")
        self.insp_exe_val.pack(side=tk.LEFT)

        a_frame = tk.Frame(right_card, bg=CARD_BG)
        a_frame.pack(fill=tk.X, pady=1)
        self._themed_card_frames.append(a_frame)
        tk.Label(a_frame, text="Args:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"), width=8, anchor="w").pack(side=tk.LEFT)
        self.insp_args_val = tk.Label(a_frame, text="—", bg=CARD_BG, fg="#cbd5e1", font=("Segoe UI", 8), anchor="w")
        self.insp_args_val.pack(side=tk.LEFT)

        x_frame = tk.Frame(right_card, bg=CARD_BG)
        x_frame.pack(fill=tk.X, pady=1)
        self._themed_card_frames.append(x_frame)
        tk.Label(x_frame, text="Presence:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"), width=8, anchor="w").pack(side=tk.LEFT)
        self.insp_exists_val = tk.Label(x_frame, text="—", bg=CARD_BG, fg="#94a3b8", font=("Segoe UI", 8, "bold"), anchor="w")
        self.insp_exists_val.pack(side=tk.LEFT)

        s_frame = tk.Frame(right_card, bg=CARD_BG)
        s_frame.pack(fill=tk.X, pady=1)
        self._themed_card_frames.append(s_frame)
        tk.Label(s_frame, text="Size/Time:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"), width=8, anchor="w").pack(side=tk.LEFT)
        self.insp_size_val = tk.Label(s_frame, text="—", bg=CARD_BG, fg="#94a3b8", font=("Segoe UI", 8), anchor="w")
        self.insp_size_val.pack(side=tk.LEFT)

        h_frame = tk.Frame(right_card, bg=CARD_BG)
        h_frame.pack(fill=tk.X, pady=1)
        self._themed_card_frames.append(h_frame)
        tk.Label(h_frame, text="SHA-256:", bg=CARD_BG, fg=FG_MUTED, font=("Segoe UI", 8, "bold"), width=8, anchor="w").pack(side=tk.LEFT)
        self.insp_sha_val = tk.Label(h_frame, text="—", bg=CARD_BG, fg="#60a5fa", font=("Consolas", 8), anchor="w")
        self.insp_sha_val.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(h_frame, text="📋 Copy Hash", font=("Segoe UI", 7), bg="#1e293b", fg="#ffffff", bd=0, padx=6, command=self._copy_selected_sha).pack(side=tk.RIGHT)

        # --- TAB 2: Raw Telemetry Log Text Box ---
        tab_raw = tk.Frame(self.inspector_notebook, bg=theme["tree_bg"], padx=6, pady=4)
        self.inspector_notebook.add(tab_raw, text="📜 Raw Telemetry Log")
        self._themed_card_frames.append(tab_raw)

        raw_top_bar = tk.Frame(tab_raw, bg=theme["tree_bg"])
        raw_top_bar.pack(fill=tk.X, pady=(0, 2))
        self._themed_card_frames.append(raw_top_bar)
        tk.Label(raw_top_bar, text="Complete forensic key-value telemetry audit dump:", bg=theme["tree_bg"], fg=FG_MUTED, font=("Segoe UI", 8)).pack(side=tk.LEFT)
        tk.Button(raw_top_bar, text="📋 Copy Full Telemetry", font=("Segoe UI", 8), bg="#1e293b", fg="#ffffff", bd=0, padx=6, command=self._copy_selected_full_telemetry).pack(side=tk.RIGHT)

        self.details_text = tk.Text(
            tab_raw, height=5, wrap=tk.WORD, font=("Consolas", 9),
            state=tk.DISABLED, bg=theme["tree_bg"], fg="#cbd5e1", insertbackground=ACCENT,
            bd=0, highlightthickness=1, highlightbackground=BORDER
        )
        details_scroll = ttk.Scrollbar(tab_raw, orient=tk.VERTICAL, command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_scroll.set)
        self.details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # --- TAB 3: Encrypted Database Telemetry ---
        tab_db = tk.Frame(self.inspector_notebook, bg=theme["tree_bg"], padx=10, pady=6)
        self.inspector_notebook.add(tab_db, text="🔒 Encrypted Local Database")
        self._themed_card_frames.append(tab_db)

        db_box = tk.Frame(tab_db, bg=CARD_BG, bd=1, relief=tk.SOLID, highlightbackground=BORDER, highlightthickness=1, padx=12, pady=8)
        db_box.pack(fill=tk.BOTH, expand=True)
        self._themed_card_frames.append(db_box)

        db_top = tk.Frame(db_box, bg=CARD_BG)
        db_top.pack(fill=tk.X, pady=(0, 4))
        self._themed_card_frames.append(db_top)
        tk.Label(db_top, text="LOCAL ENCRYPTED STORAGE (AES-256 + WINDOWS DPAPI)", bg=CARD_BG, fg=ACCENT, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)

        db_grid = tk.Frame(db_box, bg=CARD_BG)
        db_grid.pack(fill=tk.X, pady=(0, 6))
        self._themed_card_frames.append(db_grid)

        self.db_stats_labels = {}
        db_items = [
            ("Encryption Status:", "status", "Active (Protected via Windows DPAPI)"),
            ("Encrypted Events:", "events", "0 encrypted records"),
            ("Baseline Snapshots:", "baselines", "0 snapshot(s)"),
            ("Total Scans Logged:", "scans", "0 scans"),
            ("Database File Size:", "size", "0.0 KB"),
        ]

        for idx, (label_title, key_name, default_v) in enumerate(db_items):
            r = idx // 3
            c = idx % 3
            cell = tk.Frame(db_grid, bg=CARD_BG)
            cell.grid(row=r, column=c, sticky="w", padx=10, pady=2)
            self._themed_card_frames.append(cell)

            tk.Label(cell, text=label_title, font=("Segoe UI", 8, "bold"), fg=FG_MUTED, bg=CARD_BG).pack(side=tk.LEFT, padx=(0, 5))
            lbl_val = tk.Label(cell, text=default_v, font=("Segoe UI", 8), fg="#ffffff", bg=CARD_BG)
            lbl_val.pack(side=tk.LEFT)
            self.db_stats_labels[key_name] = lbl_val

        db_actions = tk.Frame(db_box, bg=CARD_BG)
        db_actions.pack(anchor="w", pady=(2, 0))
        self._themed_card_frames.append(db_actions)

        tk.Button(
            db_actions, text="🧹 Vacuum Database", bg="#1e293b", fg="#ffffff", activebackground="#334155",
            font=("Segoe UI", 8), padx=10, pady=3, bd=0, relief=tk.FLAT, cursor="hand2",
            command=self._vacuum_database
        ).pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(
            db_actions, text="📤 Export Encrypted DB", bg="#1e293b", fg="#ffffff", activebackground="#334155",
            font=("Segoe UI", 8), padx=10, pady=3, bd=0, relief=tk.FLAT, cursor="hand2",
            command=self._export_database
        ).pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(
            db_actions, text="⚙️ Configure Engine & Security...", bg="#0284c7", fg="#ffffff", activebackground="#0369a1",
            font=("Segoe UI", 8, "bold"), padx=10, pady=3, bd=0, relief=tk.FLAT, cursor="hand2",
            command=self._open_settings
        ).pack(side=tk.LEFT)

        # ========================================================
        # 6. STATUS BAR
        # ========================================================
        self.statusbar = tk.Label(
            self.root, text="Ready. Create or load a baseline to begin.",
            bg=theme["tree_bg"], fg=FG_MUTED, font=("Segoe UI", 8),
            anchor="w", padx=10, pady=3, bd=1, relief=tk.SUNKEN
        )
        self.statusbar.pack(side=tk.BOTTOM, fill=tk.X)

        self._update_db_tab()

    def _open_settings(self):
        """Open the Application Settings & Engine Configuration dialog."""
        AppSettingsWindow(self, self._on_settings_applied)

    def _on_settings_applied(self, new_config: dict):
        """Handle settings saved and applied from the settings dialog."""
        self.config = new_config
        # Update monitoring thread polling interval if running
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            new_interval = new_config.get("polling_interval_seconds", 5)
            self.monitoring_thread.update_interval(new_interval)

        poll_s = new_config.get("polling_interval_seconds", 5)
        if hasattr(self, "header_polling_badge"):
            self.header_polling_badge.configure(text=f"⏱ {poll_s}s Polling")

        # Update alert manager
        self.alert_mgr.update_config(new_config)

        # Apply theme if changed
        new_theme = new_config.get("appearance", {}).get("theme", theme_manager.DEFAULT_THEME_NAME)
        if new_theme != self.current_theme_name:
            self.apply_theme(new_theme)

        self._update_db_tab()
        self._set_statusbar("Application preferences and engine configuration updated.")

    def apply_theme(self, theme_name: str):
        """Dynamically re-theme the entire application."""
        self.current_theme_name = theme_name
        self.theme = theme_manager.get_theme(theme_name)
        theme = self.theme

        style = ttk.Style()
        style.theme_use("clam")

        BG = theme["bg"]
        CARD_BG = theme["card_bg"]
        BORDER = theme["card_border"]
        BORDER_ACCENT = theme["card_border_accent"]
        ACCENT = theme["accent_primary"]
        FG = theme["fg_primary"]
        FG_MUTED = theme["fg_secondary"]

        style.configure(".", background=BG, foreground=FG, font=("Segoe UI", 9))
        style.configure("Dark.TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD_BG)
        style.configure("Dark.TLabelframe", background=CARD_BG, foreground=FG_MUTED, bordercolor=BORDER)
        style.configure("Dark.TLabelframe.Label", background=CARD_BG, foreground=ACCENT)

        style.configure(
            "Dark.Treeview",
            background=theme["tree_bg"],
            foreground=theme["tree_fg"],
            fieldbackground=theme["tree_bg"],
            rowheight=26,
            bordercolor=BORDER
        )
        style.configure(
            "Dark.Treeview.Heading",
            background=theme["tree_heading_bg"],
            foreground=theme["tree_heading_fg"]
        )
        style.map("Dark.Treeview", background=[("selected", theme["tree_select_bg"])], foreground=[("selected", theme["tree_select_fg"])])

        style.configure("Dark.TNotebook", background=CARD_BG)
        style.configure("Dark.TNotebook.Tab", background=theme["tree_heading_bg"], foreground=FG_MUTED)
        style.map("Dark.TNotebook.Tab", background=[("selected", CARD_BG)], foreground=[("selected", ACCENT)])

        style.configure("Dark.TButton", background=theme["btn_normal_bg"], foreground=theme["btn_normal_fg"], bordercolor=BORDER_ACCENT)
        style.map("Dark.TButton", background=[("active", theme["btn_active_bg"])])

        style.configure("Dark.TCheckbutton", background=CARD_BG, foreground=FG_MUTED)
        style.map("Dark.TCheckbutton", background=[("active", CARD_BG)], foreground=[("active", FG)])
        style.configure("Dark.TEntry", fieldbackground=theme["entry_bg"], foreground=theme["entry_fg"], insertcolor=ACCENT, bordercolor=BORDER_ACCENT)

        # Re-color tk widgets
        self.root.configure(bg=BG)
        for f in getattr(self, "_themed_bg_frames", []):
            try:
                f.configure(bg=BG)
            except Exception:
                pass
        for f in getattr(self, "_themed_card_frames", []):
            try:
                f.configure(bg=CARD_BG)
            except Exception:
                pass
        for lbl in getattr(self, "_themed_labels", []):
            try:
                lbl.configure(bg=CARD_BG, fg=FG_MUTED)
            except Exception:
                pass

        if hasattr(self, "statusbar"):
            self.statusbar.configure(bg=theme["tree_bg"], fg=FG_MUTED)
        if hasattr(self, "details_text"):
            self.details_text.configure(bg=theme["tree_bg"], fg="#cbd5e1", insertbackground=ACCENT)

        self._refresh_tree_tags()
        self._update_db_tab()

    def _refresh_tree_tags(self):
        """Configure color tags for the event treeview."""
        theme = self.theme
        self.event_tree.tag_configure("suspicious", background="#2a1f0a", foreground="#fbbf24")
        self.event_tree.tag_configure("investigation_required", background="#381111", foreground="#f87171")
        self.event_tree.tag_configure("error", background="#2d1126", foreground="#f472b6")
        self.event_tree.tag_configure("remediated", background="#064e3b", foreground="#6ee7b7")
        self.event_tree.tag_configure("informational", background=theme["tree_bg"], foreground=theme["fg_secondary"])
        self.event_tree.tag_configure("even", background=theme["tree_bg"])
        self.event_tree.tag_configure("odd", background="#131d33" if theme["name"] == "Cyber Blue Team" else theme["card_bg"])

    def _update_db_tab(self):
        """Refresh encrypted database statistics in the inspector panel."""
        if not hasattr(self, "db_stats_labels") or not self.db:
            return
        stats = self.db.get_db_stats()
        if "events" in self.db_stats_labels:
            self.db_stats_labels["events"].configure(text=f"{stats.get('total_events', 0)} encrypted records")
        if "baselines" in self.db_stats_labels:
            self.db_stats_labels["baselines"].configure(text=f"{stats.get('total_baselines', 0)} snapshot(s)")
        if "scans" in self.db_stats_labels:
            self.db_stats_labels["scans"].configure(text=f"{stats.get('total_scans', 0)} scans")
        if "size" in self.db_stats_labels:
            self.db_stats_labels["size"].configure(text=f"{stats.get('size_bytes', 0) / 1024:.1f} KB")

    def _vacuum_database(self):
        """Defragment and optimize encrypted SQLite database."""
        if self.db and self.db.vacuum_db():
            self._update_db_tab()
            self._set_statusbar("Encrypted database vacuumed and defragmented successfully.")
            messagebox.showinfo("Database", "Database vacuumed and optimized successfully!", parent=self.root)
        else:
            messagebox.showerror("Error", "Database vacuum failed.", parent=self.root)

    def _export_database(self):
        """Export a copy of the encrypted database."""
        if not self.db or not os.path.exists(self.db.db_path):
            messagebox.showinfo("Export", "No database file exists yet.", parent=self.root)
            return
        dest = filedialog.asksaveasfilename(
            parent=self.root, title="Export Encrypted Database",
            defaultextension=".db", filetypes=[("SQLite DB", "*.db"), ("All Files", "*.*")],
            initialfile="registry_monitor_encrypted.db"
        )
        if dest:
            import shutil
            shutil.copy2(self.db.db_path, dest)
            messagebox.showinfo("Export Complete", f"Encrypted database exported to:\n{dest}", parent=self.root)

    def _update_status_display(self):
        """Update all dashboard displays, badges, and counters."""
        # Status label
        status_styles = {
            "STOPPED": "Red.TLabel",
            "STARTING": "Orange.TLabel",
            "MONITORING": "Green.TLabel",
            "ERROR": "Red.TLabel",
        }
        self.status_label.configure(
            text=self.status,
            style=status_styles.get(self.status, "Stat.TLabel")
        )

        # Header status badge
        if hasattr(self, "header_status_badge"):
            if self.status == "MONITORING":
                self.header_status_badge.configure(text="● MONITORING ACTIVE", bg="#064e3b", fg="#34d399")
            elif self.status == "STARTING":
                self.header_status_badge.configure(text="● STARTING ENGINE", bg="#78350f", fg="#fcd34d")
            else:
                self.header_status_badge.configure(text="● ENGINE STOPPED", bg="#450a0a", fg="#f87171")

        # Baseline label
        if self.baseline:
            created = self.baseline.get("metadata", {}).get("created_at", "Unknown")
            try:
                dt = datetime.fromisoformat(created)
                created_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                created_str = str(created)
            total_vals = self.baseline.get("metadata", {}).get("total_values_captured", 0)
            self.baseline_label.configure(
                text=f"Loaded ({total_vals} values)"
            )
        else:
            self.baseline_label.configure(text="Not loaded")

        # Scan time
        self.scan_time_label.configure(text=self.last_scan_time)
        if hasattr(self, "header_last_scan_badge"):
            self.header_last_scan_badge.configure(text=f"🕒 Last: {self.last_scan_time}")

        # Counters
        self.changes_label.configure(text=str(self.total_changes))
        self.suspicious_label.configure(text=str(self.suspicious_count))
        self.errors_label.configure(text=str(self.scan_errors))

        # Update floating desktop widget if initialized
        if hasattr(self, "floating_widget"):
            self.floating_widget.update_status(self.status, self.total_changes, self.suspicious_count)

    def _copy_to_clipboard(self, text: str, label_name: str = "Text"):
        """Copy string to clipboard safely."""
        if not text or text == "—" or text == "N/A":
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self._set_statusbar(f"Copied {label_name} to clipboard: {text[:55]}...")
        except Exception as e:
            logger.debug("Failed to copy to clipboard: %s", e)

    def _copy_selected_sha(self):
        self._copy_to_clipboard(self.selected_event_sha256, "SHA-256 Hash")

    def _copy_selected_path(self):
        self._copy_to_clipboard(self.selected_event_path, "Registry Path")

    def _copy_selected_full_telemetry(self):
        self._copy_to_clipboard(self.selected_event_full_text, "Full Event Telemetry")

    def _copy_selected_value_name(self):
        val = getattr(self, "selected_event_name", "")
        self._copy_to_clipboard(val, "Registry Value Name")

    def _show_quick_polling_menu(self, event=None):
        """Show quick timing interval popup menu when clicking header badge."""
        menu = tk.Menu(self.root, tearoff=0, bg=self.theme["card_bg"], fg=self.theme["fg"], activebackground=self.theme["accent"])
        intervals = [
            (1, "⚡ 1s - Ultra High Frequency"),
            (2, "🚀 2s - Fast Telemetry Auditing"),
            (5, "🛡️ 5s - Recommended Standard"),
            (10, "⏳ 10s - Low Overhead Monitoring"),
            (30, "💤 30s - Passive Auditing"),
            (60, "🍃 60s - Stealth Mode"),
        ]
        curr = self.config.get("polling_interval_seconds", 5)
        for s, label in intervals:
            prefix = "✓ " if s == curr else "   "
            menu.add_command(label=f"{prefix}{label}", command=lambda sec=s: self._set_polling_interval(sec))
        
        try:
            x = self.header_polling_badge.winfo_rootx()
            y = self.header_polling_badge.winfo_rooty() + self.header_polling_badge.winfo_height() + 2
            menu.tk_popup(x, y)
        except Exception as e:
            logger.debug("Quick polling menu error: %s", e)

    def _set_polling_interval(self, seconds: int):
        """Apply new polling interval immediately and persist to config and database."""
        self.config["polling_interval_seconds"] = seconds
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.update_interval(seconds)
        if hasattr(self, "header_polling_badge"):
            self.header_polling_badge.configure(text=f"⏱ {seconds}s Polling")
        # Save to config.json
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
            logger.info("Polling interval updated to %ds and saved to config.json", seconds)
        except Exception as e:
            logger.debug("Failed to write config: %s", e)
        # Save to encrypted SQLite database
        if hasattr(self, "db") and self.db:
            self.db.save_setting("polling_interval_seconds", seconds)
        self._set_statusbar(f"✓ Polling interval set to {seconds}s and applied to monitoring engine.")

    def _parse_hive_subkey(self, full_path: str) -> tuple[str, str]:
        """Extract hive and subkey from full registry path."""
        if not full_path:
            return "", ""
        parts = full_path.split("\\", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return parts[0], ""

    def _get_selected_event(self) -> dict | None:
        """Retrieve full event object for the currently selected Treeview item."""
        selection = self.event_tree.selection()
        if not selection:
            return None
        item = selection[0]
        values = self.event_tree.item(item, "values")
        if not values:
            return None
        timestamp_str = str(values[0])
        reg_path = str(values[3])
        val_name = str(values[4])

        for evt in reversed(self.events):
            evt_ts = evt.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(evt_ts)
                evt_ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                evt_ts_str = str(evt_ts)
            if (evt_ts_str == timestamp_str and
                evt.get("full_path") == reg_path and
                evt.get("value_name") == val_name):
                return evt
        return {
            "timestamp": values[0],
            "severity": values[1].lower() if len(values) > 1 else "informational",
            "change_type": values[2] if len(values) > 2 else "UNKNOWN",
            "full_path": reg_path,
            "value_name": val_name,
            "status": values[6] if len(values) > 6 else "detected"
        }

    def _remediate_selected_threat(self):
        """Manually neutralize and delete a suspicious or malicious registry value."""
        event = self._get_selected_event()
        if not event:
            suspicious_events = [
                e for e in reversed(self.events)
                if e.get("severity") in ("suspicious", "investigation_required")
                and e.get("status") != "REMEDIATED"
            ]
            if suspicious_events:
                event = suspicious_events[0]
            else:
                messagebox.showinfo(
                    "Threat Remediation",
                    "Please select an event from the telemetry table to remediate.\n\n"
                    "Tip: Select an entry with 'Suspicious' or 'Investigation' severity.",
                    parent=self.root
                )
                return

        value_name = event.get("value_name", "")
        full_path = event.get("full_path", "")
        if value_name in ("(key-level)", ""):
            messagebox.showwarning(
                "Remediation Notice",
                "This event represents a key-level or access permission change.\n"
                "Individual value deletion cannot be performed on key-level events.",
                parent=self.root
            )
            return

        if event.get("status") == "REMEDIATED":
            messagebox.showinfo(
                "Already Neutralized",
                f"Registry entry '{value_name}' has already been remediated.",
                parent=self.root
            )
            return

        hive, subkey = self._parse_hive_subkey(full_path)
        view = event.get("view", "64bit")
        current_val = event.get("current_value", "N/A")
        reason = event.get("reason", "Suspicious modification detected")
        resolved = event.get("resolved_file") or {}
        cmd_info = resolved.get("command_info") or {}
        exe_path = cmd_info.get("executable_path", "N/A")

        confirm_msg = (
            f"⚠️ THREAT REMEDIATION & DELETION WARNING\n\n"
            f"Target Registry Location:\n{full_path}\n\n"
            f"Value Name:  {value_name}\n"
            f"Value Data:  {str(current_val)[:80]}\n"
            f"Referenced:  {exe_path}\n"
            f"Severity:    {str(event.get('severity', 'UNKNOWN')).upper()}\n"
            f"Reason:      {reason}\n\n"
            f"Action: This will PERMANENTLY DELETE this registry value using the\n"
            f"Windows Registry API to neutralize attacker persistence.\n\n"
            f"Are you sure you want to delete this registry value now?"
        )

        if not messagebox.askyesno("Confirm Threat Remediation", confirm_msg, icon="warning", parent=self.root):
            return

        success, msg = registry_scanner.delete_registry_value(hive, subkey, value_name, view)
        
        if hasattr(self, "db") and self.db:
            try:
                self.db.record_remediation(
                    event_id=event.get("event_id", ""),
                    full_path=full_path,
                    value_name=value_name,
                    action="MANUAL_DELETE",
                    result="SUCCESS" if success else "FAILED",
                    details={"reason": reason, "current_val": current_val, "exe_path": exe_path, "message": msg}
                )
            except Exception as e:
                logger.debug("Failed to record remediation: %s", e)

        if success:
            event["status"] = "REMEDIATED"
            if event.get("severity") in ("suspicious", "investigation_required"):
                self.suspicious_count = max(0, self.suspicious_count - 1)
            
            self._update_event_row_status(event, "REMEDIATED")
            self._update_status_display()
            self._set_statusbar(f"✓ Threat Neutralized: Deleted '{value_name}' from {full_path}")
            
            messagebox.showinfo(
                "Threat Neutralized",
                f"✓ Success!\n\n{msg}\n\nThreat persistence has been eliminated.",
                parent=self.root
            )
        else:
            messagebox.showerror(
                "Remediation Failed",
                f"Failed to delete registry value:\n\n{msg}\n\n"
                "Tip: Ensure the application is running with Administrator privileges.",
                parent=self.root
            )

    def _auto_clean_all_threats(self):
        """Batch neutralize all detected suspicious registry threats."""
        active_threats = [
            e for e in self.events
            if e.get("severity") in ("suspicious", "investigation_required")
            and e.get("status") != "REMEDIATED"
            and e.get("value_name") not in ("(key-level)", "")
        ]

        if not active_threats:
            messagebox.showinfo(
                "Clean System",
                "✓ No active suspicious or threat entries found to clean!\n\n"
                "Your monitored registry locations are clean.",
                parent=self.root
            )
            return

        threat_summary = "\n".join([
            f"• [{e.get('value_name')}] in {e.get('full_path')}"
            for e in active_threats[:8]
        ])
        if len(active_threats) > 8:
            threat_summary += f"\n...and {len(active_threats) - 8} more"

        confirm_msg = (
            f"⚠️ BATCH THREAT REMEDIATION\n\n"
            f"Found {len(active_threats)} active threat/suspicious entries:\n\n"
            f"{threat_summary}\n\n"
            f"Action: This will attempt to delete all {len(active_threats)} entries from the\n"
            f"Windows Registry to remove malicious autostart hooks.\n\n"
            f"Do you want to proceed with batch remediation?"
        )

        if not messagebox.askyesno("Confirm Batch Threat Cleaning", confirm_msg, icon="warning", parent=self.root):
            return

        remediated_count = 0
        failed_count = 0

        for event in active_threats:
            full_path = event.get("full_path", "")
            value_name = event.get("value_name", "")
            hive, subkey = self._parse_hive_subkey(full_path)
            view = event.get("view", "64bit")

            success, msg = registry_scanner.delete_registry_value(hive, subkey, value_name, view)
            if hasattr(self, "db") and self.db:
                try:
                    self.db.record_remediation(
                        event_id=event.get("event_id", ""),
                        full_path=full_path,
                        value_name=value_name,
                        action="BATCH_CLEAN",
                        result="SUCCESS" if success else "FAILED",
                        details={"message": msg}
                    )
                except Exception as e:
                    logger.debug("Failed to record batch remediation: %s", e)

            if success:
                event["status"] = "REMEDIATED"
                self._update_event_row_status(event, "REMEDIATED")
                remediated_count += 1
            else:
                failed_count += 1

        self.suspicious_count = max(0, self.suspicious_count - remediated_count)
        self._update_status_display()
        self._set_statusbar(f"Batch remediation complete: {remediated_count} neutralized, {failed_count} failed.")

        messagebox.showinfo(
            "Batch Cleaning Complete",
            f"Remediation Summary:\n\n"
            f"✓ Neutralized: {remediated_count} threat entries\n"
            f"✗ Failed / Denied: {failed_count} entries\n\n"
            "All actions logged to encrypted database.",
            parent=self.root
        )

    def _update_event_row_status(self, event: dict, new_status: str):
        """Update the displayed status column in the event tree for a given event."""
        target_path = event.get("full_path")
        target_val = event.get("value_name")

        for item in self.event_tree.get_children():
            values = list(self.event_tree.item(item, "values"))
            if len(values) >= 7 and values[3] == target_path and values[4] == target_val:
                values[6] = new_status
                self.event_tree.item(item, values=values, tags=("remediated",))
                break

    def _show_tree_context_menu(self, event):
        """Show contextual right-click menu for selected event in event tree."""
        item = self.event_tree.identify_row(event.y)
        if item:
            self.event_tree.selection_set(item)
            self._show_event_details()
            
            menu = tk.Menu(self.root, tearoff=0, bg=self.theme["card_bg"], fg=self.theme["fg"], activebackground=self.theme["accent"])
            menu.add_command(label="🛡️ Remediate & Delete Registry Entry", command=self._remediate_selected_threat)
            menu.add_command(label="⚡ Auto-Clean All Threats", command=self._auto_clean_all_threats)
            menu.add_separator()
            menu.add_command(label="📋 Copy Registry Path", command=self._copy_selected_path)
            menu.add_command(label="📋 Copy Value Name", command=self._copy_selected_value_name)
            menu.add_command(label="📋 Copy SHA-256 Hash", command=self._copy_selected_sha)
            menu.tk_popup(event.x_root, event.y_root)

    def _matches_filter(self, event: dict) -> bool:
        """Check if an event matches current severity filter and search term."""
        sev_filter = self.severity_filter_var.get()
        sev = (event.get("severity") or "informational").lower()
        ct = event.get("change_type", "")

        if sev_filter == "Suspicious / Critical" and sev != "suspicious":
            return False
        elif sev_filter == "Investigation Required" and sev != "investigation_required":
            return False
        elif sev_filter == "Informational" and sev != "informational":
            return False
        elif sev_filter == "Errors Only" and (ct != "ERROR" and sev != "error"):
            return False

        query = self.search_var.get().strip().lower()
        if not query:
            return True

        resolved = event.get("resolved_file") or {}
        cmd_info = resolved.get("command_info") or {}
        haystack = " ".join([
            str(event.get("timestamp", "")),
            str(event.get("severity", "")),
            str(event.get("change_type", "")),
            str(event.get("full_path", "")),
            str(event.get("value_name", "")),
            str(event.get("current_value", "")),
            str(event.get("previous_value", "")),
            str(event.get("reason", "")),
            str(event.get("category", "")),
            str(cmd_info.get("executable_path", "")),
        ]).lower()

        return query in haystack

    def _on_search_filter_changed(self, event=None):
        """Re-filter the event tree based on search and severity dropdown."""
        self._refresh_event_tree()

    def _refresh_event_tree(self):
        """Clear and re-populate the event table according to filters."""
        for item in self.event_tree.get_children():
            self.event_tree.delete(item)

        matched = [e for e in self.events if self._matches_filter(e)]
        for e in matched:
            self._insert_event_row(e)

        self._update_filter_counter()

    def _clear_filters(self):
        """Reset search and filter selections."""
        self.search_var.set("")
        self.severity_filter_var.set("All Severities")
        self._refresh_event_tree()

    def _update_filter_counter(self):
        """Update the label showing how many events match current filter."""
        total = len(self.events)
        showing = len(self.event_tree.get_children())
        if hasattr(self, "event_filter_count_label"):
            if total == showing:
                self.event_filter_count_label.configure(text=f"Showing all {total} events")
            else:
                self.event_filter_count_label.configure(text=f"Showing {showing} of {total} events (Filtered)")

    def _reset_inspector_details(self):
        """Reset inspector displays to empty placeholders."""
        self.selected_event_sha256 = ""
        self.selected_event_path = ""
        self.selected_event_full_text = ""

        if hasattr(self, "details_text"):
            self.details_text.configure(state=tk.NORMAL)
            self.details_text.delete("1.0", tk.END)
            self.details_text.insert("1.0", "Select an event from the stream above to inspect forensic details.")
            self.details_text.configure(state=tk.DISABLED)

        if hasattr(self, "insp_path_val"):
            self.insp_path_val.configure(text="No event selected")
            self.insp_name_val.configure(text="—")
            self.insp_type_val.configure(text="—")
            self.insp_prev_val.configure(text="—")
            self.insp_curr_val.configure(text="—")
            self.insp_reason_val.configure(text="Select an event from the telemetry stream above.")
            self.insp_exe_val.configure(text="—")
            self.insp_args_val.configure(text="—")
            self.insp_exists_val.configure(text="—", fg="#94a3b8")
            self.insp_size_val.configure(text="—")
            self.insp_sha_val.configure(text="—")

    def _load_existing_baseline(self):
        """Try to load an existing baseline file."""
        baseline = registry_scanner.load_baseline(self.baseline_path)
        if baseline:
            if registry_scanner.verify_baseline_integrity(baseline):
                self.baseline = baseline
                self._set_statusbar("Baseline loaded successfully.")
                logger.info("Existing baseline loaded.")
            else:
                self._set_statusbar(
                    "WARNING: Baseline integrity check failed. "
                    "Consider creating a new baseline."
                )
                logger.warning("Baseline integrity verification failed.")
                self.baseline = baseline  # Load anyway but warn
        else:
            self._set_statusbar(
                "No baseline found. Use 'Create Baseline' to scan the registry."
            )
        self._update_status_display()

    def _set_statusbar(self, text: str):
        """Update the status bar text."""
        self.statusbar.configure(text=text)

    def _create_baseline(self):
        """Create a new registry baseline."""
        if self.baseline:
            confirm = messagebox.askyesno(
                "Confirm Baseline Creation",
                "A baseline already exists. Creating a new baseline will "
                "replace the current one.\n\nContinue?",
                icon="warning"
            )
            if not confirm:
                return

        if self.monitoring_thread and self.monitoring_thread.is_alive():
            messagebox.showwarning(
                "Monitoring Active",
                "Please stop monitoring before creating a new baseline."
            )
            return

        self._set_statusbar("Creating baseline... Scanning registry...")
        self.root.update_idletasks()

        try:
            baseline = registry_scanner.perform_full_scan(self.config)
            registry_scanner.save_baseline(baseline, self.baseline_path)
            if hasattr(self, "db") and self.db:
                try:
                    self.db.save_baseline(baseline)
                except Exception as e:
                    logger.debug("Failed to save baseline to encrypted db: %s", e)
            self.baseline = baseline
            self.events.clear()
            self.total_changes = 0
            self.suspicious_count = 0
            self.scan_errors = 0
            self._clear_event_tree()
            self.alert_mgr.reset_fingerprints()

            meta = baseline["metadata"]
            self._set_statusbar(
                f"Baseline created: {meta['total_values_captured']} values "
                f"from {meta['total_keys_scanned']} keys "
                f"({meta['total_access_denied']} access denied, "
                f"{meta['total_not_found']} not found)"
            )
            self._update_status_display()

            messagebox.showinfo(
                "Baseline Created",
                f"Registry baseline created successfully.\n\n"
                f"Keys scanned: {meta['total_keys_scanned']}\n"
                f"Values captured: {meta['total_values_captured']}\n"
                f"Access denied: {meta['total_access_denied']}\n"
                f"Not found: {meta['total_not_found']}\n\n"
                f"Note: This is a selected-path baseline, not a \n"
                f"complete backup of the Windows Registry."
            )
        except Exception as e:
            logger.error("Baseline creation failed: %s", e, exc_info=True)
            messagebox.showerror(
                "Baseline Error",
                f"Failed to create baseline:\n{e}"
            )
            self._set_statusbar("Baseline creation failed.")

    def _rescan_registry(self):
        """Perform a one-time rescan without replacing the baseline."""
        self._set_statusbar("Rescanning registry...")
        self.root.update_idletasks()

        try:
            scan = registry_scanner.perform_full_scan(self.config)
            meta = scan["metadata"]

            if self.baseline:
                fr = file_resolver if self.config.get(
                    "file_checks", {}).get("resolve_paths", True) else None
                events = change_detector.detect_changes(
                    self.baseline.get("scan_results", []),
                    scan.get("scan_results", []),
                    fr
                )
                if events:
                    self._process_new_events(events)
                    self._set_statusbar(
                        f"Rescan complete: {len(events)} change(s) detected."
                    )
                else:
                    self._set_statusbar(
                        f"Rescan complete: No changes detected. "
                        f"({meta['total_values_captured']} values checked)"
                    )
            else:
                self._set_statusbar(
                    f"Rescan complete ({meta['total_values_captured']} values). "
                    f"No baseline to compare against."
                )

            self.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._update_status_display()

        except Exception as e:
            logger.error("Rescan failed: %s", e, exc_info=True)
            messagebox.showerror("Rescan Error", f"Registry rescan failed:\n{e}")
            self._set_statusbar("Rescan failed.")

    def _reset_baseline(self):
        """Reset the baseline with confirmation."""
        if not self.baseline:
            messagebox.showinfo("No Baseline", "No baseline is currently loaded.")
            return

        confirm = messagebox.askyesno(
            "Confirm Baseline Reset",
            "This will DELETE the current baseline.\n\n"
            "You will need to create a new baseline before monitoring.\n\n"
            "This action cannot be undone. Continue?",
            icon="warning"
        )
        if not confirm:
            return

        # Double confirmation for safety
        confirm2 = messagebox.askyesno(
            "Final Confirmation",
            "Are you sure you want to reset the baseline?\n\n"
            "Type 'Yes' to confirm.",
            icon="warning"
        )
        if not confirm2:
            return

        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self._stop_monitoring()

        try:
            if os.path.exists(self.baseline_path):
                # Create backup before deletion
                backup_path = self.baseline_path + ".bak"
                import shutil
                shutil.copy2(self.baseline_path, backup_path)
                os.remove(self.baseline_path)
                logger.info("Baseline removed (backup at %s)", backup_path)

            self.baseline = None
            self.events.clear()
            self.total_changes = 0
            self.suspicious_count = 0
            self.scan_errors = 0
            self._clear_event_tree()
            self.alert_mgr.reset_fingerprints()
            self._update_status_display()
            self._set_statusbar("Baseline reset. Create a new baseline to begin monitoring.")

        except Exception as e:
            logger.error("Baseline reset failed: %s", e)
            messagebox.showerror("Reset Error", f"Failed to reset baseline:\n{e}")

    def _start_monitoring(self):
        """Start continuous registry monitoring."""
        if not self.baseline:
            messagebox.showwarning(
                "No Baseline",
                "Please create a baseline before starting monitoring.\n\n"
                "Use 'Create Baseline' to scan the registry first."
            )
            return

        if self.monitoring_thread and self.monitoring_thread.is_alive():
            messagebox.showinfo("Already Running", "Monitoring is already active.")
            return

        self.status = "STARTING"
        self._update_status_display()
        self._set_statusbar("Starting monitoring...")

        self.monitoring_thread = MonitoringThread(
            self.config, self.event_queue, self.baseline, file_resolver
        )
        self.monitoring_thread.start()

        self.btn_start.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)
        self.btn_create_baseline.configure(state=tk.DISABLED)
        self.btn_reset.configure(state=tk.DISABLED)

    def _stop_monitoring(self):
        """Stop continuous registry monitoring."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self._set_statusbar("Stopping monitoring...")
            self.monitoring_thread.stop()
            # Don't join with timeout to avoid blocking GUI
            self.root.after(1000, self._check_thread_stopped)
        else:
            self.status = "STOPPED"
            self._update_status_display()
            self._restore_buttons()

    def _check_thread_stopped(self):
        """Check if the monitoring thread has stopped."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.root.after(500, self._check_thread_stopped)
        else:
            self.status = "STOPPED"
            self._update_status_display()
            self._restore_buttons()
            self._set_statusbar("Monitoring stopped.")

    def _restore_buttons(self):
        """Restore button states after stopping."""
        self.btn_start.configure(state=tk.NORMAL)
        self.btn_stop.configure(state=tk.DISABLED)
        self.btn_create_baseline.configure(state=tk.NORMAL)
        self.btn_reset.configure(state=tk.NORMAL)

    def _process_queue(self):
        """Process events from the monitoring thread queue.
        
        Uses root.after() to stay on the GUI thread.
        This is the ONLY place where monitoring events are consumed.
        """
        try:
            while True:
                msg = self.event_queue.get_nowait()
                msg_type = msg.get("type")

                if msg_type == "status":
                    self.status = msg["status"]
                    self._update_status_display()
                    if self.status == "MONITORING":
                        self._set_statusbar(
                            f"Monitoring active (polling every "
                            f"{self.config.get('polling_interval_seconds', 5)}s). "
                            f"Note: Polling cannot detect changes that occur "
                            f"and reverse between intervals."
                        )

                elif msg_type == "events":
                    self._process_new_events(msg["events"])

                elif msg_type == "scan_complete":
                    try:
                        dt = datetime.fromisoformat(msg["timestamp"])
                        self.last_scan_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except (ValueError, TypeError):
                        self.last_scan_time = str(msg["timestamp"])
                    if hasattr(self, "db") and self.db:
                        try:
                            self.db.record_scan(
                                keys_scanned=msg.get("keys_scanned", 0),
                                errors=msg.get("errors", 0),
                                access_denied=msg.get("access_denied", 0),
                                changes_count=0
                            )
                        except Exception:
                            pass
                    self._update_status_display()

                elif msg_type == "error":
                    self.scan_errors += 1
                    self._update_status_display()
                    logger.error("Monitoring error: %s", msg.get("message"))

        except Empty:
            pass

        # Also check for pending alerts from the alert manager
        pending = self.alert_mgr.get_pending_alert()
        if pending:
            self._show_alert_popup(pending)

        # Re-schedule
        if not getattr(self, "_is_closed", False):
            try:
                self._queue_after_id = self.root.after(200, self._process_queue)
            except Exception:
                pass

    def _process_new_events(self, events: list[dict]):
        """Process and display new change events."""
        if hasattr(self, "db") and self.db:
            try:
                self.db.save_events(events)
            except Exception as e:
                logger.debug("Failed to save events to encrypted db: %s", e)

        for event in events:
            self.events.append(event)
            self.total_changes += 1

            severity = event.get("severity", "informational")
            if severity in ("suspicious", "investigation_required"):
                self.suspicious_count += 1

            # Add to event tree if it matches the current active search/severity filters
            if self._matches_filter(event):
                self._insert_event_row(event)

            # Log the event
            self.event_logger.log_event(event)

            # Check for alert
            if self.alert_mgr.should_alert(event):
                self._show_alert_popup(event)

        self._update_filter_counter()
        self._update_status_display()

    def _insert_event_row(self, event: dict):
        """Insert a single event row into the Treeview with dark styling tags."""
        resolved = event.get("resolved_file") or {}
        cmd_info = resolved.get("command_info") or {}
        file_path = cmd_info.get("executable_path", "")

        timestamp = event.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(timestamp)
            timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            pass

        severity = (event.get("severity") or "informational").lower()
        tags = []
        if severity == "suspicious":
            tags.append("suspicious")
        elif severity == "investigation_required":
            tags.append("investigation_required")
        elif event.get("change_type") == "ERROR" or severity == "error":
            tags.append("error")
        else:
            tags.append("informational")

        # Alternating row background
        row_count = len(self.event_tree.get_children())
        tags.append("even" if row_count % 2 == 0 else "odd")

        item_id = self.event_tree.insert(
            "", 0,  # Insert at top (newest first)
            values=(
                timestamp,
                severity.title(),
                event.get("change_type", ""),
                event.get("full_path", ""),
                event.get("value_name", ""),
                file_path,
                event.get("status", ""),
            ),
            tags=tuple(tags),
        )
        return item_id

    def _add_event_to_tree(self, event: dict):
        """Add an event to the Treeview (backward-compatible entry point)."""
        self._insert_event_row(event)
        self._update_filter_counter()

    def _clear_event_tree(self):
        """Clear all items from the event tree and reset inspector."""
        for item in self.event_tree.get_children():
            self.event_tree.delete(item)
        self._reset_inspector_details()
        self._update_filter_counter()

    def _show_event_details(self, event=None):
        """Show detailed information for the selected event in both structured cards and raw log."""
        selection = self.event_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.event_tree.item(item, "values")
        if not values:
            return

        # Find the matching event by timestamp and path
        timestamp_str = values[0]
        reg_path = values[3]
        val_name = values[4]

        matching_event = None
        for evt in reversed(self.events):
            evt_ts = evt.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(evt_ts)
                evt_ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                evt_ts_str = evt_ts

            if (evt_ts_str == timestamp_str and
                evt.get("full_path") == reg_path and
                evt.get("value_name") == val_name):
                matching_event = evt
                break

        if not matching_event:
            # Fallback: show values from treeview
            matching_event = dict(zip(
                ["timestamp", "severity", "change_type", "full_path",
                 "value_name", "file_path", "status"],
                values
            ))

        # Format details
        lines = [
            f"Event ID:        {matching_event.get('event_id', 'N/A')}",
            f"Timestamp:       {matching_event.get('timestamp', 'N/A')}",
            f"Change Type:     {matching_event.get('change_type', 'N/A')}",
            f"Severity:        {matching_event.get('severity', 'N/A')}",
            f"Registry Path:   {matching_event.get('full_path', 'N/A')}",
            f"Value Name:      {matching_event.get('value_name', 'N/A')}",
            f"Category:        {matching_event.get('category', 'N/A')}",
            f"View:            {matching_event.get('view', 'N/A')}",
            f"Previous Value:  {matching_event.get('previous_value', 'N/A')}",
            f"Current Value:   {matching_event.get('current_value', 'N/A')}",
            f"Previous Type:   {matching_event.get('previous_type', 'N/A')}",
            f"Current Type:    {matching_event.get('current_type', 'N/A')}",
            f"Reason:          {matching_event.get('reason', 'N/A')}",
            f"Status:          {matching_event.get('status', 'N/A')}",
        ]

        resolved = matching_event.get("resolved_file") or {}
        cmd = resolved.get("command_info") or {}
        meta = resolved.get("file_metadata") or {}

        if resolved:
            lines.extend([
                "",
                "--- File Resolution ---",
                f"Executable:      {cmd.get('executable_path', 'N/A')}",
                f"Arguments:       {cmd.get('arguments', 'N/A')}",
                f"File Type:       {cmd.get('file_type', 'N/A')}",
                f"Parse Method:    {cmd.get('parse_method', 'N/A')}",
                f"File Exists:     {meta.get('exists', 'N/A')}",
                f"File Size:       {meta.get('size_bytes', 'N/A')}",
                f"Modified:        {meta.get('modified_time', 'N/A')}",
                f"SHA-256:         {meta.get('sha256', 'N/A')}",
            ])

        full_text = "\n".join(lines)
        self.selected_event_full_text = full_text

        # Update raw log textbox (details_text)
        self.details_text.configure(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert("1.0", full_text)
        self.details_text.configure(state=tk.DISABLED)

        # Update Structured Cards
        if hasattr(self, "insp_path_val"):
            self.selected_event_path = matching_event.get("full_path", "")
            self.selected_event_sha256 = meta.get("sha256", "") or ""

            self.insp_path_val.configure(text=matching_event.get("full_path", "N/A"))
            self.insp_name_val.configure(
                text=f"{matching_event.get('value_name', 'N/A')}  [{matching_event.get('current_type') or matching_event.get('previous_type') or 'REG_SZ'}]"
            )

            ct = matching_event.get("change_type", "N/A")
            sev = (matching_event.get("severity") or "informational").title()
            self.insp_type_val.configure(text=f"{ct}  •  {sev}")

            prev_v = str(matching_event.get("previous_value") if matching_event.get("previous_value") is not None else "(none)")
            curr_v = str(matching_event.get("current_value") if matching_event.get("current_value") is not None else "(deleted)")
            self.insp_prev_val.configure(text=prev_v[:85] + ("..." if len(prev_v) > 85 else ""))
            self.insp_curr_val.configure(text=curr_v[:85] + ("..." if len(curr_v) > 85 else ""))
            self.insp_reason_val.configure(text=matching_event.get("reason", "N/A"))

            # Binary details
            exe_path = cmd.get("executable_path") or "(None referenced)"
            args_str = cmd.get("arguments") or "(None)"
            self.insp_exe_val.configure(text=exe_path)
            self.insp_args_val.configure(text=args_str[:75] + ("..." if len(args_str) > 75 else ""))

            exists = meta.get("exists")
            if exists is True:
                self.insp_exists_val.configure(text="● EXISTS ON DISK", fg="#10b981")
            elif exists is False:
                self.insp_exists_val.configure(text="● MISSING / ORPHAN", fg="#ef4444")
            else:
                self.insp_exists_val.configure(text="● NOT APPLICABLE", fg="#64748b")

            size_str = _format_size(meta.get("size_bytes")) if meta.get("size_bytes") is not None else "N/A"
            mod_str = meta.get("modified_time", "N/A")
            self.insp_size_val.configure(text=f"{size_str} • Mod: {mod_str}")

            sha_val = meta.get("sha256") or "N/A"
            self.insp_sha_val.configure(text=sha_val)

    def _show_alert_popup(self, event: dict):
        """Show a desktop alert popup for an event.

        This runs on the GUI thread via queue processing.
        Uses non-blocking Toplevel alert windows so monitoring continues uninterrupted.
        """
        self.alert_mgr.record_alert(event)

        try:
            NonBlockingAlertWindow(
                self.root, event,
                on_view_event=self._select_and_show_event,
                on_mute=self._mute_from_popup
            )
        except Exception as e:
            logger.warning("Failed to open non-blocking alert window (%s), fallback to messagebox.", e)
            title = "Registry Change Detected"
            if event.get("severity") == "investigation_required":
                title = "⚠ Registry Change - Investigation Required"
            elif event.get("severity") == "suspicious":
                title = "⚠ Suspicious Registry Change Detected"
            message = self.alert_mgr.format_alert_message(event)
            messagebox.showwarning(title, message)

    def _select_and_show_event(self, target_event: dict):
        """Find an event in the Treeview, select it, and show its details."""
        for item in self.event_tree.get_children():
            vals = self.event_tree.item(item, "values")
            if vals and len(vals) >= 5:
                if (vals[3] == target_event.get("full_path") and
                    vals[4] == target_event.get("value_name")):
                    self.event_tree.selection_set(item)
                    self.event_tree.see(item)
                    self._show_event_details()
                    self.root.lift()
                    return

    def _mute_from_popup(self):
        """Mute pop-up alerts from the notification popup button."""
        self.mute_var.set(True)
        self._toggle_mute()

    def _view_events(self):
        """Handler for 'View Events' control button."""
        selected = self.event_tree.selection()
        if selected:
            self._show_event_details()
            self._set_statusbar("Displaying selected event details.")
        else:
            children = self.event_tree.get_children()
            if children:
                self.event_tree.selection_set(children[0])
                self.event_tree.see(children[0])
                self._show_event_details()
                self._set_statusbar(f"Selected event 1 of {len(children)}.")
            else:
                messagebox.showinfo(
                    "No Events",
                    "No registry change events recorded yet.\n\n"
                    "Start monitoring or run 'Rescan Registry' to detect changes."
                )

    def _toggle_mute(self):
        """Toggle pop-up muting."""
        self.alert_mgr.muted = self.mute_var.get()
        state = "muted" if self.alert_mgr.muted else "enabled"
        self._set_statusbar(f"Pop-up alerts {state}. Events still logged.")

    def _toggle_hide_taskbar(self):
        """Toggle visibility of the main application button on the Windows Taskbar."""
        hide = self.hide_taskbar_var.get()
        set_taskbar_visibility(self.root, show=not hide)
        status = "hidden from" if hide else "visible on"
        self._set_statusbar(f"Application icon is now {status} the Windows Taskbar.")

    def _export_report(self):
        """Export events to CSV and generate a summary report."""
        if not self.events:
            messagebox.showinfo(
                "No Events", "No events to export. Start monitoring first."
            )
            return

        report_dir = os.path.join(
            APP_DIR,
            self.config.get("reporting", {}).get("output_directory", "data/reports")
        )
        os.makedirs(report_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # CSV Export
        csv_path = os.path.join(report_dir, f"events_{timestamp}.csv")
        try:
            report_generator.export_events_csv(self.events, csv_path)
        except Exception as e:
            messagebox.showerror("Export Error", f"CSV export failed:\n{e}")
            return

        # Summary Report
        summary_path = os.path.join(report_dir, f"summary_{timestamp}.json")
        try:
            baseline_meta = self.baseline.get("metadata", {}) if self.baseline else {}
            summary = report_generator.generate_summary_report(
                self.events, baseline_meta, self.config
            )
            report_generator.save_summary_report(summary, summary_path)
        except Exception as e:
            logger.error("Summary report generation failed: %s", e)

        # Visual Image Report Export
        visual_path = os.path.join(report_dir, f"events_visual_{timestamp}.png")
        try:
            baseline_meta = self.baseline.get("metadata", {}) if self.baseline else {}
            visual_reporter.generate_events_visual_report(self.events, baseline_meta, visual_path)
        except Exception as e:
            logger.error("Visual report generation failed: %s", e)
            visual_path = None

        self._set_statusbar(f"Report exported to {report_dir}")
        msg = (
            f"Reports exported successfully:\n\n"
            f"CSV: {csv_path}\n"
            f"Summary JSON: {summary_path}\n"
        )
        if visual_path:
            msg += f"Graphical Image: {visual_path}\n"
        msg += f"\nTotal events: {len(self.events)}"

        if messagebox.askyesno("Export Complete", f"{msg}\n\nWould you like to open the Graphical Visual Report now?"):
            if visual_path and os.path.exists(visual_path):
                VisualReportViewerDialog(self.root, visual_path, "Registry Change Monitoring - Graphical Visual Report")

    def _show_visual_report(self):
        """Generate and display the interactive graphical image report for events."""
        self._set_statusbar("Generating graphical visual report...")
        self.root.update_idletasks()

        report_dir = os.path.join(
            APP_DIR,
            self.config.get("reporting", {}).get("output_directory", "data/reports")
        )
        os.makedirs(report_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        img_path = os.path.join(report_dir, f"events_visual_{ts}.png")

        try:
            baseline_meta = self.baseline.get("metadata", {}) if self.baseline else {}
            visual_reporter.generate_events_visual_report(self.events, baseline_meta, img_path)
            self._set_statusbar(f"Graphical report generated: {os.path.basename(img_path)}")
            VisualReportViewerDialog(self.root, img_path, "Registry Change Monitoring - Graphical Visual Report")
        except Exception as e:
            logger.error("Failed to generate visual report: %s", e, exc_info=True)
            messagebox.showerror("Graphical Report Error", f"Failed to generate graphical report:\n{e}")
            self._set_statusbar("Failed to generate graphical report.")

    def _advanced_system_monitoring(self):
        """Execute Advanced System Monitoring: analyze all referenced files and display comprehensive report."""
        self._set_statusbar("Running Advanced System Monitoring... Analyzing all referenced files...")
        self.root.update_idletasks()

        try:
            # Analyze all files referenced across monitored registry locations
            scan_results = self.baseline.get("scan_results") if self.baseline else None
            report = file_resolver.analyze_all_monitored_files(self.config, scan_results)

            # Auto-save report to data/reports
            report_dir = os.path.join(
                APP_DIR,
                self.config.get("reporting", {}).get("output_directory", "data/reports")
            )
            os.makedirs(report_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = os.path.join(report_dir, f"advanced_file_analysis_{ts}.json")
            csv_path = os.path.join(report_dir, f"advanced_file_analysis_{ts}.csv")
            visual_path = os.path.join(report_dir, f"advanced_file_visual_{ts}.png")

            report_generator.export_advanced_analysis_json(report, json_path)
            report_generator.export_advanced_analysis_csv(report["files"], csv_path)
            try:
                visual_reporter.generate_advanced_file_visual_report(report, visual_path)
            except Exception as e:
                logger.error("Advanced file visual report failed: %s", e)
                visual_path = ""

            total_analyzed = report.get("summary", {}).get("total_files_analyzed", 0)
            suspicious = report.get("summary", {}).get("suspicious_or_warning_files", 0)
            self._set_statusbar(
                f"Advanced System Monitoring complete: {total_analyzed} files inspected "
                f"({suspicious} warnings/suspicious). Report displayed."
            )

            # Open interactive report dialog
            AdvancedAnalysisReportWindow(
                self.root, report,
                default_csv=csv_path,
                default_json=json_path,
                default_visual=visual_path
            )

        except Exception as e:
            logger.error("Advanced system monitoring analysis failed: %s", e, exc_info=True)
            messagebox.showerror(
                "Advanced Monitoring Error",
                f"Failed to complete advanced file analysis:\n{e}"
            )
            self._set_statusbar("Advanced System Monitoring analysis failed.")

    def _run_in_background(self):
        """Hide application from Windows taskbar and show draggable floating desktop widget."""
        set_taskbar_visibility(self.root, False)
        self.root.withdraw()
        self.floating_widget.show_floating_widget()
        self._set_statusbar("Application running in background. Click or drag floating desktop icon.")

    def _on_window_unmap(self, event):
        """Detect when user clicks the window Minimize button and switch to movable desktop icon."""
        if event.widget == self.root and self.root.state() == "iconic":
            if getattr(self, "minimize_to_icon_var", None) and self.minimize_to_icon_var.get():
                self.root.after(10, self._on_minimize_to_desktop)

    def _on_minimize_to_desktop(self):
        """Minimize application into the movable floating desktop icon."""
        self._run_in_background()
        self._set_statusbar(
            "Application minimized to movable floating desktop icon. Click or drag icon anywhere."
        )

    def _on_close(self):
        """Handle application shutdown or minimize to background floating icon."""
        ans = messagebox.askyesnocancel(
            "Registry Monitoring System",
            "Do you want to run in the background with the movable desktop floating widget?\n\n"
            "• Yes: Run in background (hides from taskbar, shows draggable floating desktop icon)\n"
            "• No: Stop monitoring and exit completely\n"
            "• Cancel: Return to application"
        )
        if ans is True:
            self._run_in_background()
            return
        elif ans is None:
            return  # Cancel

        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.stop()
            self.root.after(500, self._force_close)
            return
        self._force_close()

    def _apply_initial_taskbar(self):
        """Apply taskbar hide on startup if window is still open."""
        if not getattr(self, "_is_closed", False):
            try:
                set_taskbar_visibility(self.root, False)
            except Exception:
                pass

    def _force_close(self):
        """Force close after stopping monitoring."""
        self._is_closed = True
        if hasattr(self, "_queue_after_id"):
            try:
                self.root.after_cancel(self._queue_after_id)
            except Exception:
                pass
        if hasattr(self, "_taskbar_after_id"):
            try:
                self.root.after_cancel(self._taskbar_after_id)
            except Exception:
                pass
        if hasattr(self, "floating_widget"):
            try:
                self.floating_widget.destroy()
            except Exception:
                pass
        self.root.destroy()

    def run(self):
        """Start the application main loop."""
        logger.info("Application started.")
        self.root.mainloop()


def main():
    """Application entry point."""
    app = RegistryMonitorApp()
    if "--minimized" in sys.argv or "--background" in sys.argv:
        app.root.after(100, app._run_in_background)
    app.run()


if __name__ == "__main__":
    main()
