"""Visual Reporter Module

Generates publication-quality graphical image reports (PNG) and visual infographics
from registry monitoring change events and advanced file forensic analyses.

Leverages:
- pandas: Data structuring, aggregation, grouping, and cross-tabulation
- PIL (Pillow): Image canvas generation, graphical chart rendering, font typography,
                and layout composition
- Tkinter ImageTk: In-GUI visual rendering and interactive inspection
"""

import os
import math
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from PIL import Image, ImageDraw, ImageFont

logger = logging.getLogger(__name__)

# Standard color palette (Modern Cybersecurity Blue/Dark theme)
PALETTE = {
    "bg_main": "#f4f6f9",
    "card_bg": "#ffffff",
    "card_border": "#dce1e8",
    "header_bg": "#102a43",
    "header_text": "#ffffff",
    "header_sub": "#9fb3c8",
    "text_dark": "#1f2937",
    "text_muted": "#6b7280",
    "text_light": "#9ca3af",
    "border_light": "#e5e7eb",
    # Severity & Risk colors
    "color_critical": "#dc2626",      # Red
    "color_suspicious": "#ea580c",    # Orange
    "color_warning": "#f59e0b",       # Amber / Yellow
    "color_info": "#2563eb",          # Blue
    "color_benign": "#16a34a",        # Green
    "color_neutral": "#64748b",       # Slate Gray
    "color_purple": "#7c3aed",        # Purple
    "color_teal": "#0d9488",          # Teal
}

SEVERITY_COLORS = {
    "investigation_required": PALETTE["color_critical"],
    "suspicious": PALETTE["color_suspicious"],
    "informational": PALETTE["color_info"],
    "unknown": PALETTE["color_neutral"],
}

CHANGE_TYPE_COLORS = {
    "ADDED": PALETTE["color_benign"],
    "MODIFIED": PALETTE["color_warning"],
    "DELETED": PALETTE["color_critical"],
    "TYPE_CHANGED": PALETTE["color_purple"],
    "ERROR": PALETTE["color_critical"],
    "FILE_MODIFIED": PALETTE["color_suspicious"],
    "FILE_DELETED": PALETTE["color_critical"],
}

RISK_LEVEL_COLORS = {
    "SUSPICIOUS": PALETTE["color_critical"],
    "WARNING": PALETTE["color_suspicious"],
    "BENIGN": PALETTE["color_benign"],
    "INFO": PALETTE["color_info"],
    "UNKNOWN": PALETTE["color_neutral"],
}


def _get_font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    """Load a clean Windows font (Segoe UI or Arial), falling back to default."""
    font_candidates = []
    if bold:
        font_candidates = [
            "C:/Windows/Fonts/segoeuib.ttf",
            "C:/Windows/Fonts/arialbd.ttf",
            "C:/Windows/Fonts/calibrib.ttf",
        ]
    else:
        font_candidates = [
            "C:/Windows/Fonts/segoeui.ttf",
            "C:/Windows/Fonts/arial.ttf",
            "C:/Windows/Fonts/calibri.ttf",
        ]

    for fp in font_candidates:
        if os.path.exists(fp):
            try:
                return ImageFont.truetype(fp, size)
            except Exception:
                continue

    try:
        return ImageFont.load_default()
    except Exception:
        return None


def _draw_rounded_rectangle(draw: ImageDraw.ImageDraw, bounds: tuple[int, int, int, int],
                           fill: str, outline: str = None, radius: int = 8, width: int = 1):
    """Draw a smooth rounded rectangle on the canvas."""
    x1, y1, x2, y2 = bounds
    draw.rounded_rectangle((x1, y1, x2, y2), radius=radius, fill=fill, outline=outline, width=width)


def _draw_header(draw: ImageDraw.ImageDraw, width: int, title: str, subtitle: str, badge_text: str = "CONFIDENTIAL AUDIT"):
    """Render a modern dark blue cybersecurity header banner."""
    header_height = 95
    draw.rectangle((0, 0, width, header_height), fill=PALETTE["header_bg"])
    
    # Top decorative colored accent strip
    draw.rectangle((0, 0, width, 4), fill=PALETTE["color_info"])

    title_font = _get_font(24, bold=True)
    sub_font = _get_font(12, bold=False)
    badge_font = _get_font(10, bold=True)

    # Draw Title & Subtitle
    draw.text((30, 20), title, font=title_font, fill=PALETTE["header_text"])
    draw.text((30, 56), subtitle, font=sub_font, fill=PALETTE["header_sub"])

    # Draw right-aligned security badge
    badge_w = 160
    badge_h = 26
    badge_x = width - badge_w - 30
    badge_y = 35
    _draw_rounded_rectangle(draw, (badge_x, badge_y, badge_x + badge_w, badge_y + badge_h),
                           fill="#1e3a5f", outline="#3b82f6", radius=4)
    draw.text((badge_x + 16, badge_y + 6), badge_text, font=badge_font, fill="#93c5fd")


def _draw_footer(draw: ImageDraw.ImageDraw, width: int, height: int, footer_text: str):
    """Render a clean bottom footer strip."""
    footer_height = 40
    y1 = height - footer_height
    draw.rectangle((0, y1, width, height), fill="#e2e8f0")
    draw.line((0, y1, width, y1), fill=PALETTE["card_border"], width=1)
    
    f_font = _get_font(11, bold=False)
    draw.text((30, y1 + 12), footer_text, font=f_font, fill=PALETTE["text_muted"])
    
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ts_text = f"Generated: {now_str} | Windows Registry Change Monitoring System"
    draw.text((width - 450, y1 + 12), ts_text, font=f_font, fill=PALETTE["text_muted"])


def _draw_metric_cards(draw: ImageDraw.ImageDraw, x: int, y: int, total_width: int,
                       metrics: list[tuple[str, str, str]]):
    """Draw KPI summary cards with top colored accent indicators.
    
    metrics: list of (title, value_str, accent_color)
    """
    card_gap = 14
    num_cards = len(metrics)
    card_w = int((total_width - (card_gap * (num_cards - 1))) / num_cards)
    card_h = 75

    title_font = _get_font(11, bold=False)
    val_font = _get_font(20, bold=True)

    for i, (title, val_str, color) in enumerate(metrics):
        cx1 = x + i * (card_w + card_gap)
        cy1 = y
        cx2 = cx1 + card_w
        cy2 = cy1 + card_h

        # Card body
        _draw_rounded_rectangle(draw, (cx1, cy1, cx2, cy2), fill=PALETTE["card_bg"],
                               outline=PALETTE["card_border"], radius=6)

        # Left or top indicator bar
        draw.rounded_rectangle((cx1, cy1, cx1 + 5, cy2), radius=3, fill=color)

        # Labels
        draw.text((cx1 + 16, cy1 + 12), title, font=title_font, fill=PALETTE["text_muted"])
        draw.text((cx1 + 16, cy1 + 34), str(val_str), font=val_font, fill=color)


def _draw_donut_chart(draw: ImageDraw.ImageDraw, center: tuple[int, int],
                      outer_r: int, inner_r: int,
                      data_series: pd.Series, color_map: dict[str, str],
                      title: str, total_label: str = "Total"):
    """Render a clean donut / pie chart with percentage labels and legend."""
    cx, cy = center
    title_font = _get_font(14, bold=True)
    legend_font = _get_font(11, bold=False)
    center_num_font = _get_font(18, bold=True)
    center_lbl_font = _get_font(10, bold=False)

    # Title
    draw.text((cx - outer_r, cy - outer_r - 35), title, font=title_font, fill=PALETTE["text_dark"])

    total = data_series.sum()
    if total <= 0:
        # Empty donut placeholder
        draw.ellipse((cx - outer_r, cy - outer_r, cx + outer_r, cy + outer_r),
                     outline=PALETTE["card_border"], width=outer_r - inner_r)
        draw.text((cx - 25, cy - 8), "No Data", font=legend_font, fill=PALETTE["text_muted"])
        return

    # Draw pie segments
    start_angle = -90.0
    for label, count in data_series.items():
        if count <= 0:
            continue
        slice_angle = (count / total) * 360.0
        end_angle = start_angle + slice_angle
        color = color_map.get(str(label).lower(), color_map.get(str(label), PALETTE["color_neutral"]))

        draw.pieslice((cx - outer_r, cy - outer_r, cx + outer_r, cy + outer_r),
                      start=start_angle, end=end_angle, fill=color)
        start_angle = end_angle

    # Inner cutout to form donut
    draw.ellipse((cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r), fill=PALETTE["card_bg"])

    # Center text
    tot_str = str(int(total))
    draw.text((cx - (len(tot_str) * 6), cy - 14), tot_str, font=center_num_font, fill=PALETTE["text_dark"])
    draw.text((cx - (len(total_label) * 3), cy + 10), total_label, font=center_lbl_font, fill=PALETTE["text_muted"])

    # Draw side legend
    leg_x = cx + outer_r + 25
    leg_y = cy - outer_r + 10
    for label, count in data_series.items():
        pct = (count / total) * 100.0
        color = color_map.get(str(label).lower(), color_map.get(str(label), PALETTE["color_neutral"]))

        # Color square
        draw.rounded_rectangle((leg_x, leg_y + 2, leg_x + 12, leg_y + 14), radius=2, fill=color)

        # Label with count and percentage
        display_label = str(label).replace("_", " ").title()
        text_str = f"{display_label}: {count} ({pct:.1f}%)"
        draw.text((leg_x + 18, leg_y), text_str, font=legend_font, fill=PALETTE["text_dark"])
        leg_y += 22


def _draw_horizontal_bar_chart(draw: ImageDraw.ImageDraw, x: int, y: int, w: int, h: int,
                              data_series: pd.Series, color_map: dict[str, str],
                              title: str, max_items: int = 6):
    """Render a clean horizontal bar chart with labels, percentages, and count pills."""
    title_font = _get_font(14, bold=True)
    label_font = _get_font(11, bold=False)
    count_font = _get_font(10, bold=True)

    # Title
    draw.text((x, y), title, font=title_font, fill=PALETTE["text_dark"])
    chart_y = y + 30

    if data_series.empty:
        draw.text((x, chart_y + 20), "No data available", font=label_font, fill=PALETTE["text_muted"])
        return

    series = data_series.head(max_items)
    max_val = series.max()
    if max_val <= 0:
        max_val = 1

    bar_max_w = w - 190
    bar_h = 18
    gap = 14

    for label, val in series.items():
        # Label (truncated if needed)
        lbl_str = str(label)
        if len(lbl_str) > 22:
            lbl_str = lbl_str[:20] + ".."
        draw.text((x, chart_y + 1), lbl_str, font=label_font, fill=PALETTE["text_dark"])

        # Bar background track
        bar_x = x + 130
        draw.rounded_rectangle((bar_x, chart_y, bar_x + bar_max_w, chart_y + bar_h),
                               radius=4, fill="#f1f5f9")

        # Colored value bar
        bar_len = int((val / max_val) * bar_max_w)
        if bar_len > 0:
            color = color_map.get(str(label), color_map.get(str(label).upper(), PALETTE["color_info"]))
            draw.rounded_rectangle((bar_x, chart_y, bar_x + max(bar_len, 6), chart_y + bar_h),
                                   radius=4, fill=color)

        # Count text
        draw.text((bar_x + bar_max_w + 10, chart_y + 2), str(val), font=count_font, fill=PALETTE["text_dark"])
        chart_y += bar_h + gap


# ============================================================================
# 1. Registry Change Events Visual Report
# ============================================================================

def generate_events_visual_report(events: list[dict], baseline_metadata: dict | None,
                                  output_path: str) -> str:
    """Generate a high-resolution graphical PNG report of registry change events.
    
    Args:
        events: List of detected registry change event dicts
        baseline_metadata: Optional baseline metadata dictionary
        output_path: File path where the PNG will be saved
        
    Returns:
        Absolute path to the created PNG image file.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    width = 1350
    height = 960

    # Create high-res canvas
    img = Image.new("RGB", (width, height), PALETTE["bg_main"])
    draw = ImageDraw.Draw(img)

    # 1. Header
    now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sub = f"Live Audit Inspection Snapshot | Generated at {now_ts} | Host OS: Windows"
    _draw_header(draw, width, "Windows Registry Change Monitoring System", sub, badge_text="EVENT AUDIT REPORT")

    # 2. Convert events to Pandas DataFrame for aggregation
    if events:
        df = pd.DataFrame(events)
    else:
        df = pd.DataFrame(columns=["severity", "change_type", "category", "hive", "full_path", "value_name", "reason"])

    total_events = len(df)
    sev_counts = df["severity"].value_counts() if "severity" in df else pd.Series(dtype=int)
    type_counts = df["change_type"].value_counts() if "change_type" in df else pd.Series(dtype=int)
    cat_counts = df["category"].value_counts() if "category" in df else pd.Series(dtype=int)

    count_suspicious = int(sev_counts.get("suspicious", 0))
    count_investigation = int(sev_counts.get("investigation_required", 0))
    count_info = int(sev_counts.get("informational", 0))

    # 3. Top Metric Cards
    metrics = [
        ("Total Changes Detected", str(total_events), PALETTE["color_info"]),
        ("Investigation Required", str(count_investigation),
         PALETTE["color_critical"] if count_investigation > 0 else PALETTE["color_neutral"]),
        ("Suspicious Events", str(count_suspicious),
         PALETTE["color_suspicious"] if count_suspicious > 0 else PALETTE["color_neutral"]),
        ("Informational Events", str(count_info), PALETTE["color_benign"]),
    ]
    _draw_metric_cards(draw, 30, 115, width - 60, metrics)

    # 4. Middle Section - Cards Container (Height ~ 320)
    card1_w = 480
    card1_h = 320
    c1_x, c1_y = 30, 210

    # Card 1: Severity Donut Chart
    _draw_rounded_rectangle(draw, (c1_x, c1_y, c1_x + card1_w, c1_y + card1_h),
                           fill=PALETTE["card_bg"], outline=PALETTE["card_border"], radius=8)
    _draw_donut_chart(draw, (c1_x + 130, c1_y + 165), outer_r=90, inner_r=50,
                      data_series=sev_counts, color_map=SEVERITY_COLORS,
                      title="Changes by Severity Level", total_label="Events")

    # Card 2: Change Type Bar Chart
    c2_x = c1_x + card1_w + 20
    card2_w = width - c2_x - 30
    _draw_rounded_rectangle(draw, (c2_x, c1_y, c2_x + card2_w, c1_y + card1_h),
                           fill=PALETTE["card_bg"], outline=PALETTE["card_border"], radius=8)
    _draw_horizontal_bar_chart(draw, c2_x + 25, c1_y + 25, card2_w - 50, card1_h - 50,
                               data_series=type_counts, color_map=CHANGE_TYPE_COLORS,
                               title="Breakdown by Registry Change Type", max_items=6)

    # 5. Lower Section - Categories & Recent Notable Events Table
    c3_w = 480
    c3_h = 360
    c3_x, c3_y = 30, 550

    # Card 3: Monitored Categories Bar Chart
    _draw_rounded_rectangle(draw, (c3_x, c3_y, c3_x + c3_w, c3_y + c3_h),
                           fill=PALETTE["card_bg"], outline=PALETTE["card_border"], radius=8)
    _draw_horizontal_bar_chart(draw, c3_x + 25, c3_y + 25, c3_w - 50, c3_h - 50,
                               data_series=cat_counts, color_map={},
                               title="Changes by Security Category", max_items=7)

    # Card 4: Notable Events Table
    c4_x = c3_x + c3_w + 20
    c4_w = width - c4_x - 30
    _draw_rounded_rectangle(draw, (c4_x, c3_y, c4_x + c4_w, c3_y + c3_h),
                           fill=PALETTE["card_bg"], outline=PALETTE["card_border"], radius=8)

    tbl_title_font = _get_font(14, bold=True)
    tbl_hdr_font = _get_font(11, bold=True)
    tbl_row_font = _get_font(10, bold=False)

    draw.text((c4_x + 25, c3_y + 25), "Recent Security & Notable Events", font=tbl_title_font, fill=PALETTE["text_dark"])

    # Table Header
    ty = c3_y + 65
    draw.rectangle((c4_x + 20, ty, c4_x + c4_w - 20, ty + 26), fill="#f8fafc")
    draw.text((c4_x + 28, ty + 6), "Severity", font=tbl_hdr_font, fill=PALETTE["text_muted"])
    draw.text((c4_x + 130, ty + 6), "Type", font=tbl_hdr_font, fill=PALETTE["text_muted"])
    draw.text((c4_x + 215, ty + 6), "Value Name / Path", font=tbl_hdr_font, fill=PALETTE["text_muted"])
    draw.text((c4_x + 510, ty + 6), "Finding / Reason", font=tbl_hdr_font, fill=PALETTE["text_muted"])

    ty += 32
    # Select notable rows (or recent rows if none notable)
    notable_df = df[df["severity"].isin(["investigation_required", "suspicious"])] if not df.empty else df
    if notable_df.empty and not df.empty:
        notable_df = df

    if notable_df.empty:
        draw.text((c4_x + 30, ty + 20), "No change events recorded yet.", font=tbl_row_font, fill=PALETTE["text_muted"])
    else:
        for idx, row in notable_df.head(6).iterrows():
            sev = str(row.get("severity", "informational"))
            sev_color = SEVERITY_COLORS.get(sev.lower(), PALETTE["color_neutral"])
            badge_text = sev.replace("_", " ").title()[:12]

            # Badge pill
            _draw_rounded_rectangle(draw, (c4_x + 25, ty - 2, c4_x + 115, ty + 16),
                                   fill=sev_color, outline=None, radius=3)
            draw.text((c4_x + 30, ty), badge_text, font=_get_font(9, bold=True), fill="#ffffff")

            # Change Type
            ct = str(row.get("change_type", "UNKNOWN"))
            draw.text((c4_x + 130, ty), ct, font=tbl_row_font, fill=PALETTE["text_dark"])

            # Value name / path
            vname = str(row.get("value_name", "")) or "(Default)"
            path_part = str(row.get("full_path", "")).split("\\")[-1]
            disp_path = f"{vname} ({path_part})"
            if len(disp_path) > 38:
                disp_path = disp_path[:35] + "..."
            draw.text((c4_x + 215, ty), disp_path, font=tbl_row_font, fill=PALETTE["text_dark"])

            # Reason
            reason = str(row.get("reason", ""))
            if len(reason) > 38:
                reason = reason[:35] + "..."
            draw.text((c4_x + 510, ty), reason, font=tbl_row_font, fill=PALETTE["text_muted"])

            # Separator line
            draw.line((c4_x + 20, ty + 22, c4_x + c4_w - 20, ty + 22), fill=PALETTE["border_light"], width=1)
            ty += 28

    # 6. Footer
    base_info = "Baseline: Active Snapshot" if baseline_metadata else "Baseline: None"
    _draw_footer(draw, width, height, f"{base_info} | Audited Paths: Run, RunOnce, Defender, Firewall, UAC, LSA")

    # Save image
    img.save(output_path, "PNG", optimize=True)
    logger.info("Events visual report saved: %s (%dx%d)", output_path, width, height)
    return output_path


# ============================================================================
# 2. Advanced System Monitoring File Analysis Visual Report
# ============================================================================

def generate_advanced_file_visual_report(report_data: dict, output_path: str) -> str:
    """Generate a high-resolution graphical PNG report of the Advanced File Forensic Analysis.
    
    Args:
        report_data: Dictionary returned by analyze_all_monitored_files
        output_path: File path where the PNG will be saved
        
    Returns:
        Absolute path to the created PNG image file.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    width = 1380
    height = 980

    img = Image.new("RGB", (width, height), PALETTE["bg_main"])
    draw = ImageDraw.Draw(img)

    # 1. Header
    now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sub = f"Forensic Binary, Path Hijacking & Persistence Inspection | {now_ts} | Windows Registry Monitor"
    _draw_header(draw, width, "🛡️ Advanced System Monitoring & File Analysis", sub, badge_text="FORENSIC TRIAGE")

    files = report_data.get("files", [])
    summary = report_data.get("summary", {})

    if files:
        df = pd.DataFrame(files)
    else:
        df = pd.DataFrame(columns=["risk_level", "file_name", "exists", "file_type", "category", "finding", "sha256"])

    # Metrics
    tot_analyzed = summary.get("total_files_analyzed", len(df))
    existing_cnt = summary.get("existing_files", int((df["exists"] == True).sum()) if "exists" in df else 0)
    missing_cnt = summary.get("missing_files", int((df["exists"] == False).sum()) if "exists" in df else 0)
    warning_cnt = summary.get("suspicious_or_warning_files", 0)
    hashes_cnt = summary.get("hashes_computed", 0)

    # 2. Top Metric Cards (5 cards)
    metrics = [
        ("Files Referenced", str(tot_analyzed), PALETTE["color_info"]),
        ("Existing on Disk", str(existing_cnt), PALETTE["color_benign"]),
        ("Missing / Orphaned", str(missing_cnt), PALETTE["color_critical"] if missing_cnt > 0 else PALETTE["color_neutral"]),
        ("Security Warnings", str(warning_cnt), PALETTE["color_suspicious"] if warning_cnt > 0 else PALETTE["color_benign"]),
        ("SHA-256 Hashes", str(hashes_cnt), PALETTE["color_purple"]),
    ]
    _draw_metric_cards(draw, 30, 115, width - 60, metrics)

    # Aggregations using pandas
    risk_counts = df["risk_level"].value_counts() if "risk_level" in df else pd.Series(dtype=int)
    type_counts = df["file_type"].value_counts() if "file_type" in df else pd.Series(dtype=int)
    cat_counts = df["category"].value_counts() if "category" in df else pd.Series(dtype=int)

    # 3. Middle Section
    c1_w = 450
    c1_h = 320
    c1_x, c1_y = 30, 210

    # Card 1: Risk Level Donut Chart
    _draw_rounded_rectangle(draw, (c1_x, c1_y, c1_x + c1_w, c1_y + c1_h),
                           fill=PALETTE["card_bg"], outline=PALETTE["card_border"], radius=8)
    _draw_donut_chart(draw, (c1_x + 125, c1_y + 165), outer_r=90, inner_r=50,
                      data_series=risk_counts, color_map=RISK_LEVEL_COLORS,
                      title="File Security Risk Ratings", total_label="Binaries")

    # Card 2: File Types & Formats
    c2_w = 420
    c2_x = c1_x + c1_w + 20
    _draw_rounded_rectangle(draw, (c2_x, c1_y, c2_x + c2_w, c1_y + c1_h),
                           fill=PALETTE["card_bg"], outline=PALETTE["card_border"], radius=8)
    _draw_horizontal_bar_chart(draw, c2_x + 25, c1_y + 25, c2_w - 50, c1_h - 50,
                               data_series=type_counts, color_map={},
                               title="Referenced File Types", max_items=6)

    # Card 3: Registry Category Distribution
    c3_x = c2_x + c2_w + 20
    c3_w = width - c3_x - 30
    _draw_rounded_rectangle(draw, (c3_x, c1_y, c3_x + c3_w, c1_y + c1_h),
                           fill=PALETTE["card_bg"], outline=PALETTE["card_border"], radius=8)
    _draw_horizontal_bar_chart(draw, c3_x + 25, c1_y + 25, c3_w - 50, c1_h - 50,
                               data_series=cat_counts, color_map={},
                               title="Binaries by Registry Location", max_items=6)

    # 4. Lower Section - Forensic Risk Table
    t_x, t_y = 30, 550
    t_w = width - 60
    t_h = 370

    _draw_rounded_rectangle(draw, (t_x, t_y, t_x + t_w, t_y + t_h),
                           fill=PALETTE["card_bg"], outline=PALETTE["card_border"], radius=8)

    tbl_title_font = _get_font(14, bold=True)
    tbl_hdr_font = _get_font(11, bold=True)
    tbl_row_font = _get_font(10, bold=False)

    draw.text((t_x + 25, t_y + 20), "Forensic Findings & Binary Triage List", font=tbl_title_font, fill=PALETTE["text_dark"])

    # Table Header Row
    ty = t_y + 55
    draw.rectangle((t_x + 20, ty, t_x + t_w - 20, ty + 26), fill="#f8fafc")
    draw.text((t_x + 30, ty + 6), "Risk Level", font=tbl_hdr_font, fill=PALETTE["text_muted"])
    draw.text((t_x + 130, ty + 6), "File Name", font=tbl_hdr_font, fill=PALETTE["text_muted"])
    draw.text((t_x + 320, ty + 6), "Exists", font=tbl_hdr_font, fill=PALETTE["text_muted"])
    draw.text((t_x + 400, ty + 6), "Category", font=tbl_hdr_font, fill=PALETTE["text_muted"])
    draw.text((t_x + 590, ty + 6), "Security Finding / Path Anomaly", font=tbl_hdr_font, fill=PALETTE["text_muted"])
    draw.text((t_x + 990, ty + 6), "SHA-256 Digest (Prefix)", font=tbl_hdr_font, fill=PALETTE["text_muted"])

    ty += 32
    # Prioritize warnings and suspicious files in the visual table
    priority_df = df.sort_values(
        by="risk_level",
        key=lambda col: col.map({"SUSPICIOUS": 0, "WARNING": 1, "INFO": 2, "BENIGN": 3}).fillna(4)
    )

    if priority_df.empty:
        draw.text((t_x + 30, ty + 20), "No referenced files detected in configured registry keys.", font=tbl_row_font, fill=PALETTE["text_muted"])
    else:
        for idx, row in priority_df.head(7).iterrows():
            risk = str(row.get("risk_level", "INFO")).upper()
            risk_color = RISK_LEVEL_COLORS.get(risk, PALETTE["color_neutral"])

            # Risk Pill
            _draw_rounded_rectangle(draw, (t_x + 25, ty - 2, t_x + 115, ty + 16),
                                   fill=risk_color, outline=None, radius=3)
            draw.text((t_x + 32, ty), risk, font=_get_font(9, bold=True), fill="#ffffff")

            # File name
            fname = str(row.get("file_name", "")) or "Unknown"
            if len(fname) > 24:
                fname = fname[:22] + ".."
            draw.text((t_x + 130, ty), fname, font=tbl_row_font, fill=PALETTE["text_dark"])

            # Exists
            exists_str = "YES" if row.get("exists") else "MISSING"
            exists_color = PALETTE["color_benign"] if row.get("exists") else PALETTE["color_critical"]
            draw.text((t_x + 320, ty), exists_str, font=_get_font(10, bold=True), fill=exists_color)

            # Category
            cat_str = str(row.get("category", ""))
            if len(cat_str) > 23:
                cat_str = cat_str[:21] + ".."
            draw.text((t_x + 400, ty), cat_str, font=tbl_row_font, fill=PALETTE["text_muted"])

            # Finding
            finding = str(row.get("finding", ""))
            if len(finding) > 52:
                finding = finding[:49] + "..."
            draw.text((t_x + 590, ty), finding, font=tbl_row_font, fill=PALETTE["text_dark"])

            # SHA-256
            h_str = str(row.get("sha256", ""))
            if h_str and h_str != "None":
                h_display = h_str[:28] + "..."
            else:
                h_display = "N/A"
            draw.text((t_x + 990, ty), h_display, font=tbl_row_font, fill=PALETTE["text_muted"])

            draw.line((t_x + 20, ty + 22, t_x + t_w - 20, ty + 22), fill=PALETTE["border_light"], width=1)
            ty += 28

    # 5. Footer
    _draw_footer(draw, width, height, "Defensive Registry Security Audit | Binary & Script Integrity Verification")

    img.save(output_path, "PNG", optimize=True)
    logger.info("Advanced file visual report saved: %s (%dx%d)", output_path, width, height)
    return output_path
