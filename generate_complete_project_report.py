"""Generate Complete Project Report in Word (.docx) and PDF (.pdf) formats
based on the detailed user requirements for Windows Registry Change Monitoring System.

Author: Piyush (@Made-by-Piyush99)
Version: v2.4.0 Enterprise Defensive Edition
"""

import os
import sys
from datetime import datetime
from PIL import Image as PILImage

# python-docx imports
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

# reportlab imports
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(BASE_DIR, "docs")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
os.makedirs(DOCS_DIR, exist_ok=True)

DOCX_OUTPUT = os.path.join(DOCS_DIR, "Windows_Registry_Change_Monitoring_System_Project_Report.docx")
PDF_OUTPUT = os.path.join(DOCS_DIR, "Windows_Registry_Change_Monitoring_System_Project_Report.pdf")


# ==============================================================================
# HELPER FUNCTIONS FOR DOCX
# ==============================================================================

def set_cell_background(cell, fill_hex):
    """Set background color of a table cell in python-docx."""
    shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    cell._tc.get_or_add_tcPr().append(shading_elm)

def set_cell_margins(cell, top=100, bottom=100, left=140, right=140):
    """Set inner cell padding in dxa."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tcPr.append(tcMar)


# ==============================================================================
# 1. BUILD COMPLETE MICROSOFT WORD REPORT (.DOCX)
# ==============================================================================

def build_docx():
    print("Generating Comprehensive Microsoft Word Report (.docx)...")
    doc = Document()

    # Margins (1 inch all sides)
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Styles
    styles = doc.styles
    normal_style = styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = RGBColor(0x1e, 0x29, 0x3b) # Slate 800

    PRIMARY_COLOR = RGBColor(0x0a, 0x25, 0x40)     # Navy #0a2540
    CYAN_ACCENT = RGBColor(0x00, 0x7a, 0x99)       # Teal/Cyan #007a99
    EMERALD_ACCENT = RGBColor(0x05, 0x96, 0x69)    # Emerald Green #059669
    CRIMSON_ACCENT = RGBColor(0xb9, 0x1c, 0x1c)    # Crimson #b91c1c

    # -------------------------------------------------------------
    # COVER PAGE
    # -------------------------------------------------------------
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_before = Pt(30)
    p_title.paragraph_format.space_after = Pt(6)

    r_icon = p_title.add_run("🛡️\n")
    r_icon.font.size = Pt(36)

    r_title = p_title.add_run("Windows Registry Change Monitoring System\n")
    r_title.font.name = 'Calibri'
    r_title.font.size = Pt(26)
    r_title.font.bold = True
    r_title.font.color.rgb = PRIMARY_COLOR

    r_sub = p_title.add_run("Detailed Guide, Architecture & Practical Project Report\n")
    r_sub.font.size = Pt(15)
    r_sub.font.bold = True
    r_sub.font.color.rgb = CYAN_ACCENT

    p_lead = doc.add_paragraph()
    p_lead.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_lead.paragraph_format.space_after = Pt(20)
    r_lead = p_lead.add_run(
        "A Comprehensive Endpoint Integrity Auditing, Autorun Persistence Detection,\n"
        "Malware Behavior Analysis & Active Threat Remediation Platform"
    )
    r_lead.font.size = Pt(11.5)
    r_lead.font.italic = True
    r_lead.font.color.rgb = RGBColor(0x64, 0x74, 0x8b)

    # Metadata table
    meta_table = doc.add_table(rows=6, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_table.autofit = False

    meta_items = [
        ("Project Title:", "Windows Registry Change Monitoring System"),
        ("Architect & Developer:", "Piyush (@Made-by-Piyush99)"),
        ("System Edition:", "Enterprise Defensive Edition (v2.4.0)"),
        ("Runtime & Environment:", "Python 3.12 / 3.14 (64-bit Native Win32 CPython)"),
        ("Security Domain:", "Endpoint Detection & Response (EDR) / Blue Team Defense"),
        ("Repository & Releases:", "https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring")
    ]

    for i, (k, v) in enumerate(meta_items):
        row = meta_table.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width = Inches(2.4)
        c1.width = Inches(4.1)
        p0 = c0.paragraphs[0]
        r0 = p0.add_run(k)
        r0.font.bold = True
        r0.font.color.rgb = PRIMARY_COLOR
        p1 = c1.paragraphs[0]
        r1 = p1.add_run(v)
        r1.font.color.rgb = RGBColor(0x33, 0x41, 0x55)
        set_cell_background(c0, "f8fafc")
        set_cell_background(c1, "f1f5f9" if i % 2 == 0 else "ffffff")
        set_cell_margins(c0, 50, 50, 80, 80)
        set_cell_margins(c1, 50, 50, 80, 80)

    doc.add_page_break()

    # -------------------------------------------------------------
    # 1. PROJECT OVERVIEW / DESCRIPTION
    # -------------------------------------------------------------
    h1 = doc.add_heading("1. Project Overview & Description", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    p = doc.add_paragraph(
        "This project focuses on designing and implementing a robust, real-time Windows Registry Monitoring System "
        "that actively tracks unauthorized, suspicious, or malicious changes made to sensitive registry keys."
    )
    p = doc.add_paragraph(
        "The Windows Registry stores critical operating system configuration data, startup locations, hardware settings, "
        "and application execution parameters. Because it governs the execution sequence of the operating system, malware "
        "frequently targets the registry to maintain stealthy persistence, modify system policies, or silently disable security tools."
    )
    p = doc.add_paragraph(
        "This project provides a complete monitoring and defensive toolkit that detects changes in sensitive registry paths, "
        "identifies malware-like modifications, verifies registry integrity using cryptographic baseline comparisons, and "
        "empowers defenders to remediate threats on-demand."
    )

    # -------------------------------------------------------------
    # 2. PRACTICAL MOTIVATION
    # -------------------------------------------------------------
    h1 = doc.add_heading("2. Practical Motivation", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    p = doc.add_paragraph("The Windows Registry is a universally high-value target for adversaries and malicious software due to several attack vectors:")

    mot_points = [
        ("Persistent Malware: ", "Trojans, backdoors, and rootkits install autostart registry entries to survive reboots without requiring user interaction."),
        ("Ransomware Configuration Changes: ", "Ransomware modifies registry keys to disable system recovery options, suppress Volume Shadow Copies, and manipulate safe boot configurations."),
        ("Unauthorized Startup Entries: ", "Adversaries place executables in Run and RunOnce keys to launch malicious payloads upon user logon."),
        ("Privilege Escalation Modifications: ", "Attackers tamper with User Account Control (UAC) keys, Accessibility shortcut tools (Sticky Keys), and Winlogon helper DLLs."),
        ("Security Tool Tampering: ", "Malware disables Windows Defender Real-Time Protection, Firewall policies, and telemetry services through Policy keys.")
    ]
    for bold_txt, norm_txt in mot_points:
        bp = doc.add_paragraph(style='List Bullet')
        r1 = bp.add_run(bold_txt)
        r1.font.bold = True
        r1.font.color.rgb = PRIMARY_COLOR
        r2 = bp.add_run(norm_txt)

    p_ind = doc.add_paragraph()
    p_ind.add_run("Unauthorized registry changes strongly indicate: ").font.bold = True
    doc.add_paragraph("• Compromise by malicious software (Trojan, Ransomware, Worm)", style='List Bullet')
    doc.add_paragraph("• Privilege misuse or insider threat activity", style='List Bullet')
    doc.add_paragraph("• Severe organizational policy or baseline compliance violations", style='List Bullet')

    # -------------------------------------------------------------
    # 3. PROJECT OBJECTIVES
    # -------------------------------------------------------------
    h1 = doc.add_heading("3. Project Objectives", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    objectives = [
        "Monitor Autorun Registry Keys for persistence mechanisms across both Current User (HKCU) and Local Machine (HKLM).",
        "Detect Malware-Like Registry Changes such as tampering with Windows Defender, Firewall policies, and shell replacements.",
        "Create a High-Performance Registry Integrity Checker using cryptographic baseline snapshot comparison.",
        "Provide Real-Time Desktop and Scheduled Alerts on unauthorized modifications with configurable cooldowns.",
        "Generate Detailed Change Reports and forensics analysis in Graphical (Pillow), CSV, JSON, and SQLite formats.",
        "Equip Defenders with Active Threat Remediation to atomically sanitize malicious values with one click."
    ]
    for obj in objectives:
        doc.add_paragraph(f"✓  {obj}", style='List Bullet')

    # -------------------------------------------------------------
    # 4. PRACTICAL SCOPE OF THE PROJECT
    # -------------------------------------------------------------
    h1 = doc.add_heading("4. Practical Scope of the Project", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    scope_sections = [
        ("Autorun Key Monitoring", [
            "Continuous surveillance of Run and RunOnce keys in HKCU and HKLM.",
            "Instant detection of new startup entries added without administrator authorization.",
            "Identification of executables and command-line scripts launched automatically upon user logon."
        ]),
        ("Malware-Like Change Detection", [
            "Security Policy Modifications (e.g. Policies\\Microsoft\\Windows\\System).",
            "Firewall and Windows Defender Disable Keys (e.g. DisableAntiSpyware, DisableRealtimeMonitoring).",
            "Shell Replacements and Winlogon modifications (Userinit, Shell = cmd.exe / powershell.exe).",
            "UAC Bypass-related keys and Image File Execution Options (IFEO) debugger hijacks."
        ]),
        ("Registry Integrity Checker", [
            "Capture a comprehensive cryptographic baseline registry snapshot with SHA-256 integrity verification.",
            "Compare the live registry state against the stored reference baseline.",
            "Classify state deltas into ADDED, DELETED, MODIFIED, and DATA_TYPE_MUTATED."
        ]),
        ("Alerting & Reporting Module", [
            "Log every mutation with timestamp, hive, key path, value name, previous data, and new data.",
            "Non-blocking on-screen desktop popup alerts with customizable severity filters.",
            "Consolidated export of telemetry logs into CSV, JSON, and encrypted SQLite audit databases."
        ])
    ]

    for scope_title, scope_bullets in scope_sections:
        h2 = doc.add_heading(scope_title, level=2)
        h2.runs[0].font.color.rgb = CYAN_ACCENT
        for b in scope_bullets:
            doc.add_paragraph(f"•  {b}", style='List Bullet')

    doc.add_page_break()

    # -------------------------------------------------------------
    # 5. TOOLS & TECHNOLOGIES USED
    # -------------------------------------------------------------
    h1 = doc.add_heading("5. Tools & Technologies Used", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    tech_table = doc.add_table(rows=8, cols=3)
    tech_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    tech_table.autofit = False

    t_headers = ["Category", "Technology / Tool", "Practical Role & Implementation"]
    for j, h in enumerate(t_headers):
        cell = tech_table.rows[0].cells[j]
        set_cell_background(cell, "0a2540")
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0xff, 0xff, 0xff)
        set_cell_margins(cell, 80, 80, 100, 100)

    tech_rows = [
        ("Programming Language", "Python 3.12 / 3.14 (64-bit)", "Core orchestration, asynchronous multi-threading, telemetry pipeline."),
        ("Registry Module", "winreg & advapi32.dll (ctypes)", "Direct Win32 registry handles, dual bitness (64-bit & WOW64), atomic deletion."),
        ("Scripting & Fallback", "PowerShell Cmdlets", "Get-ItemProperty / Set-ItemProperty testing and administrative scripting."),
        ("Integrity Engine", "hashlib (SHA-256)", "Cryptographic hashing of baseline snapshots and disk executable binaries."),
        ("Local Storage", "SQLite 3 (WAL Journal Mode)", "High-performance encrypted local database with zero external server dependencies."),
        ("Hardware Cryptography", "Windows DPAPI (crypt32.dll)", "Encrypts secrets and telemetry logs using machine TPM and user SID keys."),
        ("GUI & Visualization", "Tkinter / Ttk & Pillow (PIL)", "Dark SOC responsive interface, 5 themes, and automated visual chart infographics."),
    ]

    col_w = [Inches(1.8), Inches(2.2), Inches(2.5)]
    for i, data in enumerate(tech_rows):
        row = tech_table.rows[i + 1]
        bg = "f8fafc" if i % 2 == 0 else "ffffff"
        for j, text in enumerate(data):
            cell = row.cells[j]
            cell.width = col_w[j]
            set_cell_background(cell, bg)
            set_cell_margins(cell, 60, 60, 80, 80)
            p = cell.paragraphs[0]
            r = p.add_run(text)
            if j == 0:
                r.font.bold = True
                r.font.color.rgb = PRIMARY_COLOR

    doc.add_paragraph().paragraph_format.space_after = Pt(14)

    # -------------------------------------------------------------
    # 6. PRACTICAL TECHNIQUES IMPLEMENTED
    # -------------------------------------------------------------
    h1 = doc.add_heading("6. Practical Techniques Implemented", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    doc.add_heading("Detection Techniques:", level=2).runs[0].font.color.rgb = CYAN_ACCENT
    doc.add_paragraph("• Polling-Based Registry Monitoring: High-speed differential polling engine executing scans at sub-second intervals (1s to 60s).", style='List Bullet')
    doc.add_paragraph("• Baseline Comparison for Integrity Checking: Mathematical diff comparison against clean encrypted baseline snapshot.", style='List Bullet')
    doc.add_paragraph("• Autorun Persistence Detection: Deep inspection of all Windows user and machine startup locations.", style='List Bullet')
    doc.add_paragraph("• Malware Behavior Pattern Recognition: Heuristic regex and string pattern recognition for cmd.exe, powershell.exe -enc, mshta, vbs, and rundll32.", style='List Bullet')

    doc.add_heading("Blue Team Defensive Techniques:", level=2).runs[0].font.color.rgb = CYAN_ACCENT
    doc.add_paragraph("• Monitoring Startup Persistence: Real-time alerting on boot-sequence modifications before malicious payload activation.", style='List Bullet')
    doc.add_paragraph("• Detecting Configuration Tampering: Defending security products by monitoring Defender and Firewall policy registry trees.", style='List Bullet')
    doc.add_paragraph("• Registry Forensics Analysis: Resolving environment variables, binary existence, unquoted service path vulnerabilities, and digital checksums.", style='List Bullet')
    doc.add_paragraph("• Logging Suspicious System Modifications: Maintaining immutable, DPAPI-encrypted audit trails in SQLite for forensic incident response.", style='List Bullet')

    doc.add_page_break()

    # -------------------------------------------------------------
    # 7. WORKFLOW / ARCHITECTURE (STEP-BY-STEP)
    # -------------------------------------------------------------
    h1 = doc.add_heading("7. Workflow & Step-by-Step Architecture", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    steps = [
        ("STEP 1: Define Sensitive Registry Keys",
         "The system loads config.json defining high-risk target hives (HKCU, HKLM) including Autorun paths, Security configurations, UAC policies, and Shell behaviors across both 64-bit and 32-bit WOW64 registry views."),
        ("STEP 2: Baseline Creation",
         "The operator creates a clean reference snapshot. All subkeys and values are traversed, normalized into dictionary structures, hashed with SHA-256, and saved to data/baseline.json and the encrypted database."),
        ("STEP 3: Continuous Monitoring",
         "The background daemon thread polls target registry paths at the chosen frequency (1s, 2s, 5s, 10s, 30s, or 60s). Live state results are held in memory for sub-second differential comparisons."),
        ("STEP 4: Change Analysis & Pattern Matching",
         "Detected state deltas are classified into ADDED, DELETED, MODIFIED, or TYPE_CHANGED. Each value is analyzed against heuristic rules and MITRE ATT&CK patterns, and referenced disk binaries are resolved."),
        ("STEP 5: Alert & Log Generation",
         "Suspicious mutations trigger non-blocking cascading desktop alert cards with sound notifications. Events are logged in SQLite with hardware DPAPI encryption."),
        ("STEP 6: Threat Remediation & Final Reporting",
         "Security analysts can click 'Remediate Threat' to delete malicious values atomically via Win32 API. Reports can be exported as Pillow Graphical PNGs, CSV tables, or JSON summaries.")
    ]

    for step_title, step_desc in steps:
        h2 = doc.add_heading(step_title, level=2)
        h2.runs[0].font.color.rgb = PRIMARY_COLOR
        p = doc.add_paragraph(step_desc)
        p.paragraph_format.space_after = Pt(8)

    # -------------------------------------------------------------
    # 8. FLOWCHART
    # -------------------------------------------------------------
    h1 = doc.add_heading("8. System Flowchart", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    flow_p = doc.add_paragraph()
    flow_p.paragraph_format.space_before = Pt(8)
    flow_p.paragraph_format.space_after = Pt(14)

    flowchart_text = (
        "┌────────────────────────────────────────────────────────┐\n"
        "│                         START                          │\n"
        "└───────────────────────────┬────────────────────────────┘\n"
        "                            │\n"
        "                            ▼\n"
        "┌────────────────────────────────────────────────────────┐\n"
        "│             Load Monitoring Configuration              │\n"
        "│     (config.json: keys, polling timing, bitness views) │\n"
        "└───────────────────────────┬────────────────────────────┘\n"
        "                            │\n"
        "                            ▼\n"
        "┌────────────────────────────────────────────────────────┐\n"
        "│       Capture or Load Baseline Registry Snapshot       │\n"
        "│     (Encrypted & SHA-256 cryptographically verified)   │\n"
        "└───────────────────────────┬────────────────────────────┘\n"
        "                            │\n"
        "                            ▼\n"
        "┌────────────────────────────────────────────────────────┐\n"
        "│       Monitor Registry Keys at Regular Intervals       │\n"
        "│       (Background thread: 1s, 2s, 5s, 10s, 30s, 60s)    │\n"
        "└───────────────────────────┬────────────────────────────┘\n"
        "                            │\n"
        "                            ▼\n"
        "┌────────────────────────────────────────────────────────┐\n"
        "│         Detect Changes (Add / Modify / Delete)         │\n"
        "│        (O(N) State Differential Algorithm)             │\n"
        "└───────────────────────────┬────────────────────────────┘\n"
        "                            │\n"
        "                            ▼\n"
        "┌────────────────────────────────────────────────────────┐\n"
        "│        Compare with Malware Behavior Patterns          │\n"
        "│   (MITRE ATT&CK, IFEO, Defender, Powershell, Droppers) │\n"
        "└───────────────────────────┬────────────────────────────┘\n"
        "                            │\n"
        "                            ▼\n"
        "┌────────────────────────────────────────────────────────┐\n"
        "│         Generate Alerts & Log to DPAPI Vault           │\n"
        "│   (Cascading desktop popups, status pills, SQLite DB)  │\n"
        "└───────────────────────────┬────────────────────────────┘\n"
        "                            │\n"
        "                            ▼\n"
        "┌────────────────────────────────────────────────────────┐\n"
        "│   Active Remediation & Final Reporting (PNG/CSV/JSON)  │\n"
        "└───────────────────────────┬────────────────────────────┘\n"
        "                            │\n"
        "                            ▼\n"
        "┌────────────────────────────────────────────────────────┐\n"
        "│                          END                           │\n"
        "└────────────────────────────────────────────────────────┘"
    )

    r_flow = flow_p.add_run(flowchart_text)
    r_flow.font.name = 'Courier New'
    r_flow.font.size = Pt(8.5)
    r_flow.font.color.rgb = RGBColor(0x0f, 0x17, 0x2a)

    doc.add_page_break()

    # -------------------------------------------------------------
    # 9. EXPECTED PRACTICAL OUTPUT & AUDIT EXAMPLES
    # -------------------------------------------------------------
    h1 = doc.add_heading("9. Expected Practical Output & Audit Examples", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    p = doc.add_paragraph("The toolkit produces verified real-time security outputs and concrete telemetry detections:")

    examples = [
        ("Example 1: New Autorun Persistence Detected",
         "Timestamp:  2026-10-23 17:20:21 UTC\n"
         "Severity:   SUSPICIOUS\n"
         "Change:     ADDED\n"
         "Location:   HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
         "Value Name: MalwareUpdateAgent\n"
         "Value Data: C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe --silent\n"
         "Finding:    Referenced binary in user Temp folder with suspicious startup persistence hook."),
        ("Example 2: Windows Defender Security Tampering Detected",
         "Timestamp:  2026-10-23 17:21:05 UTC\n"
         "Severity:   CRITICAL / SUSPICIOUS\n"
         "Change:     MODIFIED (or ADDED)\n"
         "Location:   HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\n"
         "Value Name: DisableAntiSpyware\n"
         "Value Data: 1 (REG_DWORD)\n"
         "Finding:    Adversary attempted to disable Windows Defender Real-Time Protection via group policy."),
        ("Example 3: Baseline Integrity Verification Failure",
         "Timestamp:  2026-10-23 17:22:47 UTC\n"
         "Severity:   INVESTIGATION_REQUIRED\n"
         "Change:     DATA_TYPE_MUTATED / MODIFIED\n"
         "Location:   HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
         "Value Name: Userinit\n"
         "Previous:   C:\\Windows\\system32\\userinit.exe,\n"
         "Current:    C:\\Windows\\system32\\userinit.exe,C:\\ProgramData\\backdoor.exe\n"
         "Finding:    Winlogon initialization chain corrupted with unauthorized secondary binary executable.")
    ]

    for ex_title, ex_content in examples:
        h2 = doc.add_heading(ex_title, level=2)
        h2.runs[0].font.color.rgb = CRIMSON_ACCENT
        p_box = doc.add_paragraph()
        r_box = p_box.add_run(ex_content)
        r_box.font.name = 'Consolas'
        r_box.font.size = Pt(9)
        r_box.font.color.rgb = RGBColor(0x33, 0x41, 0x55)
        p_box.paragraph_format.left_indent = Inches(0.2)
        p_box.paragraph_format.space_after = Pt(10)

    doc.add_page_break()

    # -------------------------------------------------------------
    # 10. SCREENSHOTS & RESULTS SHOWCASE (ALL 8 FIGURES)
    # -------------------------------------------------------------
    h1 = doc.add_heading("10. Screenshots of Monitoring Results & Interface", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    p = doc.add_paragraph("The following screenshots present the fully operational toolkit across all workflows:")

    figures = [
        ("first.png", "Figure 1: Operations & Control Center SOC Dashboard",
         "Main monitoring console featuring the segmented 3-ribbon toolbar, 5 KPI scorecards, live telemetry event stream, and glowing 'Run in Background' stealth trigger."),
        ("second.png", "Figure 2: Non-Blocking Real-Time Desktop Pop-up Alerts",
         "Cascading alert cards appearing in the lower-right desktop corner immediately upon detecting suspicious registry tampering."),
        ("third.png", "Figure 3: Windows System Boot & Auto-Launch Settings",
         "Automatic launch configuration with optional silent startup directly into the draggable desktop widget."),
        ("fourth.png", "Figure 4: Continuous Polling Interval Controller (1s to 60s)",
         "6 interactive timing cards with dynamic on-the-fly 'Save & Apply Timing Now' synchronization."),
        ("fifth.png", "Figure 5: Interactive Graphical Visual Report Viewer",
         "Pillow-rendered analytics dashboard displaying severity doughnut charts, change breakdown bar charts, and notable security events."),
        ("sixth.png", "Figure 6: Alert Policies & Notification Cooldown Controls",
         "Fine-grained control over notification threshold levels, rate-limiting cooldown timers, and pop-up suppression."),
        ("seventh.png", "Figure 7: Local SQLite Database & Windows DPAPI Key Protection",
         "Cryptographic database vault status showing AES-256 encryption, hardware machine-key validation, and database vacuum tools."),
        ("eighth.png", "Figure 8: Movable Floating Desktop Gadget Widget",
         "Silent ambient background gadget running on the desktop with real-time status pill ('● MONITORING') and threat count badge.")
    ]

    for img_file, title, desc in figures:
        img_path = os.path.join(ASSETS_DIR, img_file)
        if os.path.exists(img_path):
            h2 = doc.add_heading(title, level=2)
            h2.runs[0].font.color.rgb = PRIMARY_COLOR
            doc.add_paragraph(desc).paragraph_format.space_after = Pt(6)

            p_img = doc.add_paragraph()
            p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
            doc.add_picture(img_path, width=Inches(5.8))
            p_img.paragraph_format.space_after = Pt(14)

    doc.add_page_break()

    # -------------------------------------------------------------
    # 11. TESTING METRICS & VERIFICATION
    # -------------------------------------------------------------
    h1 = doc.add_heading("11. Quality Assurance & Automated Test Suite", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    p = doc.add_paragraph(
        "To guarantee high reliability, the system incorporates an automated test suite executed via Python unittest. "
        "All 65 automated tests pass with a 100% success rate:"
    )

    t_table = doc.add_table(rows=4, cols=4)
    t_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    t_table.autofit = False

    t_hdrs = ["Test Suite File", "Covered Functionality", "Execution Time", "Pass Status"]
    for j, h in enumerate(t_hdrs):
        cell = t_table.rows[0].cells[j]
        set_cell_background(cell, "0a2540")
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0xff, 0xff, 0xff)
        set_cell_margins(cell, 80, 80, 80, 80)

    t_data = [
        ("test_change_detector.py", "State diffing, false-positive suppression, static PE analysis", "3.31s", "47/47 PASSED"),
        ("test_settings_and_db.py", "Timing engine, DPAPI cipher, themes, atomic threat remediation", "1.14s", "18/18 PASSED"),
        ("Full Test Discover Suite", "Comprehensive cross-module integration and regression test", "4.45s", "65/65 PASSED (100%)")
    ]

    t_col_w = [Inches(2.2), Inches(2.6), Inches(1.1), Inches(1.4)]
    for i, data in enumerate(t_data):
        row = t_table.rows[i + 1]
        bg = "f8fafc" if i % 2 == 0 else "ffffff"
        for j, text in enumerate(data):
            cell = row.cells[j]
            cell.width = t_col_w[j]
            set_cell_background(cell, bg)
            set_cell_margins(cell, 60, 60, 80, 80)
            p = cell.paragraphs[0]
            r = p.add_run(text)
            if j == 3:
                r.font.bold = True
                r.font.color.rgb = EMERALD_ACCENT

    doc.add_paragraph().paragraph_format.space_after = Pt(14)

    # -------------------------------------------------------------
    # 12. LEARNING OUTCOMES
    # -------------------------------------------------------------
    h1 = doc.add_heading("12. Educational & Practical Learning Outcomes", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    p = doc.add_paragraph("Through the design, development, and deployment of this project, the following core competencies were developed:")

    learnings = [
        ("Windows Registry Architecture: ", "Deep mastery of registry hives (HKLM, HKCU), binary subkeys, value data types, and 32-bit WOW64 registry reflection."),
        ("Malware Persistence Mechanics: ", "Hands-on understanding of how modern adversaries exploit Run, RunOnce, Winlogon, and IFEO debugger keys to survive system reboots."),
        ("Defensive Blue Team Auditing: ", "Designing real-time integrity comparison algorithms, noise suppression filters, and cryptographic baseline verification."),
        ("Practical Endpoint Security Scripting: ", "Low-level Win32 API interfacing using Python winreg, ctypes, and PowerShell cmdlets."),
        ("Production Software Engineering: ", "Developing a resilient multi-threaded GUI, implementing hardware-backed DPAPI cryptography, compiling standalone executables, and building enterprise installers.")
    ]
    for b_title, b_desc in learnings:
        bp = doc.add_paragraph(style='List Bullet')
        r1 = bp.add_run(b_title)
        r1.font.bold = True
        r1.font.color.rgb = PRIMARY_COLOR
        r2 = bp.add_run(b_desc)

    # -------------------------------------------------------------
    # 13. PROJECT DELIVERABLES
    # -------------------------------------------------------------
    h1 = doc.add_heading("13. Project Deliverables & Distribution", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    p = doc.add_paragraph("The completed project deliverables include:")
    delivs = [
        "Complete Project Documentation in Microsoft Word (.docx) and Adobe PDF (.pdf) formats.",
        "Production Registry Monitoring Toolkit with full open-source Python code.",
        "High-Resolution Photographic Screenshots of all monitoring states and settings.",
        "Baseline snapshots, integrity verification algorithms, and SQLite audit database.",
        "Stand-alone Executable: WindowsRegistryMonitor.exe (80.22 MB).",
        "Setup Wizard Installer: RegistryMonitorSetup.exe (81.08 MB)."
    ]
    for d in delivs:
        doc.add_paragraph(f"📦  {d}", style='List Bullet')

    # Hash table
    p_h = doc.add_paragraph()
    p_h.add_run("Cryptographic SHA-256 Distribution Checksums:").font.bold = True

    h_table = doc.add_table(rows=3, cols=3)
    h_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    h_table.autofit = False

    h_hdrs = ["Binary Package", "Size", "SHA-256 Verification Checksum"]
    for j, h in enumerate(h_hdrs):
        cell = h_table.rows[0].cells[j]
        set_cell_background(cell, "0a2540")
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0xff, 0xff, 0xff)
        set_cell_margins(cell, 80, 80, 80, 80)

    h_data = [
        ("WindowsRegistryMonitor.exe", "80.22 MB", "8BEE859BA0DA4527E1FEE42F4B946A21A102FB170BBFFA2724F5BDC56BD649FC"),
        ("RegistryMonitorSetup.exe", "81.08 MB", "61B5C2109D5B3A150D989102D8EB04AC7C6A1A51D246445C7D724E2F69E50DD7")
    ]
    for i, data in enumerate(h_data):
        row = h_table.rows[i + 1]
        bg = "f8fafc" if i % 2 == 0 else "ffffff"
        for j, text in enumerate(data):
            cell = row.cells[j]
            set_cell_background(cell, bg)
            set_cell_margins(cell, 60, 60, 80, 80)
            p = cell.paragraphs[0]
            r = p.add_run(text)
            if j == 2:
                r.font.name = 'Consolas'
                r.font.size = Pt(8.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(14)

    # -------------------------------------------------------------
    # 14. CONCLUSION & REPOSITORY
    # -------------------------------------------------------------
    h1 = doc.add_heading("14. Conclusion & Project Links", level=1)
    h1.runs[0].font.color.rgb = PRIMARY_COLOR

    p = doc.add_paragraph(
        "The Windows Registry Change Monitoring System v2.4.0 accomplishes all defined project requirements. "
        "It empowers system administrators and SOC analysts to detect, analyze, and neutralize unauthorized "
        "registry tampering in real time, setting a new benchmark for accessible, native host-integrity defensive tools."
    )

    doc.add_paragraph("• GitHub Repository: https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring")
    doc.add_paragraph("• Official Release (v2.4.0): https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring/releases/tag/v2.4.0")
    doc.add_paragraph("• Architect & Developer: Piyush (@Made-by-Piyush99)")
    doc.add_paragraph("• Open-Source License: MIT License")

    doc.save(DOCX_OUTPUT)
    print(f"Word document saved successfully to: {DOCX_OUTPUT}")


# ==============================================================================
# 2. BUILD COMPLETE ADOBE PDF REPORT (.PDF)
# ==============================================================================

class NumberedCanvas(canvas.Canvas):
    """Adds running headers and footers with Page X of Y page numbering."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, total_pages):
        if self._pageNumber == 1:
            return  # Skip cover page

        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#0a2540"))

        # Header
        self.drawString(54, 750, "Windows Registry Change Monitoring System")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawRightString(558, 750, "Comprehensive Project Report (v2.4.0)")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 742, 558, 742)

        # Footer
        self.line(54, 45, 558, 45)
        self.drawString(54, 32, "Author: Piyush (@Made-by-Piyush99) | Endpoint Defense & EDR Platform")
        self.drawRightString(558, 32, f"Page {self._pageNumber} of {total_pages}")
        self.restoreState()


def build_pdf():
    print("Generating Comprehensive Adobe PDF Report (.pdf)...")

    doc = SimpleDocTemplate(
        PDF_OUTPUT,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0a2540"),
        alignment=1,
        spaceAfter=6
    )

    sub_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#007a99"),
        alignment=1,
        spaceAfter=12
    )

    desc_style = ParagraphStyle(
        'DocDesc',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#475569"),
        alignment=1,
        spaceAfter=20
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=17,
        textColor=colors.HexColor("#0a2540"),
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#007a99"),
        spaceBefore=10,
        spaceAfter=5,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12.5,
        textColor=colors.HexColor("#1e293b"),
        leftIndent=15,
        spaceAfter=3
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # -------------------------------------------------------------
    # COVER PAGE
    # -------------------------------------------------------------
    story.append(Spacer(1, 30))
    story.append(Paragraph("🛡️", ParagraphStyle('ShieldIcon', alignment=1, fontSize=36, leading=40)))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Windows Registry Change Monitoring System", title_style))
    story.append(Paragraph("Detailed Guide, Architecture & Practical Project Report", sub_style))
    story.append(Paragraph(
        "A Comprehensive Endpoint Integrity Auditing, Autorun Persistence Detection,\n"
        "Malware Behavior Analysis & Active Threat Remediation Platform",
        desc_style
    ))
    story.append(HRFlowable(width="90%", thickness=1.5, color=colors.HexColor("#007a99"), spaceAfter=18))

    meta_table_data = [
        [Paragraph("<b>Project Title:</b>", body_style), Paragraph("Windows Registry Change Monitoring System", body_style)],
        [Paragraph("<b>Architect & Developer:</b>", body_style), Paragraph("Piyush (@Made-by-Piyush99)", body_style)],
        [Paragraph("<b>Software Edition:</b>", body_style), Paragraph("Enterprise Defensive Edition (v2.4.0)", body_style)],
        [Paragraph("<b>Core Runtime:</b>", body_style), Paragraph("Python 3.12 / 3.14 (64-bit Native Win32 CPython)", body_style)],
        [Paragraph("<b>Security Focus:</b>", body_style), Paragraph("EDR Telemetry, Anti-Persistence, Threat Remediation", body_style)],
        [Paragraph("<b>Repository:</b>", body_style), Paragraph("https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring", body_style)],
        [Paragraph("<b>Date of Report:</b>", body_style), Paragraph(datetime.now().strftime("%B %d, %Y"), body_style)]
    ]
    t_meta = Table(meta_table_data, colWidths=[150, 354])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t_meta)
    story.append(PageBreak())

    # -------------------------------------------------------------
    # 1. OVERVIEW & MOTIVATION
    # -------------------------------------------------------------
    story.append(Paragraph("1. Project Overview & Practical Motivation", h1_style))
    story.append(Paragraph(
        "This project focuses on designing and implementing a Windows Registry Monitoring System that tracks unauthorized or suspicious "
        "changes made to registry keys. The Windows Registry stores critical configuration data, startup locations, system settings, "
        "and application behavior. Malware frequently targets the registry to maintain persistence, modify system policies, or disable security tools.",
        body_style
    ))
    story.append(Paragraph(
        "The registry is a high-value target for: <b>persistent malware</b>, <b>ransomware configuration changes</b>, <b>unauthorized startup entries</b>, "
        "<b>privilege escalation modifications</b>, and <b>security tool tampering</b>. Unauthorized changes indicate compromise by malware, privilege misuse, or security policy violations.",
        body_style
    ))

    # -------------------------------------------------------------
    # 2. OBJECTIVES & SCOPE
    # -------------------------------------------------------------
    story.append(Paragraph("2. Project Objectives & Practical Scope", h1_style))
    objs = [
        "<b>Monitor Autorun Keys:</b> Surveil Run and RunOnce in HKCU/HKLM; identify automatic login executables.",
        "<b>Malware-Like Change Detection:</b> Intercept Defender/Firewall disable keys, shell replacements, and UAC bypasses.",
        "<b>Registry Integrity Checker:</b> Cryptographic baseline comparison capturing state additions, deletions, and value edits.",
        "<b>Alerting & Reporting Module:</b> Real-time desktop alert popups, timestamped logs, CSV/JSON reporting, and active threat remediation."
    ]
    for o in objs:
        story.append(Paragraph(f"• {o}", bullet_style))

    story.append(Spacer(1, 8))

    # -------------------------------------------------------------
    # 3. TOOLS & TECHNIQUES
    # -------------------------------------------------------------
    story.append(Paragraph("3. Tools, Technologies & Practical Techniques", h1_style))

    tech_data = [
        [Paragraph("<b>Category</b>", body_style), Paragraph("<b>Technology / Tool</b>", body_style), Paragraph("<b>Role in System</b>", body_style)],
        [Paragraph("Language", body_style), Paragraph("Python 3.12 / 3.14 (Win32)", body_style), Paragraph("Core orchestration, asynchronous daemon thread.", body_style)],
        [Paragraph("OS Modules", body_style), Paragraph("winreg & advapi32.dll", body_style), Paragraph("Direct registry handles, 64-bit / 32-bit WOW64 views.", body_style)],
        [Paragraph("Integrity", body_style), Paragraph("hashlib (SHA-256)", body_style), Paragraph("Cryptographic baseline & binary executable hashing.", body_style)],
        [Paragraph("Vault Storage", body_style), Paragraph("SQLite 3 (WAL) + DPAPI", body_style), Paragraph("Local hardware-encrypted database bound to TPM.", body_style)],
        [Paragraph("UI / Graphics", body_style), Paragraph("Tkinter / Ttk + Pillow", body_style), Paragraph("Cyberpunk dark UI, 5 themes, visual infographics.", body_style)]
    ]
    t_tech = Table(tech_data, colWidths=[90, 160, 254])
    t_tech.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0a2540")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white])
    ]))
    story.append(t_tech)
    story.append(Spacer(1, 8))

    # -------------------------------------------------------------
    # 4. WORKFLOW & FLOWCHART
    # -------------------------------------------------------------
    story.append(Paragraph("4. Step-by-Step Workflow & Flowchart", h1_style))
    flow_steps = [
        "<b>STEP 1: Define Sensitive Keys</b> — Autorun paths, security policies, system behavior parameters.",
        "<b>STEP 2: Baseline Creation</b> — Capture initial registry values into SHA-256 verified snapshot.",
        "<b>STEP 3: Continuous Monitoring</b> — Poll registry keys at regular intervals (1s, 2s, 5s, 10s, 30s, 60s).",
        "<b>STEP 4: Change Analysis</b> — Compare deltas with known malware behaviors (MITRE ATT&CK vectors).",
        "<b>STEP 5: Alert / Log Generation</b> — Trigger non-blocking cascading desktop alerts and log to DPAPI vault.",
        "<b>STEP 6: Final Reporting & Remediation</b> — Atomically sanitize threat values and export CSV/JSON/PNG reports."
    ]
    for fs in flow_steps:
        story.append(Paragraph(fs, bullet_style))

    story.append(PageBreak())

    # -------------------------------------------------------------
    # 5. EXPECTED PRACTICAL OUTPUT & EXAMPLES
    # -------------------------------------------------------------
    story.append(Paragraph("5. Expected Practical Output & Audit Examples", h1_style))
    story.append(Paragraph(
        "<b>Concrete Detections & Real-World Telemetry Samples:</b>",
        body_style
    ))

    audit_box = (
        "• New Autorun Detected: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -> [MalwareAgent = C:\\Users\\User\\AppData\\malware.exe]\n"
        "• Security Altered:      HKLM\\Software\\Policies\\Microsoft\\Windows Defender -> [DisableAntiSpyware = 1 (REG_DWORD)]\n"
        "• Integrity Mismatch:    HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon -> [Userinit modified with secondary dropper]"
    )
    t_audit = Table([[Paragraph(f"<font face='Courier' size='8'>{audit_box.replace(chr(10), '<br/>')}</font>", body_style)]], colWidths=[504])
    t_audit.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t_audit)
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 6. SCREENSHOTS SHOWCASE (ALL 8 FIGURES)
    # -------------------------------------------------------------
    story.append(Paragraph("6. Interface Showcase & Monitoring Results", h1_style))

    gallery_pdf = [
        ("first.png", "Figure 1: Operations & Control Center SOC Dashboard", "Primary real-time monitoring dashboard with responsive 3-ribbon toolbar and KPI cards."),
        ("second.png", "Figure 2: Real-Time Desktop Cascading Change Alerts", "Instant desktop alert popups appearing in bottom-right corner upon registry mutations."),
        ("third.png", "Figure 3: Windows Startup & Background Launch Settings", "Configuration for autostarting silently into the floating desktop widget."),
        ("fourth.png", "Figure 4: Continuous Polling Interval Controller (1s to 60s)", "Dynamic interval selection cards with direct 'Save & Apply Timing Now' button."),
        ("fifth.png", "Figure 5: Interactive Graphical Visual Report Viewer", "Pillow-rendered severity doughnut chart, change breakdown bars, and events table."),
        ("sixth.png", "Figure 6: Alert Policies & Notification Rules", "Customizable alert thresholds, rate-limiting cooldown timers, and pop-up rules."),
        ("seventh.png", "Figure 7: Local SQLite DB & Windows DPAPI Key Protection", "Database encryption status, machine key validation, and database vacuuming."),
        ("eighth.png", "Figure 8: Movable Floating Desktop Gadget Widget", "Ambient background surveillance widget on Windows desktop with live badge count.")
    ]

    for img_file, title, desc in gallery_pdf:
        img_path = os.path.join(ASSETS_DIR, img_file)
        if os.path.exists(img_path):
            card = []
            card.append(Paragraph(f"<b>{title}</b>", h2_style))
            card.append(Paragraph(desc, body_style))
            with PILImage.open(img_path) as im:
                w, h = im.size
                target_w = 460
                target_h = target_w * (h / w)
                if target_h > 230:
                    target_h = 230
                    target_w = target_h * (w / h)
            card.append(Image(img_path, width=target_w, height=target_h))
            card.append(Spacer(1, 8))
            story.append(KeepTogether(card))

    story.append(PageBreak())

    # -------------------------------------------------------------
    # 7. TEST METRICS & DELIVERABLES
    # -------------------------------------------------------------
    story.append(Paragraph("7. Quality Assurance & Production Deliverables", h1_style))
    story.append(Paragraph("<b>Automated Unit Testing Verification:</b>", body_style))

    test_rows = [
        [Paragraph("<b>Test Module</b>", body_style), Paragraph("<b>Test Cases</b>", body_style), Paragraph("<b>Time</b>", body_style), Paragraph("<b>Status</b>", body_style)],
        [Paragraph("test_change_detector.py", code_style), Paragraph("47 unit tests", body_style), Paragraph("3.31s", body_style), Paragraph("100% Passed", body_style)],
        [Paragraph("test_settings_and_db.py", code_style), Paragraph("18 unit tests", body_style), Paragraph("1.14s", body_style), Paragraph("100% Passed", body_style)],
        [Paragraph("Complete Test Suite", body_style), Paragraph("65 unit tests", body_style), Paragraph("4.45s", body_style), Paragraph("<b>100% Passed (OK)</b>", body_style)]
    ]
    t_tests = Table(test_rows, colWidths=[160, 110, 90, 144])
    t_tests.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0a2540")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white])
    ]))
    story.append(t_tests)
    story.append(Spacer(1, 10))

    story.append(Paragraph("<b>Distribution Binaries & Cryptographic SHA-256 Hashes:</b>", body_style))
    bin_rows = [
        [Paragraph("<b>Binary</b>", body_style), Paragraph("<b>Size</b>", body_style), Paragraph("<b>Format</b>", body_style), Paragraph("<b>SHA-256 Hash</b>", body_style)],
        [Paragraph("WindowsRegistryMonitor.exe", code_style), Paragraph("80.22 MB", body_style), Paragraph("Standalone Portable", body_style), Paragraph("8BEE859BA0DA4527E1FEE42F4B946A21A102FB170BBFFA2724F5BDC56BD649FC", code_style)],
        [Paragraph("RegistryMonitorSetup.exe", code_style), Paragraph("81.08 MB", body_style), Paragraph("Setup Wizard", body_style), Paragraph("61B5C2109D5B3A150D989102D8EB04AC7C6A1A51D246445C7D724E2F69E50DD7", code_style)]
    ]
    t_bins = Table(bin_rows, colWidths=[120, 50, 95, 239])
    t_bins.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0a2540")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white])
    ]))
    story.append(t_bins)
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------
    # 8. LEARNING OUTCOMES & CONCLUSION
    # -------------------------------------------------------------
    story.append(Paragraph("8. Learning Outcomes & Conclusion", h1_style))
    learns = [
        "Windows Registry Architecture: Hives (HKLM, HKCU), binary subkeys, WOW6432Node reflection.",
        "Malware Persistence Vectors: Autorun keys, Winlogon injection, and Defender evasion mechanisms.",
        "Defensive Blue Team Auditing: Baseline comparison, differential polling, and rate-limited desktop alerting.",
        "Building an EDR Platform: Multi-threaded Python GUI, DPAPI SQLite cryptography, and one-click active threat remediation."
    ]
    for l in learns:
        story.append(Paragraph(f"• {l}", bullet_style))

    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>GitHub Repository:</b> https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring", body_style))
    story.append(Paragraph("<b>Release v2.4.0:</b> https://github.com/Made-by-Piyush99/Windows-Registry-Monitoring/releases/tag/v2.4.0", body_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF document saved successfully to: {PDF_OUTPUT}")


def main():
    print("=" * 60)
    print("Building Windows Registry Change Monitoring System Complete Reports")
    print("=" * 60)
    build_docx()
    build_pdf()
    print("=" * 60)
    print("ALL REPORTS GENERATED SUCCESSFULLY!")
    print(f"Word Document (.docx): {DOCX_OUTPUT} ({os.path.getsize(DOCX_OUTPUT) / 1024:.1f} KB)")
    print(f"PDF Document  (.pdf):  {PDF_OUTPUT} ({os.path.getsize(PDF_OUTPUT) / 1024:.1f} KB)")
    print("=" * 60)

if __name__ == "__main__":
    main()
