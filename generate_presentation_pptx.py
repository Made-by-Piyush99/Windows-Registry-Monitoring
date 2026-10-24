"""Generate Microsoft PowerPoint (.pptx) presentation.

Windows Registry Monitoring & Threat Remediation System (Enterprise Defensive Edition v2.4.0)
Author: Piyush (@Made-by-Piyush99)
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(BASE_DIR, "docs")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
os.makedirs(DOCS_DIR, exist_ok=True)

PPTX_OUTPUT = os.path.join(DOCS_DIR, "Windows_Registry_Monitoring_System_Presentation.pptx")

# Color Palette (Dark SOC / Cyber Theme)
BG_DARK = RGBColor(11, 15, 25)       # #0b0f19
CARD_BG = RGBColor(22, 30, 46)       # #161e2e
BORDER_COLOR = RGBColor(30, 41, 59)  # #1e293b
CYAN_ACCENT = RGBColor(0, 240, 255)  # #00f0ff
GREEN_ACCENT = RGBColor(16, 185, 129)# #10b981
AMBER_ACCENT = RGBColor(245, 158, 11)# #f59e0b
RED_ACCENT = RGBColor(239, 68, 68)   # #ef4444
PURPLE_ACCENT = RGBColor(168, 85, 247)# #a855f7
TEXT_WHITE = RGBColor(248, 250, 252) # #f8fafc
TEXT_MUTED = RGBColor(148, 163, 184) # #94a3b8

def apply_background(slide):
    """Fill slide with dark navy gradient-like background."""
    bg_shape = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(7.5)
    )
    bg_shape.fill.solid()
    bg_shape.fill.fore_color.rgb = BG_DARK
    bg_shape.line.fill.background() # No border
    return bg_shape

def add_header(slide, title_text, category_text="SECURITY OPERATIONS CENTER • ENDPOINT INTEGRITY AUDITING"):
    """Add standardized top header and accent line."""
    # Category badge
    cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.4))
    tf_cat = cat_box.text_frame
    tf_cat.word_wrap = True
    p_cat = tf_cat.paragraphs[0]
    p_cat.text = category_text.upper()
    p_cat.font.name = "Segoe UI"
    p_cat.font.size = Pt(9.5)
    p_cat.font.bold = True
    p_cat.font.color.rgb = CYAN_ACCENT

    # Title
    title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.7), Inches(0.8))
    tf_title = title_box.text_frame
    tf_title.word_wrap = True
    p_title = tf_title.paragraphs[0]
    p_title.text = title_text
    p_title.font.name = "Segoe UI"
    p_title.font.size = Pt(22)
    p_title.font.bold = True
    p_title.font.color.rgb = TEXT_WHITE

    # Horizontal glowing accent line
    line = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.5), Inches(11.733), Inches(0.04)
    )
    line.fill.solid()
    line.fill.fore_color.rgb = CYAN_ACCENT
    line.line.fill.background()

def add_card(slide, left, top, width, height, title, body_bullets, accent_color=CYAN_ACCENT):
    """Add a dark card with colored top border and bullet text."""
    # Outer card
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = CARD_BG
    card.line.color.rgb = BORDER_COLOR
    card.line.width = Pt(1)

    # Accent top stripe
    stripe = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, Inches(0.08))
    stripe.fill.solid()
    stripe.fill.fore_color.rgb = accent_color
    stripe.line.fill.background()

    # Content
    tb = slide.shapes.add_textbox(left + Inches(0.2), top + Inches(0.18), width - Inches(0.4), height - Inches(0.3))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_top = Inches(0.05)
    tf.margin_left = Inches(0.05)
    tf.margin_right = Inches(0.05)

    if title:
        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.name = "Segoe UI"
        p0.font.size = Pt(13)
        p0.font.bold = True
        p0.font.color.rgb = accent_color
        p0.space_after = Pt(6)

    for i, bullet in enumerate(body_bullets):
        p = tf.add_paragraph() if (title or i > 0) else tf.paragraphs[0]
        p.text = f"•  {bullet}"
        p.font.name = "Segoe UI"
        p.font.size = Pt(10)
        p.font.color.rgb = TEXT_WHITE
        p.space_after = Pt(4)

    return card

def build_presentation():
    print("Building 16:9 Dark SOC PowerPoint Presentation (.pptx)...")
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # =========================================================================
    # SLIDE 1: TITLE / COVER SLIDE
    # =========================================================================
    slide1 = prs.slides.add_slide(blank_layout)
    apply_background(slide1)

    # Decorative background card
    cov_card = slide1.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.5), Inches(1.2), Inches(10.333), Inches(5.1)
    )
    cov_card.fill.solid()
    cov_card.fill.fore_color.rgb = RGBColor(16, 24, 39)
    cov_card.line.color.rgb = CYAN_ACCENT
    cov_card.line.width = Pt(1.5)

    # Cover text frame
    cov_tb = slide1.shapes.add_textbox(Inches(2.0), Inches(1.6), Inches(9.333), Inches(4.3))
    tf = cov_tb.text_frame
    tf.word_wrap = True

    p0 = tf.paragraphs[0]
    p0.text = "🛡️  ENDPOINT DEFENSE & INTEGRITY AUDITING"
    p0.font.name = "Segoe UI"
    p0.font.size = Pt(12)
    p0.font.bold = True
    p0.font.color.rgb = CYAN_ACCENT
    p0.space_after = Pt(12)

    p1 = tf.add_paragraph()
    p1.text = "Windows Registry Change\nMonitoring System"
    p1.font.name = "Segoe UI"
    p1.font.size = Pt(32)
    p1.font.bold = True
    p1.font.color.rgb = TEXT_WHITE
    p1.space_after = Pt(8)

    p2 = tf.add_paragraph()
    p2.text = "Enterprise Defensive Edition (v2.4.0) — Sub-Second Auditing & Active Threat Remediation"
    p2.font.name = "Segoe UI"
    p2.font.size = Pt(14)
    p2.font.bold = True
    p2.font.color.rgb = GREEN_ACCENT
    p2.space_after = Pt(20)

    p3 = tf.add_paragraph()
    p3.text = "• Architect & Developer: Piyush (@Made-by-Piyush99)\n" \
              "• Platform: Windows 10 / 11 / Server (Dual 64-bit & WOW64 Bitness)\n" \
              "• Stack: Python 3.14 • Win32 API • DPAPI Encryption • SQLite3 WAL • Tkinter SOC UI"
    p3.font.name = "Segoe UI"
    p3.font.size = Pt(11)
    p3.font.color.rgb = TEXT_MUTED

    # =========================================================================
    # SLIDE 2: THE PROBLEM & MOTIVATION
    # =========================================================================
    slide2 = prs.slides.add_slide(blank_layout)
    apply_background(slide2)
    add_header(slide2, "The Core Problem: Malware Persistence via Registry", "THREAT LANDSCAPE & ATTACK SURFACE")

    add_card(slide2, Inches(0.8), Inches(1.8), Inches(3.6), Inches(5.0),
             "High-Value Target Vectors", [
                 "Over 90% of modern Windows malware exploits the Registry for persistence.",
                 "Allows payloads to survive reboots without requiring user interaction.",
                 "Ransomware tampers with safe-boot and backup policies.",
                 "Attackers hijack system configurations to disable antivirus real-time shields."
             ], RED_ACCENT)

    add_card(slide2, Inches(4.8), Inches(1.8), Inches(3.6), Inches(5.0),
             "MITRE ATT&CK Mappings", [
                 "T1547.001: HKCU/HKLM Run & RunOnce autostart keys.",
                 "T1547.004: Winlogon Userinit & Shell executable replacement.",
                 "T1546.012: Image File Execution Options (IFEO) debugger backdoors.",
                 "T1562.001: Tampering Defender policies to blind endpoint security."
             ], AMBER_ACCENT)

    add_card(slide2, Inches(8.8), Inches(1.8), Inches(3.7), Inches(5.0),
             "Defensive Solution", [
                 "Continuous sub-second differential scanning (1s - 60s).",
                 "Dual-bitness reflection (64-bit and 32-bit WOW6432Node).",
                 "Static PE file hashing & unquoted path checks.",
                 "Instant one-click active threat remediation."
             ], GREEN_ACCENT)

    # =========================================================================
    # SLIDE 3: SYSTEM ARCHITECTURE & PIPELINE
    # =========================================================================
    slide3 = prs.slides.add_slide(blank_layout)
    apply_background(slide3)
    add_header(slide3, "Multi-Threaded System Architecture & Data Flow", "ENGINEERING DESIGN & PIPELINE")

    add_card(slide3, Inches(0.8), Inches(1.8), Inches(2.7), Inches(5.0),
             "1. Sensitive Hives", [
                 "Define high-risk target hives in config.json.",
                 "Run, RunOnce, Winlogon, Policies, IFEO.",
                 "Dual 64-bit and WOW64 view enumeration."
             ], CYAN_ACCENT)

    add_card(slide3, Inches(3.8), Inches(1.8), Inches(2.7), Inches(5.0),
             "2. Integrity Baseline", [
                 "Snapshot capture with SHA-256 verification.",
                 "Store in JSON & encrypted SQLite vault.",
                 "Reference point for zero-false-positive diffs."
             ], GREEN_ACCENT)

    add_card(slide3, Inches(6.8), Inches(1.8), Inches(2.7), Inches(5.0),
             "3. Detection Engine", [
                 "Background daemon scans every 1s-60s.",
                 "O(N) state differential calculation.",
                 "Identifies ADDED, DELETED, and MODIFIED keys."
             ], AMBER_ACCENT)

    add_card(slide3, Inches(9.8), Inches(1.8), Inches(2.7), Inches(5.0),
             "4. Action & Forensics", [
                 "Cascading non-blocking desktop popups.",
                 "One-click atomic value deletion.",
                 "Pillow infographics and CSV/JSON reports."
             ], PURPLE_ACCENT)

    # =========================================================================
    # SLIDE 4: OPERATIONS DASHBOARD (WITH SCREENSHOT)
    # =========================================================================
    slide4 = prs.slides.add_slide(blank_layout)
    apply_background(slide4)
    add_header(slide4, "Operations & Control Center Dashboard (v2.4.0)", "PRIMARY REAL-TIME SOC INTERFACE")

    # Left: Explanation Card
    add_card(slide4, Inches(0.8), Inches(1.8), Inches(4.5), Inches(5.0),
             "Core Dashboard Capabilities", [
                 "Segmented 3-Ribbon Toolbar: Primary surveillance, threat defense actions, and live telemetry search.",
                 "Zero Clipping: Guaranteed 100% button visibility across all screen resolutions.",
                 "5 KPI Scorecards: Real-time system status, change counter, suspicious findings, and baseline health.",
                 "Glowing Stealth Trigger: 'Run in Background' button with dedicated teal styling.",
                 "Live Telemetry Grid: Color-coded rows with instant right-click context actions."
             ], CYAN_ACCENT)

    # Right: Embedded Screenshot (assets/first.png)
    img_first = os.path.join(ASSETS_DIR, "first.png")
    if os.path.exists(img_first):
        slide4.shapes.add_picture(img_first, Inches(5.6), Inches(1.8), Inches(6.9), Inches(5.0))

    # =========================================================================
    # SLIDE 5: ACTIVE THREAT REMEDIATION ENGINE
    # =========================================================================
    slide5 = prs.slides.add_slide(blank_layout)
    apply_background(slide5)
    add_header(slide5, "Active Threat Remediation Engine: Neutralizing Malware", "INCIDENT RESPONSE & PERSISTENCE SANITIZATION")

    add_card(slide5, Inches(0.8), Inches(1.8), Inches(5.6), Inches(5.0),
             "Atomic Value Deletion Engine", [
                 "One-Click Threat Remediation: Instantly delete rogue autorun entries and disabled Defender keys directly from the live event log.",
                 "Win32 advapi32.dll & winreg: Performs atomic deletion on the live Windows Registry without requiring host reboot.",
                 "Auto-Clean Threats: Automated batch detection and bulk sanitization of all active un-remediated high-risk events.",
                 "Visual Status Feedback: Neutralized rows receive an instant green [REMEDIATED] badge; live threat counter auto-decrements."
             ], RED_ACCENT)

    add_card(slide5, Inches(6.8), Inches(1.8), Inches(5.7), Inches(5.0),
             "Hardware-Encrypted Audit Trail", [
                 "Windows DPAPI Vault: SQLite database encrypted using machine TPM and user SID credentials via crypt32.dll.",
                 "Zero Plaintext Secrets: Configuration tokens and remediation audit logs are protected against offline theft.",
                 "remediations Table: Stores UTC timestamp, actor, full registry path, value name, and deleted payload data for compliance.",
                 "VACUUM & Optimization: Built-in database maintenance and integrity verification tools."
             ], GREEN_ACCENT)

    # =========================================================================
    # SLIDE 6: TIMING ENGINE & DESKTOP GADGET (SCREENSHOTS)
    # =========================================================================
    slide6 = prs.slides.add_slide(blank_layout)
    apply_background(slide6)
    add_header(slide6, "Stealth Background Monitoring & Fast Polling Engine", "CONTINUOUS BACKGROUND DEFENSE")

    # Left: Desktop Gadget Screenshot
    img_eighth = os.path.join(ASSETS_DIR, "eighth.png")
    if os.path.exists(img_eighth):
        slide6.shapes.add_picture(img_eighth, Inches(0.8), Inches(1.8), Inches(5.6), Inches(3.2))

    add_card(slide6, Inches(0.8), Inches(5.2), Inches(5.6), Inches(1.8),
             "Movable Desktop Gadget Widget", [
                 "Frameless topmost floating widget displaying real-time status pill and live change counter badge.",
                 "Click or double-click to restore the main application; drag anywhere on the screen."
             ], CYAN_ACCENT)

    # Right: Timing Controller Screenshot
    img_fourth = os.path.join(ASSETS_DIR, "fourth.png")
    if os.path.exists(img_fourth):
        slide6.shapes.add_picture(img_fourth, Inches(6.8), Inches(1.8), Inches(5.7), Inches(3.6))

    add_card(slide6, Inches(6.8), Inches(5.6), Inches(5.7), Inches(1.4),
             "Dynamic Timing Controller", [
                 "6 selectable timing cards (1s to 60s) with direct 'Save & Apply Timing Now' button."
             ], AMBER_ACCENT)

    # =========================================================================
    # SLIDE 7: VERIFICATION, TESTING & PACKAGING
    # =========================================================================
    slide7 = prs.slides.add_slide(blank_layout)
    apply_background(slide7)
    add_header(slide7, "Quality Assurance & Production Distribution", "TESTING BENCHMARKS & CRYPTOGRAPHIC VERIFICATION")

    add_card(slide7, Inches(0.8), Inches(1.8), Inches(5.6), Inches(5.0),
             "Automated Test Suite (100% Passed)", [
                 "65 Total Unit Tests passing in 4.45s with zero regressions.",
                 "test_change_detector.py: 47 unit tests verifying state diffing, false-positive suppression, and static PE hashing.",
                 "test_settings_and_db.py: 18 unit tests validating DPAPI ciphers, timing engine, and atomic threat remediation.",
                 "Rigorous edge-case coverage: Access Denied permissions, type mutations, and thread-safe queue consumption."
             ], GREEN_ACCENT)

    add_card(slide7, Inches(6.8), Inches(1.8), Inches(5.7), Inches(5.0),
             "Production Binaries & SHA-256 Hashes", [
                 "Standalone Portable Executable (.exe):\nWindowsRegistryMonitor.exe (80.22 MB)\nSHA-256: 8BEE859BA0DA4527E1FEE42F4B946A21A102FB170BBFFA2724F5BDC56BD649FC",
                 "Setup Wizard Installer (.exe):\nRegistryMonitorSetup.exe (81.08 MB)\nSHA-256: 61B5C2109D5B3A150D989102D8EB04AC7C6A1A51D246445C7D724E2F69E50DD7",
                 "Deployment: Inno Setup 7 LZMA2/ultra64 solid compression with administrative privilege elevation."
             ], PURPLE_ACCENT)

    # =========================================================================
    # SLIDE 8: CONCLUSION & PROJECT TAKEAWAYS
    # =========================================================================
    slide8 = prs.slides.add_slide(blank_layout)
    apply_background(slide8)
    add_header(slide8, "Summary, Learning Outcomes & Open-Source Links", "PROJECT CONCLUSION & IMPACT")

    add_card(slide8, Inches(0.8), Inches(1.8), Inches(5.6), Inches(5.0),
             "Key Learning Outcomes", [
                 "Mastery of Windows Registry architecture, binary subkeys, and WOW64 reflection.",
                 "In-depth understanding of malware persistence mechanisms and evasion tactics.",
                 "Hands-on implementation of blue team defensive integrity auditing.",
                 "Production-grade endpoint engineering with hardware DPAPI cryptography and responsive GUI."
             ], CYAN_ACCENT)

    add_card(slide8, Inches(6.8), Inches(1.8), Inches(5.7), Inches(5.0),
             "Project Links & Credits", [
                 "Lead Architect: Piyush (@Made-by-Piyush99)",
                 "GitHub Repository:\nhttps://github.com/Made-by-Piyush99/Windows-Registry-Monitoring",
                 "Latest Release (v2.4.0):\nhttps://github.com/Made-by-Piyush99/Windows-Registry-Monitoring/releases/tag/v2.4.0",
                 "License: MIT Open Source License",
                 "Thank You! Q&A Session Welcome."
             ], GREEN_ACCENT)

    prs.save(PPTX_OUTPUT)
    print(f"PowerPoint Presentation saved successfully to: {PPTX_OUTPUT}")

if __name__ == "__main__":
    build_presentation()
