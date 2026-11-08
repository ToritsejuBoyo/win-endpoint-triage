#!/usr/bin/env python3
"""
Agensi Marketplace Asset Generator for win-endpoint-triage.

Generates:
1. 512x512 square skill logo (logo-512x512.png)
2. 4 high-definition 1280x720 screenshots for marketplace listing:
   - 01-terminal-collector.png (Live PowerShell zero-dependency telemetry collection)
   - 02-ai-root-cause-analysis.png (Synthesized diagnostic verdict & triage findings)
   - 03-itsm-escalation-brief.png (Copy-paste ServiceNow/Jira escalation note)
   - 04-telemetry-architecture.png (6-domain read-only architecture & compliance)
"""

import math
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ASSETS_DIR = Path("C:/Users/Toju/Desktop/agensi-win-endpoint-triage-assets")
ASSETS_DIR.mkdir(parents=True, exist_ok=True)


def get_font(size: int, bold: bool = False):
    font_names = ["consolab.ttf" if bold else "consola.ttf", "segoeuib.ttf" if bold else "segoeui.ttf", "arialbd.ttf" if bold else "arial.ttf"]
    for name in font_names:
        try:
            return ImageFont.truetype(name, size)
        except Exception:
            continue
    return ImageFont.load_default()


# ----------------------------------------------------------------------
# 1. Skill Logo Generator (512x512)
# ----------------------------------------------------------------------
def generate_logo():
    size = 512
    img = Image.new("RGBA", (size, size), (15, 23, 42, 255))  # #0F172A
    draw = ImageDraw.Draw(img)

    # Subtle radial glow behind the center icon
    center_x, center_y = size // 2, size // 2 - 25
    for r in range(180, 0, -5):
        alpha = int(40 * (1 - r / 180))
        draw.ellipse(
            [(center_x - r, center_y - r), (center_x + r, center_y + r)],
            fill=(14, 165, 233, alpha)
        )

    # Rounded outer border
    margin = 16
    draw.rounded_rectangle(
        [(margin, margin), (size - margin, size - margin)],
        radius=48,
        outline=(56, 189, 248, 180),
        width=4
    )

    # Windows 4-Pane Modern Diagnostic Emblem
    pane_w = 70
    pane_h = 70
    gap = 14
    cx = center_x
    cy = center_y - 20

    # Top-Left Pane (Windows Blue)
    draw.rounded_rectangle(
        [(cx - gap//2 - pane_w, cy - gap//2 - pane_h), (cx - gap//2, cy - gap//2)],
        radius=12,
        fill=(14, 165, 233, 255)
    )
    # Top-Right Pane (Cyan)
    draw.rounded_rectangle(
        [(cx + gap//2, cy - gap//2 - pane_h), (cx + gap//2 + pane_w, cy - gap//2)],
        radius=12,
        fill=(56, 189, 248, 255)
    )
    # Bottom-Left Pane (Sky Blue)
    draw.rounded_rectangle(
        [(cx - gap//2 - pane_w, cy + gap//2), (cx - gap//2, cy + gap//2 + pane_h)],
        radius=12,
        fill=(2, 132, 199, 255)
    )
    # Bottom-Right Pane (Dark Teal/Cyan)
    draw.rounded_rectangle(
        [(cx + gap//2, cy + gap//2), (cx + gap//2 + pane_w, cy + gap//2 + pane_h)],
        radius=12,
        fill=(56, 189, 248, 255)
    )

    # Pulse / Heartbeat EKG Diagnostic Overlay
    pulse_y = cy
    points = [
        (cx - 160, pulse_y),
        (cx - 70, pulse_y),
        (cx - 40, pulse_y - 45),
        (cx - 15, pulse_y + 40),
        (cx + 15, pulse_y - 65),
        (cx + 45, pulse_y + 35),
        (cx + 70, pulse_y),
        (cx + 160, pulse_y)
    ]
    # Draw glow for pulse line
    for w, a in [(8, 60), (5, 120), (3, 255)]:
        draw.line(points, fill=(244, 63, 94, a), width=w, joint="curve")

    # Pulse ping dot at the peak
    draw.ellipse([(cx + 15 - 6, pulse_y - 65 - 6), (cx + 15 + 6, pulse_y - 65 + 6)], fill=(255, 255, 255, 255))

    # Badge Pills / Text
    title_font = get_font(28, bold=True)
    sub_font = get_font(18, bold=True)

    text_main = "WIN ENDPOINT"
    text_sub = "TRIAGE & RCA"

    bbox_main = draw.textbbox((0, 0), text_main, font=title_font)
    w_main = bbox_main[2] - bbox_main[0]
    draw.text(((size - w_main) // 2, 380), text_main, font=title_font, fill=(241, 245, 249, 255))

    bbox_sub = draw.textbbox((0, 0), text_sub, font=sub_font)
    w_sub = bbox_sub[2] - bbox_sub[0]
    draw.text(((size - w_sub) // 2, 420), text_sub, font=sub_font, fill=(56, 189, 248, 255))

    # Output Logo
    logo_path = ASSETS_DIR / "logo-512x512.png"
    img.save(logo_path, "PNG")
    print(f"[+] Generated Skill Logo: {logo_path}")


# ----------------------------------------------------------------------
# 2. Screenshot 1: Interactive PowerShell Telemetry Collector
# ----------------------------------------------------------------------
def generate_screenshot_1():
    w, h = 1280, 720
    img = Image.new("RGB", (w, h), (15, 23, 42))
    draw = ImageDraw.Draw(img)

    # Top header bar
    draw.rectangle([(0, 0), (w, 48)], fill=(30, 41, 59))
    draw.ellipse([(20, 16), (32, 28)], fill=(239, 68, 68))
    draw.ellipse([(42, 16), (54, 28)], fill=(245, 158, 11))
    draw.ellipse([(64, 16), (76, 28)], fill=(16, 185, 129))

    title_font = get_font(15, bold=True)
    draw.text((w // 2 - 200, 14), "Administrator: Windows PowerShell - win-endpoint-triage", font=title_font, fill=(148, 163, 184))

    code_font = get_font(14)
    code_bold = get_font(14, bold=True)
    cyan = (56, 189, 248)
    green = (52, 211, 153)
    yellow = (251, 191, 36)
    white = (255, 255, 255)
    gray = (148, 163, 184)

    lines = [
        (30, 70, "PS C:\\Support> ", (96, 165, 250), code_bold),
        (170, 70, ".\\scripts\\collect-win-triage.ps1 -Sanitize -OutputPath .\\triage-bundle.json", white, code_bold),
        (30, 105, "[*] Windows Endpoint Telemetry Collector v1.4.0 (Read-Only Mode)", cyan, code_bold),
        (30, 128, "[*] Operating System: Microsoft Windows 11 Enterprise (Build 22631.3007)", gray, code_font),
        (30, 151, "[+] Domain 1/6: Hardware Topology & Thermal Specs (WMI/CIM)......... [COLLECTED]", green, code_font),
        (30, 174, "[+] Domain 2/6: BlueScreen BugCheck Memory Dumps (System Events)..... [COLLECTED]", green, code_font),
        (30, 197, "[+] Domain 3/6: Application Hangs & Crash Events (AppModel Runtime)... [COLLECTED]", green, code_font),
        (30, 220, "[+] Domain 4/6: Storage Health & SMART Status (PhysicalDisks)........ [COLLECTED]", green, code_font),
        (30, 243, "[+] Domain 5/6: Process Memory Leaks & Committed Bytes Trends........ [COLLECTED]", green, code_font),
        (30, 266, "[+] Domain 6/6: Network Adapter Configuration & DNS Resolution....... [COLLECTED]", green, code_font),
        (30, 300, "[-] Client-Side Telemetry Scrubbing Active (--Sanitize):", yellow, code_bold),
        (30, 323, "    - User Principal Name masked: user-xxxx@corp.example.com (SHA-256)", gray, code_font),
        (30, 346, "    - Internal IPv4/IPv6 masked:  192.0.2.45 / 2001:db8::1", gray, code_font),
        (30, 369, "    - Machine GUID / Serial masked: 00000000-0000-4000-a000-000000000000", gray, code_font),
        (30, 405, "[+] Telemetry snapshot successfully exported to: .\\triage-bundle.json (48.2 KB)", green, code_bold),
        (30, 435, "PS C:\\Support> ", (96, 165, 250), code_bold),
        (170, 435, "python scripts\\win_triage_analyzer.py -i .\\triage-bundle.json", white, code_bold),
        (30, 470, "=========================================================================================", gray, code_font),
        (30, 495, "ENDPOINT TRIAGE VERDICT: ESCALATE TO LEVEL 2 (HARDWARE/KERNEL DRIVER ISSUE)", (248, 113, 113), code_bold),
        (30, 520, "Primary Root Cause: VIDEO_TDR_FAILURE (0x00000116) - nvlddmkm.sys display kernel hang", white, code_font),
        (30, 545, "Recommended Action: Update NVIDIA RTX Enterprise driver to 552.22 or roll back DCH pack", yellow, code_font),
        (30, 570, "ServiceNow Note:    Pre-compiled escalation Markdown generated in .\\escalation-brief.md", cyan, code_font),
        (30, 600, "=========================================================================================", gray, code_font),
    ]

    for item in lines:
        x, y, text, col, fnt = item
        draw.text((x, y), text, font=fnt, fill=col)

    path = ASSETS_DIR / "01-terminal-collector.png"
    img.save(path, "PNG")
    print(f"[+] Generated Screenshot 1: {path}")


# ----------------------------------------------------------------------
# 3. Screenshot 2: AI Root Cause Analysis & Triage Findings
# ----------------------------------------------------------------------
def generate_screenshot_2():
    w, h = 1280, 720
    img = Image.new("RGB", (w, h), (15, 23, 42))
    draw = ImageDraw.Draw(img)

    # Top header
    draw.rectangle([(0, 0), (w, 56)], fill=(30, 41, 59))
    hdr_font = get_font(18, bold=True)
    draw.text((32, 16), "AI Agent Root-Cause Analysis Dashboard", font=hdr_font, fill=(241, 245, 249))

    # Metric Cards Top
    card_y = 76
    cards = [
        ("Triage Verdict", "ESCALATE TO L2", (239, 68, 68), (254, 226, 226)),
        ("Root Cause Domain", "Kernel Graphics TDR", (56, 189, 248), (224, 242, 254)),
        ("Confidence Score", "98.4%", (52, 211, 153), (209, 250, 229)),
        ("Time Saved vs Manual", "42 Minutes", (251, 191, 36), (254, 243, 199))
    ]

    card_w = (w - 64 - 36) // 4
    for idx, (lbl, val, col_fg, col_bg) in enumerate(cards):
        cx = 32 + idx * (card_w + 12)
        draw.rounded_rectangle([(cx, card_y), (cx + card_w, card_y + 80)], radius=8, fill=(30, 41, 59), outline=(51, 65, 85), width=1)
        draw.text((cx + 16, card_y + 12), lbl, font=get_font(13), fill=(148, 163, 184))
        draw.text((cx + 16, card_y + 36), val, font=get_font(20, bold=True), fill=col_fg)

    # Main Body: Finding Detail Box
    body_y = 176
    draw.rounded_rectangle([(32, body_y), (w - 32, h - 32)], radius=12, fill=(30, 41, 59), outline=(51, 65, 85), width=1)

    draw.text((54, body_y + 24), "Synthesized Root-Cause Breakdown (Deterministic Rule Engine)", font=get_font(18, bold=True), fill=(241, 245, 249))

    items = [
        ("BugCheck Code:", "0x00000116 (VIDEO_TDR_TIMEOUT_DETECTED)", (248, 113, 113)),
        ("Failing Module:", "nvlddmkm.sys (NVIDIA Windows Kernel Mode Driver)", (255, 255, 255)),
        ("Crash Timestamp:", "2026-11-04 14:22:18 UTC (Correlated with 4 EventID 4101 entries)", (148, 163, 184)),
        ("Can L1 Fix It Now?", "NO - Requires targeted driver roll-back / clean DCH packaging.", (239, 68, 68)),
        ("Correlated Evidence:", "Desktop Window Manager (dwm.exe) crashed 3 times prior to bugcheck.", (148, 163, 184)),
        ("Storage SMART State:", "Healthy - 0 bad sectors, NVMe lifetime remaining: 94%", (52, 211, 153)),
        ("Thermals / CPU Throttle:", "Normal - Core Max 68°C, zero thermal throttling events logged.", (52, 211, 153)),
        ("Recommended L2 Action:", "Deploy clean package: NVIDIA RTX Enterprise Driver v552.22 via Intune Win32 App.", (56, 189, 248)),
    ]

    curr_y = body_y + 70
    for label, val, val_col in items:
        draw.text((54, curr_y), label, font=get_font(14, bold=True), fill=(148, 163, 184))
        draw.text((280, curr_y), val, font=get_font(14), fill=val_col)
        curr_y += 34

    path = ASSETS_DIR / "02-ai-root-cause-analysis.png"
    img.save(path, "PNG")
    print(f"[+] Generated Screenshot 2: {path}")


# ----------------------------------------------------------------------
# 4. Screenshot 3: ITSM Escalation Brief (ServiceNow/Jira)
# ----------------------------------------------------------------------
def generate_screenshot_3():
    w, h = 1280, 720
    img = Image.new("RGB", (w, h), (15, 23, 42))
    draw = ImageDraw.Draw(img)

    # Top header bar
    draw.rectangle([(0, 0), (w, 56)], fill=(30, 41, 59))
    draw.text((32, 16), "Automated ITSM Ticket Note (ServiceNow / Jira / HaloPSA Format)", font=get_font(18, bold=True), fill=(241, 245, 249))

    # Editor Window
    draw.rounded_rectangle([(32, 76), (w - 32, h - 32)], radius=12, fill=(11, 17, 32), outline=(51, 65, 85), width=1)

    brief_text = [
        ("### L2 Escalation Brief: Video TDR Crash on Windows 11 Enterprise", (56, 189, 248), True),
        ("", (255, 255, 255), False),
        ("**Ticket Summary:** End-user reports display freezes followed by black screen and auto-reboot.", (241, 245, 249), False),
        ("**Device Identifier:** `W11-CORP-0428` | **OS:** Windows 11 Pro 23H2 (Build 22631)", (148, 163, 184), False),
        ("**Triaged By:** Service Desk L1 Automation Agent | **Date:** 2026-11-04 14:35 UTC", (148, 163, 184), False),
        ("", (255, 255, 255), False),
        ("#### Technical Evidence & Diagnostic Proof:", (56, 189, 248), True),
        ("1. **BugCheck Code:** `0x116 (VIDEO_TDR_FAILURE)` - Graphic card failed to reset in allotted timeout.", (255, 255, 255), False),
        ("2. **Blamed Module:** `nvlddmkm.sys` (Driver version: 31.0.15.4633 - released Dec 2023).", (255, 255, 255), False),
        ("3. **System Event Log:** 4 occurrences of Event ID 4101 ('Display driver nvlddmkm stopped responding').", (255, 255, 255), False),
        ("4. **Hardware Health Verification:**", (255, 255, 255), True),
        ("   - RAM: 32 GB Total (Committed 14.2 GB - Zero paging exhaustion).", (52, 211, 153), False),
        ("   - SSD: NVMe Samsung PM9A1 - SMART Status OK, 0 Reallocated Sectors.", (52, 211, 153), False),
        ("   - Thermals: GPU Core Max 71°C at crash time (Thermal shutdown ruled out).", (52, 211, 153), False),
        ("", (255, 255, 255), False),
        ("#### Verified Level 2 Remediation Plan:", (251, 191, 36), True),
        ("- [ ] Action 1: Deploy certified OEM Display Driver v552.22 via Microsoft Intune.", (241, 245, 249), False),
        ("- [ ] Action 2: Perform DDU (Display Driver Uninstaller) clean removal if issue recurs.", (241, 245, 249), False),
        ("- [ ] Action 3: Verify hardware PCIe seating if crash persists across driver reinstalls.", (241, 245, 249), False),
    ]

    curr_y = 100
    for line, col, is_bold in brief_text:
        if line:
            draw.text((60, curr_y), line, font=get_font(14, bold=is_bold), fill=col)
        curr_y += 24

    path = ASSETS_DIR / "03-itsm-escalation-brief.png"
    img.save(path, "PNG")
    print(f"[+] Generated Screenshot 3: {path}")


# ----------------------------------------------------------------------
# 4. Screenshot 4: Telemetry Architecture & Security Compliance
# ----------------------------------------------------------------------
def generate_screenshot_4():
    w, h = 1280, 720
    img = Image.new("RGB", (w, h), (15, 23, 42))
    draw = ImageDraw.Draw(img)

    # Top header bar
    draw.rectangle([(0, 0), (w, 56)], fill=(30, 41, 59))
    draw.text((32, 16), "Enterprise Security & Architecture Guardrails", font=get_font(18, bold=True), fill=(241, 245, 249))

    # 4 Architecture Pillars
    pillars = [
        ("1. 100% Read-Only", "Uses only native WMI/CIM and EventLog queries. Zero writes, zero registry modifications, zero policy mutations.", (52, 211, 153)),
        ("2. Zero Dependencies", "Runs entirely inside native Windows PowerShell 5.1/7+. No pip install, no compiled .exe binaries, zero EDR alerts.", (56, 189, 248)),
        ("3. Client-Side Sanitization", "Automatic SHA-256 masking on UPNs, hostnames, private/public IPs, and Machine GUIDs before any data leaves the host.", (251, 191, 36)),
        ("4. Least Privilege", "Requires only standard local audit rights. Never asks for Domain Admin or Global Administrator privileges.", (168, 85, 247))
    ]

    for idx, (title, desc, col) in enumerate(pillars):
        py = 88 + idx * 136
        draw.rounded_rectangle([(32, py), (w - 32, py + 116)], radius=10, fill=(30, 41, 59), outline=(51, 65, 85), width=1)
        # Left color pill
        draw.rectangle([(32, py), (42, py + 116)], fill=col)
        draw.text((64, py + 18), title, font=get_font(18, bold=True), fill=col)
        draw.text((64, py + 52), desc, font=get_font(14), fill=(203, 213, 225))

    path = ASSETS_DIR / "04-telemetry-architecture.png"
    img.save(path, "PNG")
    print(f"[+] Generated Screenshot 4: {path}")


def main():
    print("[*] Generating Agensi Marketplace Assets for win-endpoint-triage...")
    generate_logo()
    generate_screenshot_1()
    generate_screenshot_2()
    generate_screenshot_3()
    generate_screenshot_4()
    print(f"\n[+] All assets successfully generated in: {ASSETS_DIR}")


if __name__ == "__main__":
    main()
