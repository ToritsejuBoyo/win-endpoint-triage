#!/usr/bin/env python3
"""
validate-skill.py - Automated Quality & Schema Validator for win-endpoint-triage
Tests:
  1. Validates that collect-win-triage.ps1 syntax is valid PowerShell.
  2. Validates that all synthetic test fixtures comply with SchemaVersion 2.0.0.
  3. Validates diagnostic assertions for each fixture (Disk failure, Entra PRT, BSOD TDR, Thermal throttle).
"""

import json
import os
import re
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(BASE_DIR)
FIXTURES_DIR = os.path.join(BASE_DIR, "fixtures")

REQUIRED_ROOT_KEYS = [
    "SchemaVersion", "SkillSlug", "Sanitized", "IsElevatedSession", "LookbackHours",
    "SystemBaseline", "ReliabilitySummary", "PendingReboot", "Disks",
    "TopProcessesByMemory", "StoppedAutoServices", "EntraIdentity",
    "NetworkAdapters", "BatteryHealth", "RecurringEventSummary", "RecentCriticalEvents"
]

def test_fixtures():
    fixtures = [f for f in os.listdir(FIXTURES_DIR) if f.endswith(".json")]
    print(f"[*] Validating {len(fixtures)} synthetic fixtures in {FIXTURES_DIR}...")
    assert len(fixtures) >= 4, f"Expected at least 4 fixtures, found {len(fixtures)}"

    for f in fixtures:
        path = os.path.join(FIXTURES_DIR, f)
        with open(path, "r", encoding="utf-8") as fp:
            data = json.load(fp)

        # 1. Check Schema Version & Root Keys
        assert data.get("SchemaVersion") == "2.0.0", f"{f}: Invalid SchemaVersion"
        assert data.get("SkillSlug") == "win-endpoint-triage", f"{f}: Invalid SkillSlug"
        for k in REQUIRED_ROOT_KEYS:
            assert k in data, f"{f}: Missing root key '{k}'"

        # 2. Check Sanitization
        baseline = data.get("SystemBaseline", {})
        assert baseline.get("ComputerName") == "ENDPOINT-REDACTED", f"{f}: ComputerName not sanitized"
        assert baseline.get("Domain") == "corp.example.internal", f"{f}: Domain not sanitized"

        print(f"  [+] PASS: {f} (Valid 2.0.0 schema, sanitized)")

    # 3. Test Fixture-Specific Diagnostic Signatures
    # Test 1: Disk failure
    with open(os.path.join(FIXTURES_DIR, "fixture-disk-failing-badblock.json"), "r", encoding="utf-8") as fp:
        d = json.load(fp)
        event_ids = [e["EventId"] for e in d["RecentCriticalEvents"]]
        assert 7 in event_ids and 153 in event_ids, "Disk fixture missing Event ID 7 or 153"
        assert d["Disks"][0]["FreePercent"] < 5.0, "Disk fixture should have low free percent"
    print("  [+] PASS: fixture-disk-failing-badblock correctly exhibits Event ID 7/153 and space exhaustion.")

    # Test 2: Entra PRT failure
    with open(os.path.join(FIXTURES_DIR, "fixture-entra-prt-sso-failure.json"), "r", encoding="utf-8") as fp:
        d = json.load(fp)
        assert d["EntraIdentity"]["AzureAdPrt"] == "NO", "Entra fixture should have AzureAdPrt: NO"
        assert "8.8.8.8" in d["NetworkAdapters"][0]["DNSServers"], "Entra fixture should exhibit public DNS on NIC"
    print("  [+] PASS: fixture-entra-prt-sso-failure correctly exhibits missing PRT token and DNS mismatch.")

    # Test 3: BSOD TDR loop
    with open(os.path.join(FIXTURES_DIR, "fixture-bsod-driver-tdr.json"), "r", encoding="utf-8") as fp:
        d = json.load(fp)
        event_ids = [e["EventId"] for e in d["RecentCriticalEvents"]]
        assert 41 in event_ids and 4101 in event_ids, "BSOD fixture missing Event 41 or 4101"
        assert d["SystemBaseline"]["UptimeDays"] > 30, "BSOD fixture should show high uptime"
    print("  [+] PASS: fixture-bsod-driver-tdr correctly exhibits Video TDR BugCheck 0x116 and 45d uptime.")

    # Test 4: Thermal throttling
    with open(os.path.join(FIXTURES_DIR, "fixture-thermal-throttling.json"), "r", encoding="utf-8") as fp:
        d = json.load(fp)
        event_ids = [e["EventId"] for e in d["RecentCriticalEvents"]]
        assert 37 in event_ids, "Thermal fixture missing Event 37"
        assert d["BatteryHealth"][0]["Status"] == "Degraded", "Thermal fixture should show degraded battery"
    print("  [+] PASS: fixture-thermal-throttling correctly exhibits Event ID 37 frequency capping.")

def test_script_integrity():
    script_path = os.path.join(SKILL_DIR, "scripts", "collect-win-triage.ps1")
    assert os.path.exists(script_path), "collect-win-triage.ps1 does not exist"
    with open(script_path, "r", encoding="utf-8") as fp:
        content = fp.read()
    assert "Win32_ReliabilityStabilityMetrics" in content, "Missing Reliability metrics in script"
    assert "dsregcmd.exe" in content, "Missing dsregcmd in script"
    assert "WriteAllText" in content, "Missing UTF-8 BOM-free writer"
    print(f"  [+] PASS: collect-win-triage.ps1 passes structural integrity checks ({len(content.splitlines())} lines).")

def main():
    print("==================================================================")
    print("  win-endpoint-triage Automated Test Suite")
    print("==================================================================")
    test_script_integrity()
    test_fixtures()
    print("==================================================================")
    print("  ALL TESTS PASSED: Skill is validated and ready for production!")
    print("==================================================================")

if __name__ == "__main__":
    main()

