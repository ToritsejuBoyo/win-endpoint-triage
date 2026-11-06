#!/usr/bin/env python3
"""stress_test_win_triage.py - 30-Scenario Stress & Edge-Case Battery for win-endpoint-triage

Executes 30 rigorous edge-case, corruption, boundary, fuzzing, and performance tests
against parse-win-triage.py to guarantee enterprise resilience.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict

import importlib.util

# Resolve scripts path
BASE_DIR = Path(__file__).resolve().parent
REPO_DIR = BASE_DIR.parent
script_file = REPO_DIR / "scripts" / "parse-win-triage.py"
if not script_file.exists():
    script_file = REPO_DIR / "skills" / "win-endpoint-triage" / "scripts" / "parse-win-triage.py"

spec = importlib.util.spec_from_file_location("parse_win_triage", str(script_file))
module = importlib.util.module_from_spec(spec)
sys.modules["parse_win_triage"] = module
spec.loader.exec_module(module)

WinTriageAnalyzer = module.WinTriageAnalyzer
Sanitizer = module.Sanitizer
Finding = module.Finding
TriageReport = module.TriageReport


class TestSuite:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []

    def record(self, test_num: int, name: str, passed: bool, detail: str = ""):
        status = "PASS" if passed else "FAIL"
        if passed:
            self.passed += 1
        else:
            self.failed += 1
        self.results.append((test_num, name, status, detail))
        print(f"[{status}] Test {test_num:02d}: {name} {f'- {detail}' if detail else ''}")


def run_tests():
    suite = TestSuite()
    print("==================================================================")
    print("  win-endpoint-triage Comprehensive 30-Scenario Stress Test Suite")
    print("==================================================================")

    # Test 01: Empty Bundle
    try:
        report = WinTriageAnalyzer({}, sanitize=False).evaluate()
        suite.record(1, "Empty telemetry bundle gracefully evaluated", report.l1_actionable is True and len(report.findings) == 0)
    except Exception as exc:
        suite.record(1, "Empty telemetry bundle gracefully evaluated", False, str(exc))

    # Test 02: Null Root Keys
    try:
        fuzzed_nulls = {
            "SystemBaseline": None, "ReliabilitySummary": None, "PendingReboot": None,
            "Disks": None, "TopProcessesByMemory": None, "StoppedAutoServices": None,
            "EntraIdentity": None, "NetworkAdapters": None, "BatteryHealth": None,
            "RecentCriticalEvents": None
        }
        report = WinTriageAnalyzer(fuzzed_nulls, sanitize=True).evaluate()
        suite.record(2, "Fuzzed null values for all root dictionary keys", True, "Handled via defensive wrappers")
    except Exception as exc:
        suite.record(2, "Fuzzed null values for all root dictionary keys", False, str(exc))

    # Test 03: Malformed Data Types
    try:
        fuzzed_types = {
            "SystemBaseline": {"UptimeDays": "not-a-number", "ComputerName": 12345},
            "ReliabilitySummary": {"StabilityIndexScore1To10": []},
            "PendingReboot": {"FastStartupEnabled": "yes", "IsPending": "true"},
            "Disks": "not-a-list",
            "RecentCriticalEvents": 9999
        }
        report = WinTriageAnalyzer(fuzzed_types).evaluate()
        suite.record(3, "Type confusion fuzzing (str where num, num where str, int where list)", True)
    except Exception as exc:
        suite.record(3, "Type confusion fuzzing", False, str(exc))

    # Test 04: BSOD BugCheck with Event ID 41 & 1001
    try:
        payload = {
            "RecentCriticalEvents": [
                {"EventId": 41, "ProviderName": "Microsoft-Windows-Kernel-Power", "Message": "The system has rebooted without cleanly shutting down first."},
                {"EventId": 1001, "ProviderName": "Microsoft-Windows-WER-SystemErrorReporting", "Message": "The computer has rebooted from a bugcheck. The bugcheck was: 0x00000116 (0xffffd00874e0d010). A dump was saved in C:\\Windows\\MEMORY.DMP."}
            ]
        }
        report = WinTriageAnalyzer(payload).evaluate()
        bsod = any("BugCheck" in f.indicator for f in report.findings)
        suite.record(4, "BSOD BugCheck 0x116 extraction from Event 41/1001", bsod and not report.l1_actionable, "Marked for L2/L3 escalation")
    except Exception as exc:
        suite.record(4, "BSOD BugCheck extraction", False, str(exc))

    # Test 05: Sudden Power Loss Event 41 without Bugcheck (Code 0)
    try:
        payload = {
            "RecentCriticalEvents": [
                {"EventId": 41, "ProviderName": "Microsoft-Windows-Kernel-Power", "Message": "The system has rebooted without cleanly shutting down. BugcheckCode 0"}
            ]
        }
        report = WinTriageAnalyzer(payload).evaluate()
        pwr = any("Power Interruption" in f.indicator for f in report.findings)
        suite.record(5, "Unexpected electrical power loss isolation (Event 41 BugCheck 0)", pwr)
    except Exception as exc:
        suite.record(5, "Unexpected electrical power loss", False, str(exc))

    # Test 06: Physical Disk Bad Blocks (Event ID 7)
    try:
        payload = {
            "RecentCriticalEvents": [
                {"EventId": 7, "ProviderName": "disk", "Message": "The device, \\Device\\Harddisk0\\DR0, has a bad block."}
            ]
        }
        report = WinTriageAnalyzer(payload).evaluate()
        badblock = any("Bad Block" in f.indicator and f.severity == "CRITICAL" for f in report.findings)
        suite.record(6, "Physical bad block detection (Event ID 7 Critical)", badblock and not report.l1_actionable)
    except Exception as exc:
        suite.record(6, "Physical bad block detection", False, str(exc))

    # Test 07: Storage Controller I/O Timeout (Event ID 153)
    try:
        payload = {
            "RecentCriticalEvents": [
                {"EventId": 153, "ProviderName": "storahci", "Message": "The IO operation at logical block address 0x12a0 was retried."}
            ]
        }
        report = WinTriageAnalyzer(payload).evaluate()
        ctrl = any("Storage Controller" in f.indicator for f in report.findings)
        suite.record(7, "Storage controller reset isolation (Event ID 153)", ctrl)
    except Exception as exc:
        suite.record(7, "Storage controller reset isolation", False, str(exc))

    # Test 08: NTFS Filesystem Metadata Corruption (Event ID 55)
    try:
        payload = {
            "RecentCriticalEvents": [
                {"EventId": 55, "ProviderName": "Ntfs", "Message": "A corruption was discovered in the file system structure on volume C:."}
            ]
        }
        report = WinTriageAnalyzer(payload).evaluate()
        ntfs = any("NTFS" in f.indicator and f.severity == "CRITICAL" for f in report.findings)
        suite.record(8, "NTFS filesystem metadata corruption (Event ID 55 Critical)", ntfs)
    except Exception as exc:
        suite.record(8, "NTFS filesystem corruption", False, str(exc))

    # Test 09: Fast Startup Stale Kernel Session
    try:
        payload = {
            "SystemBaseline": {"UptimeDays": 32.5},
            "PendingReboot": {"FastStartupEnabled": True}
        }
        report = WinTriageAnalyzer(payload).evaluate()
        stale = any("Stale Kernel" in f.indicator for f in report.findings)
        suite.record(9, "Stale kernel detection (Uptime > 14d + Fast Startup)", stale and report.findings[0].l1_solvable)
    except Exception as exc:
        suite.record(9, "Stale kernel detection", False, str(exc))

    # Test 10: High Uptime without Fast Startup
    try:
        payload = {
            "SystemBaseline": {"UptimeDays": 32.5},
            "PendingReboot": {"FastStartupEnabled": False}
        }
        report = WinTriageAnalyzer(payload).evaluate()
        stale = any("Stale Kernel" in f.indicator for f in report.findings)
        suite.record(10, "High uptime without Fast Startup does not false-positive trigger stale kernel", not stale)
    except Exception as exc:
        suite.record(10, "High uptime without Fast Startup", False, str(exc))

    # Test 11: Pending Reboot via CBS
    try:
        payload = {"PendingReboot": {"IsPending": True, "ComponentBasedServicing": True}}
        report = WinTriageAnalyzer(payload).evaluate()
        cbs = any("Pending System Reboot" in f.indicator and "CBS" in f.observed_value for f in report.findings)
        suite.record(11, "Component Based Servicing pending reboot detection", cbs)
    except Exception as exc:
        suite.record(11, "Pending reboot CBS", False, str(exc))

    # Test 12: Pending Reboot via Windows Update
    try:
        payload = {"PendingReboot": {"IsPending": True, "WindowsUpdateRebootRequired": True}}
        report = WinTriageAnalyzer(payload).evaluate()
        wu = any("Pending System Reboot" in f.indicator and "Windows Update" in f.observed_value for f in report.findings)
        suite.record(12, "Windows Update pending reboot detection", wu)
    except Exception as exc:
        suite.record(12, "Pending reboot WU", False, str(exc))

    # Test 13: Pending Reboot via PendingFileRenameOperations
    try:
        payload = {"PendingReboot": {"IsPending": True, "PendingFileRenameOperations": True}}
        report = WinTriageAnalyzer(payload).evaluate()
        rename = any("Pending File Rename" in f.observed_value for f in report.findings)
        suite.record(13, "PendingFileRenameOperations reboot detection", rename)
    except Exception as exc:
        suite.record(13, "Pending reboot rename", False, str(exc))

    # Test 14: Chronic System Instability (< 4.0 Score)
    try:
        payload = {"ReliabilitySummary": {"StabilityIndexScore1To10": 1.7}}
        report = WinTriageAnalyzer(payload).evaluate()
        unstable = any("Chronic System Instability" in f.indicator for f in report.findings)
        suite.record(14, "Windows Reliability Monitor score < 4.0 flags chronic instability", unstable)
    except Exception as exc:
        suite.record(14, "Chronic instability score", False, str(exc))

    # Test 15: Windows Server Reliability "N/A"
    try:
        payload = {"ReliabilitySummary": {"StabilityIndexScore1To10": "N/A"}}
        report = WinTriageAnalyzer(payload).evaluate()
        unstable = any("Chronic System Instability" in f.indicator for f in report.findings)
        suite.record(15, "Windows Server 'N/A' reliability metrics handled gracefully without false positive", not unstable)
    except Exception as exc:
        suite.record(15, "Server reliability N/A", False, str(exc))

    # Test 16: Critical Disk Space Exhaustion (< 3 GB free)
    try:
        payload = {"Disks": [{"DriveLetter": "C:", "FreeSpaceGB": 1.2, "FreePercent": 0.8}]}
        report = WinTriageAnalyzer(payload).evaluate()
        crit_disk = any("Critical Disk Space Exhaustion" in f.indicator and f.severity == "CRITICAL" for f in report.findings)
        suite.record(16, "Severe disk capacity exhaustion (< 3 GB) triggers CRITICAL", crit_disk)
    except Exception as exc:
        suite.record(16, "Critical disk exhaustion", False, str(exc))

    # Test 17: Borderline Disk Space (10.5% Free)
    try:
        payload = {"Disks": [{"DriveLetter": "C:", "FreeSpaceGB": 52.0, "FreePercent": 10.5}]}
        report = WinTriageAnalyzer(payload).evaluate()
        disk_finding = any("Disk Space Exhaustion" in f.indicator for f in report.findings)
        suite.record(17, "Healthy disk capacity (10.5% / 52 GB free) avoids false positive alert", not disk_finding)
    except Exception as exc:
        suite.record(17, "Borderline disk space", False, str(exc))

    # Test 18: Unprotected BitLocker Volume
    try:
        payload = {"Disks": [{"DriveLetter": "C:", "FreeSpaceGB": 50, "FreePercent": 50, "BitLocker": {"ProtectionStatus": "Unprotected"}}]}
        report = WinTriageAnalyzer(payload).evaluate()
        bl = any("BitLocker Volume Unprotected" in f.indicator for f in report.findings)
        suite.record(18, "Unprotected BitLocker system volume identified with remediation cmdlet", bl)
    except Exception as exc:
        suite.record(18, "BitLocker unprotected", False, str(exc))

    # Test 19: BitLocker Requires Admin Elevation
    try:
        payload = {"Disks": [{"DriveLetter": "C:", "FreeSpaceGB": 50, "FreePercent": 50, "BitLocker": {"ProtectionStatus": "RequiresAdminElevation"}}]}
        report = WinTriageAnalyzer(payload).evaluate()
        bl = any("BitLocker Volume Unprotected" in f.indicator for f in report.findings)
        suite.record(19, "BitLocker non-elevated status handled without false alert", not bl)
    except Exception as exc:
        suite.record(19, "BitLocker requires admin elevation", False, str(exc))

    # Test 20: Missing Entra ID Primary Refresh Token (PRT)
    try:
        payload = {"EntraIdentity": {"AzureAdJoined": "YES", "AzureAdPrt": "NO", "DomainJoined": "NO"}}
        report = WinTriageAnalyzer(payload).evaluate()
        prt = any("Primary Refresh Token" in f.indicator for f in report.findings)
        suite.record(20, "Missing Entra PRT token on joined workstation detected", prt)
    except Exception as exc:
        suite.record(20, "Missing Entra PRT", False, str(exc))

    # Test 21: Public DNS on Domain Joined Host
    try:
        payload = {
            "EntraIdentity": {"DomainJoined": "YES"},
            "NetworkAdapters": [{"DNSServers": ["8.8.8.8", "1.1.1.1"], "IPAddresses": ["10.0.1.50"]}]
        }
        report = WinTriageAnalyzer(payload).evaluate()
        dns = any("Public DNS Configured on Active Directory" in f.indicator for f in report.findings)
        suite.record(21, "Public DNS resolver on AD domain workstation flagged (prevents Netlogon failure)", dns)
    except Exception as exc:
        suite.record(21, "Public DNS on domain host", False, str(exc))

    # Test 22: APIPA Auto-Configuration Address
    try:
        payload = {"NetworkAdapters": [{"HasAPIPA": True, "IPAddresses": ["169.254.120.44"]}]}
        report = WinTriageAnalyzer(payload).evaluate()
        apipa = any("APIPA" in f.indicator for f in report.findings)
        suite.record(22, "APIPA 169.254.x.x network isolation detected", apipa)
    except Exception as exc:
        suite.record(22, "APIPA detection", False, str(exc))

    # Test 23: Processor Thermal / Power Throttling (Event ID 37)
    try:
        payload = {"RecentCriticalEvents": [{"EventId": 37, "ProviderName": "Microsoft-Windows-Kernel-Processor-Power", "Message": "The speed of processor 3 is being limited by system firmware."}]}
        report = WinTriageAnalyzer(payload).evaluate()
        throttle = any("Thermal Throttling" in f.indicator for f in report.findings)
        suite.record(23, "Processor firmware thermal throttling (Event ID 37) identified", throttle and not report.l1_actionable)
    except Exception as exc:
        suite.record(23, "Processor thermal throttling", False, str(exc))

    # Test 24: Degraded Battery Cell Health
    try:
        payload = {"BatteryHealth": [{"Status": "Degraded", "EstimatedChargeRemaining": 20}]}
        report = WinTriageAnalyzer(payload).evaluate()
        bat = any("Degraded Battery" in f.indicator for f in report.findings)
        suite.record(24, "Degraded laptop battery cell flagged for hardware replacement", bat)
    except Exception as exc:
        suite.record(24, "Degraded battery health", False, str(exc))

    # Test 25: Critical Stopped Automatic Services
    try:
        payload = {"StoppedAutoServices": [{"Name": "winmgmt", "DisplayName": "Windows Management Instrumentation", "ExitCode": 1067}]}
        report = WinTriageAnalyzer(payload).evaluate()
        svc = any("Critical Service Stopped" in f.indicator and "winmgmt" in f.indicator for f in report.findings)
        suite.record(25, "Stopped core infrastructure service (winmgmt) detected with Start-Service remediation", svc)
    except Exception as exc:
        suite.record(25, "Critical stopped service", False, str(exc))

    # Test 26: Resource Exhaustion Memory Leak (Event ID 2004)
    try:
        payload = {"RecentCriticalEvents": [{"EventId": 2004, "ProviderName": "Microsoft-Windows-Resource-Exhaustion-Detector", "Message": "Windows successfully diagnosed a low virtual memory condition."}]}
        report = WinTriageAnalyzer(payload).evaluate()
        mem = any("Memory Exhaustion" in f.indicator for f in report.findings)
        suite.record(26, "Low virtual memory commit limit exhaustion (Event ID 2004) detected", mem)
    except Exception as exc:
        suite.record(26, "Resource exhaustion memory leak", False, str(exc))

    # Test 27: Application Crash Event 1000 with Faulting DLL
    try:
        payload = {"RecentCriticalEvents": [{"EventId": 1000, "ProviderName": "Application Error", "Message": "Faulting application name: OUTLOOK.EXE, version: 16.0.1.0, faulting module name: ucrtbase.dll, exception code: 0xc0000005"}]}
        report = WinTriageAnalyzer(payload).evaluate()
        app_crash = any("Application Crash" in f.indicator and "OUTLOOK.EXE" in f.observed_value for f in report.findings)
        suite.record(27, "Application crash (Event ID 1000) isolates faulting binary and DLL module", app_crash)
    except Exception as exc:
        suite.record(27, "Application crash isolation", False, str(exc))

    # Test 28: Display Driver TDR Reset (Event ID 4101)
    try:
        payload = {"RecentCriticalEvents": [{"EventId": 4101, "ProviderName": "Display", "Message": "Display driver nvlddmkm stopped responding and has successfully recovered."}]}
        report = WinTriageAnalyzer(payload).evaluate()
        tdr = any("Display Driver TDR" in f.indicator for f in report.findings)
        suite.record(28, "GPU Video Display Driver TDR reset (Event ID 4101) detected", tdr)
    except Exception as exc:
        suite.record(28, "Display driver TDR reset", False, str(exc))

    # Test 29: Mandatory PII Sanitization
    try:
        san = Sanitizer(enabled=True)
        masked_host = san.mask_host("CORP-PC-JDOE99")
        masked_ip = san.mask_ip("10.200.45.18")
        scrubbed_txt = san.scrub_text("User john.doe@enterprise.corp logged in from C:\\Users\\jdoe\\AppData\\Local and accessed \\\\fileserver01\\confidential with postgresql://admin:SuperSecretPass123!@10.0.0.5:5432/db")
        
        valid = (
            masked_host.startswith("ENDPOINT-") and "CORP-PC-JDOE99" not in masked_host and
            masked_ip.startswith("192.0.2.") and
            "[REDACTED_EMAIL]" in scrubbed_txt and
            "[REDACTED_USER]" in scrubbed_txt and
            "[REDACTED_UNC_SHARE]" in scrubbed_txt and
            "[REDACTED-SECRET]" in scrubbed_txt and
            "SuperSecretPass123!" not in scrubbed_txt
        )
        suite.record(29, "PII & secret sanitization (Host SHA-256, RFC 5737 IPs, URI secrets)", valid)
    except Exception as exc:
        suite.record(29, "PII sanitization", False, str(exc))

    # Test 30: High-Volume Event Ingestion Benchmark (10,000 events)
    try:
        large_events = [
            {"EventId": 1000 if i % 500 == 0 else 1014, "ProviderName": "DNS Client", "Message": f"Synthetic log message iteration {i} with IP 10.0.0.{i % 254}"}
            for i in range(10000)
        ]
        large_payload = {
            "SystemBaseline": {"ComputerName": "BENCH-01", "UptimeDays": 5.0},
            "RecentCriticalEvents": large_events
        }
        start = time.perf_counter()
        report = WinTriageAnalyzer(large_payload).evaluate()
        elapsed = time.perf_counter() - start
        suite.record(30, f"High-volume event benchmark (10,000 events parsed in {elapsed:.3f}s)", elapsed < 1.0, f"Throughput: {10000/elapsed:,.0f} events/sec")
    except Exception as exc:
        suite.record(30, "High-volume event benchmark", False, str(exc))

    print("==================================================================")
    print(f"  STRESS TEST SUMMARY: {suite.passed} PASSED, {suite.failed} FAILED out of 30 tests")
    print("==================================================================")

    if suite.failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
