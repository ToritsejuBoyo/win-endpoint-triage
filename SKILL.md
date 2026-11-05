---
name: win-endpoint-triage
description: Diagnose Windows 10/11 and Windows Server endpoint issues (slow performance, freezes, BSODs, application crashes, disk exhaustion, thermal throttling, and Entra ID/SSO login loops) from exported JSON/Event Viewer telemetry, and package a verified L2/L3 escalation brief. Use whenever troubleshooting Windows workstations, analyzing Event Viewer logs, or preparing ticket escalations.
---

# Windows Endpoint Triage & Escalation Packager (`win-endpoint-triage`)

## Purpose & Target Roles
Designed for **Help Desk Analysts (L1/L2), Desktop Support Engineers, MSP Technicians, and Field Support Engineers**. This skill eliminates incomplete ticket escalations, "ticket ping-pong", and 45-minute manual Event Viewer hunts by pairing a zero-dependency, read-only PowerShell collector (`scripts/collect-win-triage.ps1`) with a deterministic 6-domain diagnostic methodology.

## Operating Rules & Safety Guardrails
1. **Read-Only First Principle:** Never instruct the technician to execute destructive or disruptive commands (`chkdsk /f /r` forcing unexpected reboots, registry wipes, `bcdedit` edits, driver uninstalls, or user profile deletions) before gathering and verifying telemetry.
2. **Evidence-Backed Root Cause:** Every diagnostic claim must cite a verified finding (Event ID, provider, timestamp, resource metric, or registry flag) from the telemetry bundle, cross-referenced against `references/windows-event-ids-and-thresholds.md`.
3. **Automated PII Sanitization:** When `--generate-proof-of-work` or external sharing is requested, ensure all hostnames (`ENDPOINT-REDACTED`), usernames (`USER-REDACTED`), domain names (`corp.example.internal`), and internal IPs (`10.x.xxx.xxx`) are masked.
4. **No Hallucinated Fixes:** Never prescribe generic consumer advice ("run `sfc /scannow` and reinstall Windows") unless Component-Based Servicing (CBS) or Windows Error Reporting corruption is explicitly proven in the logs.

---

## Step 1: Telemetry & Input Acquisition

Determine how the technician is interacting with the target endpoint:

### Mode A: Zero-Friction Remote One-Liner (Preferred)
Instruct the technician to run this command in PowerShell on the user's PC (or via ScreenConnect, NinjaOne, Datto, or Splashtop remote terminal):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/ToritsejuBoyo/win-endpoint-triage/main/scripts/collect-win-triage.ps1 | iex"
```
Or with custom lookback and sanitization flags:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { $(irm https://raw.githubusercontent.com/ToritsejuBoyo/win-endpoint-triage/main/scripts/collect-win-triage.ps1) } -HoursBack 48 -Sanitize"
```
Ask the technician to upload or paste the generated `win-triage-<timestamp>.json` file.

### Mode B: Local Script Execution
If the repository is cloned locally:
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\collect-win-triage.ps1 -HoursBack 48 -Sanitize
```

### Mode C: Interactive Fallback Mode (Locked-Down Endpoints)
If corporate policy or environment restrictions prevent script execution, request these 4 targeted read-only one-liners from the technician:
1. **Uptime & Fast Startup:** `(Get-CimInstance Win32_OperatingSystem).LastBootUpTime; (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power').HiberbootEnabled`
2. **Drive C: Free Space:** `Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" | Select Size, FreeSpace`
3. **Recent Critical/Error Events:** `Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 15 | Select TimeCreated, Id, ProviderName, Message | Format-List`
4. **Entra SSO State:** `dsregcmd /status | Select-String 'AzureAdJoined','AzureAdPrt','DomainJoined'`

---

## Step 2: 6-Domain Diagnostic Evaluation Workflow

Execute the analysis across all six domains in strict sequence:

### Domain 1: System Stability, Reboot Hygiene & Fast Startup
1. Inspect `SystemBaseline.UptimeDays`, `SystemBaseline.LastBootUpTime`, and `PendingReboot`.
2. Inspect `ReliabilitySummary.StabilityIndexScore1To10` (Windows Reliability Index from `Win32_ReliabilityStabilityMetrics`).
   - Score `< 4.0`: Endpoint is in chronic instability (frequent app/system crashes).
   - `UptimeDays > 14` AND `PendingReboot.FastStartupEnabled == true`: Flag **Stale Kernel Session**. Fast Startup saves kernel state to disk on shutdown, preventing Windows Update patches from initializing and creating zombie driver states.

### Domain 2: Storage Health, Disk I/O & BitLocker Posture
1. Check `Disks`:
   - System Drive (`C:`) free space `< 10%` or `< 10 GB` triggers **Critical Resource Starvation** (blocks pagefile expansion, VSS snapshots, and temp space).
2. Scan `RecentCriticalEvents` for:
   - Event ID `7` (`disk` bad block) -> **Physical media failure**. Immediate drive backup/swap.
   - Event ID `129` / `153` (`storahci` / `stornvme` controller reset/IO timeout) -> **Controller hang or failing SSD**.
   - Event ID `55` (`Ntfs` corruption) -> File system metadata corruption.
3. Check `BitLocker`: If `ProtectionStatus == 'Unprotected'`, flag compliance gap.

### Domain 3: Kernel Crashes, BSODs & Application Exception Stacks
1. Check for Unexpected Shutdowns:
   - Event ID `41` (`Kernel-Power`) + Event ID `1001` (`BugCheck`): Extract stop code (e.g. `0x0000009F`, `0x00000116`, `0x0000001A`) and minidump path (`C:\Windows\Minidump\*.dmp`).
   - If Event ID `41` has `BugcheckCode == 0`, suspect sudden power interruption, PSU/battery drop, or forced 5-second power button hold.
2. Check Application Errors:
   - Event ID `1000` (`Application Error`): Extract Faulting Application, Faulting Module (DLL), and Exception Code:
     * `0xc0000005` (`STATUS_ACCESS_VIOLATION`): Memory access violation / bad DLL hook.
     * `0xc0000409` (`STATUS_STACK_BUFFER_OVERRUN`): Security fast-fail.
   - Event ID `1002` (`Application Hang`): UI thread blocked on disk I/O, hung printer spooler, or SMB timeout.
   - Event ID `4101` (`Display` driver TDR reset): GPU driver timed out and recovered.

### Domain 4: Modern Workplace Identity, Entra PRT & Network DNS
1. Inspect `EntraIdentity`:
   - If `AzureAdPrt == 'NO'` on an Entra-joined or Hybrid-joined device: Flag **Missing Primary Refresh Token (PRT)**. This causes silent Office 365, Teams, and OneDrive authentication prompts/loops.
2. Inspect `NetworkAdapters`:
   - Check for APIPA address (`169.254.x.x`), missing default gateway, or public DNS (`8.8.8.8`, `1.1.1.1`) configured on an Active Directory domain endpoint (causing Event ID `5719` `NETLOGON` and Event ID `1129` `GroupPolicy` failures).

### Domain 5: Hardware Health, Thermal Throttling & Battery Wear
1. Inspect `RecentCriticalEvents` for Event ID `37` (`Microsoft-Windows-Kernel-Processor-Power`):
   - "The speed of processor X is being limited by system firmware."
   - Indicates **Thermal Throttling or Power Brick Under-Wattage** (common on laptops with clogged heat pipes or third-party USB-C chargers throttling CPU to 0.79 GHz).
2. Inspect `BatteryHealth`: Check remaining charge and runtime for degraded cells.

### Domain 6: Background Services & Security Agent Conflicts
1. Inspect `StoppedAutoServices`:
   - Distinguish benign trigger-start services from critical infrastructure services (`Winmgmt`, `LanmanWorkstation`, `Dhcp`, `Dnscache`, `Sense`, `CSFalconService`).
2. Identify top memory consumers in `TopProcessesByMemory` and cross-reference with Event ID `2004` (`Resource-Exhaustion-Detector`).

---

## Step 3: "Can L1 Fix It Now?" Decision Tree

Provide an unequivocal verdict to the technician:

```text
Decision Logic:
1. Is the root cause physical hardware failure (Disk Bad Block Event 7, failing RAM, dying battery)?
   -> NO. L1 cannot fix. Escalate immediately for hardware replacement.
2. Is the root cause severe file system / disk controller failure (Event 153 loop, NVMe drop)?
   -> NO. L1 cannot fix safely. Escalate to L2 Desktop Engineering.
3. Is the root cause high uptime + Fast Startup session lock (>14 days) + pending update?
   -> YES. Instruct clean reboot (Restart-Computer -Force) and verify.
4. Is the root cause disk space exhaustion on C: (>90% full)?
   -> YES. Instruct safe temp file cleanup / cleanmgr and verify.
5. Is the root cause Entra PRT missing?
   -> YES. Instruct user lock/unlock, dsregcmd /debug, or PRT renewal.
```

---

## Step 4: Output Deliverable Structure

Always populate and generate the completed assessment using the templates in `assets/l2-escalation-brief-template.md`:

1. **Executive Triage Summary:**
   - Primary Suspected Cause & Confidence Rating (%).
   - Secondary Contributing Factors.
   - "Can L1 Fix It Now?" Verdict (YES with commands / NO with escalation reason).
2. **Correlated Evidence Matrix:**
   - Table mapping Subsystem, Event ID, Timestamp, Metric, and Technical Meaning.
3. **Safe L1 Action Plan:**
   - Numbered, non-destructive commands with expected outputs and verification checks.
4. **Copy-Paste Multi-ITSM Escalation Notes:**
   - **Format 1:** Rich Markdown (for ServiceNow, Jira Service Management, Confluence).
   - **Format 2:** Plaintext Key-Value Table (for ConnectWise Manage, HaloPSA, Autotask).

---

## Step 5: Portfolio / Proof-of-Work Mode (`--generate-proof-of-work`)

When invoked with `--generate-proof-of-work`, strip all PII and append:
- **Case Study Title:** e.g., "Enterprise Endpoint Triage: Root-Cause Isolation of Latent NVMe Controller Timeouts".
- **Problem Statement & Business Impact:** Quantified productivity loss.
- **Telemetry & Investigative Technique:** How PowerShell telemetry correlation beat manual Event Viewer hunting.
- **Root Cause & Resolution:** Technical post-mortem.
- **Resume-Ready Bullet Point:** Example:
  > *"Diagnosed complex Windows endpoint performance degradation across 45+ enterprise devices by analyzing Event ID 153/4101 telemetry and Entra PRT states, slashing average Mean Time to Triage (MTTT) from 45 minutes to under 3 minutes."*
