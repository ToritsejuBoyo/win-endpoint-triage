# Windows Endpoint Event IDs, Exception Codes & Diagnostic Thresholds Reference

This reference is used by the `win-endpoint-triage` skill to map raw Windows telemetry to root-cause hypotheses with high precision.

---

## 1. Critical System & Kernel Event IDs (`System` Log)

| Event ID | Provider / Source | Severity | Technical Meaning | Primary Root Cause & Next Step |
| --- | --- | --- | --- | --- |
| **41** | `Microsoft-Windows-Kernel-Power` | Critical | System rebooted without cleanly shutting down first. | Check `BugcheckCode` in Event XML. If `BugcheckCode == 0`, suspect sudden power loss, PSU/battery fault, thermal trip, or forced 5-second power button hold. If non-zero, correlate with Event ID `1001`. |
| **1001** | `Microsoft-Windows-WER-SystemErrorReporting` / `BugCheck` | Error | System rebooted from a BugCheck (BSOD). | Extract hex stop code (`0x0000009F`, `0x00000116`, etc.) and minidump path (`C:\Windows\Minidump\*.dmp`). Escalate dump analysis if recurring. |
| **6008** | `EventLog` | Error | Previous system shutdown at time/date was unexpected. | Confirms hard freeze or power loss timestamp. Compare timestamp with UPS/power logs or user activity. |
| **161** | `volmgr` | Error | Dump file generation failed due to error during dump creation. | Often caused by missing/disabled pagefile on `C:`, BitLocker filter driver lock, or failing NVMe/SSD controller dropping offline during crash. |
| **7** | `disk` | Error | The device `\Device\Harddisk0\DR0` has a bad block. | Physical NAND/platter media degradation. Immediate backup and hardware replacement required; do not waste time on software reinstalls. |
| **51 / 55** | `disk` / `Ntfs` | Error | An error was detected on device during a paging operation / NTFS file system structure is corrupt. | File system corruption or storage bus instability. Schedule maintenance window for `chkdsk C: /scan` (online read-only check first). |
| **129 / 153** | `storahci` / `stornvme` / `disk` | Warning | Reset to device `\Device\RaidPort0` was issued / IO operation retried. | Storage controller hang, outdated NVMe firmware, or aggressive PCIe Link State Power Management (ASPM). Causes 30-second system freezes. |
| **37** | `Microsoft-Windows-Kernel-Processor-Power` | Warning | The speed of processor X in group Y is being limited by system firmware. | **Thermal Throttling or Power Supply Inadequacy.** CPU is artificially throttled to base or minimum speed (e.g. 0.79 GHz) due to clogged fans, failing thermal paste, or an under-wattage charger. |
| **2004** | `Microsoft-Windows-Resource-Exhaustion-Detector` | Warning | Windows successfully diagnosed a low virtual memory condition. | Extract the top 3 processes named in the event payload (commit charge in bytes). Check if pagefile is manually capped or `C:` drive is full. |
| **4101** | `Display` | Warning | Display driver `nvlddmkm` / `amdkmdag` / `igfx` stopped responding and has successfully recovered. | GPU Timeout Detection and Recovery (TDR). Causes black-screen flicker or Teams/Browser hardware acceleration crashes. |
| **1014** | `Microsoft-Windows-DNS-Client` | Warning | Name resolution for the name timed out after none of the configured DNS servers responded. | Inspect `NetworkAdapters.DNSServers`. Common when VPN split-tunnel leaves stale DNS resolvers or ISP router drops UDP/53. |
| **5719** | `NETLOGON` | Error | This computer was not able to set up a secure session with a domain controller. | Endpoint has non-domain DNS configured (e.g., `8.8.8.8` or `1.1.1.1`), VLAN routing blocks TCP/UDP 88/389/445, or secure channel broken (`Test-ComputerSecureChannel`). |
| **1129** | `Microsoft-Windows-GroupPolicy` | Error | Processing of Group Policy failed because of lack of network connectivity to a domain controller. | Downstream symptom of DNS mismatch (`1014`) or `NETLOGON` (`5719`) failure. |
| **7000 / 7009 / 7031 / 7034** | `Service Control Manager` | Error | Service failed to start / timed out (30000ms) / terminated unexpectedly. | Identify the failing service binary and exit code. Check if dependent services or service account passwords expired. |

---

## 2. Application Crash & Hang Event IDs (`Application` Log)

| Event ID | Provider / Source | Key Payload Fields to Extract | Common Exception Codes & Meaning |
| --- | --- | --- | --- |
| **1000** | `Application Error` | `Faulting application name`, `Faulting module name`, `Exception code`, `Faulting offset` | - `0xc0000005` (`STATUS_ACCESS_VIOLATION`): Null pointer dereference, buggy third-party DLL injection/AV hook, or faulty RAM.<br>- `0xc0000409` (`STATUS_STACK_BUFFER_OVERRUN`): Fast-fail security check triggered.<br>- `0xc00000fd` (`STATUS_STACK_OVERFLOW`): Infinite recursion in app/plugin.<br>- `0xe0434352`: Unhandled .NET CLR exception (check preceding Event ID `1026`). |
| **1002** | `Application Hang` | `Hanging application name`, `Hang type` | UI thread blocked waiting on synchronous disk I/O, mapped network drive (`SMB` timeout), or printer spooler (`spoolsv.exe`) hang. |
| **1026** | `.NET Runtime` | Stack trace & unhandled exception class | Pinpoints exact .NET configuration file corruption, missing runtime dependency, or TLS/certificate failure. |
| **1001** | `Windows Error Reporting` | `Bucket ID`, `CabGuid`, `Problem signature P1-P9` | Correlates with `1000`/`1002` or `LiveKernelEvent` (e.g., `141` hardware GPU error). |

---

## 3. Modern Workplace & Entra ID Diagnostics (`dsregcmd /status`)

| Parameter | Healthy Value | Degraded / Failing Value | Impact & Resolution |
| --- | --- | --- | --- |
| **AzureAdJoined** | `YES` | `NO` | Device is not cloud-joined. If expected to be Intune-managed, enrollment failed. |
| **DomainJoined** | `YES` / `NO` | Matches organization topology | If on-prem AD joined, check line of sight to Domain Controllers. |
| **AzureAdPrt** | `YES` | `NO` | **Critical SSO Failure.** Primary Refresh Token missing. Causes repeated login prompts across Outlook, Teams, OneDrive, and SharePoint. Re-issue via `dsregcmd /debug` or user relog. |
| **EnterpriseJoined** | `NO` (typically) | `YES` | On-prem DRS join (legacy). |

---

## 4. Operational Threshold Matrix

| Metric / Indicator | Healthy Range | Warning Threshold | Critical / Action Required |
| --- | --- | --- | --- |
| **Reliability Stability Index** | `7.0 – 10.0` | `4.0 – 6.9` | `< 4.0` (Chronic application / OS crashes) |
| **Uptime (`UptimeDays`)** | `0 – 7 days` | `8 – 14 days` | `> 14 days` (Fast Startup kernel state stale) |
| **System Drive (`C:`) Free Space** | `> 20%` and `> 25 GB` | `10% – 15%` or `10 – 20 GB` | `< 10%` or `< 10 GB` (Blocks Windows Update, pagefile growth, and VSS snapshots) |
| **Physical Memory Usage** | `< 80%` | `80% – 90%` | `> 90%` accompanied by Event ID `2004` |
| **Domain Endpoint DNS Servers** | Internal AD DC IPs only | Mixed Internal + Secondary slow DC | Any public DNS (`8.8.8.8`, `1.1.1.1`, ISP router IP) on an AD-joined NIC |
| **Battery Health** | Full charge >= 80% of design | 60% – 79% of design | < 60% of design capacity (Swollen battery or shutdown risk) |

---

## 5. Safe One-Liner Verification Commands (For L1 Analysts)

```powershell
# 1. Check Uptime & Fast Startup State
[PSCustomObject]@{ LastBoot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime; FastStartup=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power').HiberbootEnabled }

# 2. Pull Top 15 System & App Errors from Last 24 Hours
Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 15 | Select-Object TimeCreated, LogName, Id, ProviderName, Message | Format-List

# 3. Verify Active Directory Secure Channel & DNS (Domain Machines Only)
Test-ComputerSecureChannel -Verbose; Get-DnsClientServerAddress -AddressFamily IPv4

# 4. Check Entra ID PRT Status
dsregcmd /status | Select-String 'AzureAdJoined','AzureAdPrt','DomainJoined'
```
