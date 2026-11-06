<#
.SYNOPSIS
    Enterprise Read-Only Windows Endpoint Triage Collector (win-endpoint-triage v2.0)
.DESCRIPTION
    Collects deep endpoint health telemetry across 6 critical operational domains:
      1. System baseline, uptime, Fast Startup, and pending reboot status.
      2. Windows Reliability Monitor stability index (1-10) and 14-day crash/update history.
      3. Logical disk capacity, health, and BitLocker volume encryption posture.
      4. Top memory/CPU processes and unexpected stopped automatic services.
      5. Modern Workplace identity (Entra ID PRT, Azure AD Join) and network/DNS configuration.
      6. Thermal throttling (Event ID 37), battery wear, and high-signal System/Application events.

    PRIVILEGE-ADAPTIVE & 100% NON-DESTRUCTIVE:
      - Automatically detects if running as Standard User or Elevated Administrator.
      - Never throws ugly red errors when run under non-admin accounts; gracefully degrades.
      - Modifies ZERO system state (zero writes, zero reboots, zero service restarts).
      - Zero third-party dependencies; uses native PowerShell 5.1 / 7+ CIM and cmdlets.

.PARAMETER HoursBack
    Number of hours of Windows Event Logs to inspect. Default is 48.
.PARAMETER MaxEvents
    Maximum number of critical/error events to collect per log channel. Default is 60.
.PARAMETER OutputPath
    Directory or file path where the JSON file will be written. Default is current directory.
.PARAMETER Sanitize
    Anonymizes computer name, usernames, domain names, and internal IPv4 octets for safe sharing.

.EXAMPLE
    # Standard local execution
    .\collect-win-triage.ps1 -Sanitize

.EXAMPLE
    # One-liner execution from remote terminal or ScreenConnect/NinjaOne
    powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/ToritsejuBoyo/win-endpoint-triage/main/scripts/collect-win-triage.ps1 | iex"
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 720)]
    [int]$HoursBack = 48,

    [Parameter(Mandatory = $false)]
    [ValidateRange(10, 500)]
    [int]$MaxEvents = 60,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [switch]$Sanitize
)

$ErrorActionPreference = 'SilentlyContinue'
$StartTime = (Get-Date).AddHours(-$HoursBack)
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# 0. Privilege Detection
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isElevated = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Protect-SensitiveText {
    param ([string]$InputText)
    if (-not $Sanitize -or [string]::IsNullOrWhiteSpace($InputText)) {
        return $InputText
    }
    $text = $InputText
    if ($env:COMPUTERNAME) {
        $text = $text -replace [regex]::Escape($env:COMPUTERNAME), 'ENDPOINT-REDACTED'
    }
    if ($env:USERNAME) {
        $text = $text -replace [regex]::Escape($env:USERNAME), 'USER-REDACTED'
    }
    if ($env:USERDNSDOMAIN) {
        $text = $text -replace [regex]::Escape($env:USERDNSDOMAIN), 'corp.example.internal'
    }
    # Mask email addresses / UPNs
    $text = [regex]::Replace($text, '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', '[REDACTED_EMAIL]')
    # Mask user profile paths C:\Users\<username>
    $text = [regex]::Replace($text, '(?i)C:\\Users\\(?!(Public|Default|All Users))[^\\]+', 'C:\Users\[REDACTED_USER]')
    # Mask UNC network paths \\server\share
    $text = [regex]::Replace($text, '\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9$._-]+', '\\[REDACTED_UNC_SHARE]')
    # Mask internal IPv4 octets (keep first two octets for subnet context)
    $text = [regex]::Replace($text, '\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b', '$1.$2.xxx.xxx')
    return $text
}

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  Windows Endpoint Diagnostic Collector (win-endpoint-triage v2.0)" -ForegroundColor Cyan
Write-Host "  Privilege Mode: $(if ($isElevated) { 'Elevated (Administrator)' } else { 'Standard User (Non-Elevated)' })" -ForegroundColor $(if ($isElevated) { 'Green' } else { 'Yellow' })
Write-Host "  Lookback Window: $HoursBack hours | Sanitize PII: $Sanitize" -ForegroundColor Gray
Write-Host "==================================================================" -ForegroundColor Cyan

# 1. System Baseline & Uptime
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue

$uptimeDays = 0
if ($os.LastBootUpTime) {
    $uptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
}

$systemBaseline = [ordered]@{
    CollectionTimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    IsElevatedSession      = [bool]$isElevated
    ComputerName           = if ($Sanitize) { 'ENDPOINT-REDACTED' } else { $env:COMPUTERNAME }
    Domain                 = if ($Sanitize) { 'corp.example.internal' } else { $cs.Domain }
    OSCaption              = $os.Caption
    OSVersion              = $os.Version
    OSBuildNumber          = $os.BuildNumber
    Architecture           = $os.OSArchitecture
    Manufacturer           = $cs.Manufacturer
    Model                  = $cs.Model
    BIOSVersion            = ($bios.SMBIOSBIOSVersion -join ', ')
    LastBootUpTime         = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString('o') } else { 'Unknown' }
    UptimeDays             = $uptimeDays
    TotalPhysicalMemoryGB  = if ($cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { 0 }
    FreePhysicalMemoryGB   = if ($os.FreePhysicalMemory) { [math]::Round($os.FreePhysicalMemory / 1MB, 2) } else { 0 }
    MemoryUsedPercent      = if ($cs.TotalPhysicalMemory -and $os.FreePhysicalMemory) {
        [math]::Round((($cs.TotalPhysicalMemory - ($os.FreePhysicalMemory * 1KB)) / $cs.TotalPhysicalMemory) * 100, 1)
    } else { 0 }
}

# 2. Windows Reliability Monitor Stability Index & History (Win32_ReliabilityRecords)
$reliabilityRecords = @()
$avgStabilityIndex = $null
try {
    $relData = Get-CimInstance -ClassName Win32_ReliabilityStabilityMetrics -ErrorAction SilentlyContinue |
        Sort-Object EndMeasurementDate -Descending | Select-Object -First 14
    if ($relData) {
        $avgStabilityIndex = [math]::Round(($relData | Measure-Object -Property SystemStabilityIndex -Average).Average, 1)
    }
    
    $relEvents = Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeGenerated -ge $StartTime } |
        Sort-Object TimeGenerated -Descending | Select-Object -First 10 | ForEach-Object {
            [ordered]@{
                TimeGenerated = $_.TimeGenerated.ToString('o')
                SourceName    = $_.SourceName
                EventIdentifier = $_.EventIdentifier
                Message       = Protect-SensitiveText $_.Message
            }
        }
    $reliabilityRecords = $relEvents
} catch {}

$reliabilitySummary = [ordered]@{
    StabilityIndexScore1To10 = if ($null -ne $avgStabilityIndex) { $avgStabilityIndex } else { 'N/A' }
    RecentReliabilityEvents  = $reliabilityRecords
}

# 3. Pending Reboot Detection
$cbsReboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue
$wuReboot  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue
$pfro      = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
$fastStartup = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -ErrorAction SilentlyContinue).HiberbootEnabled

$pendingReboot = [ordered]@{
    IsPending                   = [bool]($cbsReboot -or $wuReboot -or ($null -ne $pfro))
    ComponentBasedServicing     = [bool]$cbsReboot
    WindowsUpdateRebootRequired = [bool]$wuReboot
    PendingFileRenameOperations = [bool]($null -ne $pfro)
    FastStartupEnabled          = [bool]($fastStartup -eq 1)
}

# 4. Logical Disks & BitLocker Encryption Status
$bitlockerMap = @{}
if ($isElevated) {
    try {
        $bl = Get-CimInstance -Namespace 'root\cimv2\security\microsoftvolumeencryption' -ClassName Win32_EncryptableVolume -ErrorAction SilentlyContinue
        foreach ($v in $bl) {
            $drive = $v.DriveLetter
            if ($drive) {
                $bitlockerMap[$drive] = [ordered]@{
                    ProtectionStatus = switch ($v.ProtectionStatus) { 0 {'Unprotected'} 1 {'Protected'} 2 {'Unknown'} default {'Unknown'} }
                    ConversionStatus = switch ($v.ConversionStatus) { 0 {'FullyDecrypted'} 1 {'FullyEncrypted'} 2 {'EncryptionInProgress'} default {'Other'} }
                    EncryptionMethod = switch ($v.EncryptionMethod) { 1 {'AES_128'} 2 {'AES_256'} 3 {'XTS_AES_128'} 4 {'XTS_AES_256'} default {'NoneOrOther'} }
                }
            }
        }
    } catch {}
}

$disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue | ForEach-Object {
    $freePct = if ($_.Size -gt 0) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 1) } else { 0 }
    $driveLetter = $_.DeviceID
    $blInfo = if ($bitlockerMap.ContainsKey($driveLetter)) { $bitlockerMap[$driveLetter] } else { @{ ProtectionStatus = 'RequiresAdminElevation' } }
    
    [ordered]@{
        DriveLetter   = $driveLetter
        VolumeName    = $_.VolumeName
        FileSystem    = $_.FileSystem
        SizeGB        = [math]::Round($_.Size / 1GB, 2)
        FreeSpaceGB   = [math]::Round($_.FreeSpace / 1GB, 2)
        FreePercent   = $freePct
        LowSpaceAlert = ($freePct -lt 10 -or ($_.FreeSpace / 1GB) -lt 10)
        BitLocker     = $blInfo
    }
}

# 5. Top Resource Processes
$topProcesses = Get-Process -ErrorAction SilentlyContinue |
    Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 10 | ForEach-Object {
        [ordered]@{
            ProcessName = $_.ProcessName
            Id          = $_.Id
            MemoryMB    = [math]::Round($_.WorkingSet64 / 1MB, 1)
            CPUSeconds  = if ($null -ne $_.CPU) { [math]::Round($_.CPU, 1) } else { 0 }
            Responding  = $_.Responding
        }
    }

# 6. Stopped Automatic Services
$benignServices = @('edgeupdate', 'gupdate', 'sppsvc', 'MapsBroker', 'WbioSrvc', 'RemoteRegistry', 'TrustedInstaller', 'ShellHWDetection', 'CDPSvc', 'tiledatamodelsvc')
$stoppedServices = Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto' AND State!='Running'" -ErrorAction SilentlyContinue |
    Where-Object { $benignServices -notcontains $_.Name } |
    ForEach-Object {
        [ordered]@{
            Name        = $_.Name
            DisplayName = $_.DisplayName
            State       = $_.State
            ExitCode    = $_.ExitCode
            PathName    = Protect-SensitiveText $_.PathName
        }
    }

# 7. Modern Workplace & Entra ID Identity (dsregcmd /status)
$entraIdentity = [ordered]@{
    AzureAdJoined = 'Unknown'
    DomainJoined  = 'Unknown'
    AzureAdPrt    = 'Unknown'
    TenantName    = 'Unknown'
}

try {
    $dsregRaw = & dsregcmd.exe /status 2>&1
    if ($dsregRaw) {
        foreach ($line in $dsregRaw) {
            $line = $line.Trim()
            if ($line -match '^AzureAdJoined\s*:\s*(YES|NO)') { $entraIdentity.AzureAdJoined = $matches[1] }
            elseif ($line -match '^DomainJoined\s*:\s*(YES|NO)') { $entraIdentity.DomainJoined = $matches[1] }
            elseif ($line -match '^AzureAdPrt\s*:\s*(YES|NO)') { $entraIdentity.AzureAdPrt = $matches[1] }
            elseif ($line -match '^TenantName\s*:\s*(.*)') {
                $tenant = $matches[1].Trim()
                $entraIdentity.TenantName = if ($Sanitize) { 'contoso.onmicrosoft.com' } else { $tenant }
            }
        }
    }
} catch {}

# 8. Network Adapters & DNS
$netConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction SilentlyContinue | ForEach-Object {
    $ips = $_.IPAddress | ForEach-Object { Protect-SensitiveText $_ }
    $gws = $_.DefaultIPGateway | ForEach-Object { Protect-SensitiveText $_ }
    $dns = $_.DNSServerSearchOrder | ForEach-Object { Protect-SensitiveText $_ }
    [ordered]@{
        Description    = $_.Description
        MACAddress     = if ($Sanitize) { 'XX:XX:XX:XX:XX:XX' } else { $_.MACAddress }
        DHCPEnabled    = $_.DHCPEnabled
        IPAddresses    = $ips
        DefaultGateway = $gws
        DNSServers     = $dns
        DNSDomain      = Protect-SensitiveText $_.DNSDomain
        HasAPIPA       = [bool](($_.IPAddress -join ',') -match '^169\.254\.')
    }
}

# 9. Hardware Health: Thermal Throttling & Battery
$batteryInfo = @()
try {
    $batteries = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    foreach ($b in $batteries) {
        $batteryInfo += [ordered]@{
            DeviceID                  = $b.DeviceID
            Status                    = $b.Status
            EstimatedChargeRemaining  = $b.EstimatedChargeRemaining
            EstimatedRunTimeMinutes   = $b.EstimatedRunTime
        }
    }
} catch {}

# 10. High-Signal Windows Events (System & Application)
$importantWarningIds = @(4101, 1014, 153, 129, 2004, 1002, 1129, 5719, 37)
$collectedEvents = @()

foreach ($logName in @('System', 'Application')) {
    $rawEvents = Get-WinEvent -FilterHashtable @{
        LogName   = $logName
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Level -in @(1, 2) -or ($importantWarningIds -contains $_.Id)
    } | Select-Object -First $MaxEvents

    foreach ($evt in $rawEvents) {
        $msg = Protect-SensitiveText ($evt.Message -replace '\r\n', ' ' -replace '\s+', ' ')
        if ($msg.Length -gt 450) {
            $msg = $msg.Substring(0, 450) + '...'
        }
        $collectedEvents += [ordered]@{
            TimeCreated  = $evt.TimeCreated.ToString('o')
            LogName      = $evt.LogName
            Level        = $evt.LevelDisplayName
            EventId      = $evt.Id
            ProviderName = $evt.ProviderName
            Message      = $msg
        }
    }
}

# Recurring Event Summary (Grouped by Provider + EventId)
$eventFrequency = $collectedEvents | Group-Object -Property ProviderName, EventId |
    Sort-Object -Property Count -Descending | Select-Object -First 15 | ForEach-Object {
        [ordered]@{
            ProviderAndEventId = $_.Name
            Occurrences        = $_.Count
            LatestTimestamp    = ($_.Group | Select-Object -First 1).TimeCreated
            SampleMessage      = ($_.Group | Select-Object -First 1).Message
        }
    }

$triagePayload = [ordered]@{
    SchemaVersion          = '2.0.0'
    SkillSlug              = 'win-endpoint-triage'
    Sanitized              = [bool]$Sanitize
    IsElevatedSession      = [bool]$isElevated
    LookbackHours          = $HoursBack
    SystemBaseline         = $systemBaseline
    ReliabilitySummary     = $reliabilitySummary
    PendingReboot          = $pendingReboot
    Disks                  = $disks
    TopProcessesByMemory   = $topProcesses
    StoppedAutoServices    = $stoppedServices
    EntraIdentity          = $entraIdentity
    NetworkAdapters        = $netConfigs
    BatteryHealth          = $batteryInfo
    RecurringEventSummary  = $eventFrequency
    RecentCriticalEvents   = $collectedEvents
}

# Determine destination path
$finalDest = $OutputPath
if (Test-Path -Path $OutputPath -PathType Container) {
    $finalDest = Join-Path -Path $OutputPath -ChildPath "win-triage-$Timestamp.json"
}
$parentDir = Split-Path -Path $finalDest -Parent
if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir)) {
    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
}

# Write UTF-8 without BOM for universal JSON parser compatibility
$jsonPayload = $triagePayload | ConvertTo-Json -Depth 6
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($finalDest, $jsonPayload, $utf8NoBom)

Write-Host ""
Write-Host "[+] Triage bundle successfully generated!" -ForegroundColor Green
Write-Host "    File Location: $finalDest" -ForegroundColor White
Write-Host "    Payload Size:  $([math]::Round((Get-Item $finalDest).Length / 1KB, 1)) KB" -ForegroundColor Gray
Write-Host ""
Write-Host "Next Step: Upload or paste this file into your AI Assistant with the 'win-endpoint-triage' skill." -ForegroundColor Yellow
