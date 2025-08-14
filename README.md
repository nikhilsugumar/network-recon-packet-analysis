# Network Recon + Packet Analysis

Python wrapper around Nmap + Tshark to run basic recon, capture packets, flag insecure protocols, and produce a simple report/visuals.

## Requirements
- Nmap
- Wireshark/Tshark
- Python 3 + matplotlib

## Run
python recon.py
# then follow prompts

## Notes
- Default interface is "en0" (macOS). Change INTERFACE if needed.
- Packet capture may require sudo and permission in your environment. Only run where you have authorization.
