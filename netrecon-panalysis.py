import subprocess
import os
import re
from datetime import datetime
import matplotlib.pyplot as plt

# quick settings (change if needed)
NMAP_FILE = "scan_results.txt"
PCAP_FILE = "packets.pcap"
REPORT_FILE = "network_report.txt"
IFACE = "en0"  

def run_nmap(target):
    print(f"[scan] Nmap scanning {target} ...")
    with open(NMAP_FILE, "w") as f:
        subprocess.run(["nmap", "-A", target], stdout=f)
    print(f"[done] results in {NMAP_FILE}")

def capture_packets(seconds=30):
    print(f"[cap] grabbing packets for {seconds}s on {IFACE}")
    subprocess.run(["tshark", "-i", IFACE, "-a", f"duration:{seconds}", "-w", PCAP_FILE])
    print(f"[done] packets saved -> {PCAP_FILE}")

def parse_nmap():
    print("[parse] looking through Nmap output...")
    ports = []
    os_guess = None
    services = []

    with open(NMAP_FILE, "r") as f:
        for line in f:
            if re.search(r"\d+/tcp\s+open", line):
                ports.append(line.strip())
            if "Running:" in line:
                os_guess = line.strip()
            if re.search(r"\d+/tcp\s+open\s+\w+", line):
                services.append(line.strip())
    return ports, os_guess, services

def analyze_pcap():
    print("[parse] reading pcap for bad protocols...")
    issues = []

    def tshark_search(expr):
        out = subprocess.run(
            ["tshark", "-r", PCAP_FILE, "-Y", expr],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )
        return out.stdout.decode()

    
    if "ftp" in tshark_search("ftp"):
        issues.append("FTP found (cleartext)")
    if "telnet" in tshark_search("telnet"):
        issues.append("Telnet found (super insecure)")
    if "irc" in tshark_search("tcp.port == 6667"):
        issues.append("IRC traffic found (possible malware C2)")
    if "http" in tshark_search("http"):
        issues.append("HTTP found (unencrypted web)")
    if "ssh" in tshark_search("ssh"):
        issues.append("SSH found (secure remote access)")

    return issues

def write_report(ports, os_guess, services, issues):
    with open(REPORT_FILE, "w") as f:
        f.write(f"Network Recon + Packet Analysis\nGenerated {datetime.now()}\n\n")
        f.write("=== Open Ports ===\n")
        f.write("\n".join(ports) + "\n\n")

        f.write("=== OS Guess ===\n")
        f.write(f"{os_guess or 'Unknown'}\n\n")

        f.write("=== Services ===\n")
        f.write("\n".join(services) + "\n\n")

        f.write("=== Protocol Issues ===\n")
        f.write("\n".join(issues) + "\n")

    print(f"[ok] report written to {REPORT_FILE}")

def visualize(ports, services, issues):
    # open ports chart
    if ports:
        plt.bar([p.split("/")[0] for p in ports], [1]*len(ports))
        plt.title("Open TCP Ports")
        plt.show()

    # service freq chart
    if services:
        freq = {}
        for s in services:
            name = s.split()[-1]
            freq[name] = freq.get(name, 0) + 1
        plt.bar(freq.keys(), freq.values())
        plt.title("Service Frequency")
        plt.show()

    # protocol issues chart
    if issues:
        labels = [i.split()[0] for i in issues]
        plt.bar(labels, [1]*len(labels), color="red")
        plt.title("Protocol Warnings")
        plt.show()

def main():
    target = input("Target (IP or subnet): ").strip()
    secs = input("Capture duration in sec (default 30): ").strip()
    secs = int(secs) if secs else 30

    run_nmap(target)
    capture_packets(secs)

    ports, os_guess, services = parse_nmap()
    issues = analyze_pcap()

    write_report(ports, os_guess, services, issues)
    visualize(ports, services, issues)

if __name__ == "__main__":
    main()
