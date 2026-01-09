import re
from collections import defaultdict
from datetime import datetime

LOG_FILE = "sample_auth.log"
THRESHOLD = 4

def analyze_logs():
    attempts = defaultdict(int)

    with open(LOG_FILE, "r") as file:
        for line in file:
            if "Failed password" in line:
                ip = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
                if ip:
                    attempts[ip[0]] += 1

    print("\n=== CyberShield Security Report ===")
    print("Date:", datetime.now())
    print("----------------------------------")

    for ip, count in attempts.items():
        if count >= THRESHOLD:
            print(f"[ALERT] Suspicious activity from {ip} ({count} failed attempts)")

    print("\nAnalysis completed.")

if __name__ == "__main__":
    print("TurkishScholar-CyberShield Started...")
    analyze_logs()
