import subprocess
from datetime import datetime

# ==============================
# CONFIGURATION
# ==============================
INTERFACE = "Wi-Fi 3"   # your interface
DURATION = 120          # capture time in seconds
OUTPUT_FILE = "realtime_capture.pcap"


# ==============================
# START CAPTURE
# ==============================

print(f"[{datetime.now()}] Starting packet capture on {INTERFACE}...")

# Tshark command
command = [
    "tshark",
    "-i", INTERFACE,
    "-a", f"duration:{DURATION}",
    "-w", OUTPUT_FILE
]

try:
    subprocess.run(command, check=True)
    print(f"[{datetime.now()}] Capture complete. Saved to {OUTPUT_FILE}")

except subprocess.CalledProcessError as e:
    print("Error during capture:", e)