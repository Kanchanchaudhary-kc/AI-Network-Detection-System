import subprocess
from datetime import datetime
import os

# CONFIGURATION
INTERFACE = "Wi-Fi 3"
DURATION = 120
OUTPUT_FILE = "realtime_capture.pcap" # Keeping it in the realtime folder

def run_capture():
    print(f"[{datetime.now()}] Starting packet capture on {INTERFACE}...")
    
    # Create folder if it doesn't exist
    if not os.path.exists("realtime"):
        os.makedirs("realtime")

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

if __name__ == "__main__":
    run_capture()




