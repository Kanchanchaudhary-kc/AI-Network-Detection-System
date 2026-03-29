# ==============================
# RUN CICFlowMeter automatically
# ==============================

import subprocess
import os

# 1. Use the EXACT path to the CICFlowMeter bin folder
cfm_bin_dir = r"C:\CICFlowMeter-4.0\bin"
input_pcap = r"C:\Users\Kanchan Chaudhary\Desktop\AI-Network-Detection-System\realtime\realtime_capture.pcap"
output_dir = r"C:\Users\Kanchan Chaudhary\Desktop\AI-Network-Detection-System\realtime"

def run_feature_extraction():
    # Use the same command that worked in PowerShell
    # We use 'cwd' to force Python to run it FROM the bin folder
    try:
        subprocess.run(
            [".\\cfm.bat", input_pcap, output_dir], 
            shell=True, 
            cwd=cfm_bin_dir, # This is the "Magic" fix
            check=True
        )
        print("Success! Features extracted.")
    except subprocess.CalledProcessError as e:
        print(f"Extraction failed: {e}")

if __name__ == "__main__":
    run_feature_extraction()

