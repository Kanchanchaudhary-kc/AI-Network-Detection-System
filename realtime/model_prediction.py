import pandas as pd
import numpy as np
import joblib
import glob
import os
import csv
from datetime import datetime

# ==============================
# CONFIGURATION & MODEL LOADING
# ==============================
LOG_DIR = "../realtime" 
os.makedirs(LOG_DIR, exist_ok=True)

RF_MODEL = joblib.load("../models/retrained/random_forest.pkl")
ISO_FOREST = joblib.load("../models/retrained/isolation_forest_model.pkl")
SCALER = joblib.load("../models/scaler.pkl")
LE = joblib.load("../models/label_encoder.pkl")

# Sensitivity: If Benign probability is LESS than this, we flag it as an attack.
# Adjust to 0.95 or 0.99 if it's still too quiet.
BENIGN_THRESHOLD = 0.70 

def save_logs(log_data, filename):
    log_file = os.path.join(LOG_DIR, filename)
    file_exists = os.path.isfile(log_file)
    with open(log_file, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['Timestamp', 'Source_IP', 'Dest_IP', 'Dest_Port', 'Protocol', 'Anomaly_Status', 'Classification'])
        writer.writerow(log_data)

def rename_live_columns(df):
    mapping = {
        'Dst Port': 'Destination Port',
        'Total Fwd Packet': 'Total Fwd Packets',
        'Total Bwd packets': 'Total Backward Packets',
        'Total Length of Fwd Packet': 'Total Length of Fwd Packets',
        'Total Length of Bwd Packet': 'Total Length of Bwd Packets',
        'Packet Length Min': 'Min Packet Length',
        'Packet Length Max': 'Max Packet Length',
        'Fwd Segment Size Avg': 'Avg Fwd Segment Size',
        'Bwd Segment Size Avg': 'Avg Bwd Segment Size',
        'Fwd Bytes/Bulk Avg': 'Fwd Avg Bytes/Bulk',
        'Fwd Packet/Bulk Avg': 'Fwd Avg Packets/Bulk',
        'Fwd Bulk Rate Avg': 'Fwd Avg Bulk Rate',
        'Bwd Bytes/Bulk Avg': 'Bwd Avg Bytes/Bulk',
        'Bwd Packet/Bulk Avg': 'Bwd Avg Packets/Bulk',
        'Bwd Bulk Rate Avg': 'Bwd Avg Bulk Rate',
        'FWD Init Win Bytes': 'Init_Win_bytes_forward',
        'Bwd Init Win Bytes': 'Init_Win_bytes_backward',
        'Fwd Act Data Pkts': 'act_data_pkt_fwd',
        'Fwd Seg Size Min': 'min_seg_size_forward',
        'CWR Flag Count': 'CWE Flag Count'
    }
    df.columns = df.columns.str.strip()
    return df.rename(columns=mapping)

def run_prediction():
    # 1. Find the latest flow file from CICFlowMeter
    csv_files = glob.glob(os.path.join(".", "*_Flow.csv"), recursive=True)
    if not csv_files: 
        print("No traffic data found.")
        return
    latest_csv = max(csv_files, key=os.path.getctime)
    
    df_raw = pd.read_csv(latest_csv)
    df_renamed = rename_live_columns(df_raw)
    
    # 2. Critical: Align features to exactly 78 columns
    if 'Fwd Header Length' in df_renamed.columns:
        df_renamed['Fwd Header Length.1'] = df_renamed['Fwd Header Length']

    train_cols = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
        'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
        'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
        'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
        'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
        'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
        'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
        'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
        'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
        'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
        'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
        'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
        'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
        'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
        'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
        'Bwd Packet/Bulk Avg', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
        'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
        'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
        'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
        'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ]

    for col in train_cols:
        if col not in df_renamed.columns:
            df_renamed[col] = 0

    # 3. Fix the "Infinity" and "Value too large" Error
    X_input = pd.DataFrame(df_renamed[train_cols].values)
    X_input.columns = [str(i) for i in range(len(X_input.columns))]
    
    # Pre-processing to prevent Scaler Crash
    X_input = X_input.replace([np.inf, -np.inf], np.nan)
    X_input = X_input.fillna(0)
    X_input = X_input.astype(np.float64)

    # 4. Scale and Predict
    X_scaled = SCALER.transform(X_input)
    is_anomaly = ISO_FOREST.predict(X_scaled)
    probs = RF_MODEL.predict_proba(X_scaled)

    # 5. Hybrid Logic: Reduce False Positives
    classes = [c.upper() for c in LE.classes_]
    benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0

    print(f"\n--- HYBRID IDS REPORT: {os.path.basename(latest_csv)} ---")

    for i in range(len(X_scaled)):
        b_prob = probs[i][benign_idx]
        is_iso_anomaly = (is_anomaly[i] == -1)
        
        # Logic: If RF is < 80% sure it's Benign AND Isolation Forest agrees it's weird
        # OR if RF is very sure it's an attack (< 50% Benign)
        if (b_prob < 0.80 and is_iso_anomaly) or (b_prob < 0.50):
            attack_probs = probs[i].copy()
            attack_probs[benign_idx] = 0
            text_label = LE.inverse_transform([np.argmax(attack_probs)])[0]
            is_rf_attack = True
        else:
            text_label = "BENIGN"
            is_rf_attack = False

        src_ip = df_raw.iloc[i].get('Src IP', df_raw.iloc[i].get('Source IP', 'N/A'))
        dst_ip = df_raw.iloc[i].get('Dst IP', df_raw.iloc[i].get('Destination IP', 'N/A'))
        
        log_entry = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            src_ip, dst_ip, 
            df_raw.iloc[i].get('Dst Port', 'N/A'),
            df_raw.iloc[i].get('Protocol', 'N/A'),
            "Anomaly" if is_iso_anomaly else "Normal", 
            text_label
        ]

        save_logs(log_entry, "all_logs.csv")

        if is_rf_attack:
            save_logs(log_entry, "alerts.csv")
            print(f"\033[91m [!] ALERT: {text_label} detected from {src_ip} \033[0m")
        elif is_iso_anomaly:
            save_logs(log_entry, "anomaly_logs.csv")
            print(f"\033[93m [?] SUSPICIOUS: Outlier from {src_ip} \033[0m")
        else:
            print(f"Flow {i+1}: [✓] Normal")


if __name__ == "__main__":
    run_prediction()
