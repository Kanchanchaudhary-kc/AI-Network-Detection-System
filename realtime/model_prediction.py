import pandas as pd
import numpy as np
import joblib
import glob
import os
import csv # Added for efficient logging
from datetime import datetime # Added for timestamps

# ==============================
# CONFIGURATION & MODEL LOADING
# ==============================
RF_MODEL = joblib.load("../models/retrained/random_forest.pkl")
ISO_FOREST = joblib.load("../models/retrained/isolation_forest_model.pkl")
SCALER = joblib.load("../models/scaler.pkl")
LE = joblib.load("../models/label_encoder.pkl")

# New Helper Function for Logging
def save_logs(log_data, log_file="detection_history.csv"):
    """Appends a single prediction row to the log CSV"""
    file_exists = os.path.isfile(log_file)
    with open(log_file, 'a', newline='') as f:
        writer = csv.writer(f)
        # Add header only if file is new
        if not file_exists:
            writer.writerow(['Timestamp', 'Source_IP', 'Dest_IP', 'Dest_Port', 'Protocol', 'Anomaly_Status', 'Classification'])
        writer.writerow(log_data)

def rename_live_columns(df):
    """Bridges the gap between live CICFlowMeter names and Training names"""
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

def preprocess_live_data(df):
    """Cleans numeric data and handles infinity/NaNs"""
    non_features = [
        'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 
        'Destination Port', 'Protocol', 'Timestamp', 'Label',
        'Src IP', 'Src Port', 'Dst IP', 'Dst Port'
    ]
    X = df.drop(columns=[c for c in non_features if c in df.columns], errors='ignore')
    X = X.select_dtypes(include=[np.number])
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0) 
    return X

def run_prediction():
    csv_files = glob.glob(os.path.join(".", "*_Flow.csv"), recursive=True)
    if not csv_files: 
        print("No traffic data found.")
        return
    latest_csv = max(csv_files, key=os.path.getctime)
    
    df_raw = pd.read_csv(latest_csv)
    df_renamed = rename_live_columns(df_raw)
    
    if 'Fwd Header Length' in df_renamed.columns:
        df_renamed['Fwd Header Length.1'] = df_renamed['Fwd Header Length']

    X_features = preprocess_live_data(df_renamed)

    train_cols = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets',
        'Total Backward Packets', 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets', 'Fwd Packet Length Max',
        'Fwd Packet Length Min', 'Fwd Packet Length Mean',
        'Fwd Packet Length Std', 'Bwd Packet Length Max',
        'Bwd Packet Length Min', 'Bwd Packet Length Mean',
        'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
        'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
        'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
        'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
        'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
        'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
        'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
        'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
        'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
        'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
        'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
        'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
        'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
        'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
        'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
        'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
        'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
        'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
        'Idle Std', 'Idle Max', 'Idle Min'
    ]

    for col in train_cols:
        if col not in X_features.columns:
            X_features[col] = 0

    X_final = X_features[train_cols]
    X_input = X_final.copy()
    X_input.columns = [str(i) for i in range (len(X_input.columns))]

    X_scaled = SCALER.transform(X_input)
    is_anomaly = ISO_FOREST.predict(X_scaled)
    numeric_preds = RF_MODEL.predict(X_scaled)

    print(f"\n--- HYBRID IDS REPORT: {os.path.basename(latest_csv)} ---")
    
    for i in range(len(X_scaled)):
        text_label = LE.inverse_transform([numeric_preds[i]])[0]
        status = "Anomaly" if is_anomaly[i] == -1 else "Normal"
        
        # --- LOGGING LOGIC START ---
        # Extract metadata for the log (using raw df indices)
        src_ip = df_raw.iloc[i].get('Src IP', 'N/A')
        dst_ip = df_raw.iloc[i].get('Dst IP', 'N/A')
        dst_port = df_raw.iloc[i].get('Dst Port', 'N/A')
        proto = df_raw.iloc[i].get('Protocol', 'N/A')
        
        log_entry = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            src_ip, dst_ip, dst_port, proto, status, text_label
        ]
        save_logs(log_entry)
        # --- LOGGING LOGIC END ---

        if status == "Anomaly":
            display_status = f"[!] {status}"
        else:
            display_status = f"[✓] {status}"
            
        print(f"FLOW {i+1}: {display_status} , Classification: {text_label}")

if __name__ == "__main__":
    run_prediction()

