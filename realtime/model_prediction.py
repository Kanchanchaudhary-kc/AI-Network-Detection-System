import pandas as pd
import numpy as np
import joblib
import glob
import os

# ==============================
# CONFIGURATION & MODEL LOADING
# ==============================
# Adjust paths as needed (e.g., os.path.join("..", "models", "scaler.pkl"))
RF_MODEL = joblib.load("../models/retrained/random_forest.pkl")
ISO_FOREST = joblib.load("../models/retrained/isolation_forest_model.pkl")
SCALER = joblib.load("../models/scaler.pkl")
LE = joblib.load("../models/label_encoder.pkl")

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
    # 1. Identify non-numeric metadata
    non_features = [
        'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 
        'Destination Port', 'Protocol', 'Timestamp', 'Label',
        'Src IP', 'Src Port', 'Dst IP', 'Dst Port' # Catch live variants
    ]
    
    # 2. Drop metadata
    X = df.drop(columns=[c for c in non_features if c in df.columns], errors='ignore')
    
    # 3. Force numeric only (Removes IPs)
    X = X.select_dtypes(include=[np.number])
    
    # 4. Handle math errors
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0) 
    return X

def run_prediction():
    # 1. Find latest CSV
    csv_files = glob.glob(os.path.join(".", "*_Flow.csv"), recursive=True)
    if not csv_files: 
        print("No traffic data found.")
        return
    latest_csv = max(csv_files, key=os.path.getctime)
    
    # 2. Load Data
    df_raw = pd.read_csv(latest_csv)
    
    # 3. Rename and Add Duplicate Column (Required by Training Set)
    df_renamed = rename_live_columns(df_raw)
    if 'Fwd Header Length' in df_renamed.columns:
        df_renamed['Fwd Header Length.1'] = df_renamed['Fwd Header Length']

    # 4. Basic Cleaning
    X_features = preprocess_live_data(df_renamed)

    # 5. Define Training Columns Order
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

    # 6. Final Alignment (Fixes the KeyError)
    # Ensure any completely missing columns are added as 0
    for col in train_cols:
        if col not in X_features.columns:
            X_features[col] = 0

    X_final = X_features[train_cols] # Force correct order
    X_input = X_final.copy()
    X_input.columns = [str(i) for i in range (len(X_input.columns))]


    # 7. Scale and Predict
    X_scaled = SCALER.transform(X_input)
    is_anomaly = ISO_FOREST.predict(X_scaled)
    numeric_preds = RF_MODEL.predict(X_scaled)

    # 8. Hybrid Report
    print(f"\n--- HYBRID IDS REPORT: {os.path.basename(latest_csv)} ---")
    for i in range(len(X_scaled)):
        # Translate number back to text label
        text_label = LE.inverse_transform([numeric_preds[i]])[0]
        
        # -1 = Anomaly, 1 = Normal
        status = "[!] anomaly" if is_anomaly[i] == -1 else "[✓] normal"
        
        print(f"FLOW {i+1}: {status} , Classification: {text_label}")

if __name__ == "__main__":
    run_prediction()
