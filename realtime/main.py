from realtime_capture import run_capture
from feature_generation import run_feature_extraction
from model_prediction import run_prediction

def main():
    # Step 1: Capture 120s of traffic
    run_capture()

    # Step 2: Generate features from that PCAP
    run_feature_extraction()

    # Step 3: Run the AI model on the resulting CSV
    run_prediction()

if __name__ == "__main__":
    main()
