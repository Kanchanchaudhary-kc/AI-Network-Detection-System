AI-Powered Real-Time Network Anomaly and Malware Detection System
This project implements a real-time machine learning–based system for detecting anomalous and malware-related network behavior. It captures live network traffic using Wireshark, processes it using Python and PyShark, extracts flow-level features, and classifies traffic using trained ML models. A lightweight GUI displays real-time alerts, detection statistics, and logs.

1.	Project Objectives
⦁	Capture real-time network traffic from the college internal network
⦁	Extract flow-based features using Python and PyShark
⦁	Train ML models on CICIDS2017 and NSL-KDD datasets
⦁	Classify live traffic as benign, anomalous, or malware-related
⦁	Develop a GUI for real-time alert visualization
⦁	Evaluate model performance based on accuracy, precision, recall, and F1-score

2.	Features
⦁	Real-time packet capture (Wireshark)
⦁	Real-time feature extraction
⦁	ML-powered anomaly and malware detection
⦁	GUI with live alerts
⦁	Logging system for analysis
⦁	Modular architecture for easy modification

3.	Tools & Technologies
⦁	Wireshark – real-time packet capture
⦁	PyShark – packet parsing in Python
⦁	Python, Scikit-learn, NumPy, Pandas
⦁	Streamlit / Tkinter – GUI
⦁	CICIDS2017, NSL-KDD – datasets
⦁	Git & GitHub – version control

4.	Project Structure
AI-Network-Detection-System/
├──.gitignore
├── README.md
├── docs/
│   ├── requirements.md
│   ├── literature_review.md
│   └── architecture.md
├── datasets/
├── notebooks/
│   ├── 01_data_exploration.ipynb
├── models/
└── gui/

5.	Methodology
⦁	Real-time packet capture using Wireshark
⦁	Packet parsing using PyShark
⦁	Flow-level feature extraction
⦁	ML model training & evaluation
⦁	Integration of real-time detection pipeline
⦁	GUI-based alerting

6.	Setup Instructions
⦁	Install Wireshark
⦁	Install Python libraries:
⦁	pip install pyshark scikit-learn pandas numpy streamlit
⦁	Configure Wireshark capture interface
⦁	Run the feature extraction script
⦁	Start the real-time detection module
⦁	Launch the GUI
⦁	More detailed instructions will be added as the project progresses.

7.	Evidence / Logs / Screenshots
This section will contain:
⦁	Wireshark capture screenshots
⦁	Testing logs
⦁	Attack simulation results
⦁	GUI screenshots
(Will be added weekly following project progress.)

8.	Version Control
This repository follows the college requirement of:
⦁	3–5 commits per week
⦁	Regular updates
⦁	Clear commit messages
⦁	Proper documentation and screenshots

9. Datasets USed
⦁	CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
⦁	NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html
Note: Raw datasets are not included in the repository due to size limitations.