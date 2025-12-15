1.	Introduction
Modern networks experience increasingly sophisticated threats such as malware injections, unauthorized access, and zero-day attacks. Traditional intrusion detection systems primarily rely on signatures, making them ineffective against emerging threats. This project aims to build an AI-powered real-time anomaly and malware detection system capable of capturing live network traffic, extracting flow-level features, and classifying malicious behavior using machine learning techniques.
2.	Problem Statement
Signature-based IDS solutions cannot detect unknown or evolving attacks. Academic studies largely focus on offline datasets, while most student projects simulate traffic rather than capturing real packets. This leaves a gap in accessible, real-time systems that integrate packet capture, ML-based detection, and a usable interface. A real-time, ML-driven detection prototype is needed to improve situational awareness and offer rapid alerting for anomalous or malware-related behavior.
3.	Objectives
⦁	Implement a real-time packet capture mechanism using Wireshark and Python (via PyShark).
⦁	Extract meaningful features from captured packets for ML-based classification.
⦁	Train ML models on datasets like CICIDS2017 and NSL-KDD for anomaly and malware detection.
⦁	Integrate the trained ML model with the live capture pipeline to enable real-time anomaly classification.
⦁	Develop a simple GUI for displaying real-time alerts, statistics, and threat classifications.
⦁	Evaluate system performance using classification metrics and real-time detection latency.
4.	Project Scope
The system will include:
⦁	Real-time packet capture from the college’s internal network
⦁	Feature extraction for ML models
⦁	Machine learning training, evaluation, and real-time inference
⦁	A lightweight GUI for alerts
⦁	Logging for testing and validation
The system will not include:
⦁	Enterprise-level deployment
⦁	Automated remediation actions
⦁	Encrypted traffic decryption
⦁	Distributed sensor networks
These areas are considered future enhancements.
5.	Functional Requirements
⦁	Capture live packets continuously
⦁	Aggregate packets into flow-level data
⦁	Extract features such as duration, protocol, packet count, bytes, ports
⦁	Classify incoming flows using ML models
⦁	Display alerts for anomalies or malware
⦁	Log all detections with timestamps
6.	Non-Functional Requirements
⦁	Real-time performance with low latency
⦁	High model accuracy, precision, recall
⦁	Lightweight GUI for end-user interaction
⦁	Maintainability with proper documentation and modular code
⦁	Secure handling of captured traffic data
7.	Tools and Technologies
⦁	Wireshark
⦁	PyShark
⦁	Python, Scikit-learn, NumPy, Pandas
⦁	Streamlit or Tkinter (GUI)
⦁	CICIDS2017, NSL-KDD datasets
⦁	Git and GitHub