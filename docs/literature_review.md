1.	Signature-Based Intrusion Detection Systems
Traditional IDS tools such as Snort and Suricata function by matching signatures of known attacks. Although effective for documented threats, they fail to detect zero-day attacks or behaviorally distinct malware. These systems lack learning capability and therefore cannot adapt to evolving attack patterns.
2.	Commercial AI-Based Security Tools
Advanced security platforms like Darktrace, CrowdStrike, and SentinelOne use machine learning for anomaly detection but are:
⦁	proprietary,
⦁	expensive,
⦁	black-box systems with limited transparency.
Such systems are not suitable for academic experimentation or custom feature extraction, which your proposed system addresses.
3.	Academic Machine Learning Research
Several researchers have explored ML for anomaly detection using offline datasets.
The paper Integrating Machine Learning with Digital Forensics to Enhance Anomaly Detection and Mitigation Strategies (Ndibe, 2025) highlights how ML algorithms such as Random Forest, SVM, and KNN can support forensic analysis. However:
⦁	The study focuses on post-incident analysis rather than real-time detection.
⦁	It does not use live packet capture.
⦁	No malware behavior classification pipeline is implemented.
⦁	No user interface or deployable prototype is provided.
This forms a major research gap.
4.	Identified Research Gap
Existing systems are either signature-based, proprietary, or limited to offline ML experiments. There is a need for:
⦁	A real-time packet capture system
⦁	Integrated ML-based classification
⦁	Live anomaly/malware detection
⦁	A user-friendly GUI
⦁	An open, academic prototype
My project directly fills this gap.