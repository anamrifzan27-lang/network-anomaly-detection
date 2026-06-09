# Network Anomaly Detection System

A Python-based intrusion detection system that analyses network 
traffic from PCAP files and flags anomalous behaviour using 
unsupervised machine learning.

Built as part of my BSc Cybersecurity & Digital Forensics coursework 
at Kingston University.

---

## What it does
- Loads and parses network packets from PCAP files using Scapy
- Extracts key features: source/destination IP, ports, 
  protocol, packet size, TCP flags
- Applies Isolation Forest (unsupervised ML) to detect anomalies
- Logs all detected anomalies in real time to alerts.log
- Evaluates performance using accuracy, precision, recall, F1-score
- Visualises results with a confusion matrix and scatter plot

## Results achieved
- Accuracy: 86.44%
- Detection method: Isolation Forest (unsupervised learning)
- Tested on a sample of 50,000 packets

---

## Tools & Libraries
- Python 3
- Scapy — packet capture and analysis
- Scikit-learn — Isolation Forest model
- Pandas & NumPy — data processing
- Matplotlib & Seaborn — visualisation

---

## How to run

Install dependencies:
pip install scapy scikit-learn pandas numpy matplotlib seaborn

Place your PCAP files in the same directory:
- benign.pcap
- attack.pcap

Run the script:
python anomaly_detection.py

---

## Key concepts demonstrated
- Anomaly-based vs signature-based intrusion detection
- Unsupervised machine learning for security
- Network packet feature extraction
- Real-time alert logging
- Model evaluation with confusion matrix

---

*Academic project — BSc Cybersecurity & Digital Forensics, 
Kingston University*
