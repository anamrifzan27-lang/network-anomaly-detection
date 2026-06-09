import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import logging


# Logging setup

logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

print("Starting anomaly detection...")


# Function to extract features from PCAP

def extract_features(pcap_file, label):
    packets = rdpcap(pcap_file)
    data = []

    for pkt in packets:
        if IP in pkt:
            src_port = 0
            dst_port = 0
            flags = 0

            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = int(pkt[TCP].flags)
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            data.append({
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": pkt[IP].proto,
                "packet_size": len(pkt),
                "flags": flags,
                "label": label
            })

    return pd.DataFrame(data)

# Load PCAP files

benign_df = extract_features("benign.pcap", 0)
attack_df = extract_features("attack.pcap", 1)

df = pd.concat([benign_df, attack_df], ignore_index=True)

print("Packets loaded:", len(df))


# Feature selection

features = df[[
    "protocol",
    "packet_size",
    "src_port",
    "dst_port",
    "flags"
]]


# Isolation Forest (Unsupervised)

model = IsolationForest(
    n_estimators=100,
    contamination=0.1,
    random_state=42
)

df["anomaly"] = model.fit_predict(features)

# Convert output: -1 = anomaly, 1 = normal
df["anomaly"] = df["anomaly"].map({1: 0, -1: 1})


# Log detected anomalies

anomalies = df[df["anomaly"] == 1]

for _, row in anomalies.iterrows():
    logging.info(
        f"Anomaly detected | Src: {row['src_ip']} | Dst: {row['dst_ip']} | Size: {row['packet_size']}"
    )

print("Total anomalies detected:", len(anomalies))

from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import seaborn as sns


sample_size = 50000  
if len(df) > sample_size:
    eval_df = df.sample(sample_size, random_state=42)
else:
    eval_df = df

# Confusion Matrix
cm = confusion_matrix(eval_df["label"], eval_df["anomaly"])

plt.figure(figsize=(6,4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Normal", "Anomaly"],
            yticklabels=["Normal", "Anomaly"])
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix (sampled)")
plt.show()

# Metrics
accuracy = accuracy_score(eval_df["label"], eval_df["anomaly"])
precision = precision_score(eval_df["label"], eval_df["anomaly"])
recall = recall_score(eval_df["label"], eval_df["anomaly"])
f1 = f1_score(eval_df["label"], eval_df["anomaly"])

print(f"Accuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1-score: {f1:.4f}")

# Log summary instead of every anomaly
logging.info(f"Evaluation on {len(eval_df)} packets | "
             f"Accuracy={accuracy:.4f}, Precision={precision:.4f}, "
             f"Recall={recall:.4f}, F1={f1:.4f}")




# Visualization 

plt.figure()
plt.scatter(
    df.index,
    df["packet_size"],
    c=df["anomaly"]
)
plt.xlabel("Packet Index")
plt.ylabel("Packet Size")
plt.title("Anomaly Detection using Isolation Forest")
plt.show()
