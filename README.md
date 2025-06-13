# Packet Sniffer with Anomaly Detection

## Description
This project captures network packets using Scapy and detects anomalies with an Isolation Forest model from Scikit-learn. It’s ideal for monitoring network traffic and identifying suspicious activity.

## Prerequisites
- Python 3.8+
- Administrative privileges (e.g., sudo on Linux) for packet capturing
- Network interface access

## Installation
1. **Clone the Repository**: Download and extract this ZIP file.
2. **Install Dependencies**: Run `pip install -r requirements.txt`.
3. **Verify Scapy**: Ensure Scapy can capture packets (may require `sudo`).

## Usage
### Training Mode
Train the model on normal traffic:
```bash
sudo python src/packet_sniffer.py --interface eth0 --mode train --duration 60 --model model.pkl
