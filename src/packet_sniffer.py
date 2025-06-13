#!/usr/bin/env python3

import argparse
import os
from scapy.all import sniff, IP
from sklearn.ensemble import IsolationForest
import numpy as np
import pickle
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Feature extraction function
def extract_features(packet):
    """Extract features from a packet for anomaly detection."""
    if IP in packet:
        return [
            float(packet[IP].src.split('.')[-1]),  # Last octet of source IP
            float(packet[IP].dst.split('.')[-1]),  # Last octet of destination IP
            float(packet[IP].len),                 # Packet length
            float(packet[IP].proto)                # Protocol number
        ]
    return None

# Packet sniffing function
def capture_packets(interface, duration, count=None):
    """Capture packets from the specified interface."""
    logging.info(f"Starting packet capture on {interface} for {duration} seconds...")
    packets = sniff(iface=interface, timeout=duration, count=count or 0)
    return packets

# Training mode
def train_model(packets, model_path):
    """Train the Isolation Forest model on captured packets."""
    features = [extract_features(pkt) for pkt in packets if extract_features(pkt)]
    if not features:
        logging.error("No valid packets captured for training.")
        return False
    
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(features)
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    logging.info(f"Model trained and saved to {model_path}")
    return True

# Detection mode
def detect_anomalies(packets, model_path):
    """Detect anomalies in captured packets using the trained model."""
    if not os.path.exists(model_path):
        logging.error(f"Model file {model_path} not found.")
        return
    
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    
    features = [extract_features(pkt) for pkt in packets if extract_features(pkt)]
    if not features:
        logging.error("No valid packets captured for detection.")
        return
    
    predictions = model.predict(features)
    for pkt, pred in zip(packets, predictions):
        if pred == -1:  # Anomaly detected
            logging.warning(f"Anomaly detected: {pkt.summary()}")

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer with Anomaly Detection")
    parser.add_argument('--interface', required=True, help="Network interface to sniff (e.g., eth0)")
    parser.add_argument('--mode', choices=['train', 'detect'], required=True, help="Mode: train or detect")
    parser.add_argument('--duration', type=int, default=60, help="Capture duration in seconds")
    parser.add_argument('--model', default='model.pkl', help="Path to save/load the model")
    
    args = parser.parse_args()
    
    packets = capture_packets(args.interface, args.duration)
    
    if args.mode == 'train':
        train_model(packets, args.model)
    elif args.mode == 'detect':
        detect_anomalies(packets, args.model)

if __name__ == "__main__":
    main()
