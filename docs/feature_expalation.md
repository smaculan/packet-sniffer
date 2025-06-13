# Feature Explanation for Packet Sniffer with Anomaly Detection

This document explains the features extracted from network packets for anomaly detection.

## Extracted Features
1. **Source IP (Last Octet)**: The last octet of the source IP address, converted to a float. Represents the origin of the packet.
2. **Destination IP (Last Octet)**: The last octet of the destination IP address. Indicates the packet's target.
3. **Packet Length**: The total length of the packet in bytes. Anomalies may involve unusual sizes.
4. **Protocol Number**: The IP protocol number (e.g., 6 for TCP, 17 for UDP). Unusual protocols can indicate anomalies.

## Rationale
These features are chosen for their simplicity and relevance to network behavior:
- IP addresses help identify unusual traffic patterns.
- Packet length and protocol can flag malformed or malicious packets.
- The Isolation Forest model uses these to detect deviations from normal traffic.

For a production system, additional features like port numbers, timestamps, and payload analysis could enhance detection.
