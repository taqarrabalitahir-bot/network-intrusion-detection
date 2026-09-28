# Network Intrusion Detection System (NIDS)

A Python-based lightweight Network Intrusion Detection System designed to continuously monitor traffic, apply custom security rules (DDoS and Port Scan detection), and execute automated response logging mechanisms.

## Project Features
- **Continuous Monitoring:** Real-time packet parsing via Scapy interface hooks.
- **DDoS/Flooding Rule:** Tracks packet frequency per IP and alerts if a threshold is breached.
- **Port Scan Rule:** Flags unauthorized access to high-risk systemic ports (FTP, SSH, Telnet, SMB).
- **Automated Response:** Permanently logs attack vectors directly into `security_alerts.txt`.
