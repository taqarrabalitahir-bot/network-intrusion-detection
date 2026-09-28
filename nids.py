import sys
import time
from scapy.all import sniff, IP, TCP, UDP

SENSITIVE_PORTS = (21, 22, 23, 445)
ip_tracker = {}
ALERTS_COUNT = 0

# FIXED: Removed symbols to prevent Windows PowerShell charmap encoding crashes
def trigger_response_mechanism(alert_message):
    global ALERTS_COUNT
    ALERTS_COUNT += 1
    print(alert_message)
    
    with open("security_alerts.txt", "a") as log_file:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] {alert_message}\n")

def detect_intrusion(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = time.time()
        
        if src_ip not in ip_tracker:
            ip_tracker[src_ip] = []
            
        ip_tracker[src_ip].append(current_time)
        ip_tracker[src_ip] = [t for t in ip_tracker[src_ip] if current_time - t < 2]
        
        # Rule 1: Detect Flooding Threats
        if len(ip_tracker[src_ip]) > 20:
            msg = f"[ALERT] FLOOD THREAT IDENTIFIED: {src_ip} -> Targeting: {dst_ip}"
            trigger_response_mechanism(msg)
            
        # Rule 2: Detect Port Scanning
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            if dst_port in SENSITIVE_PORTS:
                msg = f"[ALERT] PORT SCAN DETECTED! {src_ip} scanning sensitive Port {dst_port}"
                trigger_response_mechanism(msg)

print("="*50)
print("     LOCAL NETWORK INTRUSION DETECTION SYSTEM     ")
print("="*50)
print("[*] Continuous threat monitoring active...")
print("[*] Logs are being actively saved to security_alerts.txt")
print("[*] Press Ctrl+C to safely exit and check logs.")

try:
    sniff(prn=detect_intrusion, store=False)
except KeyboardInterrupt:
    print("\n" + "="*40)
    print(f" Total Intrusions Logged/Blocked: {ALERTS_COUNT}")
    print("="*40)
    sys.exit(0)
