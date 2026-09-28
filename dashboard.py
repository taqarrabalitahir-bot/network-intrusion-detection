import os
import matplotlib.pyplot as plt

def generate_security_dashboard():
    log_file = "security_alerts.txt"
    
    # Check if the log file exists and has data
    if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
        print("[-] Error: security_alerts.txt is empty or missing. Run nids.py first to gather metrics!")
        return

    flood_count = 0
    port_scan_count = 0

    # Read the logged records from your NIDS engine execution
    with open(log_file, "r") as file:
        for line in file:
            if "FLOOD THREAT" in line:
                flood_count += 1
            elif "PORT SCAN" in line:
                port_scan_count += 1

    # Prepare data arrays for the visual layout chart representation
    threat_types = ['DDoS Flood Threats', 'Port Scan Threats']
    threat_counts = [flood_count, port_scan_count]
    chart_colors = ['#ff4d4d', '#ffa64d']

    # Build the graphical presentation frame interface dashboard layout
    plt.figure(figsize=(7, 5))
    bars = plt.bar(threat_types, threat_counts, color=chart_colors, edgecolor='black', width=0.5)
    
    # Design custom aesthetic text overlays directly onto metrics frame
    plt.title("NIDS Threat Incident Detection Dashboard", fontsize=14, fontweight='bold', pad=15)
    plt.ylabel("Total Incidents Captured/Logged", fontsize=12, labelpad=10)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Affix explicit data count variables atop visual metrics indicators
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.2, int(yval), ha='center', va='bottom', fontsize=12, fontweight='bold')

    # Display the final completed high-quality vector chart rendering window interface layout
    print("[*] Displaying graphical security analytics visualization engine pipeline...")
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    generate_security_dashboard()
