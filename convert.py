from scapy.all import PcapReader
import pandas as pd
import numpy as np
from collections import defaultdict


PCAP_FILE = "Friday-WorkingHours.pcap"   
OUTPUT = PCAP_FILE.replace(".pcap", "_labeled.csv")

# CIC-IDS2017 official attacker & victim IPs
ATTACKER_IPS = {"172.16.0.1"}
VICTIM_IPS   = {f"192.168.10.{i}" for i in range(1, 256)}

# Known attack ports per day
ATTACK_PORTS = {
    "Monday":    set(),
    "Tuesday":   {80, 8080},
    "Wednesday": {21, 22, 80, 8080},
    "Thursday":  {21, 22, 80, 443, 445, 3389},
    "Friday":    {80, 8080}     
}

DAY = PCAP_FILE.split("-")[0].capitalize() 
print(f"Processing {DAY} → {OUTPUT}")

flows = defaultdict(lambda: {
    'start': None,
    'end': None,
    'fwd_pkts': 0, 'bwd_pkts': 0,
    'fwd_bytes': 0, 'bwd_bytes': 0,
    'fwd_sizes': [], 'bwd_sizes': [],
    'src_ip': None, 'dst_ip': None,
    'proto': None
})

print("Reading PCAP — this may take 5–15 minutes for Friday file...")
with PcapReader(PCAP_FILE) as pcap:
    for i, pkt in enumerate(pcap, 1):
        if i % 250_000 == 0:
            print(f"   Processed {i:,} packets...")

        if 'IP' not in pkt:
            continue

        src = pkt['IP'].src
        dst = pkt['IP'].dst
        sport = pkt.sport if hasattr(pkt, 'sport') else 0
        dport = pkt.dport if hasattr(pkt, 'dport') else 0
        payload_len = len(pkt.payload) if hasattr(pkt, 'payload') else 0
        total_len = len(pkt) 
        ts = pkt.time

        key = (min(src,dst), max(src,dst), pkt['IP'].proto, min(sport,dport), max(sport,dport))
        f = flows[key]

        if f['start'] is None:
            f['start'] = ts
            f['src_ip'] = src
            f['dst_ip'] = dst
            f['proto'] = pkt['IP'].proto

        f['end'] = ts

        # Forward = direction from lower IP to higher IP (standard CICFlowMeter convention)
        if src < dst or (src == dst and sport < dport):
            f['fwd_pkts'] += 1
            f['fwd_bytes'] += total_len
            f['fwd_sizes'].append(total_len)
        else:
            f['bwd_pkts'] += 1
            f['bwd_bytes'] += total_len
            f['bwd_sizes'].append(total_len)

print("Building DataFrame...")
records = []
for key, f in flows.items():
    duration = max(f['end'] - f['start'], 1e-6)

    src = f['src_ip']
    dst = f['dst_ip']
    total_pkts = f['fwd_pkts'] + f['bwd_pkts']

    label = "BENIGN"   # default

    # FRIDAY SPECIFIC LABELING (DoS Hulk + Slowhttptest)
    if DAY == "Friday":
        if src == "172.16.0.1" and dst.startswith("192.168.10."):
            # Both Hulk and Slowhttptest use ports 80/8080
            if total_pkts > 50:                              # Hulk = very high packet count
                label = "DoS Hulk"
            elif total_pkts > 10 and duration > 30:         # Slowhttptest = long duration, fewer packets
                label = "DoS slowhttptest"
            else:
                label = "DoS"                                 # fallback


    elif DAY == "Tuesday":
        if src == "172.16.0.1" and dst.startswith("192.168.10."):
            label = "Web Attack"
    elif DAY == "Wednesday":
        if src == "172.16.0.1" and dst.startswith("192.168.10."):
            label = "DoS"
    elif DAY == "Thursday":
        if src == "172.16.0.1" and dst.startswith("192.168.10."):
            if total_pkts < 200:
                label = "Infiltration"
            else:
                label = "Web Attack"

    records.append({
        'Flow Duration': duration * 1e6,
        'Total Fwd Packets': f['fwd_pkts'],
        'Total Backward Packets': f['bwd_pkts'],
        'Total Length of Fwd Packets': f['fwd_bytes'],
        'Total Length of Bwd Packets': f['bwd_bytes'],
        'Fwd Packet Length Mean': np.mean(f['fwd_sizes']) if f['fwd_sizes'] else 0.0,
        'Bwd Packet Length Mean': np.mean(f['bwd_sizes']) if f['bwd_sizes'] else 0.0,
        'Flow Bytes/s': (f['fwd_bytes'] + f['bwd_bytes']) / duration,
        'Flow Packets/s': (f['fwd_pkts'] + f['bwd_pkts']) / duration,
        'Label': label
    })

df = pd.DataFrame(records)

#no inf
df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

df.to_csv(OUTPUT, index=False)
print(f"\nSUCCESS → {len(df):,} flows saved to {OUTPUT}")
print("\nLabel distribution:")
print(df['Label'].value_counts())