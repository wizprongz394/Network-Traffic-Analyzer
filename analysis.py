import pandas as pd
import datetime
from scapy.all import rdpcap

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    data = []
    for pkt in packets:
        if pkt.haslayer('IP'):
            data.append({
                'timestamp': float(pkt.time),  # Ensure timestamp is float
                'src_ip': pkt['IP'].src,
                'dst_ip': pkt['IP'].dst,
                'protocol': pkt.proto,
                'length': len(pkt)
            })

    df = pd.DataFrame(data)

    # Handle empty or malformed files
    if df.empty:
        return {
            'traffic_per_sec': pd.Series(dtype=int),
            'traffic_smoothed': pd.Series(dtype=float),
            'top_talkers': pd.Series(dtype=int),
            'protocol_counts': {},
            'hints': ["⚠️ No valid IP packets found in the uploaded PCAP."]
        }

    df['timestamp'] = df['timestamp'].astype(float)
    df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
    df.set_index('datetime', inplace=True)

    # Traffic stats
    traffic_per_sec = df.resample('1s').size()
    traffic_smoothed = traffic_per_sec.rolling(window=3).mean()

    # Top Talkers
    top_talkers = df['src_ip'].value_counts().head(5)

    # Protocol breakdown
    protocol_counts = df['protocol'].value_counts().to_dict()

    # Suggestions
    hints = []
    if traffic_per_sec.mean() > 1000:
        hints.append("⚠️ High average traffic. Possible backup or DDoS.")
    if not top_talkers.empty and top_talkers.iloc[0] > df.shape[0] * 0.4:
        hints.append(f"⚠️ {top_talkers.index[0]} is sending over 40% of traffic.")
    if 17 in protocol_counts and protocol_counts[17] > df.shape[0] * 0.3:
        hints.append("⚠️ High UDP traffic. Could indicate streaming or attack.")
    if not hints:
        hints.append("✅ No immediate bottlenecks or suspicious traffic detected.")

    return {
        'traffic_per_sec': traffic_per_sec,
        'traffic_smoothed': traffic_smoothed,
        'top_talkers': top_talkers,
        'protocol_counts': protocol_counts,
        'hints': hints
    }
