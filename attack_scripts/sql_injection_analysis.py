from scapy.all import rdpcap
from scapy.layers.inet import TCP, IP
from scapy.layers.http import HTTPRequest
import re

SQLI_PATTERNS = [
    r"' or '1'='1",
    r"' OR 1=1 --",
    r"UNION.*SELECT",
    r"DROP\s+TABLE",
    r"'--",
    r"admin' --",
    r"'#",
    r"1=1",
    r"or\s+\d+=\d+",
]

def load_pcap(path):
    try:
        return rdpcap(path)
    except Exception as e:
        print(f"[!] Failed to load PCAP: {e}")
        return []

def find_sqli_attempts(packets):
    findings = []

    for pkt in packets:
        if pkt.haslayer(HTTPRequest):
            try:
                http_layer = pkt[HTTPRequest]
                host = http_layer.Host.decode() if http_layer.Host else ""
                path = http_layer.Path.decode() if http_layer.Path else ""
                payload = bytes(pkt[TCP].payload).decode("utf-8", errors="ignore")

                full_request = f"{host}{path} {payload}"
                for pattern in SQLI_PATTERNS:
                    if re.search(pattern, full_request, re.IGNORECASE):
                        findings.append({
                            "src": pkt[IP].src if pkt.haslayer(IP) else "N/A",
                            "payload": full_request[:300]
                        })
                        break

            except Exception as e:
                continue

    return findings
