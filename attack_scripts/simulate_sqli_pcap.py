# simulate_sqli_pcap.py

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest, HTTP

def generate_sqli_packet():
    # Simulate a GET request with SQL injection payload
    ip = IP(src="192.168.1.10", dst="192.168.1.20")
    tcp = TCP(sport=12345, dport=80, flags="PA", seq=1000, ack=100)
    
    # SQL injection attempt in the URI
    http_payload = (
        "GET /login.php?user=admin&pass=' OR '1'='1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: Scapy-SQLi-Test\r\n"
        "Accept: */*\r\n\r\n"
    )

    pkt = ip / tcp / Raw(load=http_payload)
    return pkt

if __name__ == "__main__":
    pkt = generate_sqli_packet()
    wrpcap("fake_sqli.pcap", [pkt])
    print("✅ Generated fake_sqli.pcap with SQL injection payload.")
