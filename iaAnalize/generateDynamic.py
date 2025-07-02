import random
import time
from datetime import datetime, timedelta

def gen_alert(event_type=None, src_ip=None, timestamp=None):
    ts = timestamp if timestamp else datetime.now().strftime("%b %d %H:%M:%S")
    usernames = ['root', 'admin', 'user', 'test']

    types = {
        "icmp_ping": ("ICMP Ping Detected", "{ICMP}"),
        "nmap_scan": ("Nmap Scripting Engine scan", "{TCP}"),
        # "failed_login" and "successful_login" handled separately
    }

    if event_type is None:
        event_type = random.choice(list(types.keys()) + ["failed_login", "successful_login"])

    if src_ip is None:
        src_ip = f"192.168.1.{random.randint(1,254)}"
    dst = "10.0.0.1"

    hostname = "server"
    pid = random.randint(1000, 9999)
    port = random.randint(1024, 65535)
    user = random.choice(usernames)

    if event_type == "failed_login":
        return f"{ts} {hostname} sshd[{pid}]: Failed password for {user} from {src_ip} port {port} ssh2"
    elif event_type == "successful_login":
        return f"{ts} {hostname} sshd[{pid}]: Accepted password for {user} from {src_ip} port {port} ssh2"
    elif event_type == "nmap_scan":
        msg = "Nmap Scripting Engine"
        proto = "{TCP}"
        dst_port = random.randint(1, 1024)
        return f"{ts} [**] [1:1000000:1] {msg} [**] [Priority: {random.randint(1,3)}] {proto} {src_ip}:{port} -> {dst}:{dst_port}"
    else:
        msg, proto = types[event_type]
        return f"{ts} [**] [1:1000000:1] {msg} [**] [Priority: {random.randint(1,3)}] {proto} {src_ip} -> {dst}"

def append_logs_forever(filename, bruteforce_chance=0.02, burst_size=25, nmap_chance=0.01, nmap_burst_size=10,  interval_seconds=1):
    """
    Continuously append new log entries every 'interval_seconds' seconds to simulate a live log.
    Includes brute force bursts, failed and successful login attempts, and other events.
    """
    current_time = datetime.now()

    print(f"Starting to append logs to {filename} every {interval_seconds}s...")

    while True:
        ts_str = current_time.strftime("%b %d %H:%M:%S")

        with open(filename, 'a') as f:
            if random.random() < bruteforce_chance:
                attacker_ip = f"192.168.1.{random.randint(1,254)}"
                for _ in range(burst_size):
                    alert_line = gen_alert(event_type="failed_login", src_ip=attacker_ip, timestamp=ts_str)
                    f.write(alert_line + "\n")
                    print(f"Appended log: {alert_line}")
                    current_time += timedelta(seconds=1)
            elif random.random() < nmap_chance:
                scanner_ip = f"192.168.1.{random.randint(1,254)}"
                for _ in range(nmap_burst_size):
                    alert_line = gen_alert(event_type="nmap_scan", src_ip=scanner_ip, timestamp=ts_str)
                    f.write(alert_line + "\n")
                    print(f"Appended log: {alert_line}")
                    current_time += timedelta(seconds=1)
            else:
                r = random.random()
                if r < 0.05:
                    alert_line = gen_alert(event_type="failed_login", timestamp=ts_str)
                elif r < 0.15:  # 10% chance successful login
                    alert_line = gen_alert(event_type="successful_login", timestamp=ts_str)
                else:
                    alert_line = gen_alert(timestamp=ts_str)

                f.write(alert_line + "\n")
                print(f"Appended log: {alert_line}")
                current_time += timedelta(seconds=1)

        time.sleep(interval_seconds)

if __name__ == "__main__":
    append_logs_forever('synthetic_snort_dynamic.log', bruteforce_chance=0.1, burst_size=15, nmap_chance=0.01, nmap_burst_size=10, interval_seconds=2)
