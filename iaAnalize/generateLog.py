import random
from datetime import datetime, timedelta

def gen_alert(event_type=None, src_ip=None, timestamp=None):
    """
    Generate a synthetic log line for various event types:
    - failed_login: failed ssh login attempt
    - successful_login: successful ssh login
    - icmp_ping, nmap_scan: network events
    """
    ts = timestamp if timestamp else datetime.now().strftime("%b %d %H:%M:%S")

    usernames = ['root', 'admin', 'user', 'test']

    types = {
        "icmp_ping": ("ICMP Ping Detected", "{ICMP}"),
        "nmap_scan": ("Nmap Scripting Engine scan", "{TCP}"),
        # failed_login and successful_login handled separately
    }

    if event_type is None:
        # Choose randomly from all types including the login types
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
    else:
        msg, proto = types[event_type]
        return f"{ts} [**] [1:1000000:1] {msg} [**] [Priority: {random.randint(1,3)}] {proto} {src_ip} -> {dst}"

def generate_clean_log(filename, total_lines=1000000):
    """
    Generate a clean synthetic log file with a mix of:
    - failed login attempts (~5%)
    - successful login attempts (~5%)
    - other network events
    No brute force bursts included.
    """
    current_time = datetime.now() - timedelta(days=1)  # start 1 day ago

    with open(filename, 'w') as f:
        for _ in range(total_lines):
            ts_str = current_time.strftime("%b %d %H:%M:%S")

            r = random.random()
            if r < 0.05:
                alert_line = gen_alert(event_type="failed_login", timestamp=ts_str)
            elif r < 0.25:
                alert_line = gen_alert(event_type="successful_login", timestamp=ts_str)
            else:
                alert_line = gen_alert(timestamp=ts_str)

            f.write(alert_line + "\n")
            current_time += timedelta(seconds=1)

if __name__ == "__main__":
    generate_clean_log('synthetic_snort.log', total_lines=1000000)
    print("Clean synthetic log generated with successful and failed login attempts.")
