import random
from datetime import datetime, timedelta

def gen_alert(event_type=None, src_ip=None, timestamp=None):
    # Use passed timestamp or fallback to current time string
    ts = timestamp if timestamp else datetime.now().strftime("%b %d %H:%M:%S")

    # Usernames for failed login simulation
    usernames = ['root', 'admin', 'user', 'test']

    types = {
        "icmp_ping": ("ICMP Ping Detected", "{ICMP}"),
        "nmap_scan": ("Nmap Scripting Engine scan", "{TCP}"),
        "failed_login": None,  # handled separately below
    }

    if event_type is None:
        event_type = random.choice(list(types.keys()))

    if src_ip is None:
        src_ip = f"192.168.1.{random.randint(1,254)}"
    dst = "10.0.0.1"

    if event_type == "failed_login":
        user = random.choice(usernames)
        hostname = "server"
        pid = random.randint(1000, 9999)
        port = random.randint(1024, 65535)
        # Example sshd failed login log format:
        # "Jul 01 14:23:45 server sshd[1234]: Failed password for root from 192.168.1.5 port 4242 ssh2"
        return f"{ts} {hostname} sshd[{pid}]: Failed password for {user} from {src_ip} port {port} ssh2"
    else:
        msg, proto = types[event_type]
        return f"{ts} [**] [1:1000000:1] {msg} [**] [Priority: {random.randint(1,3)}] {proto} {src_ip} -> {dst}"

def generate_log(filename, total_lines=100000, bruteforce_chance=0.02, burst_size=25):
    current_time = datetime.now() - timedelta(days=1)  # start 1 day ago

    with open(filename, 'w') as f:
        line_count = 0

        while line_count < total_lines:
            ts_str = current_time.strftime("%b %d %H:%M:%S")

            if random.random() < bruteforce_chance:
                attacker_ip = f"192.168.1.{random.randint(1,254)}"
                for _ in range(burst_size):
                    alert_line = gen_alert(event_type="failed_login", src_ip=attacker_ip, timestamp=ts_str)
                    f.write(alert_line + "\n")
                    line_count += 1
                    current_time += timedelta(seconds=1)
                    if line_count >= total_lines:
                        break
            else:
                # Randomly sometimes generate a failed login event
                if random.random() < 0.05:  # ~5% chance for failed login outside bruteforce bursts
                    alert_line = gen_alert(event_type="failed_login", timestamp=ts_str)
                else:
                    alert_line = gen_alert(timestamp=ts_str)
                f.write(alert_line + "\n")
                line_count += 1
                current_time += timedelta(seconds=1)

if __name__ == "__main__":
    generate_log('synthetic_snort.log', total_lines=1000, bruteforce_chance=0.1, burst_size=15)
    print("Synthetic log with random brute force bursts and failed login attempts generated.")
