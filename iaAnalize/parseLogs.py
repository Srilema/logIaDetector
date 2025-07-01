import re
import pandas as pd
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os

# Parse functions (same as your current code)
def parse_log_line(line):
    ssh_match = re.search(
        r'(?P<timestamp>\w{3} +\d+ \d+:\d+:\d+).*Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)',
        line
    )
    if ssh_match:
        return {
            'event': 'failed_login',
            'ip': ssh_match.group('ip'),
            'timestamp': parse_timestamp(ssh_match.group('timestamp'))
        }

    if 'Nmap Scripting Engine' in line:
        snort_match = re.search(
            r'(?P<timestamp>\w{3} +\d+ \d+:\d+:\d+).*?(\d+\.\d+\.\d+\.\d+):\d+ ->',
            line
        )
        if snort_match:
            return {
                'event': 'nmap_scan',
                'ip': snort_match.group(2),
                'timestamp': parse_timestamp(snort_match.group('timestamp'))
            }

    return None

def parse_timestamp(raw_ts):
    try:
        return datetime.strptime(f"{datetime.now().year} {raw_ts}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

# Feature extraction
def extract_features(df):
    df['minute'] = df['timestamp'].dt.floor('min')
    
    agg = df.groupby('minute').agg(
        failed_logins=('event', lambda x: (x == 'failed_login').sum()),
        nmap_scans=('event', lambda x: (x == 'nmap_scan').sum()),
        unique_ips=('ip', pd.Series.nunique)
    ).reset_index()

    return agg

# Watchdog Handler
class LogHandler(FileSystemEventHandler):
    def __init__(self, filepath):
        self.filepath = filepath
        self.offset = os.path.getsize(filepath)

    def on_modified(self, event):
        if event.src_path == self.filepath:
            with open(self.filepath, 'r') as f:
                f.seek(self.offset)
                new_lines = f.readlines()
                self.offset = f.tell()

            parsed_logs = []
            for line in new_lines:
                parsed = parse_log_line(line)
                if parsed and parsed['timestamp']:
                    parsed_logs.append(parsed)

            if parsed_logs:
                df = pd.DataFrame(parsed_logs)
                features = extract_features(df)
                print("New Features:")
                print(features)

# Main Watch Function
def watch_log(filepath):
    event_handler = LogHandler(filepath)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(filepath) or '.', recursive=False)
    observer.start()

    print(f"Watching {filepath} for new log lines...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Entry point
if __name__ == "__main__":
    log_path = '../logs/exemple.log'  # Adjust path as needed
    watch_log(log_path)
