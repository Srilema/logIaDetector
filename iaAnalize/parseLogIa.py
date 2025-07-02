import re
import os
import time
from datetime import datetime
import pandas as pd
import joblib
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configurations
LOG_PATH = './synthetic_snort_dynamic.log'  # Adjust as needed
MODEL_PATH = './models/isoforest_model.pkl'  # Path to your trained model
ALERT_ENDPOINT = "http://127.0.0.1:8080/alerts"  # Replace with your dashboard API URL

# Load trained IsolationForest model once
model = joblib.load(MODEL_PATH)

def parse_log_line(line):
    """
    Parse a log line to extract events of interest.
    Returns a dict or None.
    """
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
    """
    Parse a timestamp string from the log into a datetime object.
    """
    try:
        return datetime.strptime(f"{datetime.now().year} {raw_ts}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

def extract_features(df):
    """
    Extract features aggregated by minute from parsed logs.
    """
    df['minute'] = df['timestamp'].dt.floor('min')
    
    agg = df.groupby('minute').agg(
        failed_logins=('event', lambda x: (x == 'failed_login').sum()),
        nmap_scans=('event', lambda x: (x == 'nmap_scan').sum()),
        unique_ips=('ip', pd.Series.nunique)
    ).reset_index()

    return agg

def send_alert(row):
    """
    Send an anomaly alert to the configured dashboard endpoint.
    """
    alert_data = {
        "timestamp": row['minute'].isoformat(),
        "failed_logins": int(row['failed_logins']),
        "nmap_scans": int(row['nmap_scans']),
        "unique_ips": int(row['unique_ips']),
        "alert": "Anomaly detected by IsolationForest"
    }
    try:
        response = requests.post(ALERT_ENDPOINT, json=alert_data)
        response.raise_for_status()
        print(f"[ALERT SENT] {row['minute']}")
    except Exception as e:
        print(f"[ALERT FAILED] {e}")

class LogHandler(FileSystemEventHandler):
    """
    Watches the log file and processes new lines for anomaly detection.
    """
    def __init__(self, filepath):
        self.filepath = os.path.abspath(filepath)
        while not os.path.exists(self.filepath):
            print(f"[WAIT] {self.filepath} not yet created ...")
            time.sleep(1)
        self.offset = os.path.getsize(self.filepath)

    def on_modified(self, event):
        if not event.src_path.endswith(os.path.basename(self.filepath)):
            return
        print(f"[EVENT] {event.src_path} modified")

        with open(self.filepath, 'r') as f:
            f.seek(self.offset)
            new_lines = f.readlines()
            self.offset = f.tell()
        print(f"[DEBUG] Read {len(new_lines)} new lines")

        parsed_logs = [parse_log_line(l) for l in new_lines]
        parsed_logs = [p for p in parsed_logs if p and p['timestamp']]
        print(f"[DEBUG] Parsed {len(parsed_logs)} usable entries")

        if parsed_logs:
            df = pd.DataFrame(parsed_logs)
            features = extract_features(df)
            print("[INFO] Features:")
            print(features)

            X = features[['failed_logins', 'nmap_scans', 'unique_ips']]
            features['anomaly'] = model.predict(X)
            print("[DEBUG] Predictions:")
            print(features)

            # Only consider true anomalies
            anomalies = features[features['anomaly'] == -1]

            # Filter anomalies by significance
            def is_meaningful(row):
                return row['failed_logins'] > 5 or row['nmap_scans'] > 0 or row['unique_ips'] > 3

            significant = anomalies[anomalies.apply(is_meaningful, axis=1)]

            if not significant.empty:
                print("[DETECTED] Significant anomalies!")
                print(significant)
                for _, row in significant.iterrows():
                    send_alert(row)



def watch_log(filepath):
    """
    Starts watchdog observer to monitor log file changes.
    """
    event_handler = LogHandler(filepath)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(filepath) or '.', recursive=False)
    observer.start()

    print(f"[INFO] Watching {filepath} for new log lines...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    watch_log(LOG_PATH)
