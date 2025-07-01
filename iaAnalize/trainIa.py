import pandas as pd
from datetime import datetime
from parseLogs import parse_log_line, extract_features  # adjust import if needed
from sklearn.ensemble import IsolationForest
import joblib
# Include your parse_timestamp function if required

def load_and_prepare_data(logfile):
    parsed_logs = []
    with open(logfile, 'r') as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed and parsed['timestamp']:
                parsed_logs.append(parsed)

    df = pd.DataFrame(parsed_logs)
    features = extract_features(df)
    return features

if __name__ == "__main__":
    log_path = 'synthetic_snort.log'  # your training log path here
    feature_df = load_and_prepare_data(log_path)

    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    X = feature_df[['failed_logins', 'nmap_scans', 'unique_ips']]
    model.fit(X)

    joblib.dump(model, 'models/isoforest_model.pkl')
    print("Model trained and saved.")
