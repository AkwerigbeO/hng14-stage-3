import time
import collections
import statistics
import os
import yaml
import datetime
import json

# --- LOAD CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, 'config.yaml'), 'r') as f:
    conf = yaml.safe_load(f)

AUDIT_LOG_PATH = conf['logging']['audit_log_path']
Z_SCORE_LIMIT = conf['thresholds']['z_score_limit']
RATE_MULTIPLIER = conf['thresholds']['rate_multiplier']

class AnomalyDetector:
    def __init__(self):
        self.history = collections.defaultdict(list)  # {timestamp: [ip1, ip2...]}
        self.ip_counts = collections.defaultdict(lambda: collections.defaultdict(int)) # {timestamp: {ip: count}}
        self.baseline_data = [] # List of total RPS per second
        self.baseline_mean = 0.0
        self.baseline_stddev = 1.0
        self.last_recalc_time = time.time()

    def log_baseline(self):
        """Writes baseline updates to the audit log for Screenshot #6."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{timestamp} | ACTION: SYSTEM | DETAILS: baseline_recalc | Mean: {self.baseline_mean:.2f} | StdDev: {self.baseline_stddev:.2f}\n"
        try:
            with open(AUDIT_LOG_PATH, "a") as f:
                f.write(entry)
        except Exception as e:
            print(f"⚠️ Could not write baseline to audit log: {e}")

    def calculate_baseline(self):
        """Recalculates the mean and standard deviation of traffic."""
        if len(self.baseline_data) > 10: # Need at least 10 seconds of data
            self.baseline_mean = statistics.mean(self.baseline_data)
            self.baseline_stddev = statistics.stdev(self.baseline_data)
            self.log_baseline()
            # Keep only the last hour (3600 seconds) of data
            self.baseline_data = self.baseline_data[-3600:]

    def get_total_rps(self):
        """Returns the average requests per second over the last 5 seconds.
        
        Averaging over 5 seconds smooths out jitter and ensures the
        dashboard always has a meaningful value, even if the Flask
        request arrives between log bursts.
        """
        now = int(time.time())
        total = sum(len(self.history.get(t, [])) for t in range(now - 5, now + 1))
        return round(total / 5.0, 2)

    def get_top_ips(self, n=10):
        """Returns the top N busiest IPs aggregated over the last 10 seconds.
        
        A wider window prevents the UI from showing empty tables
        when there is a brief pause between log lines.
        """
        now = int(time.time())
        combined = collections.defaultdict(int)
        for t in range(now - 10, now + 1):
            for ip, count in self.ip_counts.get(t, {}).items():
                combined[ip] += count
        return sorted(combined.items(), key=lambda x: x[1], reverse=True)[:n]

    def process_line(self, line):
        """
        Analyzes a single log line.
        Handles both JSON and Standard Nginx formats.
        Uses a fallback chain for IP extraction from JSON logs.
        """
        try:
            line = line.strip()
            if not line:
                return False, None, 0, 0

            # Detect if log is JSON (Nginx JSON format)
            if line.startswith('{'):
                log_data = json.loads(line)
                # Fallback chain: try multiple common field names
                ip = (log_data.get('source_ip')
                      or log_data.get('remote_addr')
                      or log_data.get('client_ip')
                      or '')
                # Strip whitespace and reject empty/invalid values
                ip = ip.strip()
                if not ip or ip == '-':
                    return False, None, 0, 0
            else:
                # Standard Nginx combined format
                parts = line.split()
                if not parts:
                    return False, None, 0, 0
                ip = parts[0].strip()
                if not ip or ip == '-':
                    return False, None, 0, 0
        except (json.JSONDecodeError, Exception):
            return False, None, 0, 0

        now = int(time.time())

        # 2. Update tracking
        self.history[now].append(ip)
        self.ip_counts[now][ip] += 1

        # 3. Periodically update baseline
        if time.time() - self.last_recalc_time > 60:
            self.baseline_data.append(self.get_total_rps())
            self.calculate_baseline()
            self.last_recalc_time = time.time()

        # 4. Check for Anomaly
        ip_rate = self.ip_counts[now][ip]

        # Avoid division by zero
        safe_stddev = self.baseline_stddev if self.baseline_stddev > 0 else 1.0
        z_score = (ip_rate - self.baseline_mean) / safe_stddev

        # Logic: Anomaly if Z-score is high AND rate is significantly above baseline
        is_anomaly = (z_score > Z_SCORE_LIMIT) and (ip_rate > (self.baseline_mean * RATE_MULTIPLIER))

        # Clean up old history (keep only last 15 seconds for the wider aggregation windows)
        old_keys = [t for t in self.history.keys() if t < now - 15]
        for t in old_keys:
            self.history.pop(t, None)
            self.ip_counts.pop(t, None)

        return is_anomaly, ip, ip_rate, z_score
