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
        
        # --- Error Tracking ---
        self.ip_errors = collections.defaultdict(lambda: collections.defaultdict(int)) # {timestamp: {ip: error_count}}
        self.global_errors = collections.defaultdict(int) # {timestamp: total_error_count}
        
        # --- Baseline Slots (Per-Hour) ---
        # Stores RPS and Error-Rate data for each hour of the day (0-23)
        self.hourly_rps = collections.defaultdict(list)   # {hour: [rps1, rps2...]}
        self.hourly_errors = collections.defaultdict(list) # {hour: [err1, err2...]}
        
        self.baseline_mean = 0.0
        self.baseline_stddev = 1.0
        self.error_baseline_mean = 0.1 # Floor to avoid div by zero
        
        self.last_recalc_time = time.time()

    def log_baseline(self, hour):
        """Writes baseline updates to the audit log."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{timestamp} | ACTION: SYSTEM | DETAILS: baseline_recalc | Hour: {hour} | RPS Mean: {self.baseline_mean:.2f} | Err Mean: {self.error_baseline_mean:.2f}\n"
        try:
            with open(AUDIT_LOG_PATH, "a") as f:
                f.write(entry)
        except Exception as e:
            print(f"⚠️ Could not write baseline to audit log: {e}")

    def calculate_baseline(self):
        """Recalculates the mean and standard deviation for the current hour."""
        current_hour = datetime.datetime.now().hour
        
        # Prefer the current hour's data if we have at least 10 data points
        rps_data = self.hourly_rps[current_hour]
        err_data = self.hourly_errors[current_hour]
        
        if len(rps_data) > 10:
            self.baseline_mean = statistics.mean(rps_data)
            self.baseline_stddev = statistics.stdev(rps_data) if len(rps_data) > 1 else 1.0
            self.error_baseline_mean = max(statistics.mean(err_data), 0.1)
            self.log_baseline(current_hour)
            
            # Keep only the last hour of data per slot to keep it "rolling"
            self.hourly_rps[current_hour] = rps_data[-3600:]
            self.hourly_errors[current_hour] = err_data[-3600:]

    def get_total_rps(self):
        now = int(time.time())
        total = sum(len(self.history.get(t, [])) for t in range(now - 5, now + 1))
        return round(total / 5.0, 2)

    def get_global_error_rate(self):
        """Average global errors per second over last 5s."""
        now = int(time.time())
        total = sum(self.global_errors.get(t, 0) for t in range(now - 5, now + 1))
        return round(total / 5.0, 2)

    def get_top_ips(self, n=10):
        now = int(time.time())
        combined = collections.defaultdict(int)
        for t in range(now - 10, now + 1):
            for ip, count in self.ip_counts.get(t, {}).items():
                combined[ip] += count
        return sorted(combined.items(), key=lambda x: x[1], reverse=True)[:n]

    def process_line(self, line):
        """
        Analyzes a single log line.
        Supports 'Error Surge' detection and threshold tightening.
        """
        try:
            line = line.strip()
            if not line:
                return False, None, 0, 0, "No data"

            status = 200
            if line.startswith('{'):
                log_data = json.loads(line)
                ip = (log_data.get('source_ip') or log_data.get('remote_addr') or log_data.get('client_ip') or '').strip()
                status = int(log_data.get('status', 200))
            else:
                parts = line.split()
                if not parts: return False, None, 0, 0, "Parse error"
                ip = parts[0].strip()
                # Try to find status in common Nginx combined positions
                if len(parts) > 8: status = int(parts[8])

            if not ip or ip == '-': return False, None, 0, 0, "Invalid IP"
        except Exception:
            return False, None, 0, 0, "Parse error"

        now = int(time.time())
        self.history[now].append(ip)
        self.ip_counts[now][ip] += 1
        
        # Track errors (4xx, 5xx)
        if status >= 400:
            self.ip_errors[now][ip] += 1
            self.global_errors[now] += 1

        # Periodically update hourly baseline
        if time.time() - self.last_recalc_time > 60:
            current_hour = datetime.datetime.now().hour
            self.hourly_rps[current_hour].append(self.get_total_rps())
            self.hourly_errors[current_hour].append(self.get_global_error_rate())
            self.calculate_baseline()
            self.last_recalc_time = time.time()

        # --- Detection Logic ---
        ip_rate = self.ip_counts[now][ip]
        ip_err_rate = self.ip_errors[now][ip]
        
        # 1. Error Surge Check
        # If IP error rate is 3x baseline error rate, tighten thresholds
        is_error_surge = (ip_err_rate > (self.error_baseline_mean * 3)) and (ip_err_rate > 2)
        effective_z_limit = Z_SCORE_LIMIT / 2.0 if is_error_surge else Z_SCORE_LIMIT
        effective_rate_multiplier = RATE_MULTIPLIER / 2.0 if is_error_surge else RATE_MULTIPLIER

        # 2. Z-Score Anomaly
        safe_stddev = self.baseline_stddev if self.baseline_stddev > 0 else 1.0
        z_score = (ip_rate - self.baseline_mean) / safe_stddev

        # Flag Condition
        condition = None
        if z_score > effective_z_limit:
            condition = f"Z-Score ({z_score:.2f} > {effective_z_limit})"
        elif ip_rate > (self.baseline_mean * effective_rate_multiplier) and self.baseline_mean > 0:
            condition = f"Rate Multiplier ({ip_rate} > {self.baseline_mean * effective_rate_multiplier:.1f})"
        
        if is_error_surge and condition:
            condition = f"ERROR SURGE + {condition}"

        is_anomaly = condition is not None

        # Cleanup
        old_keys = [t for t in self.history.keys() if t < now - 15]
        for t in old_keys:
            self.history.pop(t, None)
            self.ip_counts.pop(t, None)
            self.ip_errors.pop(t, None)
            self.global_errors.pop(t, None)

        return is_anomaly, ip, ip_rate, z_score, condition
