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
MIN_RATE_LIMIT = conf['thresholds'].get('min_rate_limit', 2.0)
BASELINE_STATE_PATH = os.path.join(BASE_DIR, 'baseline_data.json')

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

    def load_state(self):
        """Restore persisted hourly baseline data from disk (crash recovery)."""
        try:
            if os.path.exists(BASELINE_STATE_PATH):
                with open(BASELINE_STATE_PATH, 'r') as f:
                    state = json.load(f)
                for hour_str, values in state.get('hourly_rps', {}).items():
                    self.hourly_rps[int(hour_str)] = values
                for hour_str, values in state.get('hourly_errors', {}).items():
                    self.hourly_errors[int(hour_str)] = values
                # Immediately compute a baseline from the loaded data
                self.calculate_baseline()
                print(f"📊 Loaded baseline state: {len(self.hourly_rps)} hour slots, mean={self.baseline_mean:.2f}")
        except Exception as e:
            print(f"⚠️ Could not load baseline state: {e}")

    def save_state(self):
        """Persist hourly baseline data to disk so restarts don't lose memory."""
        try:
            state = {
                'hourly_rps': {str(k): v[-3600:] for k, v in self.hourly_rps.items() if v},
                'hourly_errors': {str(k): v[-3600:] for k, v in self.hourly_errors.items() if v},
            }
            with open(BASELINE_STATE_PATH, 'w') as f:
                json.dump(state, f)
        except Exception as e:
            print(f"⚠️ Could not save baseline state: {e}")

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
        """Recalculates the mean and standard deviation using multi-hour data.
        
        Strategy:
        1. Merge data from the CURRENT hour and PREVIOUS hour (two hourly slots).
        2. If combined data has >= 2 samples, compute the baseline (fast warm-up).
        3. If no hourly data at all, fall back to a global estimate from all hours.
        This ensures the baseline is never stuck at 0.00 for long.
        """
        current_hour = datetime.datetime.now().hour
        prev_hour = (current_hour - 1) % 24
        
        # Merge current + previous hour data (multi-hour awareness)
        rps_data = list(self.hourly_rps.get(current_hour, []))
        err_data = list(self.hourly_errors.get(current_hour, []))
        rps_data += self.hourly_rps.get(prev_hour, [])
        err_data += self.hourly_errors.get(prev_hour, [])
        
        # Fallback: if current+prev hour have nothing, use ALL available hours
        if len(rps_data) < 2:
            for hour in range(24):
                if hour != current_hour and hour != prev_hour:
                    rps_data += self.hourly_rps.get(hour, [])
                    err_data += self.hourly_errors.get(hour, [])
        
        # Fast warm-up: only need 2 samples to start (was 11 before)
        if len(rps_data) >= 2:
            self.baseline_mean = statistics.mean(rps_data)
            self.baseline_stddev = statistics.stdev(rps_data) if len(rps_data) > 1 else 1.0
            self.error_baseline_mean = max(statistics.mean(err_data), 0.1) if err_data else 0.1
            self.log_baseline(current_hour)
            
            # Keep only the last hour of data per slot to keep it "rolling"
            self.hourly_rps[current_hour] = self.hourly_rps[current_hour][-3600:]
            self.hourly_errors[current_hour] = self.hourly_errors[current_hour][-3600:]
        elif len(rps_data) == 1:
            # Even a single sample is better than 0.00
            self.baseline_mean = rps_data[0]
            self.baseline_stddev = 1.0

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

        # Periodically update hourly baseline (every 30s for faster warm-up)
        if time.time() - self.last_recalc_time > 30:
            current_hour = datetime.datetime.now().hour
            self.hourly_rps[current_hour].append(self.get_total_rps())
            self.hourly_errors[current_hour].append(self.get_global_error_rate())
            self.calculate_baseline()
            self.save_state()
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
        elif ip_rate > (self.baseline_mean * effective_rate_multiplier) and self.baseline_mean > 0 and ip_rate > MIN_RATE_LIMIT:
            condition = f"Rate Multiplier ({ip_rate} > {self.baseline_mean * effective_rate_multiplier:.1f}) & Rate > {MIN_RATE_LIMIT}"
        
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
