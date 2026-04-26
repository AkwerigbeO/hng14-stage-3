import json
import time
import math
from collections import deque
import config
from datetime import datetime

class AnomalyDetector:
    def __init__(self):
        # Sliding Windows (60-second retention)
        self.ip_windows = {} 
        self.global_window = deque()
        
        # Baseline Statistics
        self.baseline_mean = 5.0   # Starts at 5.0 to prevent dividing by zero early on
        self.baseline_stddev = 1.0 
        self.last_baseline_calc = time.time()
        
        # 30-minute history for baseline (1800 seconds)
        self.history_counts = deque(maxlen=1800) 

    def process_line(self, line):
        """Parses a JSON log line, updates windows, and checks for anomalies."""
        try:
            # HNG Requirement: Read Nginx JSON logs
            log_data = json.loads(line)
            ip = log_data.get("source_ip", "")
            if not ip:
                return False, "", 0, 0.0

            now = time.time()
            
            # 1. Update Global Window
            self.global_window.append(now)
            
            # 2. Update Per-IP Window
            if ip not in self.ip_windows:
                self.ip_windows[ip] = deque()
            self.ip_windows[ip].append(now)
            
            # 3. Clean up old entries (> 60 seconds) for this specific IP
            while self.ip_windows[ip] and self.ip_windows[ip][0] < now - 60:
                self.ip_windows[ip].popleft()

            # Rate = requests per second over the last 60 seconds
            rate = len(self.ip_windows[ip]) / 60.0

            # 4. Check if it's time to recalculate the baseline
            self._update_baseline(now)

            # 5. Anomaly Logic (Z-Score > 3.0 OR Rate > 5x Mean)
            z_score = 0.0
            is_anomaly = False
            
            if self.baseline_mean > 0:
                # Prevent division by zero
                safe_stddev = self.baseline_stddev if self.baseline_stddev > 0 else 1.0
                z_score = (rate - self.baseline_mean) / safe_stddev
                
                if z_score > 3.0 or rate > (5 * self.baseline_mean):
                    is_anomaly = True

            return is_anomaly, ip, rate, z_score

        except json.JSONDecodeError:
            # Silently ignore lines that aren't valid JSON (like Nginx startup messages)
            return False, "", 0, 0.0
        except Exception as e:
            print(f"❌ Error processing line: {e}")
            return False, "", 0, 0.0

    def _update_baseline(self, now):
        """Recalculates the mean and stddev every 60 seconds and logs it."""
        if now - self.last_baseline_calc >= 60:
            current_global_rps = self.get_total_rps()
            self.history_counts.append(current_global_rps)
            
            if len(self.history_counts) > 0:
                # Calculate Mean
                self.baseline_mean = sum(self.history_counts) / len(self.history_counts)
                
                # Calculate Standard Deviation
                if len(self.history_counts) > 1:
                    variance = sum((x - self.baseline_mean) ** 2 for x in self.history_counts) / len(self.history_counts)
                    self.baseline_stddev = math.sqrt(variance)
                else:
                    self.baseline_stddev = 1.0
                    
            self.last_baseline_calc = now
            
            # HNG Requirement: Audit Log must contain baseline recalculations
            try:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_entry = f"{timestamp} | ACTION: SYSTEM | baseline_recalc | mean: {self.baseline_mean:.2f} | stddev: {self.baseline_stddev:.2f}\n"
                with open(config.AUDIT_LOG_PATH, "a") as f:
                    f.write(log_entry)
            except Exception as e:
                print(f"⚠️ Could not write baseline to audit log: {e}")

    # --- DASHBOARD UI METHODS ---

    def get_total_rps(self):
        """Returns the total global requests per second."""
        now = time.time()
        while self.global_window and self.global_window[0] < now - 60:
            self.global_window.popleft()
        return len(self.global_window) / 60.0

    def get_top_ips(self, limit=10):
        """Returns a sorted list of the top IPs for the live UI."""
        ip_counts = []
        now = time.time()
        
        # Use list() to avoid "dictionary changed size during iteration" errors
        for ip in list(self.ip_windows.keys()):
            window = self.ip_windows[ip]
            
            # Clean up old data
            while window and window[0] < now - 60:
                window.popleft()
            
            if len(window) > 0:
                ip_counts.append({"ip": ip, "count": len(window)})
            else:
                # Remove inactive IPs to save memory
                del self.ip_windows[ip]
        
        # Sort highest to lowest
        sorted_ips = sorted(ip_counts, key=lambda x: x["count"], reverse=True)
        return sorted_ips[:limit]
