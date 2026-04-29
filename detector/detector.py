import collections
import datetime
import json
import os
import statistics
import time

import yaml


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "config.yaml"), "r") as f:
    conf = yaml.safe_load(f)

AUDIT_LOG_PATH = conf["logging"]["audit_log_path"]
Z_SCORE_LIMIT = conf["thresholds"]["z_score_limit"]
RATE_MULTIPLIER = conf["thresholds"]["rate_multiplier"]
MIN_RATE_LIMIT = conf["thresholds"].get("min_rate_limit", 2.0)
BASELINE_STATE_PATH = os.path.join(BASE_DIR, "baseline_data.json")

WINDOW_SECONDS = 60
BASELINE_SECONDS = 30 * 60
BASELINE_RECALC_SECONDS = 60
CURRENT_HOUR_MIN_SAMPLES = 300
MEAN_FLOOR = 0.1
STDDEV_FLOOR = 0.05
ERROR_RATE_FLOOR = 0.1


class AnomalyDetector:
    def __init__(self):
        # Required 60s deque windows: one global, one per source IP.
        self.global_window = collections.deque()
        self.ip_windows = collections.defaultdict(collections.deque)
        self.ip_error_windows = collections.defaultdict(collections.deque)

        # Completed per-second slots used for the rolling 30-minute baseline.
        self.baseline_counts = collections.deque(maxlen=BASELINE_SECONDS)
        self.baseline_error_counts = collections.deque(maxlen=BASELINE_SECONDS)
        self.hourly_rps = collections.defaultdict(list)
        self.hourly_errors = collections.defaultdict(list)

        self.current_second = None
        self.current_second_count = 0
        self.current_second_errors = 0

        self.baseline_mean = MEAN_FLOOR
        self.baseline_stddev = STDDEV_FLOOR
        self.error_baseline_mean = ERROR_RATE_FLOOR
        self.last_recalc_time = time.time()

    def load_state(self):
        """Restore persisted baseline data from disk."""
        try:
            if not os.path.exists(BASELINE_STATE_PATH):
                return
            with open(BASELINE_STATE_PATH, "r") as f:
                state = json.load(f)

            self.baseline_counts = collections.deque(
                state.get("baseline_counts", [])[-BASELINE_SECONDS:],
                maxlen=BASELINE_SECONDS,
            )
            self.baseline_error_counts = collections.deque(
                state.get("baseline_error_counts", [])[-BASELINE_SECONDS:],
                maxlen=BASELINE_SECONDS,
            )
            for hour_str, values in state.get("hourly_rps", {}).items():
                self.hourly_rps[int(hour_str)] = values[-3600:]
            for hour_str, values in state.get("hourly_errors", {}).items():
                self.hourly_errors[int(hour_str)] = values[-3600:]

            self.calculate_baseline(write_audit=False)
            print(
                f"Loaded baseline state: {len(self.baseline_counts)} seconds, "
                f"mean={self.baseline_mean:.2f}, stddev={self.baseline_stddev:.2f}"
            )
        except Exception as e:
            print(f"Could not load baseline state: {e}")

    def save_state(self):
        """Persist rolling and hourly baseline data so restarts keep learning."""
        try:
            state = {
                "baseline_counts": list(self.baseline_counts),
                "baseline_error_counts": list(self.baseline_error_counts),
                "hourly_rps": {
                    str(k): v[-3600:] for k, v in self.hourly_rps.items() if v
                },
                "hourly_errors": {
                    str(k): v[-3600:] for k, v in self.hourly_errors.items() if v
                },
            }
            with open(BASELINE_STATE_PATH, "w") as f:
                json.dump(state, f)
        except Exception as e:
            print(f"Could not save baseline state: {e}")

    def log_baseline(self, condition):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = (
            f"[{timestamp}] ACTION SYSTEM | {condition} | "
            f"Rate: {self.get_total_rps():.2f} | "
            f"Baseline: mean={self.baseline_mean:.2f},stddev={self.baseline_stddev:.2f},"
            f"error_mean={self.error_baseline_mean:.2f} | Duration: n/a\n"
        )
        try:
            with open(AUDIT_LOG_PATH, "a") as f:
                f.write(entry)
        except Exception as e:
            print(f"Could not write baseline audit entry: {e}")

    def _append_completed_second(self, second, count, error_count):
        hour = datetime.datetime.fromtimestamp(second).hour
        rps = float(count)
        error_rate = float(error_count)

        self.baseline_counts.append(rps)
        self.baseline_error_counts.append(error_rate)
        self.hourly_rps[hour].append(rps)
        self.hourly_errors[hour].append(error_rate)
        self.hourly_rps[hour] = self.hourly_rps[hour][-3600:]
        self.hourly_errors[hour] = self.hourly_errors[hour][-3600:]

    def _roll_second_slots(self, now_sec):
        if self.current_second is None:
            self.current_second = now_sec
            return

        while self.current_second < now_sec:
            self._append_completed_second(
                self.current_second,
                self.current_second_count,
                self.current_second_errors,
            )
            self.current_second += 1
            self.current_second_count = 0
            self.current_second_errors = 0

    def _cleanup_windows(self, now):
        cutoff = now - WINDOW_SECONDS
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()

        for ip in list(self.ip_windows.keys()):
            while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
                self.ip_windows[ip].popleft()
            if not self.ip_windows[ip]:
                del self.ip_windows[ip]

        for ip in list(self.ip_error_windows.keys()):
            while self.ip_error_windows[ip] and self.ip_error_windows[ip][0] < cutoff:
                self.ip_error_windows[ip].popleft()
            if not self.ip_error_windows[ip]:
                del self.ip_error_windows[ip]

    def calculate_baseline(self, write_audit=True):
        """Recalculate effective baseline from rolling 30m data every 60s.

        If the current hour has at least five minutes of per-second samples, it
        becomes the preferred baseline. Otherwise the rolling 30-minute window
        is used.
        """
        current_hour = datetime.datetime.now().hour
        current_hour_rps = self.hourly_rps.get(current_hour, [])
        current_hour_errors = self.hourly_errors.get(current_hour, [])

        if len(current_hour_rps) >= CURRENT_HOUR_MIN_SAMPLES:
            rps_data = current_hour_rps[-3600:]
            error_data = current_hour_errors[-3600:]
            condition = f"baseline_recalc current_hour={current_hour}"
        else:
            rps_data = list(self.baseline_counts)
            error_data = list(self.baseline_error_counts)
            condition = "baseline_recalc rolling_30m"

        if rps_data:
            mean = statistics.mean(rps_data)
            stddev = statistics.stdev(rps_data) if len(rps_data) > 1 else STDDEV_FLOOR
            self.baseline_mean = max(mean, MEAN_FLOOR)
            self.baseline_stddev = max(stddev, STDDEV_FLOOR)

        if error_data:
            self.error_baseline_mean = max(statistics.mean(error_data), ERROR_RATE_FLOOR)

        if write_audit:
            self.log_baseline(condition)

    def maybe_recalculate_baseline(self):
        if time.time() - self.last_recalc_time >= BASELINE_RECALC_SECONDS:
            self.calculate_baseline()
            self.save_state()
            self.last_recalc_time = time.time()

    def get_total_rps(self):
        return round(len(self.global_window) / WINDOW_SECONDS, 2)

    def get_top_ips(self, n=10):
        top = [(ip, len(window)) for ip, window in self.ip_windows.items()]
        return sorted(top, key=lambda item: item[1], reverse=True)[:n]

    def _parse_line(self, line):
        line = line.strip()
        if not line:
            return None

        if line.startswith("{"):
            log_data = json.loads(line)
            return {
                "ip": (
                    log_data.get("source_ip")
                    or log_data.get("remote_addr")
                    or log_data.get("client_ip")
                    or ""
                ).strip(),
                "timestamp": log_data.get("timestamp"),
                "method": log_data.get("method") or log_data.get("request_method"),
                "path": log_data.get("path") or log_data.get("request_uri"),
                "status": int(log_data.get("status", 200)),
                "response_size": int(
                    log_data.get("response_size") or log_data.get("body_bytes_sent") or 0
                ),
            }

        parts = line.split()
        if not parts:
            return None
        status = int(parts[8]) if len(parts) > 8 else 200
        return {
            "ip": parts[0].strip(),
            "timestamp": None,
            "method": parts[5].strip('"') if len(parts) > 5 else None,
            "path": parts[6] if len(parts) > 6 else None,
            "status": status,
            "response_size": int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0,
        }

    def process_line(self, line):
        """Parse one Nginx log line and evaluate IP anomaly state."""
        try:
            event = self._parse_line(line)
            if not event or not event["ip"] or event["ip"] == "-":
                return False, None, 0, 0, "Invalid log line"
        except Exception:
            return False, None, 0, 0, "Parse error"

        now = time.time()
        now_sec = int(now)
        ip = event["ip"]
        status = event["status"]

        self._roll_second_slots(now_sec)

        self.global_window.append(now)
        self.ip_windows[ip].append(now)
        self.current_second_count += 1

        if status >= 400:
            self.ip_error_windows[ip].append(now)
            self.current_second_errors += 1

        self._cleanup_windows(now)
        self.maybe_recalculate_baseline()

        ip_rate = len(self.ip_windows[ip]) / WINDOW_SECONDS
        ip_error_rate = len(self.ip_error_windows.get(ip, ())) / WINDOW_SECONDS
        safe_stddev = self.baseline_stddev if self.baseline_stddev > 0 else STDDEV_FLOOR
        z_score = (ip_rate - self.baseline_mean) / safe_stddev

        is_error_surge = ip_error_rate > (self.error_baseline_mean * 3)
        effective_z_limit = Z_SCORE_LIMIT / 2.0 if is_error_surge else Z_SCORE_LIMIT
        effective_rate_multiplier = RATE_MULTIPLIER / 2.0 if is_error_surge else RATE_MULTIPLIER

        condition = None
        if z_score > effective_z_limit:
            condition = f"Z-Score ({z_score:.2f} > {effective_z_limit:.2f})"
        elif (
            ip_rate > (self.baseline_mean * effective_rate_multiplier)
            and ip_rate > MIN_RATE_LIMIT
        ):
            condition = (
                f"Rate Multiplier ({ip_rate:.2f} > "
                f"{self.baseline_mean * effective_rate_multiplier:.2f})"
            )

        if is_error_surge and condition:
            condition = f"ERROR SURGE + {condition}"

        return condition is not None, ip, round(ip_rate, 2), z_score, condition
