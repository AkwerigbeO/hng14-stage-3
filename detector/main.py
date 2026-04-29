import datetime
import os
import subprocess
import threading
import time

import yaml

import dashboard
from blocker import ban_ip
from dashboard import banned_lock, currently_banned, metrics_lock
from detector import AnomalyDetector
from notifier import send_slack_alert
from unbanner import run_unbanner


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "config.yaml"), "r") as f:
    conf = yaml.safe_load(f)

LOG_FILE_PATH = conf["logging"]["log_file_path"]
AUDIT_LOG_PATH = conf["logging"]["audit_log_path"]

HOME_IP = os.environ.get("HOME_IP", "127.0.0.1")
WHITELIST = {"127.0.0.1", HOME_IP}

banned_ip_cache = {}
ALERT_COOLDOWN_SEC = 300
offense_counts = {}
BACKOFF_SCHEDULE = conf["security"]["backoff_schedule"]
PERMANENT_BAN_MINUTES = conf["security"]["permanent_ban_minutes"]
last_global_alert_time = 0


def tail_f(filename):
    """Stream the Nginx log file in real time."""
    return subprocess.Popen(["tail", "-F", filename], stdout=subprocess.PIPE, text=True)


def update_dashboard_stats(detector_obj):
    with metrics_lock:
        dashboard.metrics_data["global_rps"] = detector_obj.get_total_rps()
        dashboard.metrics_data["mean"] = detector_obj.baseline_mean
        dashboard.metrics_data["stddev"] = detector_obj.baseline_stddev
        dashboard.metrics_data["top_ips"] = detector_obj.get_top_ips(10)
        with banned_lock:
            dashboard.metrics_data["banned_ips"] = list(currently_banned)


def _parse_action_line(line):
    parts = line.strip().split(" | ")
    if len(parts) < 2 or "ACTION " not in parts[0]:
        return None, None
    ip = parts[0].split("ACTION ", 1)[1].strip()
    action = parts[1].strip().upper()
    return ip, action


def _load_existing_bans():
    """Rebuild ban and offense state from the audit log after a restart."""
    try:
        if not os.path.exists(AUDIT_LOG_PATH):
            return
        with open(AUDIT_LOG_PATH, "r") as f:
            for line in f:
                ip, action = _parse_action_line(line)
                if not ip:
                    continue
                if action == "BAN":
                    currently_banned.add(ip)
                    offense_counts[ip] = offense_counts.get(ip, 0) + 1
                elif action == "UNBAN":
                    currently_banned.discard(ip)
        print(f"Loaded {len(currently_banned)} active bans and {len(offense_counts)} offense records")
    except Exception as e:
        print(f"Could not load existing bans: {e}")


def _baseline_label(detector_obj):
    return f"mean={detector_obj.baseline_mean:.2f},stddev={detector_obj.baseline_stddev:.2f}"


def _write_audit(ip, action, condition, rate, baseline, duration):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (
        f"[{timestamp}] ACTION {ip} | {action} | {condition} | "
        f"Rate: {rate} | Baseline: {baseline} | Duration: {duration}\n"
    )
    with open(AUDIT_LOG_PATH, "a") as af:
        af.write(entry)


def run_engine():
    global last_global_alert_time
    print("HNG Stage 3 Anomaly Engine starting...")

    _load_existing_bans()

    threading.Thread(target=run_unbanner, daemon=True).start()
    threading.Thread(target=dashboard.run_dashboard, daemon=True).start()
    print("Live Metrics Dashboard running on port 5000...")

    detector = AnomalyDetector()
    detector.load_state()
    log_stream = tail_f(LOG_FILE_PATH)

    while True:
        line = log_stream.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue

        is_anomaly, ip, rate, z_score, condition = detector.process_line(line)
        if ip is None:
            continue

        update_dashboard_stats(detector)

        global_rate = detector.get_total_rps()
        safe_stddev = detector.baseline_stddev if detector.baseline_stddev > 0 else 0.05
        global_z = (global_rate - detector.baseline_mean) / safe_stddev
        global_multiplier_limit = conf["thresholds"]["rate_multiplier"] * detector.baseline_mean

        if (
            detector.baseline_mean > 0
            and (
                global_z > conf["thresholds"]["z_score_limit"]
                or global_rate > global_multiplier_limit
            )
        ):
            current_time = time.time()
            if current_time - last_global_alert_time > 60:
                baseline = _baseline_label(detector)
                condition_label = (
                    f"Global Traffic Spike z={global_z:.2f} "
                    f"multiplier_limit={global_multiplier_limit:.2f}"
                )
                print(f"GLOBAL ANOMALY DETECTED! Rate: {global_rate}/s")
                send_slack_alert(
                    "GLOBAL",
                    global_rate,
                    global_z,
                    None,
                    condition_label,
                    baseline,
                )
                last_global_alert_time = current_time

        if not is_anomaly or ip in WHITELIST:
            continue

        current_time = time.time()
        if ip in banned_ip_cache and (current_time - banned_ip_cache[ip]) < ALERT_COOLDOWN_SEC:
            continue

        print(f"IP ANOMALY DETECTED: {ip} | {condition}")

        offense = offense_counts.get(ip, 0)
        if offense >= len(BACKOFF_SCHEDULE):
            duration = PERMANENT_BAN_MINUTES
            duration_label = "PERMANENT"
        else:
            duration = BACKOFF_SCHEDULE[offense]
            duration_label = f"{duration}m"

        if ban_ip(ip, duration):
            offense_counts[ip] = offense + 1
            banned_ip_cache[ip] = current_time
            with banned_lock:
                currently_banned.add(ip)

            baseline = _baseline_label(detector)
            audit_condition = f"condition={condition}; offense={offense + 1}"
            _write_audit(ip, "BAN", audit_condition, rate, baseline, duration_label)
            send_slack_alert(ip, rate, z_score, duration, condition, baseline)
            update_dashboard_stats(detector)


if __name__ == "__main__":
    run_engine()
