import time
import threading
import subprocess
import os
import yaml
import datetime

from detector import AnomalyDetector
from blocker import ban_ip
from unbanner import run_unbanner
from notifier import send_slack_alert
import dashboard
from dashboard import metrics_lock, currently_banned, banned_lock


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, 'config.yaml'), 'r') as f:
    conf = yaml.safe_load(f)

LOG_FILE_PATH = conf['logging']['log_file_path']
AUDIT_LOG_PATH = conf['logging']['audit_log_path']

# Build Whitelist from environment variables
HOME_IP = os.environ.get("HOME_IP", "127.0.0.1")
WHITELIST = ["127.0.0.1", HOME_IP]

# ─── Banned IP Cache (prevents duplicate Slack alerts) ───
# Maps IP -> timestamp of last alert. If an IP is already in this cache
# and the cooldown hasn't expired, we skip the ban+alert cycle entirely.
banned_ip_cache = {}
ALERT_COOLDOWN_SEC = 300  # 5-minute cooldown per IP

# ─── Offense Tracking (for backoff schedule) ───
# Tracks how many times each IP has been banned.
# Does NOT reset on unban — escalates: 10m → 30m → 2h → permanent.
offense_counts = {}
BACKOFF_SCHEDULE = [10, 30, 120]  # minutes per offense (4th+ = permanent)

# Debounce timer for GLOBAL alerts
last_global_alert_time = 0


def tail_f(filename):
    """Streams the Nginx log file in real-time."""
    process = subprocess.Popen(['tail', '-F', filename], stdout=subprocess.PIPE, text=True)
    return process


def update_dashboard_stats(detector_obj):
    """Updates the shared dictionary in dashboard.py so the Live UI is accurate.
    
    All writes are guarded by metrics_lock to prevent the Flask
    request thread from reading a half-written state.
    """
    with metrics_lock:
        dashboard.metrics_data["global_rps"] = detector_obj.get_total_rps()
        dashboard.metrics_data["mean"] = detector_obj.baseline_mean
        dashboard.metrics_data["stddev"] = detector_obj.baseline_stddev
        dashboard.metrics_data["top_ips"] = detector_obj.get_top_ips(10)
        with banned_lock:
            dashboard.metrics_data["banned_ips"] = list(currently_banned)


def _load_existing_bans():
    """On startup, scan the audit log once to rebuild the currently_banned set
    and offense_counts for correct backoff escalation.
    """
    global offense_counts
    try:
        if not os.path.exists(AUDIT_LOG_PATH):
            return
        with open(AUDIT_LOG_PATH, "r") as f:
            for line in f:
                if "DETAILS: BAN" in line:
                    parts = line.strip().split(" | ")
                    if len(parts) >= 2:
                        ip = parts[1].replace("ACTION: ", "").strip()
                        currently_banned.add(ip)
                        offense_counts[ip] = offense_counts.get(ip, 0) + 1
                elif "DETAILS: UNBAN" in line:
                    parts = line.strip().split(" | ")
                    if len(parts) >= 2:
                        ip = parts[1].replace("ACTION: ", "").strip()
                        currently_banned.discard(ip)
        print(f"📋 Loaded {len(currently_banned)} existing bans, {len(offense_counts)} offense records")
    except Exception as e:
        print(f"⚠️ Could not load existing bans: {e}")


def run_engine():
    global last_global_alert_time
    print("🚀 HNG Stage 3 Anomaly Engine Starting...")
    
    # 0. Rebuild in-memory ban state from audit log (crash recovery)
    _load_existing_bans()

    # 1. Start the Unbanner in a background thread
    ub_thread = threading.Thread(target=run_unbanner, daemon=True)
    ub_thread.start()
    
    # 2. Start the Live Metrics Dashboard in a background thread
    dash_thread = threading.Thread(target=dashboard.run_dashboard, daemon=True)
    dash_thread.start()
    print("📊 Live Metrics Dashboard running on port 5000...")
    
    # 3. Initialize the detector and log stream
    detector = AnomalyDetector()
    detector.load_state()  # Restore persisted baseline (survives restarts)
    log_stream = tail_f(LOG_FILE_PATH)

    while True:
        line = log_stream.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
            
        # 4. Analyze the log line
        is_anomaly, ip, rate, z_score, condition = detector.process_line(line)

        # Skip lines where IP couldn't be extracted
        if ip is None:
            continue
        
        # 5. Keep the UI updated
        update_dashboard_stats(detector)
        
        # ---------------------------------------------------------
        # 6. GLOBAL ANOMALY CHECK (HNG Requirement: Alert Only)
        # ---------------------------------------------------------
        global_rate = detector.get_total_rps()
        safe_stddev = detector.baseline_stddev if detector.baseline_stddev > 0 else 1.0
        global_z = (global_rate - detector.baseline_mean) / safe_stddev
        
        # Flag if Z-score > 3.0 OR rate exceeds multiplier (only if baseline is established)
        if (global_z > 3.0 or global_rate > (conf['thresholds']['rate_multiplier'] * detector.baseline_mean)) and detector.baseline_mean > 0:
            current_time = time.time()
            # Debounce: Only send a global alert once every 60 seconds
            if current_time - last_global_alert_time > 60:
                print(f"🌍 GLOBAL ANOMALY DETECTED! Rate: {global_rate}/s")
                send_slack_alert("GLOBAL", global_rate, global_z, 0, "Global Traffic Spike")
                last_global_alert_time = current_time

        # ---------------------------------------------------------
        # 7. PER-IP ANOMALY CHECK (Block & Alert)
        # ---------------------------------------------------------
        if is_anomaly:
            if ip in WHITELIST:
                continue

            current_time = time.time()

            if ip in banned_ip_cache and (current_time - banned_ip_cache[ip]) < ALERT_COOLDOWN_SEC:
                continue

            print(f"⚠️ IP ANOMALY DETECTED: {ip} | {condition}")
            
            # HNG Requirement: Auto-Unban backoff schedule
            # Uses in-memory offense counter — survives unbans, loaded from audit log on restart
            offense = offense_counts.get(ip, 0)
            if offense >= len(BACKOFF_SCHEDULE):
                new_duration = 999999  # permanent
                duration_label = "PERMANENT"
            else:
                new_duration = BACKOFF_SCHEDULE[offense]
                duration_label = f"{new_duration}m"
            
            if ban_ip(ip, new_duration):
                # Increment offense count AFTER successful ban
                offense_counts[ip] = offense + 1
                banned_ip_cache[ip] = current_time
                with banned_lock:
                    currently_banned.add(ip)

                # Format exact audit log as required: [timestamp] ACTION ip | condition | rate | baseline | duration
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                audit_entry = f"[{timestamp}] ACTION {ip} | {condition} | Rate: {rate} | Baseline: {detector.baseline_mean:.2f} | Duration: {duration_label} (offense #{offense + 1})\n"
                with open(AUDIT_LOG_PATH, "a") as af:
                    af.write(audit_entry)

                send_slack_alert(ip, rate, z_score, new_duration, condition)
                update_dashboard_stats(detector)

if __name__ == "__main__":
    run_engine()
