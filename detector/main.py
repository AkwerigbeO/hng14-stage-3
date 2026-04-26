import time
import threading
import subprocess
import config
from detector import AnomalyDetector
from blocker import ban_ip
from unbanner import run_unbanner
from notifier import send_slack_alert
import dashboard # Your new dashboard.py file


WHITELIST = config.WHITELIST

# Debounce timer to prevent Slack spam during a global DDoS
last_global_alert_time = 0 

def tail_f(filename):
    """Streams the Nginx log file in real-time."""
    process = subprocess.Popen(['tail', '-F', filename], stdout=subprocess.PIPE, text=True)
    return process

def update_dashboard_stats(detector_obj):
    """Updates the shared dictionary in dashboard.py so the Live UI is accurate."""
    dashboard.metrics_data["global_rps"] = detector_obj.get_total_rps()
    dashboard.metrics_data["mean"] = detector_obj.baseline_mean
    dashboard.metrics_data["stddev"] = detector_obj.baseline_stddev
    dashboard.metrics_data["top_ips"] = detector_obj.get_top_ips(10)
    
    # Read banned IPs directly from the audit log to keep the UI honest
    banned_list = []
    try:
        with open(config.AUDIT_LOG_PATH, "r") as f:
            lines = f.readlines()
            for line in lines:
                if " | BAN" in line:
                    ip = line.split(" | ")[1].replace("ACTION: ", "").strip()
                    if ip not in banned_list:
                        banned_list.append(ip)
                elif " | UNBAN" in line:
                    ip = line.split(" | ")[1].replace("ACTION: ", "").strip()
                    if ip in banned_list:
                        banned_list.remove(ip)
        dashboard.metrics_data["banned_ips"] = banned_list
    except FileNotFoundError:
        pass

def run_engine():
    global last_global_alert_time
    print("🚀 HNG Stage 3 Anomaly Engine Starting...")
    
    # 1. Start the Unbanner in a background thread
    ub_thread = threading.Thread(target=run_unbanner, daemon=True)
    ub_thread.start()
    
    # 2. Start the Live Metrics Dashboard in a background thread
    dash_thread = threading.Thread(target=dashboard.run_dashboard, daemon=True)
    dash_thread.start()
    print("📊 Live Metrics Dashboard running on port 5000...")
    
    # 3. Initialize the detector and log stream
    detector = AnomalyDetector()
    log_stream = tail_f(config.LOG_FILE_PATH)

    while True:
        line = log_stream.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
            
        # 4. Analyze the log line
        is_anomaly, ip, rate, z_score = detector.process_line(line)
        
        # 5. Keep the UI updated
        update_dashboard_stats(detector)
        
        # ---------------------------------------------------------
        # 6. GLOBAL ANOMALY CHECK (HNG Requirement: Alert Only)
        # ---------------------------------------------------------
        global_rate = detector.get_total_rps()
        safe_stddev = detector.baseline_stddev if detector.baseline_stddev > 0 else 1.0
        global_z = (global_rate - detector.baseline_mean) / safe_stddev
        
        # Flag if Z-score > 3.0 OR rate is 5x the mean (only if baseline is established)
        if (global_z > 3.0 or global_rate > (5 * detector.baseline_mean)) and detector.baseline_mean > 0:
            current_time = time.time()
            # Debounce: Only send a global alert once every 60 seconds
            if current_time - last_global_alert_time > 60:
                print(f"🌍 GLOBAL ANOMALY DETECTED! Rate: {global_rate}/s")
                send_slack_alert("GLOBAL", global_rate, global_z, 0)
                last_global_alert_time = current_time

        # ---------------------------------------------------------
        # 7. PER-IP ANOMALY CHECK (Block & Alert)
        # ---------------------------------------------------------
        if is_anomaly:
            if ip in WHITELIST:
                # Silently ignore whitelisted IPs to avoid log spam
                continue

            print(f"⚠️ IP ANOMALY DETECTED: {ip} | Rate: {rate} | Z-Score: {z_score:.2f}")
            
            # HNG Requirement: Auto-Unban backoff schedule (10 min, 30 min, 2 hours)
            try:
                with open(config.AUDIT_LOG_PATH, "r") as f:
                    ban_count = f.read().count(f"ACTION: {ip} | BAN")
            except FileNotFoundError:
                ban_count = 0
            
            if ban_count == 0:
                new_duration = 10
            elif ban_count == 1:
                new_duration = 30
            elif ban_count == 2:
                new_duration = 120
            else:
                new_duration = 999999 # Effectively permanent for repeat offenders
            
            # Execute the Ban and Notify Slack
            if ban_ip(ip, new_duration):
                send_slack_alert(ip, rate, z_score, new_duration)
                update_dashboard_stats(detector) # Force UI update immediately so the ban shows up
