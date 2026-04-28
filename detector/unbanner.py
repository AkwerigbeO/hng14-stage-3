import time
import os
import yaml
import datetime
import sys
from blocker import unban_ip
from notifier import send_unban_notification

# --- LOAD CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, 'config.yaml'), 'r') as f:
    conf = yaml.safe_load(f)

AUDIT_LOG_PATH = conf['logging']['audit_log_path']

def _get_banned_lock_and_set():
    """Lazily import the shared state from main.py to avoid circular imports."""
    try:
        import main as main_module
        return main_module.banned_lock, main_module.currently_banned
    except (ImportError, AttributeError):
        return None, None

def run_unbanner():
    print("🔓 Unbanner service started. Monitoring for expirations...")
    
    while True:
        try:
            if not os.path.exists(AUDIT_LOG_PATH):
                time.sleep(10)
                continue

            current_time = datetime.datetime.now()
            
            # This dict will store only the LATEST state for each IP
            # Format: { "ip": unban_datetime_obj }
            # If an IP is permanent or already unbanned, it won't be in here.
            pending_unbans = {}

            with open(AUDIT_LOG_PATH, 'r') as f:
                for line in f:
                    if not line.strip() or " | " not in line:
                        continue
                    
                    parts = line.strip().split(" | ")
                    if len(parts) < 3:
                        continue
                    
                    timestamp_str = parts[0].strip("[] ")
                    action_part = parts[1].replace("ACTION: ", "").strip()
                    details_part = parts[2].replace("DETAILS: ", "").strip()
                    ip = action_part

                    try:
                        if "BAN" in details_part and "for " in details_part:
                            duration_str = details_part.split("for ")[1].split("m")[0]
                            duration_min = int(duration_str)

                            # If it's a permanent ban (999999), ensure it's NOT in unban queue
                            if duration_min >= 999999:
                                if ip in pending_unbans:
                                    del pending_unbans[ip]
                                continue

                            ban_time = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                            unban_at = ban_time + datetime.timedelta(minutes=duration_min)
                            
                            # Overwrite with newest entry found in log
                            pending_unbans[ip] = unban_at
                        
                        elif "UNBAN" in details_part:
                            # If we see an UNBAN, the IP is no longer a candidate for auto-unbanning
                            if ip in pending_unbans:
                                del pending_unbans[ip]

                    except (IndexError, ValueError):
                        continue

            # ─── Execute Expirations ───
            for ip, unban_time in pending_unbans.items():
                if current_time >= unban_time:
                    if unban_ip(ip):
                        print(f"✅ Auto-Unbanned {ip} (Duration {unban_time} expired)")
                        send_unban_notification(ip)

                        # Sync with UI
                        lock, banned_set = _get_banned_lock_and_set()
                        if lock and banned_set is not None:
                            with lock:
                                banned_set.discard(ip)
                                
        except Exception as e:
            print(f"❌ Unbanner Error: {e}")

        time.sleep(15)

if __name__ == "__main__":
    run_unbanner()