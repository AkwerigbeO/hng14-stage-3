import time
import os
import yaml
import datetime
import sys
from blocker import unban_ip

# --- LOAD CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, 'config.yaml'), 'r') as f:
    conf = yaml.safe_load(f)

AUDIT_LOG_PATH = conf['logging']['audit_log_path']


def _get_banned_lock_and_set():
    """Lazily import the shared state from main.py to avoid circular imports.
    
    Returns (banned_lock, currently_banned) or (None, None) if main.py
    hasn't been imported yet (e.g. when unbanner.py is run standalone).
    """
    try:
        import main as main_module
        return main_module.banned_lock, main_module.currently_banned
    except (ImportError, AttributeError):
        return None, None


def run_unbanner():
    print("🔓 Unbanner service started and monitoring audit logs...")
    
    while True:
        try:
            if not os.path.exists(AUDIT_LOG_PATH):
                time.sleep(10)
                continue

            current_time = datetime.datetime.now()
            active_bans = {}
            unbanned_ips = set()

            with open(AUDIT_LOG_PATH, 'r') as f:
                lines = f.readlines()

            for line in lines:
                # 1. Skip completely empty lines
                if not line.strip() or " | " not in line:
                    continue
                
                parts = line.strip().split(" | ")
                # 2. Ensure we have all 3 parts (Timestamp, Action, Details)
                if len(parts) < 3:
                    continue
                
                timestamp_str = parts[0]
                action_part = parts[1].replace("ACTION: ", "").strip()
                details_part = parts[2].replace("DETAILS: ", "").strip()

                try:
                    if "BAN" in details_part:
                        # 3. Defensively check for the "for" keyword
                        if "for " in details_part:
                            ip = action_part
                            duration_str = details_part.split("for ")[1].replace("m", "")
                            duration_min = int(duration_str)
                            
                            ban_time = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                            unban_at = ban_time + datetime.timedelta(minutes=duration_min)
                            active_bans[ip] = unban_at
                    
                    elif "UNBAN" in details_part:
                        unbanned_ips.add(action_part)
                
                except (IndexError, ValueError):
                    # Skip lines that have 'BAN' but are missing 'for' or a valid number
                    continue

            # 4. Check for expirations
            for ip, unban_time in active_bans.items():
                if ip not in unbanned_ips and current_time >= unban_time:
                    if unban_ip(ip):
                        print(f"✅ Auto-Unbanned {ip} (Duration expired)")

                        # Remove from the shared in-memory set so the dashboard updates
                        lock, banned_set = _get_banned_lock_and_set()
                        if lock is not None and banned_set is not None:
                            with lock:
                                banned_set.discard(ip)
                    
        except Exception as e:
            print(f"❌ Critical Error in unbanner loop: {e}")

        time.sleep(15)

if __name__ == "__main__":
    run_unbanner()
