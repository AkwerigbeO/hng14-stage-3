import subprocess
import datetime
import os
import yaml

# --- LOAD CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(BASE_DIR, 'config.yaml')

with open(config_path, 'r') as f:
    conf = yaml.safe_load(f)

AUDIT_LOG_PATH = conf['logging']['audit_log_path']

def log_event(ip, action, details):
    """Helper to write structured events to the audit log."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} | ACTION: {ip} | DETAILS: {action} {details}\n"
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(log_entry)

def ban_ip(ip, duration_min):
    """
    Blocks an IP using iptables and logs the event.
    Returns True if successful.
    """
    try:
        # 1. Execute the system command
        # -I DOCKER-USER inserts the rule at the top of the chain.
        # This is CRITICAL for Docker environments because Docker traffic
        # bypasses the standard 'INPUT' chain.
        subprocess.run(['iptables', '-I', 'DOCKER-USER', '-s', ip, '-j', 'DROP'], check=True)
        
        # 2. Log the action for your Audit-log.png
        log_event(ip, "BAN", f"for {duration_min}m")
        print(f"🚫 Successfully banned {ip} for {duration_min} minutes (DOCKER-USER).")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to ban {ip}: {e}")
        return False

def unban_ip(ip):
    """
    Removes the block for an IP and logs the event.
    """
    try:
        # 1. Execute the system command
        # -D DOCKER-USER deletes the specific rule
        subprocess.run(['iptables', '-D', 'DOCKER-USER', '-s', ip, '-j', 'DROP'], check=True)
        
        # 2. Log the action
        log_event(ip, "UNBAN", "Duration expired")
        print(f"🔓 Successfully unbanned {ip} (DOCKER-USER).")
        return True
    except subprocess.CalledProcessError as e:
        # This often happens if the rule was already manually deleted
        print(f"⚠️ Could not unban {ip} (Rule might not exist in DOCKER-USER): {e}")
        return False
