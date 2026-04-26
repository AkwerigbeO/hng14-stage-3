import os
import yaml
import time
import datetime
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, 'config.yaml'), 'r') as f:
    conf = yaml.safe_load(f)

def run_unbanner():
    print("⏲️ Unbanner Service Started...")
    while True:
        time.sleep(60)
        try:
            with open(AUDIT_LOG_PATH, "r") as f:
                lines = f.readlines()

            bans = {}
            unbans = set()

            for line in lines:
                line = line.strip()
                if not line or " | " not in line: # SAFETY: Skip empty or malformed lines
                    continue
                    
                parts = line.split(" | ")
                if len(parts) >= 3:
                    try:
                        log_time_str = parts[0]
                        action_part = parts[1] 
                        event_type = parts[2]

                        ip = action_part.replace("ACTION: ", "").strip()
                        log_time = datetime.datetime.strptime(log_time_str, "%Y-%m-%d %H:%M:%S")

                        if event_type == "BAN" and len(parts) >= 4:
                            duration_str = parts[3].replace("DURATION:", "").replace("m", "").strip()
                            duration = int(duration_str)
                            expiry_time = log_time + datetime.timedelta(minutes=duration)
                            bans[ip] = expiry_time
                            if ip in unbans:
                                unbans.remove(ip)
                                
                        elif event_type == "UNBAN":
                            unbans.add(ip)
                    except (ValueError, IndexError):
                        # Skip if this specific line is corrupted
                        continue

            now = datetime.datetime.now()

            for ip, expiry_time in bans.items():
                if ip not in unbans and now >= expiry_time:
                    print(f"⏳ Ban expired for {ip}. Unbanning now...")
                    try:
                        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                        unban_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        with open(AUDIT_LOG_PATH, "a") as f:
                            f.write(f"{unban_time} | ACTION: {ip} | UNBAN\n")
                        print(f"✅ Successfully unbanned {ip}")
                    except subprocess.CalledProcessError:
                        # Rule might have been deleted manually, that's fine
                        unban_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        with open(AUDIT_LOG_PATH, "a") as f:
                            f.write(f"{unban_time} | ACTION: {ip} | UNBAN\n")

        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"❌ Error in unbanner service: {e}")
