import subprocess
import datetime
import config

def ban_ip(ip, duration):
    """
    Executes the iptables command to drop packets from the offending IP.
    Records the action in the audit log for the Unbanner to track.
    """
    try:
        # We call iptables directly because the container is already 'privileged' root
        command = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(command, check=True)
        
        # Log the action for the Unbanner service to pick up later
        ban_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{ban_time} | ACTION: {ip} | BAN | DURATION: {duration}m\n"
        
        with open(config.AUDIT_LOG_PATH, "a") as f:
            f.write(log_entry)
            
        print(f"✅ Successfully banned {ip} for {duration} minutes.")
        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ Iptables Error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error in blocker: {e}")
        return False
