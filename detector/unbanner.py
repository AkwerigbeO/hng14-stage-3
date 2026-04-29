import datetime
import os
import time

import yaml

import dashboard
from blocker import unban_ip
from dashboard import banned_lock, currently_banned, metrics_lock
from notifier import send_unban_notification


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "config.yaml"), "r") as f:
    conf = yaml.safe_load(f)

AUDIT_LOG_PATH = conf["logging"]["audit_log_path"]
PERMANENT_BAN_MINUTES = conf["security"]["permanent_ban_minutes"]


def _parse_duration_minutes(duration_part):
    duration_value = duration_part.replace("Duration:", "").strip()
    if duration_value.upper().startswith("PERMANENT"):
        return PERMANENT_BAN_MINUTES
    if duration_value.endswith("m"):
        duration_value = duration_value[:-1]
    return int(duration_value)


def _parse_audit_line(line):
    parts = line.strip().split(" | ")
    if len(parts) < 6 or "ACTION " not in parts[0]:
        return None

    timestamp_str = parts[0].split("]", 1)[0].strip("[")
    ip = parts[0].split("ACTION ", 1)[1].strip()
    action = parts[1].strip().upper()

    try:
        timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "ip": ip,
        "action": action,
        "duration": _parse_duration_minutes(parts[5]) if action == "BAN" else None,
    }


def _write_unban_audit(ip):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (
        f"[{timestamp}] ACTION {ip} | UNBAN | condition=ban_expired | "
        "Rate: n/a | Baseline: n/a | Duration: expired\n"
    )
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(entry)


def run_unbanner():
    print("Unbanner service started. Monitoring for expirations...")

    while True:
        try:
            if not os.path.exists(AUDIT_LOG_PATH):
                time.sleep(10)
                continue

            current_time = datetime.datetime.now()
            pending_unbans = {}

            with open(AUDIT_LOG_PATH, "r") as f:
                for line in f:
                    event = _parse_audit_line(line)
                    if not event:
                        continue

                    ip = event["ip"]
                    if event["action"] == "BAN":
                        if event["duration"] >= PERMANENT_BAN_MINUTES:
                            pending_unbans.pop(ip, None)
                            continue
                        pending_unbans[ip] = event["timestamp"] + datetime.timedelta(
                            minutes=event["duration"]
                        )
                    elif event["action"] == "UNBAN":
                        pending_unbans.pop(ip, None)

            for ip, unban_time in pending_unbans.items():
                if current_time >= unban_time and unban_ip(ip):
                    print(f"Auto-unbanned {ip}")
                    _write_unban_audit(ip)
                    send_unban_notification(ip)

                    with banned_lock:
                        currently_banned.discard(ip)
                    with metrics_lock:
                        dashboard.metrics_data["banned_ips"] = list(currently_banned)

        except Exception as e:
            print(f"Unbanner error: {e}")

        time.sleep(15)


if __name__ == "__main__":
    run_unbanner()
