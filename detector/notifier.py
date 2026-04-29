import datetime
import json
import os

import requests


SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")


def send_slack_alert(ip, rate, z_score, duration, condition="Anomaly Detected", baseline=None):
    """Send anomaly or global-spike notifications to Slack."""
    if not SLACK_WEBHOOK_URL:
        print(f"SLACK_WEBHOOK_URL not set; skipping alert for {ip}")
        return False

    if duration is None:
        duration_display = "Alert only"
    elif duration >= 999999:
        duration_display = "PERMANENT"
    else:
        duration_display = f"{duration} minutes"

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = "Global Traffic Anomaly Detected" if ip == "GLOBAL" else "Anomaly Detected and IP Blocked"
    color = "#ff6600" if ip == "GLOBAL" else "#ff0000"

    payload = {
        "text": title,
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "IP / Scope", "value": str(ip), "short": True},
                    {"title": "Condition", "value": str(condition), "short": True},
                    {"title": "Current Rate", "value": f"{rate} req/s", "short": True},
                    {"title": "Baseline", "value": str(baseline or "n/a"), "short": True},
                    {"title": "Z-Score", "value": f"{z_score:.2f}", "short": True},
                    {"title": "Ban Duration", "value": duration_display, "short": True},
                    {"title": "Timestamp", "value": timestamp, "short": True},
                ],
                "footer": "HNG Stage 3 Anomaly Engine",
            }
        ],
    }

    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if response.status_code == 200:
            print(f"Slack alert sent for {ip}")
        else:
            print(f"Slack returned status {response.status_code} for {ip}")
        return response.status_code == 200
    except Exception as e:
        print(f"Failed to send Slack alert: {e}")
        return False


def send_unban_notification(ip, baseline=None):
    """Send a notification to Slack when an IP is unbanned."""
    if not SLACK_WEBHOOK_URL:
        return False

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = {
        "text": f"IP Unbanned: {ip}",
        "attachments": [
            {
                "color": "#34d399",
                "fields": [
                    {"title": "IP", "value": str(ip), "short": True},
                    {"title": "Condition", "value": "Auto-unban", "short": True},
                    {"title": "Current Rate", "value": "n/a", "short": True},
                    {"title": "Baseline", "value": str(baseline or "n/a"), "short": True},
                    {"title": "Ban Duration", "value": "Expired", "short": True},
                    {"title": "Timestamp", "value": timestamp, "short": True},
                ],
                "footer": "HNG Stage 3 Anomaly Engine",
            }
        ],
    }

    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        return response.status_code == 200
    except Exception:
        return False
