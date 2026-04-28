import os
import json
import requests
import datetime

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

def send_slack_alert(ip, rate, z_score, duration, condition="Anomaly Detected"):
    """
    Sends a formatted alert to Slack.
    Includes: condition fired, current rate, baseline, timestamp, ban duration.
    Gracefully skips if SLACK_WEBHOOK_URL is not configured.
    """
    if not SLACK_WEBHOOK_URL:
        print(f"⚠️ SLACK_WEBHOOK_URL not set — skipping alert for {ip}")
        return False

    # Format duration for display
    if duration >= 999999:
        duration_display = "🔒 PERMANENT"
    else:
        duration_display = f"{duration} minutes"

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Use different formatting for global vs per-IP alerts
    if ip == "GLOBAL":
        title = "🌍 *Global Traffic Anomaly Detected!*"
        color = "#ff6600"
    else:
        title = "🚨 *Anomaly Detected & IP Blocked!*"
        color = "#ff0000"

    payload = {
        "text": title,
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "IP / Scope", "value": str(ip), "short": True},
                    {"title": "Condition", "value": str(condition), "short": True},
                    {"title": "Request Rate", "value": f"{rate} req/s", "short": True},
                    {"title": "Z-Score", "value": f"{z_score:.2f}", "short": True},
                    {"title": "Ban Duration", "value": duration_display, "short": True},
                    {"title": "Timestamp", "value": timestamp, "short": True},
                ],
                "footer": "HNG Stage 3 Anomaly Engine"
            }
        ]
    }

    try:
        response = requests.post(
            SLACK_WEBHOOK_URL, 
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        if response.status_code == 200:
            print(f"✅ Slack alert sent for {ip}")
        else:
            print(f"⚠️ Slack returned status {response.status_code} for {ip}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Failed to send Slack alert: {e}")
        return False

def send_unban_notification(ip):
    """
    Sends a notification to Slack when an IP is unbanned.
    """
    if not SLACK_WEBHOOK_URL:
        return False

    payload = {
        "text": f"🔓 *IP Unbanned:* `{ip}`",
        "attachments": [
            {
                "color": "#34d399",
                "text": f"The ban duration for {ip} has expired and the IP has been removed from iptables.",
                "footer": "HNG Stage 3 Anomaly Engine"
            }
        ]
    }

    try:
        requests.post(SLACK_WEBHOOK_URL, data=json.dumps(payload), headers={'Content-Type': 'application/json'}, timeout=10)
        return True
    except Exception:
        return False
