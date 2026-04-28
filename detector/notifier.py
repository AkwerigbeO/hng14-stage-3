import os
import json
import requests

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

def send_slack_alert(ip, rate, z_score, duration):
    """
    Sends a formatted alert to Slack.
    Returns True if successful, False otherwise.
    Gracefully skips if SLACK_WEBHOOK_URL is not configured.
    """
    if not SLACK_WEBHOOK_URL:
        print(f"⚠️ SLACK_WEBHOOK_URL not set — skipping alert for {ip}")
        return False

    payload = {
        "text": "🚨 *Anomaly Detected & IP Blocked!*",
        "attachments": [
            {
                "color": "#ff0000",
                "fields": [
                    {"title": "Attacker IP", "value": str(ip), "short": True},
                    {"title": "Request Rate", "value": f"{rate} req/min", "short": True},
                    {"title": "Z-Score", "value": f"{z_score:.2f}", "short": True},
                    {"title": "Ban Duration", "value": f"{duration} minutes", "short": True},
                ],
                "footer": "HNG Stage 3 Anomaly Engine",
                "ts":  None # Slack adds timestamp automatically
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
