import requests
import json
import config

def send_slack_alert(ip, rate, z_score, duration):
    """
    Sends a formatted alert to Slack.
    """
    payload = {
        "text": "🚨 *Anomaly Detected & IP Blocked!*",
        "attachments": [
            {
                "color": "#ff0000",
                "fields": [
                    {"title": "Attacker IP", "value": ip, "short": True},
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
            config.SLACK_WEBHOOK_URL, 
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'}
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Failed to send Slack alert: {e}")
        return False
