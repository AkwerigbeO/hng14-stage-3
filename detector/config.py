import yaml
import os

# 1. Load the safe YAML file
config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
with open(config_path, 'r') as f:
    conf = yaml.safe_load(f)

# 2. Pull secrets from the Docker Environment Variables
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
HOME_IP = os.environ.get("HOME_IP", "127.0.0.1") # Defaults to localhost if not found

# 3. Build your Whitelist dynamically
WHITELIST = ["127.0.0.1", HOME_IP]

# 4. Map the rest of your YAML settings
LOG_FILE_PATH = conf['logging']['log_file_path']
AUDIT_LOG_PATH = conf['logging']['audit_log_path']
DEFAULT_BAN_TIME = conf['security']['default_ban_time']
BACKOFF_MULTIPLIER = conf['security']['backoff_multiplier']
Z_SCORE_LIMIT = conf['thresholds']['z_score_limit']
RATE_MULTIPLIER = conf['thresholds']['rate_multiplier']
