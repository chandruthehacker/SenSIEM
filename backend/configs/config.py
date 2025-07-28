import json
from dotenv import load_dotenv
import os

from backend.utils.log_finder import is_log_file


load_dotenv()

BASE_DIR = os.path.dirname(__file__)
DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, "configs.json")
FALLBACK_CONFIG_PATH = os.path.abspath(os.path.join(BASE_DIR, "..","configs", "config.json"))

# Final CONFIG_PATH to be used
CONFIG_PATH = (
    DEFAULT_CONFIG_PATH if os.path.exists(DEFAULT_CONFIG_PATH)
    else FALLBACK_CONFIG_PATH if os.path.exists(FALLBACK_CONFIG_PATH)
    else DEFAULT_CONFIG_PATH
)


DEFAULT_CONFIG = {
  "backendIP": "127.0.0.1",
  "backendPort": "8787",
  "apiUrl":"http://127.0.0.1:8787/api",
  "logSources": [],
  "detectionRules": [],
  "newRuleName": "",
  "newRuleDefinition": "",
  "alertThresholds": {
    "logVolume": 10000,
    "errorRate": 11,
    "criticalEvents": 11
  },
  "notificationSettings": {
    "emailEnabled": "false",
    "emailRecipient": "",
    "emailSender": "",
    "emailSmtpServer": "",
    "emailSmtpPort": "587",
    "emailPassword": "",
    "slackEnabled": "false",
    "slackWebhookUrl": "",
    "telegramEnabled": "false",
    "telegramBotToken": "",
    "telegramChatId": ""
  },
  "forwarderConfig": {
    "ip": "127.0.0.1",
    "port": "9000",
    "token": ""
  },
  "bruteForceThreshold": 5,
  "bruteForceInterval": 1,
  "alertRefreshInterval": 5,
  "email": "",
  "slackWebhook": "",
  "telegramBotToken": "",
  "telegramChatId": ""
}



# Function to update or add a key-value pair in the .env file
def update_env_variable(key: str, value: str, env_path: str = ".env"):
    lines = []
    found = False

    # Read existing lines from .env if it exists
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            lines = f.readlines()

    # Update the value if key exists
    for i, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[i] = f"{key}={value}\n"
            found = True
            break

    # If key not found, add it
    if not found:
        lines.append(f"{key}={value}\n")

    # Write back to the file
    with open(env_path, 'w') as f:
        f.writelines(lines)

   
class Config:
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", 8787))
    DB_PATH = os.getenv("DB_PATH", "./database/sensiem_logs.db")
    ALERT_REFRESH_INTERVAL = int(os.getenv("ALERT_REFRESH_INTERVAL", 5))

def save_config(config):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
        
def load_config():
    if not os.path.exists(CONFIG_PATH):
        return DEFAULT_CONFIG
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        content = f.read().strip()
        if not content:
            print("⚠️  Config file is empty. Writing default structure...\n", DEFAULT_CONFIG)
            save_config(DEFAULT_CONFIG)
            return DEFAULT_CONFIG
        return json.loads(content)


def remove_invalid_paths() -> bool:
    config = load_config()
    log_sources = config.get("logSources")

    # If logSources is a dict (deprecated format), remove it
    if isinstance(log_sources, dict):
        config.pop("logSources", None)
        save_config(config)
        return True

    # If logSources is a list (expected format), validate entries
    if isinstance(log_sources, list):
        valid_sources = []
        for entry in log_sources:
            path = entry.get("path")
            if path and os.path.exists(path) and is_log_file(path):
                valid_sources.append(entry)

        removed = [src for src in log_sources if src not in valid_sources]

        if removed:
            config["logSources"] = valid_sources
            save_config(config)
            return True

    return False

