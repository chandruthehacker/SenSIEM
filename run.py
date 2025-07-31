import json
import subprocess
import webbrowser
import time
from pathlib import Path
import uvicorn
import threading

from backend.configs.config import load_config, save_config
from backend.detections.detections_runner import run_all_active_rules_sync
from backend.sensiem import get_detection_rules
from backend.utils.database.database_operations import insert_default_detection_rules
from backend.utils.database.models import create_tables
from backend.utils.validation import is_valid_ip, is_valid_port

# Constants
host = "127.0.0.1"
port = 8787

# Load and validate config
config = load_config()
backendIP = config.get("backendIP", host)
backendPort = int(config.get("backendPort", port))

if not is_valid_ip(backendIP):
    backendIP = host
    config["backendIP"] = backendIP

if not is_valid_port(backendPort):
    backendPort = port
    config["backendPort"] = backendPort

apiUrl = f"http://{backendIP}:{backendPort}/api"
config["apiUrl"] = apiUrl

# Save updated backend config
save_config(config)

# Write config for frontend
frontend_config = {
    "backendIP": backendIP,
    "backendPort": backendPort,
    "apiUrl": apiUrl
}
frontend_config_path = Path("frontend/src/configs/config.json")
frontend_config_path.parent.mkdir(parents=True, exist_ok=True)

try:
    with open(frontend_config_path, 'w', encoding='utf-8') as f:
        json.dump(frontend_config, f, indent=2)
except Exception as e:
    print(f"[ERROR] Writing frontend config failed: {e}")

# Paths
backend_app = "backend.sensiem:app"
frontend_path = Path(__file__).resolve().parent / "frontend"
frontend_url = f"http://{backendIP}:{backendPort}"

def start_frontend():
    subprocess.Popen(["cmd", "/c", "npm run dev"], cwd=frontend_path)

def open_browser():
    time.sleep(3)
    webbrowser.open(frontend_url)

if __name__ == "__main__":
    create_tables()
    insert_default_detection_rules()

    # Start frontend and browser in background
    threading.Thread(target=start_frontend, daemon=True).start()
    threading.Thread(target=open_browser, daemon=True).start()

    # ✅ Run detection in background so it doesn't block the server
    threading.Thread(target=run_all_active_rules_sync, daemon=True).start()

    # ✅ Start the FastAPI backend
    uvicorn.run(backend_app, host=backendIP, port=backendPort, reload=True)