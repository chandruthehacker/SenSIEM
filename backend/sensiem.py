from contextlib import asynccontextmanager
from io import StringIO
import os
import sqlite3
import threading
from fastapi import FastAPI, File, Form, Request, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime, timedelta

from backend.detections.detections_runner import run_all_active_rules_sync
from backend.forwarder.forwarder import start_forwarder
from backend.parser.log_parser import ingest_logs
from backend.utils.database.database_operations import add_log_source_to_db, delete_log_source, get_db_connection, get_log_paths
from backend.utils.database.query import get_filtered_logs, get_logs_from_db, get_top_ips_from_db, getAlerts, getDashBoardmetrics, getGeoSuspiciousIPs, getLogLevelDistribution, getNoisySource, getSystemErrors, getTimeSeries, getTopAlerts
from backend.utils.log_finder import log_type_find, specific_log_type_find
from backend.utils.validation import is_log_content_valid, is_valid_ip, is_valid_path, is_valid_port
from backend.configs.config import load_config, save_config


# --- App Setup ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
DATABASE_PATH = os.path.join(BASE_DIR, "database", "sensiem.db")

def start_embedded_forwarder():
    thread = threading.Thread(target=start_forwarder, daemon=True)
    thread.start()
    print("🚀 Embedded forwarder started.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    start_embedded_forwarder()
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LogLevelItem(BaseModel):
    name: str
    value: int
    color: str


# Mount static React files
app.mount("/static", StaticFiles(directory=os.path.join(FRONTEND_PATH, "assets")), name="static")

# --- Models ---
class IngestPayload(BaseModel):
    host: str
    path: str
    line: str
    timestamp: str

class SearchQuery(BaseModel):
    searchQuery: Optional[str] = ""
    filters: Dict[str, str]

class PathInput(BaseModel):
    path: str
    
class LogSourceInput(BaseModel):
    path: str
    type: str
    

# --- Routes ---

@app.get("/api/test")
async def test_api():
    return {"status": "FastAPI and forwarder running ✅"}

@app.get("/api/metrics")
async def dashboard_metrics():
    try:
        return JSONResponse(content=getDashBoardmetrics())
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/api/search-logs")
async def search_logs(req: Request):
    body = await req.json()
    filters = body.get("filters", {})
    query = body.get("query", {})
    kv = query.get("kv", {})
    msgs = query.get("msgs", [])

    logs = get_filtered_logs(kv, msgs)

    now = datetime.now()

    # Apply date filter
    if filters.get("dateRange") != "all":
        days_map = {"1h": 1/24, "24h": 1, "7d": 7, "30d": 30}
        cutoff = now - timedelta(days=days_map.get(filters["dateRange"], 0))
        logs = [
            log for log in logs 
            if datetime.fromisoformat(log["timestamp"]) >= cutoff
        ]

    # Log level
    if filters.get("logLevel") != "all":
        level_filter = filters["logLevel"].strip().lower()
        
        logs = [
            log for log in logs 
            if (log.get("log_level") or "").strip().lower() == level_filter
        ]

    # Source
    if filters.get("source") != "all":
        logs = [
            log for log in logs 
            if log.get("type", "").lower() == filters["source"].lower()
        ]
    return {"logs": logs}

@app.get("/api/log-level-distribution", response_model=List[LogLevelItem])
async def get_log_level_distribution():
    return getLogLevelDistribution()

@app.get("/api/top-alerts")
async def get_top_alerts():
    try:
        data = getTopAlerts()
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching top Alerts: {str(e)}")

@app.get("/api/ips/top")
async def get_top_ips():
    try:
        data = get_top_ips_from_db()
        return JSONResponse(content=data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching top IPs: {str(e)}")

@app.get("/api/geo-suspicious-ips")
async def get_geo_suspicious_ips():
    try:
        data = await getGeoSuspiciousIPs()
        return JSONResponse(content=data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching top Geo Location: {str(e)}")

@app.get("/api/time-series-logs-alerts")
async def get_time_series_logs_alerts():
    try:
        data = getTimeSeries()
        return JSONResponse(content=data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching top Geo Location: {str(e)}")

@app.get("/api/noisy-sources")
async def get_noisy_source(limit: int = 5):
    try:
        data = getNoisySource()
        return JSONResponse(content=data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching Noisy Sources: {str(e)}")

@app.get("/api/system-errors", response_model=List[Dict[str, str]])
async def get_system_errors():
    try:
        data = getSystemErrors()
        return JSONResponse(content=data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching System Errors: {str(e)}")

@app.get("/api/get-logs")
async def get_logs():
    logs = get_logs_from_db()
    return JSONResponse(content={"logs": logs})

class Alert(BaseModel):
    id: int
    type: str
    description: str
    timestamp: str
    source: str
    severity: str
    status: str

@app.get("/api/get-alerts", response_model=List[Alert])
async def get_alerts():
    try:
        alerts = getAlerts()
        return JSONResponse(content=alerts)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching System Errors: {str(e)}")

@app.get("/api/get-settings")
async def getSettings():
    try:
        configs = load_config()
        logSources = get_log_paths()
        configs["logSources"] = logSources["logSources"]
        return JSONResponse(content=configs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching System Errors: {str(e)}")

@app.post("/api/save-settings")
async def saveSettings(request: Request):
    data = await request.json()
    errors = []

    # Validate backend IP
    backend_ip = data.get("backendIP", "")
    if not is_valid_ip(backend_ip):
        errors.append(f"IP '{backend_ip}' is invalid. Please enter a valid IP address.")

    # Validate backend Port
    try:
        backend_port = int(data.get("backendPort", ""))
    except (ValueError, TypeError):
        backend_port = -1  # Invalid port value

    if not is_valid_port(backend_port):
        errors.append(f"Port '{data.get('backendPort')}' is invalid. Please enter a valid port number between 1 and 65535.")

    # Validate logSources
    log_sources = data.get("logSources", {})
    for group, paths in log_sources.items():
        for path in paths:
            if not is_valid_path(path):
                errors.append(f"Log file path '{path}' in group '{group}' is invalid or does not exist.")

    if errors:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "errors": errors}
        )

    # Everything is valid, save the config
    save_config(data)

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": "Settings saved successfully"}
    )

@app.post("/api/save-backend-settings")
async def saveBackendSetting(request: Request):
    data = await request.json()
    errors = []

    # Validate backend IP
    backend_ip = data.get("backendIP", "")
    if not is_valid_ip(backend_ip):
        errors.append(f"\nIP '{backend_ip}' is invalid. Please enter a valid IP address.")

    # Validate backend Port
    try:
        backend_port = int(data.get("backendPort", ""))
    except (ValueError, TypeError):
        backend_port = -1

    if not is_valid_port(backend_port):
        errors.append(f"\n\nPort '{data.get('backendPort')}' is invalid. Please enter a valid port number between 1 and 65535.")
    
    if errors:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "errors": errors}
        )

    config = load_config()
    
    config["backendIP"] = backend_ip
    config["backendPort"] = backend_port

    save_config(config)

    return JSONResponse(
        status_code=200,
        content={"status": "success", "message": "Settings saved successfully"}
    )

@app.post("/api/delete-log-path")
async def delete_log_path(request: Request):
    data = await request.json()
    log_type = data.get("type")
    log_path = data.get("path")

    if not log_type or not log_path:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Both 'type' and 'path' are required"}
        )
        
    db_result = delete_log_source(log_path, log_type)

    if db_result["status"] != "ok":
        return JSONResponse(status_code=404, content=db_result)

    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "message": f"Path '{log_path}' of type '{log_type}' deleted from database successfully."
        }
    )

@app.post("/api/validate-path")
async def validate_path(data: PathInput):
    path = data.path.strip().strip('"').strip("'")

    # Step 2: Validate file
    if not os.path.exists(path):
        return {"status": "error", "message": "File does not exist", "type":"unknown"}
    if not os.path.isfile(path):
        return {"status": "error", "message": "Path is not a file", "type":"unknown"}
    if not os.access(path, os.R_OK):
        return {"status": "error", "message": "File is not readable", "type":"unknown"}
    log_type = "unknown"
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in range(50):
                line = f.readline()
                if not line:
                    break
                result = log_type_find(line)
                if result != "unknown":
                    log_type = result
                    break
    except Exception as e:
        return {"status": "error", "message": f"Failed to read file: {str(e)}", "type": "unknown"}

    if log_type == "unknown":
        return {"status": "error", "message": "File is not a valid or recognized log type", "type": log_type}

    return {"status": "ok", "message": "Valid path", "type": log_type}

@app.post("/api/add-log-source")
async def add_log_source(data: LogSourceInput):
    path = data.path.strip().strip('"').strip("'")
    log_type = data.type.strip().lower()

    # Validate path exists early
    if not is_valid_path(path):
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "Invalid or inaccessible log file path", "type": "unknown"}
        )

    # Try detecting valid content
    try:
        detected_type = "unknown"
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in range(50):  # Read first 50 lines for detection
                line = f.readline()
                if not line:
                    break
                result = specific_log_type_find(line, log_type)
                if result != "unknown":
                    detected_type = result
                    break
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"Failed to read file: {str(e)}", "type": "unknown"}
        )

    # If log content is not valid
    if detected_type == "unknown":
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": "No valid logs found. File may not match the selected type.", "type": "unknown"}
        )

    db_response = add_log_source_to_db(path, detected_type)
    
    if db_response["status"] == "ok":
        # ⭐ Trigger the forwarder restart after successfully adding a new log source
        threading.Thread(target=start_forwarder, daemon=True).start()
        print("Triggered forwarder restart due to new log source.")

    return JSONResponse(content={**db_response, "type": detected_type, "path": path})

@app.post("/api/check-log")
async def check_log_file_or_content(
    file: Optional[UploadFile] = File(None),
    content: Optional[str] = Form(None)
):

    if file:
        try:
            raw = await file.read()
            text = raw.decode("utf-8", errors="ignore")

            if not text.strip():
                return {"result": "error", "message": "File is empty or unreadable.", "type":"auto"}

            return is_log_content_valid(text)
        except Exception as e:
            return {"result": "error", "message": "Error reading log file.", "type":"auto"}
    elif content is not None:
        if not content.strip():
            return {"result": "error", "message": "Content is empty.", "type":"auto"}
        return is_log_content_valid(content)
    else:
        return {"result": "error", "message": "No file or content provided", "type":"auto"}

@app.post("/api/ingest-log")
async def ingest_log(
    file: Optional[UploadFile] = File(None),
    content: Optional[str] = Form(None),
    type: str = Form(...)
):
    try:
        if not file and not content:
            return JSONResponse(status_code=400, content={"status": "error", "message": "No file or content provided."})

        text = (await file.read()).decode("utf-8", errors="ignore") if file else content
        if not text.strip():
            return JSONResponse(status_code=400, content={"status": "error", "message": "Empty log content."})

        f = StringIO(text)
        detected_type = "unknown"

        for _ in range(50):
            line = f.readline()
            if not line.strip():
                break
            detected = specific_log_type_find(line, type)
            if detected != "unknown":
                detected_type = detected
                break
        
        path = "Ingested Log " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if detected_type != "unknown":
            ingest_logs(text, detected_type, path)
            return {"status": "success", "message": "Valid logs ingested.", "detected_type": detected_type}

        return {"status": "error", "message": "Invalid log content for selected type.", "detected_type": detected_type}

    except Exception as e:
        return {"status": "error", "message": f"Ingestion failed: {str(e)}"}

class RuleToggleRequest(BaseModel):
    active: bool

@app.get("/api/detection-rules")
async def get_detection_rules():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM detection_rules ORDER BY id ASC")
        rows = cursor.fetchall()
        rules = []
        for row in rows:
            rules.append({
                "id": row["id"],
                "name": row["name"],
                "description": row["description"],
                "rule_type": row["rule_type"],
                "log_type": row["log_type"],
                "condition": row["condition"],
                "threshold": row["threshold"],
                "time_window": row["time_window"],
                "interval_minutes": row["interval_minutes"],
                "active": row["active"],
                "last_run": row["last_run"]
            })
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

@app.patch("/api/detection-rules/{rule_id}")
async def update_detection_rule(rule_id: int, data: RuleToggleRequest):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Update rule status
        cursor.execute("UPDATE detection_rules SET active = ? WHERE id = ?", (int(data.active), rule_id))
        conn.commit()

        # Re-run all active rules after the update
        try:
            run_all_active_rules_sync()
        except Exception as rule_error:
            print(f"[ERROR] Failed to execute rules after update: {rule_error}")

        return {
            "status": "success",
            "rule_id": rule_id,
            "active": data.active
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update rule: {e}")

    finally:
        conn.close()

# --- Frontend Routing ---
@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    index_path = os.path.join(FRONTEND_PATH, "index.html")
    file_path = os.path.join(FRONTEND_PATH, full_path)

    if os.path.exists(file_path) and os.path.isfile(file_path):
        return FileResponse(file_path)
    else:
        return FileResponse(index_path)
