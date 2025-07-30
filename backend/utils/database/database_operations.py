from collections import defaultdict
import sqlite3
import sys
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import os
from threading import Thread

from backend.utils.database.models import ParsedLog

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))


DATABASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "database", "sensiem.db"))


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def add_log_source_to_db(path: str, log_type: str) -> dict:
    if not os.path.isfile(path) and "Ingested Log" not in path:
        return {"status": "error", "message": "Log file does not exist"}

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS log_sources (
                source_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                path TEXT UNIQUE,
                log_type TEXT,
                added_on TEXT,
                active INTEGER DEFAULT 1,
                source_tag TEXT,
                last_position TEXT DEFAULT '0'
            )
        """)

        # Check if already exists
        cursor.execute("SELECT * FROM log_sources WHERE path=? AND log_type=?", (path, log_type))
        if cursor.fetchone():
            return {"status": "exists", "message": "Log source already exists"}
        
        name = os.path.basename(path) or "Ingested Log"
            

        added_on = datetime.now(timezone.utc).isoformat()
        source_tag = ""  # Can be customized later

        cursor.execute("""
            INSERT INTO log_sources (name, path, log_type, added_on, active, source_tag)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, path, log_type, added_on, 1, source_tag))

        conn.commit()
        return {"status": "ok", "message": "Log source added successfully"}

    except Exception as e:
        return {"status": "error", "message": f"Database error: {str(e)}"}

    finally:
        conn.close()

def delete_log_source(path_to_delete: str, log_type: str) -> dict:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM log_sources WHERE path = ? AND log_type = ? ", (path_to_delete,log_type,))
        row = cursor.fetchone()

        if not row:
            return {"status": "error", "message": "Log source not found in database"}
        
        cursor.execute("SELECT * FROM parsed_logs WHERE file_path = ? AND type = ? ", (path_to_delete,log_type,))
        row = cursor.fetchone()

        if not row:
            return {"status": "error", "message": "Parsed Log not found in database"}

        cursor.execute("DELETE FROM log_sources WHERE path = ? AND log_type = ? ", (path_to_delete,log_type,))
        cursor.execute("DELETE FROM parsed_logs WHERE file_path = ? AND type = ? ", (path_to_delete,log_type,))
        conn.commit()

        return {"status": "ok", "message": f"Log source at '{path_to_delete}' deleted successfully"}

    except Exception as e:
        return {"status": "error", "message": f"Database error: {str(e)}"}

    finally:
        conn.close()

def get_log_paths():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT log_type, path FROM log_sources WHERE active = 1")
        rows = cursor.fetchall()

        log_sources = defaultdict(list)

        for log_type, path in rows:
            log_sources[log_type].append(path)

        return {
            "logSources": dict(log_sources)
        }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Database error: {str(e)}"
        }

    finally:
        conn.close()

def add_parsed_log_to_db(parsed_data):

    con = get_db_connection()
    cursor = con.cursor()
    
    try:
        timestamp = datetime.strptime(parsed_data['timestamp'], "%m/%d/%Y %I:%M:%S %p")
        
        if not parsed_data.get('log_level'):
            parsed_data['log_level'] = 'INFO'

        cursor.execute(
            """
            INSERT INTO parsed_logs (
                timestamp, log_level, source, host, process, message, raw_log, type, file_path, source_id,
                event_id, username, status_code, url, method, protocol, src_ip, dest_ip, src_port, dest_port,
                rule, signature, action, user_agent, device, mail_subject, file_hash, tags
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                timestamp,
                parsed_data.get('log_level'),
                parsed_data.get('source'),
                parsed_data.get('host'),
                parsed_data.get('process'),
                parsed_data.get('message'),
                parsed_data.get('raw_log'),
                parsed_data.get('type'),
                parsed_data.get('file_path'),
                parsed_data.get('source_id'),

                parsed_data.get('event_id'),
                parsed_data.get('username'),
                parsed_data.get('status_code'),
                parsed_data.get('url'),
                parsed_data.get('method'),
                parsed_data.get('protocol'),
                parsed_data.get('src_ip'),
                parsed_data.get('dest_ip'),
                parsed_data.get('src_port'),
                parsed_data.get('dest_port'),

                parsed_data.get('rule'),
                parsed_data.get('signature'),
                parsed_data.get('action'),
                parsed_data.get('user_agent'),
                parsed_data.get('device'),
                parsed_data.get('mail_subject'),
                parsed_data.get('file_hash'),
                parsed_data.get('tags'),
            )
        )
        con.commit()
    
    except Exception as e:
        print(f"❌ Failed to insert log via cursor: {e}")
    finally:
        con.close()

def create_alert(rule_type, severity, message, log_id=None, ip=None, host=None, source=None, status="new"):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO alerts (
                rule_type,
                log_id,
                alert_time,
                severity,
                message,
                status,
                acknowledged_at,
                resolved_at,
                ip,
                host,
                source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rule_type,
            log_id,
            datetime.utcnow(),
            severity,
            message,
            status,
            None,       # acknowledged_at
            None,       # resolved_at
            ip,
            host,
            source
        ))

        conn.commit()
        return {"status": "success", "message": "Alert created."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

def insert_default_detection_rules():
    default_rules = [
        {
            "name": "Brute Force Login (Same IP)",
            "description": "Detects 5+ failed logins from a single IP in 2 minutes.",
            "rule_type": "brute_force",
            "log_type": "auth",
            "condition": "failed_login",
            "threshold": 5,
            "time_window": 120,
            "interval_minutes": 1,
            "active": True
        },
        {
            "name": "Suspicious Privilege Escalation",
            "description": "Detects sudden use of sudo/su or privilege escalation attempts.",
            "rule_type": "privilege_escalation",
            "log_type": "auth",
            "condition": "sudo,su",
            "threshold": 2,
            "time_window": 300,  # 5 minutes
            "interval_minutes": 2,
            "active": True
        },
        {
            "name": "Excessive Error Logs",
            "description": "Detects abnormal volume of ERROR logs from the same process.",
            "rule_type": "log_level",
            "log_type": "application",
            "condition": "ERROR",
            "threshold": 15,
            "time_window": 300,  # 5 minutes
            "interval_minutes": 2,
            "active": True
        },
        {
            "name": "High Volume Web Requests",
            "description": "Detects 200+ web requests from a single IP in 60 seconds.",
            "rule_type": "web_requests",
            "log_type": "web",
            "condition": "*",
            "threshold": 200,
            "time_window": 60,  # 1 minute
            "interval_minutes": 1,
            "active": True
        },
        {
            "name": "SSH Access From New Geo-Location",
            "description": "Detects SSH login from a location not previously used by the user.",
            "rule_type": "geo_anomaly",
            "log_type": "auth",
            "condition": "ssh_login",
            "threshold": 1,
            "time_window": 600,  # 10 minutes
            "interval_minutes": 5,
            "active": True
        }
    ]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detection_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            description TEXT,
            rule_type TEXT,
            log_type TEXT,
            condition TEXT,
            threshold INTEGER,
            time_window INTEGER,
            interval_minutes INTEGER,
            active BOOLEAN,
            last_run TIMESTAMP,
            created_at TIMESTAMP
        )
    """)

    for rule in default_rules:
        cursor.execute("""
            SELECT COUNT(*) FROM detection_rules WHERE name = ?
        """, (rule["name"],))
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                INSERT INTO detection_rules 
                (name, description, rule_type, log_type, condition, threshold, time_window, interval_minutes, active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule["name"], rule["description"], rule["rule_type"], rule["log_type"],
                rule["condition"], rule["threshold"], rule["time_window"],
                rule["interval_minutes"], rule["active"], datetime.utcnow()
            ))

    conn.commit()
    conn.close()


