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

        # Get the log source and its source_id
        cursor.execute(
            "SELECT * FROM log_sources WHERE path = ? AND log_type = ?",
            (path_to_delete, log_type)
        )
        log_source = cursor.fetchone()

        if not log_source:
            return {"status": "error", "message": "Log source not found in database"}

        source_id = log_source["id"]

        # Step 1: Get all parsed log IDs that are about to be deleted
        cursor.execute(
            "SELECT id FROM parsed_logs WHERE file_path = ? AND type = ?",
            (path_to_delete, log_type)
        )
        deleting_log_ids = [row["id"] for row in cursor.fetchall()]

        # Step 2: Find detection rules where last_run_id is in the logs being deleted
        if deleting_log_ids:
            placeholders = ",".join(["?"] * len(deleting_log_ids))
            cursor.execute(
                f"""
                SELECT id, last_run_id FROM detection_rules
                WHERE last_run_id IN ({placeholders}) AND log_type = ?
                """,
                (*deleting_log_ids, log_type)
            )
            affected_rules = cursor.fetchall()
        else:
            affected_rules = []

        # Step 3: Delete alerts and logs and log source
        cursor.execute("DELETE FROM alerts WHERE log_source_id = ?", (source_id,))
        cursor.execute(
            "DELETE FROM parsed_logs WHERE file_path = ? AND type = ?",
            (path_to_delete, log_type)
        )
        cursor.execute(
            "DELETE FROM log_sources WHERE path = ? AND log_type = ?",
            (path_to_delete, log_type)
        )

        # Step 4: If affected_rules exist, update their last_run_id to new latest log or NULL
        if affected_rules:
            cursor.execute(
                "SELECT id FROM parsed_logs WHERE file_path = ? AND type = ? ORDER BY id DESC LIMIT 1",
                (path_to_delete, log_type)
            )
            new_last_log = cursor.fetchone()
            new_last_run_id = new_last_log["id"] if new_last_log else None

            for rule in affected_rules:
                cursor.execute(
                    "UPDATE detection_rules SET last_run_id = ? WHERE id = ?",
                    (new_last_run_id, rule["id"])
                )

        conn.commit()
        return {
            "status": "ok",
            "message": f"Log source and related alerts deleted successfully for path '{path_to_delete}'"
        }

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

def create_alert(rule_id, severity, message, source_id, log_id=None, ip=None, host=None, source=None, log_level=None, rule_type=None, rule_name=None):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            rule_id, severity, message, log_source_id, log_id, ip, host, source,
            log_level, rule_type, rule_name, alert_time, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rule_id, severity, message, source_id, log_id, ip, host, source,
        log_level, rule_type, rule_name, datetime.utcnow(), "new"
    ))

    conn.commit()
    conn.close()

def insert_default_detection_rules():
    default_rules = [
        {
            "name": "Brute Force Login (Same IP)",
            "description": "Detects 5 or more failed login attempts from a single IP within 2 minutes.",
            "rule_type": "Brute-force",
            "log_type": "auth",
            "condition": "failed_login",
            "threshold": 5,
            "time_window": 120,
            "interval_minutes": 1,
            "active": True
        },
        {
            "name": "Success After Failed Logins",
            "description": "Detects successful login immediately after multiple failed attempts, indicating a potential brute force attempt.",
            "rule_type": "Success-after-fail",
            "log_type": "auth",
            "condition": "mixed_login",
            "threshold": 3,
            "time_window": 180,
            "interval_minutes": 2,
            "active": True
        },
        {
            "name": "Account Brute Force (Same User)",
            "description": "Detects repeated failed logins for the same user account, indicating password guessing.",
            "rule_type": "Account Brute-force",
            "log_type": "auth",
            "condition": "failed_login",
            "threshold": 5,
            "time_window": 180,
            "interval_minutes": 2,
            "active": False
        },
        {
            "name": "Suspicious Process Execution",
            "description": "Detects execution of suspicious processes such as netcat or nmap.",
            "rule_type": "Suspicious Process",
            "log_type": "process",
            "condition": "nc,ncat,nmap,hydra",
            "threshold": 1,
            "time_window": 300,
            "interval_minutes": 2,
            "active": False
        },
        {
            "name": "Odd Hour Login Detected",
            "description": "Detects successful logins outside of business hours (e.g., between 12 AM and 5 AM).",
            "rule_type": "Odd Hour Login",
            "log_type": "auth",
            "condition": "successful_login",
            "threshold": 1,
            "time_window": 300,
            "interval_minutes": 5,
            "active": False
        },
        {
            "name": "Account Spray Attack",
            "description": "Detects multiple failed logins using many usernames from a single IP (spray attack).",
            "rule_type": "Account Spray",
            "log_type": "auth",
            "condition": "failed_login",
            "threshold": 10,
            "time_window": 180,
            "interval_minutes": 2,
            "active": False
        },
        {
            "name": "Access Denied Flood",
            "description": "Detects a flood of access denied logs from a user or IP in a short time.",
            "rule_type": "Access Denied Flood",
            "log_type": "auth",
            "condition": "access_denied",
            "threshold": 10,
            "time_window": 120,
            "interval_minutes": 1,
            "active": False
        },
        {
            "name": "Syslog Unauthorized Access",
            "description": "Detects a high number of 'authentication failure' logs from a single source.",
            "rule_type": "Syslog Unauthorized Access",
            "log_type": "syslog",
            "condition": "authentication failure",
            "threshold": 5,
            "time_window": 300,
            "interval_minutes": 2,
            "active": True
        },
        {
            "name": "Syslog Privilege Escalation",
            "description": "Detects logs indicating failed sudo or su attempts.",
            "rule_type": "Syslog Privilege Escalation",
            "log_type": "syslog",
            "condition": "sudo,su",
            "threshold": 1,
            "time_window": 300,
            "interval_minutes": 2,
            "active": True
        },
        {
            "name": "Syslog Service Restart Flood",
            "description": "Detects frequent restarts of a single service in a short time window, indicating instability or attack.",
            "rule_type": "Syslog Service Restart Flood",
            "log_type": "syslog",
            "condition": "restarting,stopping",
            "threshold": 3,
            "time_window": 600,
            "interval_minutes": 5,
            "active": False
        },
        {
            "name": "Web Application Attack",
            "description": "Detects SQL injection, local file inclusion, or directory traversal patterns in web requests.",
            "rule_type": "Web Application Attack",
            "log_type": "apache",
            "condition": "' OR 1=1,../../,proc/self/environ",
            "threshold": 1,
            "time_window": 60,
            "interval_minutes": 1,
            "active": True
        },
        {
            "name": "High 404 Detection",
            "description": "Detects a high number of 404 (Not Found) errors from a single IP, a sign of content or vulnerability scanning.",
            "rule_type": "High 404 Detection",
            "log_type": "apache",
            "condition": "404",
            "threshold": 20,
            "time_window": 600,
            "interval_minutes": 5,
            "active": True
        },
        {
            "name": "Windows Failed Login Brute Force",
            "description": "Detects a high number of failed logins (Event ID 4625) from a single IP on a Windows machine.",
            "rule_type": "Windows Failed Login Brute Force",
            "log_type": "windows_event",
            "condition": "4625",
            "threshold": 10,
            "time_window": 180,
            "interval_minutes": 2,
            "active": True
        },
        {
            "name": "Windows Audit Log Cleared",
            "description": "Detects when the Windows Security Event Log has been cleared (Event ID 1102), a critical security event.",
            "rule_type": "Windows Audit Log Cleared",
            "log_type": "windows_event",
            "condition": "1102",
            "threshold": 1,
            "time_window": 300,
            "interval_minutes": 5,
            "active": False
        },
        {
            "name": "Firewall Port Scan Detection",
            "description": "Detects an IP attempting to connect to 10 or more different ports in a short time, indicating a port scan.",
            "rule_type": "Firewall Port Scan Detection",
            "log_type": "firewall",
            "condition": "port scan",
            "threshold": 10,
            "time_window": 180,
            "interval_minutes": 2,
            "active": True
        },
        {
            "name": "IDS/IPS Exploit Detection",
            "description": "Alerts when the IDS/IPS detects traffic matching a known exploit or malware signature.",
            "rule_type": "IDS/IPS Exploit Detection",
            "log_type": "ids_ips",
            "condition": "CVE,Exploit,Malware",
            "threshold": 1,
            "time_window": 60,
            "interval_minutes": 1,
            "active": True
        },
        {
            "name": "VPN Unusual Login Hours",
            "description": "Detects successful VPN logins outside of normal working hours (10 PM - 6 AM).",
            "rule_type": "VPN Unusual Login Hours",
            "log_type": "vpn",
            "condition": "connected",
            "threshold": 1,
            "time_window": 3600,
            "interval_minutes": 10,
            "active": False
        },
        {
            "name": "Cloud IAM Changes",
            "description": "Detects changes to cloud IAM policies or creation of new credentials, a sign of account compromise.",
            "rule_type": "Cloud IAM Changes",
            "log_type": "cloud",
            "condition": "create-policy,update-policy,delete-policy",
            "threshold": 1,
            "time_window": 300,
            "interval_minutes": 5,
            "active": True
        },
        {
            "name": "DNS Tunneling Detection",
            "description": "Detects unusually long DNS queries, which can be a sign of data exfiltration or command and control traffic.",
            "rule_type": "DNS Tunneling Detection",
            "log_type": "dns",
            "condition": "100",
            "threshold": 1,
            "time_window": 60,
            "interval_minutes": 1,
            "active": True
        },
        {
            "name": "Antivirus Threat Detection",
            "description": "Alerts on any antivirus logs indicating malware detection or a quarantine failure.",
            "rule_type": "Antivirus Threat Detection",
            "log_type": "antivirus",
            "condition": "malware detected,quarantine failed",
            "threshold": 1,
            "time_window": 60,
            "interval_minutes": 1,
            "active": True
        },
        {
            "name": "Zeek Suspicious User Agent",
            "description": "Detects web traffic with user agents known to be associated with scanners or bots.",
            "rule_type": "Zeek Suspicious User Agent",
            "log_type": "zeek",
            "condition": "nmap,nikto,sqlmap",
            "threshold": 1,
            "time_window": 300,
            "interval_minutes": 5,
            "active": True
        },
        {
            "name": "Email Phishing Detection",
            "description": "Identifies emails with suspicious subjects, which may be part of a phishing campaign.",
            "rule_type": "Email Phishing Detection",
            "log_type": "email",
            "condition": "invoice,urgent,password change",
            "threshold": 1,
            "time_window": 300,
            "interval_minutes": 5,
            "active": True
        },
        {
            "name": "WAF Blocked SQLi/XSS",
            "description": "Alerts when the Web Application Firewall blocks a request containing SQLi or XSS patterns.",
            "rule_type": "WAF Blocked SQLi/XSS",
            "log_type": "waf",
            "condition": "blocked",
            "threshold": 1,
            "time_window": 60,
            "interval_minutes": 1,
            "active": True
        },
        {
            "name": "Database Unauthorized Access",
            "description": "Detects failed login attempts or access denied errors in database logs.",
            "rule_type": "Database Unauthorized Access",
            "log_type": "database",
            "condition": "authentication failure,access denied",
            "threshold": 3,
            "time_window": 180,
            "interval_minutes": 2,
            "active": True
        },
        {
            "name": "Proxy Malware URL Access",
            "description": "Detects attempts to access URLs known to host malware or command and control servers.",
            "rule_type": "Proxy Malware URL Access",
            "log_type": "proxy",
            "condition": "bad.com,malware.net",
            "threshold": 1,
            "time_window": 60,
            "interval_minutes": 1,
            "active": True
        }
    ]


    conn = get_db_connection()
    cursor = conn.cursor()

    # Ensure table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detection_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            description TEXT,
            rule_type TEXT,
            log_type TEXT,
            condition TEXT,
            threshold INTEGER,
            time_window INTEGER,
            interval_minutes INTEGER DEFAULT 5,
            active BOOLEAN DEFAULT 1,
            last_run_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (last_run_id) REFERENCES parsed_logs(id)
        )
    """)

    # Insert missing rules
    for rule in default_rules:
        cursor.execute("SELECT 1 FROM detection_rules WHERE name = ?", (rule["name"],))
        exists = cursor.fetchone()
        if not exists:
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
