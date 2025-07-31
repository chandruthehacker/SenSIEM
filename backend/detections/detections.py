from datetime import datetime, timedelta
from backend.utils.database.database_operations import get_db_connection, create_alert


def run_brute_force_detection(rule_id, log_type, time_window_minutes, threshold, last_run_str=None):
    print(f"[INFO] Running Brute Force Detection | Rule ID: {rule_id}")
    conn = get_db_connection()
    cursor = conn.cursor()

    # ⬇️ Get rule_name and rule_type
    cursor.execute("SELECT name, rule_type FROM detection_rules WHERE id = ?", (rule_id,))
    rule = cursor.fetchone()
    rule_name = rule["name"]
    rule_type = rule["rule_type"]

    now = datetime.utcnow()
    window_start = datetime.fromisoformat(last_run_str) - timedelta(minutes=1) if last_run_str else now - timedelta(days=3650)

    cursor.execute("""
        SELECT id, source_id, timestamp, src_ip, host, type, message, log_level
        FROM parsed_logs
        WHERE type = ?
          AND log_level IN ('WARNING', 'ERROR', 'CRITICAL')
          AND (
              message LIKE '%Failed password for%' OR
              message LIKE '%failed login%' OR
              message LIKE '%authentication failure%'
          )
          AND timestamp >= ?
    """, (log_type, window_start))

    logs = cursor.fetchall()
    
    ip_failures = {}
    for log in logs:
        ip = log["src_ip"]
        if not ip:
            continue
        if ip not in ip_failures:
            ip_failures[ip] = {
                "count": 1,
                "log_id": log["id"],
                "host": log["host"],
                "source": log["type"],
                "source_id": log["source_id"],
                "log_level": log["log_level"]
            }
        else:
            ip_failures[ip]["count"] += 1

    for ip, data in ip_failures.items():
        if data["count"] >= threshold:
            alert_message = (
                f"Brute-force attack detected from IP {ip}: "
                f"{data['count']} failed login attempts since {window_start.isoformat()}."
            )
            create_alert(
                rule_id=rule_id,
                severity="High",
                message=alert_message,
                source_id=data["source_id"],
                log_id=data["log_id"],
                ip=ip,
                host=data["host"],
                source=data["source"],
                log_level=data["log_level"],
                rule_type=rule_type,
                rule_name=rule_name
            )

    conn.close()


def run_anomaly_detection():
    pass

def run_failed_login_detection():
    pass
def run_port_scan_detection():
    pass
def run_geo_location_alerts():
    pass

def run_custom_pattern_detection():
    pass