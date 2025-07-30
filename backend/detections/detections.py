from datetime import datetime, timedelta
from backend.utils.database.database_operations import get_db_connection, create_alert


def run_brute_force_detection(rule_type, log_type, time_window_minutes, threshold):
    print("Brute Force")
    conn = get_db_connection()
    cursor = conn.cursor()

    now = datetime.utcnow()
    window_start = now - timedelta(minutes=time_window_minutes)

    # Get all failed SSH login logs within the time window
    cursor.execute("""
        SELECT id, timestamp, src_ip, host, source, message, log_level
        FROM parsed_logs
        WHERE type = ?
          AND (log_level = 'WARNING' OR log_level = 'ERROR' OR log_level = 'CRITICAL')
          AND (
              message LIKE '%Failed password for%' OR
              message LIKE '%failed login%' OR
              message LIKE '%authentication failure%'
          )
          AND timestamp >= ?
    """, (log_type, window_start))

    logs = cursor.fetchall()

    # Track failed attempts per IP
    ip_failures = {}

    for log in logs:
        ip = log["src_ip"]
        if ip not in ip_failures:
            ip_failures[ip] = {
                "count": 1,
                "log_id": log["id"],
                "host": log.get("host"),
                "source": log.get("source")
            }
        else:
            ip_failures[ip]["count"] += 1

    # Generate alert if threshold is exceeded
    for ip, data in ip_failures.items():
        if data["count"] >= threshold:
            alert_message = (
                f"Brute-force attack detected from IP {ip}: "
                f"{data['count']} failed login attempts in the last {time_window_minutes} minutes."
            )

            create_alert(
                rule_type=rule_type,
                severity="high",
                message=alert_message,
                log_id=data["log_id"],
                ip=ip,
                host=data["host"],
                source=data["source"]
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