from datetime import datetime, timedelta
from backend.detections.detections import run_brute_force_detection, run_anomaly_detection
from backend.utils.database.database_operations import get_db_connection  # etc.

def run_all_active_rules():
    now = datetime.utcnow()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM detection_rules WHERE active = 1")
    rules = cursor.fetchall()

    for rule in rules:
        last_run = rule["last_run"]
        interval = rule["interval_minutes"] or 5
        due_time = last_run + timedelta(minutes=interval) if last_run else None

        if not last_run or now >= due_time:
            if rule["rule_type"] == "brute_force":
                run_brute_force_detection(rule["id"], rule["log_type"], rule["time_window"], rule["threshold"])
            elif rule["rule_type"] == "anomaly":
                run_anomaly_detection(rule["id"], rule["log_type"])
            # Add more rule_type checks as needed

            # Update last_run time
            cursor.execute(
                "UPDATE detection_rules SET last_run = ? WHERE id = ?", (now, rule["id"])
            )
    conn.commit()
    conn.close()
