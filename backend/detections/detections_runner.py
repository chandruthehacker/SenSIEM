from datetime import datetime, timedelta
import sqlite3
from backend.detections.detections import (
    run_brute_force_detection,
    run_anomaly_detection,
    run_failed_login_detection,
    run_port_scan_detection,
    run_geo_location_alerts,
    run_custom_pattern_detection
)
from backend.utils.database.database_operations import get_db_connection

DETECTION_FUNCTIONS = {
    "brute_force": run_brute_force_detection,
    "anomaly": run_anomaly_detection,
    "failed_login": run_failed_login_detection,
    "port_scan": run_port_scan_detection,
    "geo_location": run_geo_location_alerts,
    "custom_pattern": run_custom_pattern_detection,
    # Add more detection types as needed
}

def run_all_active_rules_sync():
    """
    Iterates through all active detection rules and executes their corresponding
    detection functions if they are due for execution.
    This function is synchronous and uses direct sqlite3 connections.
    """
    now = datetime.utcnow()
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Fetch active detection rules
        cursor.execute("SELECT * FROM detection_rules WHERE active = 1")
        rules = cursor.fetchall()

        for rule in rules:
            last_run_str = rule["last_run"]
            # Parse last_run from ISO string to datetime object
            last_run_dt = datetime.fromisoformat(last_run_str) if last_run_str else None

            interval_minutes = rule["interval_minutes"] or 5 # Default to 5 if somehow null
            due_time = (last_run_dt + timedelta(minutes=interval_minutes)) if last_run_dt else None

            # If rule is due for execution (or has never run)
            if not last_run_dt or now >= due_time:
                rule_type = rule["rule_type"]
                detection_function = DETECTION_FUNCTIONS.get(rule_type)

                if detection_function:
                    try:
                        # Pass rule parameters dynamically based on rule_type
                        # Ensure parameters match the function signatures
                        if rule_type == "brute_force":
                            detection_function(rule["id"], rule["log_type"], rule["time_window"], rule["threshold"])
                        elif rule_type == "anomaly":
                            detection_function(rule["id"], rule["log_type"])
                        elif rule_type == "failed_login":
                            detection_function(rule["id"], rule["log_type"], rule["threshold"])
                        elif rule_type == "port_scan":
                            # Assuming 'condition' or another field holds port_threshold
                            port_threshold = rule["condition"] if rule["condition"] else 100
                            detection_function(rule["id"], rule["log_type"], int(port_threshold))
                        elif rule_type == "geo_location":
                            # Using 'condition' for region
                            region = rule["condition"] if rule["condition"] else "restricted"
                            detection_function(rule["id"], rule["log_type"], region)
                        elif rule_type == "custom_pattern":
                            # Using 'condition' for pattern
                            pattern = rule["condition"] if rule["condition"] else ""
                            detection_function(rule["id"], rule["log_type"], pattern)
                        # Extend with more conditions if needed for other rule types

                        # Update last_run timestamp to now (ISO format string)
                        cursor.execute(
                            "UPDATE detection_rules SET last_run = ? WHERE id = ?", (now.isoformat(), rule["id"])
                        )
                        conn.commit() # Commit the rule's last_run update
                    except Exception as e:
                        print(f"[ERROR] Failed to run detection {rule_type} for rule {rule['id']}: {e}")
                else:
                    print(f"[WARNING] Unsupported detection rule type: {rule_type} for rule ID: {rule['id']}")
            # else:
            #     print(f"Rule {rule['name']} (ID: {rule['id']}) not due for execution yet.")
    except sqlite3.Error as e:
        print(f"[CRITICAL ERROR] Database error in run_all_active_rules: {e}")
    except Exception as e:
        print(f"[CRITICAL ERROR] Unexpected error in run_all_active_rules: {e}")
    finally:
        conn.close()
