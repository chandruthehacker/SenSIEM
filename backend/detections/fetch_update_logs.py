import sqlite3

from backend.utils.database.database_operations import get_db_connection

def _fetch_rule_and_logs(rule_id: int, last_run_id: int | None, conditions: str,
                         params: tuple) -> tuple | None:
    """Fetch rule details and matching logs with optional id filter."""
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT name, rule_type, last_run_id FROM detection_rules WHERE id = ?", (rule_id,))
        rule = cursor.fetchone()
        if not rule:
            print(f"[WARN] Rule with ID {rule_id} not found.")
            return None

        last_run_id = rule["last_run_id"]
        last_run_id = int(last_run_id) if last_run_id is not None else None
        if not last_run_id:
            last_run_id = 0
        # List of columns to fetch from parsed_logs
        columns = [
            "id", "timestamp", "log_level", "source", "host", "process", "message", "raw_log",
            "type", "file_path", "source_id", "event_id", "username", "status_code", "url",
            "method", "protocol", "src_ip", "dest_ip", "src_port", "dest_port", "rule",
            "signature", "action", "user_agent", "device", "mail_subject", "file_hash",
            "tags", "alert"
        ]

        # Base WHERE clause
        where_clause = conditions.strip()

        # Append last_run_id filter if provided
        if last_run_id is not None:
            where_clause += " AND id > ?"
            params = params + (last_run_id,)

        # Final query
        query = f"""
            SELECT {', '.join(columns)}
            FROM parsed_logs
            WHERE {where_clause}
            ORDER BY timestamp ASC
        """

        cursor.execute(query, params)
        logs = cursor.fetchall()
        return rule, logs, conn

    except Exception as e:
        print(f"[ERROR] Database operation failed for rule {rule_id}: {e}")
        return None, None, conn
    finally:
        conn.close()

def _update_last_run_id(rule_id: int, latest_log_id: int):
    """Helper function to update the last_run_id for a rule."""
    if not latest_log_id:
        return
        
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE detection_rules SET last_run_id = ? WHERE id = ?", (latest_log_id, rule_id))
        conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to update last_run_id for rule {rule_id}: {e}")
    finally:
        conn.close()