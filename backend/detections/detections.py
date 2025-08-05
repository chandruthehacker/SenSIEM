from collections import defaultdict, deque
from datetime import datetime, timedelta
import re
from typing import Any, Dict, List, Tuple
from backend.detections.fetch_update_logs import _fetch_rule_and_logs, _update_last_run_id
from backend.utils.database.database_operations import create_alert, get_db_connection


# Brute Force Detection
def run_brute_force_detection(rule_id: int, log_type: str, threshold: int, **kwargs):
    print(f"[INFO] Running Brute Force Login Detection | Rule ID: {rule_id}")

    conditions = "type = ? AND (message LIKE '%failed login%' OR message LIKE '%Failed password%')"
    params = (log_type,)

    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs:
        print("[INFO] No logs found for detection.")
        return

    # Group logs by IP
    logs_by_ip = defaultdict(list)
    for log in logs:
        src_ip = log["src_ip"]
        if src_ip:
            logs_by_ip[src_ip].append(log)

    latest_log_id = 0

    for ip, ip_logs in logs_by_ip.items():
        # Sort logs by timestamp
        sorted_logs = sorted(ip_logs, key=lambda log: log["timestamp"])

        for i in range(len(sorted_logs)):
            window = [sorted_logs[i]]
            time_i = datetime.strptime(sorted_logs[i]["timestamp"], "%Y-%m-%d %H:%M:%S")

            for j in range(i + 1, len(sorted_logs)):
                time_j = datetime.strptime(sorted_logs[j]["timestamp"], "%Y-%m-%d %H:%M:%S")
                if (time_j - time_i).total_seconds() <= 60:
                    window.append(sorted_logs[j])
                else:
                    break

            if len(window) >= threshold:
                last_log = window[-1]
                print(f"[ALERT] Triggered | IP: {ip}, Count: {len(window)}")
                alert_message = (
                    f"Brute force attack from IP {ip}: {len(window)} failed logins "
                    f"between {window[0]['timestamp']} and {window[-1]['timestamp']}."
                )

                create_alert(
                    rule_id=rule_id,
                    severity="High",
                    message=alert_message,
                    source_id=last_log["source_id"],
                    log_id=last_log["id"],
                    ip=ip,
                    host=last_log["host"],
                    source='auth.log',
                    log_level=last_log["log_level"],
                    rule_type=rule["rule_type"],
                    rule_name=rule["name"]
                )

                # Track latest log ID when alert created
                latest_log_id = max(latest_log_id, last_log["id"])
                break  # Stop checking this IP after alert

            # Even if alert not triggered, track latest log ID
            latest_log_id = max(latest_log_id, sorted_logs[i]["id"])

    if latest_log_id > 0:
        _update_last_run_id(rule_id, latest_log_id)

def run_success_after_fail_detection(
    rule_id: int,
    log_type: str,
    threshold: int,
    **kwargs
):
    print(f"[INFO] Running Success After Fail Detection | Rule ID: {rule_id}")

    # Filter logs with relevant messages
    conditions = (
        "type = ? AND (message LIKE '%Failed password%' OR message LIKE '%Accepted password%' OR message LIKE '%failed login%')"
    )
    params = (log_type,)

    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs:
        print("[INFO] No logs found for detection.")
        return

    # Group logs by IP
    logs_by_ip = defaultdict(list)
    for log in logs:
        ip = log["src_ip"]
        if ip:
            logs_by_ip[ip].append(log)

    latest_log_id = 0

    for ip, ip_logs in logs_by_ip.items():
        # Already sorted by timestamp via SQL
        failed_logs = []
        success_logs = []

        for log in ip_logs:
            msg = log["message"].lower()
            if "failed" in msg:
                failed_logs.append(log)
            elif "accepted" in msg:
                success_logs.append(log)

        # Check each success against recent fails within 5 minutes
        for success_log in success_logs:
            try:
                success_time = datetime.strptime(success_log["timestamp"], "%Y-%m-%d %H:%M:%S")
            except Exception as e:
                print(f"[WARN] Skipping success log due to timestamp error: {e}")
                continue

            recent_fails = []
            for fail_log in failed_logs:
                try:
                    fail_time = datetime.strptime(fail_log["timestamp"], "%Y-%m-%d %H:%M:%S")
                except Exception as e:
                    print(f"[WARN] Skipping fail log due to timestamp error: {e}")
                    continue

                if 0 < (success_time - fail_time).total_seconds() <= 300:
                    recent_fails.append(fail_log)

            if len(recent_fails) >= threshold:
                print(f"[ALERT] Triggered | IP: {ip}, Fails: {len(recent_fails)} before success")

                alert_message = (
                    f"Successful login after {len(recent_fails)} failed attempts "
                    f"from IP {ip} within 5 minutes, "
                    f"between {recent_fails[0]['timestamp']} and {success_log['timestamp']}."
                )

                create_alert(
                    rule_id=rule_id,
                    severity="High",
                    message=alert_message,
                    source_id=success_log["source_id"],
                    log_id=success_log["id"],
                    ip=ip,
                    host=success_log["host"],
                    source=success_log["source"],
                    log_level=success_log["log_level"],
                    rule_type=rule["rule_type"],
                    rule_name=rule["name"]
                )

    max_log_id_in_batch = max(log["id"] for log in logs)
    _update_last_run_id(rule_id, max_log_id_in_batch)

    if conn:
        conn.close()

def run_account_brute_force_detection(rule_id: int, log_type: str, threshold: int, **kwargs):
    print(f"[INFO] Running Account Brute Force Detection | Rule ID: {rule_id}")
    time_window_minutes = kwargs.get('time_window_minutes', 1)
    time_window_seconds = int(time_window_minutes) * 60
    time_window_start = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    conditions = "type = ? AND (message LIKE '%failed login%' OR message LIKE '%Failed password%') AND timestamp > ?"
    params = (log_type, time_window_start.strftime("%Y-%m-%d %H:%M:%S"))
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return

    user_failures = defaultdict(lambda: {"count": 0, "last_log": None})
    latest_log_id = 0
    for log in logs:
        user = log.get("username")
        if user:
            user_failures[user]["count"] += 1
            user_failures[user]["last_log"] = log
            latest_log_id = max(latest_log_id, log["id"])

    for user, data in user_failures.items():
        if data["count"] >= threshold:
            last_log = data["last_log"]
            alert_message = f"Account brute force attack on user '{user}': {data['count']} failed logins in {time_window_seconds} seconds."
            create_alert(rule_id=rule_id, severity="High", message=alert_message, 
                         source_id=last_log["source_id"], log_id=last_log["id"], 
                         ip=last_log["src_ip"], host=last_log["host"], source=last_log["source"], 
                         log_level=last_log["log_level"], rule_type=rule["rule_type"], 
                         rule_name=rule["name"])
    _update_last_run_id(rule_id, latest_log_id)

def run_suspicious_process_detection(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running Suspicious Process Detection | Rule ID: {rule_id}")
    conditions_list = kwargs.get('condition', '')
    if not conditions_list: return
    
    patterns = conditions_list.split(',')
    conditions = f"type = ? AND (process LIKE ? {' OR process LIKE ?' * (len(patterns) - 1)})"
    params = (log_type,) + tuple(f"%{p}%" for p in patterns)

    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
    
    latest_log_id = 0
    for log in logs:
        alert_message = f"Suspicious process '{log['process']}' executed on host '{log['host']}'."
        create_alert(rule_id=rule_id, severity="Critical", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_odd_hour_login_detection(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running Odd Hour Login Detection | Rule ID: {rule_id}")
    time_window_minutes = kwargs.get('time_window_minutes', 10)
    time_window_seconds = int(time_window_minutes) * 60
    time_window_start = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    conditions = "type = ? AND (message LIKE '%accepted password%' OR message LIKE '%successful login%') AND timestamp > ?"
    params = (log_type, time_window_start.strftime("%Y-%m-%d %H:%M:%S"))
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return

    latest_log_id = 0
    for log in logs:
        log_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
        log_hour = log_time.hour
        if log_hour >= 22 or log_hour <= 5:
            alert_message = f"Successful login for user '{log['username']}' at unusual hour ({log_time.strftime('%I:%M %p')})."
            create_alert(rule_id=rule_id, severity="Medium", message=alert_message, 
                         source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                         host=log["host"], source=log["source"], log_level=log["log_level"], 
                         rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_account_spray_detection(rule_id: int, log_type: str, threshold: int, **kwargs):
    print(f"[INFO] Running Account Spray Detection | Rule ID: {rule_id}")
    time_window_minutes = kwargs.get('time_window_minutes', 1)
    time_window_seconds = int(time_window_minutes) * 60
    time_window_start = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    conditions = "type = ? AND (message LIKE '%failed login%' OR message LIKE '%Failed password%') AND timestamp > ?"
    params = (log_type, time_window_start.strftime("%Y-%m-%d %H:%M:%S"))
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return

    ip_users = defaultdict(set)
    latest_log_id = 0
    for log in logs:
        ip, user = log.get("src_ip"), log.get("username")
        if ip and user: ip_users[ip].add(user)
        latest_log_id = max(latest_log_id, log["id"])

    for ip, users in ip_users.items():
        if len(users) >= threshold:
            alert_message = f"Account spray attack from IP {ip}: tried {len(users)} different usernames in {time_window_seconds} seconds."
            create_alert(rule_id=rule_id, severity="High", message=alert_message, 
                         source_id=None, log_id=latest_log_id, ip=ip, host=None, 
                         source=log_type, log_level="CRITICAL", rule_type=rule["rule_type"], 
                         rule_name=rule["name"])
    _update_last_run_id(rule_id, latest_log_id)

def run_access_denied_flood_detection(rule_id: int, log_type: str, threshold: int, **kwargs):
    print(f"[INFO] Running Access Denied Flood Detection | Rule ID: {rule_id}")
    time_window_minutes = kwargs.get('time_window_minutes', 1)
    time_window_seconds = int(time_window_minutes) * 60
    time_window_start = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    conditions = "type = ? AND message LIKE '%access denied%' AND timestamp > ?"
    params = (log_type, time_window_start.strftime("%Y-%m-%d %H:%M:%S"))
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return

    access_denied_count = defaultdict(lambda: {"count": 0, "last_log": None})
    latest_log_id = 0
    for log in logs:
        ip, user = log.get("src_ip"), log.get("username")
        key = user if user else ip
        if key:
            access_denied_count[key]["count"] += 1
            access_denied_count[key]["last_log"] = log
            latest_log_id = max(latest_log_id, log["id"])

    for key, data in access_denied_count.items():
        if data["count"] >= threshold:
            last_log = data["last_log"]
            alert_message = f"Access denied flood detected for '{key}': {data['count']} attempts in {time_window_seconds} seconds."
            create_alert(rule_id=rule_id, severity="Medium", message=alert_message, 
                         source_id=last_log["source_id"], log_id=last_log["id"], 
                         ip=last_log["src_ip"], host=last_log["host"], source=last_log["source"], 
                         log_level=last_log["log_level"], rule_type=rule["rule_type"], 
                         rule_name=rule["name"])
    _update_last_run_id(rule_id, latest_log_id)

def run_syslog_unauthorized_access(rule_id: int, log_type: str, threshold: int, **kwargs):
    print(f"[INFO] Running Syslog Unauthorized Access Detection | Rule ID: {rule_id}")
    time_window_minutes = kwargs.get('time_window_minutes', 5)
    time_window_seconds = int(time_window_minutes) * 60
    time_window_start = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    conditions = "type = ? AND message LIKE '%authentication failure%' AND timestamp > ?"
    params = (log_type, time_window_start.strftime("%Y-%m-%d %H:%M:%S"))
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
    
    ip_failures = defaultdict(int)
    latest_log_id = 0
    for log in logs:
        ip = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', log.get("message", ""))
        if ip: ip_failures[ip.group(0)] += 1
        latest_log_id = max(latest_log_id, log["id"])

    for ip, count in ip_failures.items():
        if count >= threshold:
            alert_message = f"High number of syslog authentication failures ({count}) from IP {ip}."
            create_alert(rule_id=rule_id, severity="High", message=alert_message, 
                         source_id=None, log_id=latest_log_id, ip=ip, host=None, 
                         source=log_type, log_level="CRITICAL", rule_type=rule["rule_type"], 
                         rule_name=rule["name"])
    _update_last_run_id(rule_id, latest_log_id)

def run_syslog_privilege_escalation(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running Syslog Privilege Escalation Detection | Rule ID: {rule_id}")
    conditions_list = kwargs.get('condition', '')
    if not conditions_list: return
    
    patterns = conditions_list.split(',')
    conditions = f"type = ? AND (message LIKE ? {' OR message LIKE ?' * (len(patterns) - 1)})"
    params = (log_type,) + tuple(f"%{p}%" for p in patterns)

    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
    
    latest_log_id = 0
    for log in logs:
        alert_message = f"Privilege escalation attempt detected on host '{log['host']}'. Message: {log['message']}"
        create_alert(rule_id=rule_id, severity="Critical", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_syslog_service_restart_flood(rule_id: int, log_type: str, threshold: int, **kwargs):
    print(f"[INFO] Running Syslog Service Restart Flood Detection | Rule ID: {rule_id}")
    time_window_minutes = kwargs.get('time_window_minutes', 5)
    time_window_seconds = int(time_window_minutes) * 60
    time_window_start = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    conditions = "type = ? AND (message LIKE '%restarting%' OR message LIKE '%stopping%') AND timestamp > ?"
    params = (log_type, time_window_start.strftime("%Y-%m-%d %H:%M:%S"))
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
    
    service_restarts = defaultdict(int)
    latest_log_id = 0
    for log in logs:
        service_restarts[log.get("process", "unknown")] += 1
        latest_log_id = max(latest_log_id, log["id"])
    
    for service, count in service_restarts.items():
        if count >= threshold:
            alert_message = f"Service '{service}' is restarting frequently ({count} times) on host '{log['host']}'."
            create_alert(rule_id=rule_id, severity="High", message=alert_message, 
                         source_id=None, log_id=latest_log_id, ip=None, host=log["host"], 
                         source=log_type, log_level="CRITICAL", rule_type=rule["rule_type"], 
                         rule_name=rule["name"])
    _update_last_run_id(rule_id, latest_log_id)

def run_web_app_attack(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running Web Application Attack Detection | Rule ID: {rule_id}")
    conditions_list = kwargs.get('condition', '')
    if not conditions_list: return
    
    patterns = conditions_list.split(',')
    conditions = f"type = ? AND (url LIKE ? {' OR url LIKE ?' * (len(patterns) - 1)})"
    params = (log_type,) + tuple(f"%{p}%" for p in patterns)

    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
    
    latest_log_id = 0
    for log in logs:
        alert_message = f"Potential web attack detected: {log['url']} from {log['src_ip']}"
        create_alert(rule_id=rule_id, severity="High", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_high_404_detection(rule_id: int, log_type: str, threshold: int, **kwargs):
    print(f"[INFO] Running High 404 Detection | Rule ID: {rule_id}")
    time_window_minutes = kwargs.get('time_window_minutes', 10)
    time_window_seconds = int(time_window_minutes) * 60
    time_window_start = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    conditions = "type = ? AND status_code = ? AND timestamp > ?"
    params = (log_type, "404", time_window_start.strftime("%Y-%m-%d %H:%M:%S"))
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return

    ip_404_count = defaultdict(int)
    latest_log_id = 0
    for log in logs:
        ip_404_count[log.get("src_ip")] += 1
        latest_log_id = max(latest_log_id, log["id"])
        
    for ip, count in ip_404_count.items():
        if count >= threshold:
            alert_message = f"High number of 404 errors ({count}) from IP {ip}, possibly a content scan."
            create_alert(rule_id=rule_id, severity="Medium", message=alert_message, 
                         source_id=None, log_id=latest_log_id, ip=ip, host=None, 
                         source=log_type, log_level="WARNING", rule_type=rule["rule_type"], 
                         rule_name=rule["name"])
    _update_last_run_id(rule_id, latest_log_id)

def run_auth_brute_force_same_ip(rule_id, log_type, time_window_minutes, threshold):
    """Detects brute-force login attempts from a single IP."""
    print(f"[INFO] Running Brute Force (Same IP) Detection | Rule ID: {rule_id}")
    conditions = "type = ? AND message LIKE '%Failed password%' OR message LIKE '%authentication failure%'"
    params = (log_type,)
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return

    ip_failures = defaultdict(lambda: {"count": 0, "last_log": None})
    latest_log_id = 0
    time_window_start = datetime.utcnow() - timedelta(minutes=time_window_minutes)

    for log in logs:
        log_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
        if log_time < time_window_start: continue
        
        ip = log.get("src_ip")
        if ip:
            ip_failures[ip]["count"] += 1
            ip_failures[ip]["last_log"] = log
            latest_log_id = max(latest_log_id, log["id"])

    for ip, data in ip_failures.items():
        if data["count"] >= threshold:
            last_log = data["last_log"]
            alert_message = (f"Brute-force login detected from IP {ip}: {data['count']} failed attempts.")
            create_alert(
                rule_id=rule_id, severity="Critical", message=alert_message, 
                source_id=last_log["source_id"], log_id=last_log["id"], 
                ip=ip, host=last_log["host"], source=last_log["source"], 
                log_level=last_log["log_level"], rule_type=rule["rule_type"], rule_name=rule["name"]
            )
    _update_last_run_id(rule_id, latest_log_id)

def run_windows_failed_login_detection(rule_id: int, log_type: str, threshold: int, **kwargs):
    print(f"[INFO] Running Windows Failed Login Detection | Rule ID: {rule_id}")
    time_window_minutes = kwargs.get('time_window_minutes', 5)
    time_window_seconds = int(time_window_minutes) * 60
    time_window_start = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    conditions = "type = ? AND event_id = ? AND timestamp > ?"
    params = (log_type, "4625", time_window_start.strftime("%Y-%m-%d %H:%M:%S"))
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return

    ip_failures = defaultdict(int)
    latest_log_id = 0
    for log in logs:
        ip_failures[log.get("src_ip")] += 1
        latest_log_id = max(latest_log_id, log["id"])
        
    for ip, count in ip_failures.items():
        if count >= threshold:
            alert_message = f"Windows brute force attack detected from IP {ip}: {count} failed logins."
            create_alert(rule_id=rule_id, severity="High", message=alert_message, 
                         source_id=None, log_id=latest_log_id, ip=ip, host=None, 
                         source=log_type, log_level="CRITICAL", rule_type=rule["rule_type"], 
                         rule_name=rule["name"])
    _update_last_run_id(rule_id, latest_log_id)

def run_windows_failed_login(rule_id, log_type, time_window_minutes, threshold):
    """Detects brute force attacks via Windows Event Log ID 4625."""
    print(f"[INFO] Running Windows Failed Login Detection | Rule ID: {rule_id}")
    conditions = "type = ? AND event_id = ?"
    params = (log_type, "4625")
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
        
    ip_failures = defaultdict(lambda: {"count": 0, "last_log": None})
    latest_log_id = 0
    time_window_start = datetime.utcnow() - timedelta(minutes=time_window_minutes)

    for log in logs:
        log_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
        if log_time < time_window_start: continue
        
        ip = log.get("src_ip")
        if ip:
            ip_failures[ip]["count"] += 1
            ip_failures[ip]["last_log"] = log
            latest_log_id = max(latest_log_id, log["id"])

    for ip, data in ip_failures.items():
        if data["count"] >= threshold:
            last_log = data["last_log"]
            alert_message = (f"Brute-force attack detected from IP {ip} ({data['count']} failed login attempts) via Windows Event Logs.")
            create_alert(
                rule_id=rule_id, severity="High", message=alert_message, 
                source_id=last_log["source_id"], log_id=last_log["id"], ip=ip, 
                host=last_log["host"], source=last_log["source"], log_level=last_log["log_level"], 
                rule_type=rule["rule_type"], rule_name=rule["name"]
            )
    _update_last_run_id(rule_id, latest_log_id)

def run_windows_audit_log_cleared(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running Windows Audit Log Cleared | Rule ID: {rule_id}")
    conditions = "type = ? AND event_id = ?"
    params = (log_type, "1102")
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
    
    latest_log_id = 0
    for log in logs:
        alert_message = f"Windows Security Event Log was cleared on host '{log['host']}'."
        create_alert(rule_id=rule_id, severity="Critical", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_firewall_port_scan_detection(rule_id: int, log_type: str, threshold: int, **kwargs):
    print(f"[INFO] Running Firewall Port Scan Detection | Rule ID: {rule_id}")
    time_window_minutes = kwargs.get('time_window_minutes', 5)
    time_window_seconds = int(time_window_minutes) * 60
    time_window_start = datetime.utcnow() - timedelta(seconds=time_window_seconds)
    
    conditions = "type = ? AND action = 'denied' AND timestamp > ?"
    params = (log_type, time_window_start.strftime("%Y-%m-%d %H:%M:%S"))
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
    
    ip_ports = defaultdict(set)
    latest_log_id = 0
    for log in logs:
        ip_ports[log.get("src_ip")].add(log.get("dest_port"))
        latest_log_id = max(latest_log_id, log["id"])

    for ip, ports in ip_ports.items():
        if len(ports) >= threshold:
            alert_message = f"Port scan detected from IP {ip}: attempted to connect to {len(ports)} different ports."
            create_alert(rule_id=rule_id, severity="High", message=alert_message, 
                         source_id=None, log_id=latest_log_id, ip=ip, host=None, 
                         source=log_type, log_level="CRITICAL", rule_type=rule["rule_type"], 
                         rule_name=rule["name"])
    _update_last_run_id(rule_id, latest_log_id)

def run_ids_exploit_detection(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running IDS Exploit Detection | Rule ID: {rule_id}")
    conditions_list = kwargs.get('condition', '')
    if not conditions_list: return
    
    patterns = conditions_list.split(',')
    conditions = f"type = ? AND (signature LIKE ? {' OR signature LIKE ?' * (len(patterns) - 1)})"
    params = (log_type,) + tuple(f"%{p}%" for p in patterns)

    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
        
    latest_log_id = 0
    for log in logs:
        alert_message = f"IDS/IPS alert: '{log['signature']}' from {log['src_ip']}"
        create_alert(rule_id=rule_id, severity="Critical", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_vpn_unusual_login_hours(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running VPN Unusual Login Hours | Rule ID: {rule_id}")
    time_window_minutes = kwargs.get('time_window_minutes', 10)
    time_window_seconds = int(time_window_minutes) * 60
    time_window_start = datetime.utcnow() - timedelta(seconds=time_window_seconds)

    conditions = "type = ? AND message LIKE '%connected%' AND timestamp > ?"
    params = (log_type, time_window_start.strftime("%Y-%m-%d %H:%M:%S"))
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return

    latest_log_id = 0
    for log in logs:
        log_time = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
        log_hour = log_time.hour
        if log_hour >= 22 or log_hour <= 6:
            alert_message = f"Successful VPN login for user '{log['username']}' at unusual hour ({log_time.strftime('%I:%M %p')})."
            create_alert(rule_id=rule_id, severity="Medium", message=alert_message, 
                         source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                         host=log["host"], source=log["source"], log_level=log["log_level"], 
                         rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_cloud_iam_changes(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running Cloud IAM Changes | Rule ID: {rule_id}")
    conditions_list = kwargs.get('condition', '')
    if not conditions_list: return
    
    patterns = conditions_list.split(',')
    conditions = f"type = ? AND (action LIKE ? {' OR action LIKE ?' * (len(patterns) - 1)})"
    params = (log_type,) + tuple(f"%{p}%" for p in patterns)

    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
    
    latest_log_id = 0
    for log in logs:
        alert_message = f"Privilege change detected on cloud platform: action '{log['action']}' by user '{log['username']}'"
        create_alert(rule_id=rule_id, severity="Critical", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_dns_tunneling_detection(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running DNS Tunneling Detection | Rule ID: {rule_id}")
    condition = kwargs.get('condition', '100')
    try: length_threshold = int(condition)
    except (ValueError, TypeError): length_threshold = 100
    
    conditions = "type = ? AND LENGTH(message) > ?"
    params = (log_type, length_threshold)
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
        
    latest_log_id = 0
    for log in logs:
        alert_message = f"Possible DNS tunneling attempt with a long message from {log['src_ip']}: {log['message']}"
        create_alert(rule_id=rule_id, severity="High", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_antivirus_detection(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running Antivirus Detection | Rule ID: {rule_id}")
    conditions = "type = ? AND (message LIKE '%malware detected%' OR message LIKE '%quarantine failed%')"
    params = (log_type,)
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
        
    latest_log_id = 0
    for log in logs:
        alert_message = f"Antivirus alert on host '{log['host']}': {log['message']}"
        create_alert(rule_id=rule_id, severity="High", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_zeek_suspicious_user_agent(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running Zeek Suspicious User Agent | Rule ID: {rule_id}")
    conditions_list = kwargs.get('condition', '')
    if not conditions_list: return
    
    patterns = conditions_list.split(',')
    conditions = f"type = ? AND (user_agent LIKE ? {' OR user_agent LIKE ?' * (len(patterns) - 1)})"
    params = (log_type,) + tuple(f"%{p}%" for p in patterns)

    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
    
    latest_log_id = 0
    for log in logs:
        alert_message = f"Suspicious user agent '{log['user_agent']}' detected from {log['src_ip']}."
        create_alert(rule_id=rule_id, severity="Medium", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_email_phishing_detection(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running Email Phishing Detection | Rule ID: {rule_id}")
    conditions_list = kwargs.get('condition', '')
    if not conditions_list: return
    
    patterns = conditions_list.split(',')
    conditions = f"type = ? AND (mail_subject LIKE ? {' OR mail_subject LIKE ?' * (len(patterns) - 1)})"
    params = (log_type,) + tuple(f"%{p}%" for p in patterns)

    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
    
    latest_log_id = 0
    for log in logs:
        alert_message = f"Potential phishing email detected with subject: '{log['mail_subject']}'"
        create_alert(rule_id=rule_id, severity="Medium", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_waf_sqli_xss_detection(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running WAF SQLi/XSS Detection | Rule ID: {rule_id}")
    conditions = "type = ? AND action = ? AND (message LIKE '%SQLi%' OR message LIKE '%XSS%')"
    params = (log_type, "blocked")
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
        
    latest_log_id = 0
    for log in logs:
        alert_message = f"WAF blocked a web attack from {log['src_ip']}: {log['message']}"
        create_alert(rule_id=rule_id, severity="Critical", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_db_unauthorized_access(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running Database Unauthorized Access Detection | Rule ID: {rule_id}")
    conditions = "type = ? AND (message LIKE '%authentication failure%' OR message LIKE '%access denied%')"
    params = (log_type,)
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs: return
        
    latest_log_id = 0
    for log in logs:
        alert_message = f"Unauthorized database access attempt from {log['src_ip']} for user '{log['username']}'"
        create_alert(rule_id=rule_id, severity="High", message=alert_message, 
                     source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"], 
                     host=log["host"], source=log["source"], log_level=log["log_level"], 
                     rule_type=rule["rule_type"], rule_name=rule["name"])
        latest_log_id = max(latest_log_id, log["id"])
    _update_last_run_id(rule_id, latest_log_id)

def run_proxy_malware_url_access(rule_id: int, log_type: str, **kwargs):
    print(f"[INFO] Running Proxy Malware URL Access Detection | Rule ID: {rule_id}")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get condition list from the detection_rules table
    cursor.execute("SELECT condition FROM detection_rules WHERE id = ?", (rule_id,))
    row = cursor.fetchone()

    if not row or not row["condition"]:
        print(f"[WARNING] Rule {rule_id} is missing a condition. Skipping.")
        return

    patterns = [p.strip() for p in row["condition"].split(",") if p.strip()]
    if not patterns:
        print(f"[WARNING] Rule {rule_id} has an empty condition list. Skipping.")
        return

    # Build WHERE clause dynamically
    like_clause = " OR ".join(["url LIKE ?"] * len(patterns))
    conditions = f"type = ? AND ({like_clause})"
    params = (log_type,) + tuple(f"%{p}%" for p in patterns)

    # Fetch matching logs
    rule, logs, conn = _fetch_rule_and_logs(rule_id, None, conditions, params)
    if not rule or not logs:
        return

    latest_log_id = 0
    for log in logs:
        alert_message = f"Proxy access to known malicious URL detected: {log['url']} from IP {log['src_ip']}"
        create_alert(
            rule_id=rule_id, severity="Critical", message=alert_message,
            source_id=log["source_id"], log_id=log["id"], ip=log["src_ip"],
            host=log["host"], source=log["source"], log_level=log["log_level"],
            rule_type=rule["rule_type"], rule_name=rule["name"]
        )
        latest_log_id = max(latest_log_id, log["id"])

    _update_last_run_id(rule_id, latest_log_id)
