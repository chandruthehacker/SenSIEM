from functools import partial
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import sqlite3
from backend.utils.database.database_operations import get_db_connection
scheduler = BackgroundScheduler()

# --- Detection Imports ---
from backend.detections.detections import (
    # Existing Functions
    run_brute_force_detection,
    run_success_after_fail_detection,
    run_account_brute_force_detection,
    run_suspicious_process_detection,
    run_odd_hour_login_detection,
    run_account_spray_detection,
    run_access_denied_flood_detection,

    # Syslog
    run_syslog_unauthorized_access,
    run_syslog_privilege_escalation,
    run_syslog_service_restart_flood,

    # Apache / Nginx Logs
    run_web_app_attack,
    run_high_404_detection,

    # Windows Event Logs
    run_windows_failed_login,
    run_windows_audit_log_cleared,

    # Firewall Logs
    run_firewall_port_scan_detection,

    # IDS/IPS Logs
    run_ids_exploit_detection,

    # VPN Logs
    run_vpn_unusual_login_hours,

    # Cloud Logs
    run_cloud_iam_changes,

    # DNS Logs
    run_dns_tunneling_detection,

    # Antivirus Logs
    run_antivirus_detection,

    # Zeek Logs
    run_zeek_suspicious_user_agent,

    # Email Logs
    run_email_phishing_detection,

    # Web Application Firewall (WAF) Logs
    run_waf_sqli_xss_detection,

    # Database Logs
    run_db_unauthorized_access,

    # Proxy Logs
    run_proxy_malware_url_access,
)

DETECTION_FUNCTIONS = {
    # Existing Detections
    "Brute-force": run_brute_force_detection,
    "Success-after-fail": run_success_after_fail_detection,
    "Account Brute-force": run_account_brute_force_detection,
    "Suspicious Process": run_suspicious_process_detection,
    "Odd Hour Login": run_odd_hour_login_detection,
    "Account Spray": run_account_spray_detection,
    "Access Denied Flood": run_access_denied_flood_detection,

    # New Detections
    "Syslog Unauthorized Access": run_syslog_unauthorized_access,
    "Syslog Privilege Escalation": run_syslog_privilege_escalation,
    "Syslog Service Restart Flood": run_syslog_service_restart_flood,
    "Web Application Attack": run_web_app_attack,
    "High 404 Detection": run_high_404_detection,
    "Windows Failed Login Brute Force": run_windows_failed_login,
    "Windows Audit Log Cleared": run_windows_audit_log_cleared,
    "Firewall Port Scan Detection": run_firewall_port_scan_detection,
    "IDS/IPS Exploit Detection": run_ids_exploit_detection,
    "VPN Unusual Login Hours": run_vpn_unusual_login_hours,
    "Cloud IAM Changes": run_cloud_iam_changes,
    "DNS Tunneling Detection": run_dns_tunneling_detection,
    "Antivirus Threat Detection": run_antivirus_detection,
    "Zeek Suspicious User Agent": run_zeek_suspicious_user_agent,
    "Email Phishing Detection": run_email_phishing_detection,
    "WAF Blocked SQLi/XSS": run_waf_sqli_xss_detection,
    "Database Unauthorized Access": run_db_unauthorized_access,
    "Proxy Malware URL Access": run_proxy_malware_url_access,
}

# --- Execute Detection for a Rule (Only If Active) ---
def _run_detection(rule_row):
    rule_type = rule_row["rule_type"]

    if not rule_row["active"]:
        print(f"[SKIPPED] Rule {rule_row['id']} is inactive.")
        return

    if rule_type not in DETECTION_FUNCTIONS:
        print(f"[SKIPPED] Unknown rule type: {rule_type}")
        return

    try:
        time_window = rule_row["time_window"] or 1
        threshold = rule_row["threshold"] or 1

        DETECTION_FUNCTIONS[rule_type](
            rule_id=rule_row["id"],
            log_type=rule_row["log_type"],
            time_window_minutes=time_window,
            threshold=threshold,
        )
    except Exception as e:
        print(f"[ERROR] While executing rule ID {rule_row['id']}: {e}")

# --- Schedule One Rule ---
def update_single_rule_schedule(rule_id: int):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM detection_rules WHERE id = ?", (rule_id,))
        rule = cursor.fetchone()

        if not rule:
            print(f"[ERROR] Rule ID {rule_id} not found.")
            return

        job_id = f"rule_{rule_id}"
        scheduler.remove_job(job_id) if scheduler.get_job(job_id) else None

        if rule["active"]:
            interval = rule["interval_minutes"] or 5
            scheduler.add_job(
                func=partial(_run_detection, rule),
                trigger=IntervalTrigger(seconds=10),
                id=job_id,
                replace_existing=True,
            )
            print(f"[SCHEDULER] Scheduled Rule {rule_id} ({rule['rule_type']}) every {interval} minutes")
        else:
            print(f"[SCHEDULER] Rule {rule_id} is inactive. Not scheduled.")

    except Exception as e:
        print(f"[ERROR] Could not update schedule for Rule {rule_id}: {e}")
    finally:
        conn.close()

# --- Schedule All Active Rules ---
def start_rule_scheduler():
    print("[INFO] Starting rule scheduler")
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        existing_jobs = {job.id for job in scheduler.get_jobs()}
        cursor.execute("SELECT * FROM detection_rules")
        rules = cursor.fetchall()

        active_rules = [r for r in rules if r["active"]]
        scheduled_job_ids = set()

        for rule in active_rules:
            job_id = f"rule_{rule['id']}"
            interval = rule["interval_minutes"] or 5

            scheduler.add_job(
                func=partial(_run_detection, rule),
                trigger=IntervalTrigger(seconds=10),
                id=job_id,
                replace_existing=True,
            )
            scheduled_job_ids.add(job_id)
            print(f"[SCHEDULED] Rule {rule['id']} ({rule['rule_type']}) every {interval} minutes")

        # Cleanup unused jobs
        for job_id in existing_jobs - scheduled_job_ids:
            if job_id.startswith("rule_"):
                scheduler.remove_job(job_id)
                print(f"[REMOVED] Obsolete job: {job_id}")

        print(f"[DEBUG] Final scheduled jobs: {[job.id for job in scheduler.get_jobs()]}")

    except Exception as e:
        print(f"[ERROR] Failed to start scheduler: {e}")
    finally:
        conn.close()

# --- Run Scheduler ---
def start_scheduler_once():
    if not scheduler.running:
        scheduler.start()
        print("[INFO] APScheduler started.")
