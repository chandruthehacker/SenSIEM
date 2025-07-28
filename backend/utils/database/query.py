import asyncio
from collections import Counter
from datetime import datetime, timedelta
import ipaddress
import sqlite3
from typing import Dict, List

from fastapi import requests
import httpx
from backend.utils.database.database_operations import get_db_connection

LOG_LEVEL_COLORS = {
    "INFO": "#22c55e",      # Tailwind green-600
    "WARNING" or "WARNING": "#f59e0b",   # Tailwind amber-500
    "ERROR": "#ef4444",     # Tailwind red-600
    "CRITICAL": "#7c3aed",  # Tailwind violet-600
    "ALERT": "#f97316",     # Tailwind orange-500
}

def get_logs_from_db():
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM parsed_logs
        WHERE timestamp IS NOT NULL AND TRIM(timestamp) != ''
        ORDER BY datetime(timestamp) DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_filtered_logs(kv: dict, msgs: list):
    con = get_db_connection()
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    base_query = "SELECT * FROM parsed_logs WHERE 1=1"
    params = []

    # Key-value filters (exact match)
    for key, val in kv.items():
        if key in [
            "host", "process", "source", "log_level", "type",
            "src_ip", "dest_ip", "src_port", "dest_port", "username"
        ]:
            base_query += f" AND {key} = ?"
            params.append(val)

    # Free-text search (OR conditions)
    if msgs:
        or_clauses = []
        for term in msgs:
            term = term.strip('"').strip("'")  # Clean term
            like_term = f"%{term}%"
            or_clauses.append("(message LIKE ? OR raw_log LIKE ? OR tags LIKE ?)")
            params.extend([like_term, like_term, like_term])

        if or_clauses:
            base_query += " AND (" + " OR ".join(or_clauses) + ")"

    # 🔥 Order by real timestamp, descending
    base_query += " ORDER BY datetime(timestamp) DESC"

    cur.execute(base_query, params)
    rows = cur.fetchall()
    logs = [dict(row) for row in rows]

    con.close()
    return logs


def getLogLevelDistribution():
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT log_level, COUNT(*) as count
        FROM parsed_logs
        GROUP BY log_level
    """

    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    result = []
    for level, count in rows:
        level_str = level if level else "UNKNOWN"
        result.append({
            "name": level_str,
            "value": count,
            "color": LOG_LEVEL_COLORS.get(level_str, "#6b7280")
        })
    return result

def get_count(cursor, query, params):
    cursor.execute(query, params)
    return cursor.fetchone()[0] or 0

def getDashBoardmetrics():
    now = datetime.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    today_end = now

    # Format timestamps as SQL-compatible strings
    today_start_str = today_start.strftime("%Y-%m-%d %H:%M:%S")
    today_end_str = today_end.strftime("%Y-%m-%d %H:%M:%S")
    yesterday_start_str = yesterday_start.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Logs
    today_logs = get_count(cursor,
        "SELECT COUNT(*) FROM parsed_logs WHERE timestamp BETWEEN ? AND ?",
        (today_start_str, today_end_str)
    )
    yesterday_logs = get_count(cursor,
        "SELECT COUNT(*) FROM parsed_logs WHERE timestamp BETWEEN ? AND ?",
        (yesterday_start_str, today_start_str)
    )

    # Alerts
    today_alerts = get_count(cursor,
        "SELECT COUNT(*) FROM parsed_logs WHERE alert = 1 AND timestamp BETWEEN ? AND ?",
        (today_start_str, today_end_str)
    )
    yesterday_alerts = get_count(cursor,
        "SELECT COUNT(*) FROM parsed_logs WHERE alert = 1 AND timestamp BETWEEN ? AND ?",
        (yesterday_start_str, today_start_str)
    )

    # Errors
    today_errors = get_count(cursor,
        "SELECT COUNT(*) FROM parsed_logs WHERE log_level = 'ERROR' AND timestamp BETWEEN ? AND ?",
        (today_start_str, today_end_str)
    )
    yesterday_errors = get_count(cursor,
        "SELECT COUNT(*) FROM parsed_logs WHERE log_level = 'ERROR' AND timestamp BETWEEN ? AND ?",
        (yesterday_start_str, today_start_str)
    )

    today_error_rate = (today_errors / today_logs) * 100 if today_logs else 0
    yesterday_error_rate = (yesterday_errors / yesterday_logs) * 100 if yesterday_logs else 0

    # Sources
    cursor.execute(
        "SELECT COUNT(DISTINCT source) FROM parsed_logs WHERE timestamp BETWEEN ? AND ?",
        (today_start_str, today_end_str)
    )
    today_sources = cursor.fetchone()[0] or 0

    cursor.execute(
        "SELECT COUNT(DISTINCT source) FROM parsed_logs WHERE timestamp BETWEEN ? AND ?",
        (yesterday_start_str, today_start_str)
    )
    yesterday_sources = cursor.fetchone()[0] or 0

    conn.close()

    # Change % and trend
    def get_change_and_trend(today, yesterday):
        diff = today - yesterday
        if yesterday == 0:
            return ("+∞%", "up") if today > 0 else ("0%", "stable")
        percent = round((diff / yesterday) * 100, 1)
        trend = "up" if percent > 0 else "down" if percent < 0 else "stable"
        sign = "+" if percent > 0 else ""
        return (f"{sign}{percent}%", trend)

    return {
        "total_logs_today": today_logs,
        "total_logs_yesterday": yesterday_logs,
        "total_logs_change": get_change_and_trend(today_logs, yesterday_logs),

        "active_alerts": today_alerts,
        "alerts_change": get_change_and_trend(today_alerts, yesterday_alerts),

        "error_rate": round(today_error_rate, 1),
        "error_rate_change": get_change_and_trend(today_error_rate, yesterday_error_rate),

        "sources_active": today_sources,
        "sources_change": get_change_and_trend(today_sources, yesterday_sources),
    }

def calculate_severity(count):
    if count >= 10:
        return "high"
    elif count >= 5:
        return "medium"
    return "low"

def getTopAlerts():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT log_sources.name
        FROM parsed_logs
        JOIN log_sources ON parsed_logs.source_id = log_sources.id
        WHERE parsed_logs.log_level IN ('ERROR', 'CRITICAL', 'ALERT')
    """)
    sources = [row[0] for row in cursor.fetchall()]
    conn.close()

    source_count = Counter(sources)
    top_alerts = sorted(source_count.items(), key=lambda x: x[1], reverse=True)[:5]

    return [
        {"source": source, "count": count, "severity": calculate_severity(count)}
        for source, count in top_alerts
    ]

def get_top_ips_from_db(limit=10):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all potential IPs from host, src_ip, dest_ip
    cursor.execute("""
        SELECT host, src_ip, dest_ip 
        FROM parsed_logs 
        WHERE 
            (host IS NOT NULL AND TRIM(host) != '') OR 
            (src_ip IS NOT NULL AND TRIM(src_ip) != '') OR 
            (dest_ip IS NOT NULL AND TRIM(dest_ip) != '')
    """)
    
    rows = cursor.fetchall()
    conn.close()

    ip_counter = Counter()

    for host, src_ip, dest_ip in rows:
        for ip in (host, src_ip, dest_ip):
            if ip:
                ip = ip.strip()
                try:
                    ipaddress.ip_address(ip)  # Validate IP
                    ip_counter[ip] += 1
                except ValueError:
                    continue

    # Get the most common IPs by count
    top_ips = ip_counter.most_common(limit)

    return [{"ip": ip, "count": count} for ip, count in top_ips]

async def get_country_from_ip(ip: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(f"https://ipapi.co/{ip}/country_name/")
            if response.status_code == 200:
                return response.text.strip()
    except Exception:
        pass
    return "Unknown"

async def getGeoSuspiciousIPs():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT host, src_ip, dest_ip 
        FROM parsed_logs 
        WHERE log_level IN ('CRITICAL', 'ALERT', 'WARNING') AND (
            (host IS NOT NULL AND host != '') OR 
            (src_ip IS NOT NULL AND src_ip != '') OR 
            (dest_ip IS NOT NULL AND dest_ip != '')
        )
    """)

    rows = cursor.fetchall()
    conn.close()

    ip_counter = Counter()

    for host, src_ip, dest_ip in rows:
        for ip in (host, src_ip, dest_ip):
            if ip:
                ip = ip.strip()
                try:
                    ipaddress.ip_address(ip)  # Validate IP
                    ip_counter[ip] += 1
                except ValueError:
                    continue

    top_ips = ip_counter.most_common(5)

    # Parallel async country fetch
    countries = await asyncio.gather(*(get_country_from_ip(ip) for ip, _ in top_ips))

    result = []
    for (ip, count), country in zip(top_ips, countries):
        result.append({
            "ip": ip,
            "count": count,
            "country": country
        })
    return result

def getTimeSeries():
    conn = get_db_connection()
    cursor = conn.cursor()

    now = datetime.now()
    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)

    interval_hours = [0, 4, 8, 12, 16, 20]
    time_labels = [f"{str(h).zfill(2)}:00" for h in interval_hours]
    time_buckets = {label: {"logs": 0, "alerts": 0} for label in time_labels}

    for i in range(len(interval_hours)):
        start = start_of_day + timedelta(hours=interval_hours[i])
        end = (
            start_of_day + timedelta(hours=interval_hours[i + 1])
            if i + 1 < len(interval_hours)
            else now.replace(hour=23, minute=59, second=59)
        )
        label = f"{str(interval_hours[i]).zfill(2)}:00"

        # Format datetime to match DB timestamp format
        start_str = start.strftime("%Y-%m-%d %H:%M:%S")
        end_str = end.strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            SELECT COUNT(*) FROM parsed_logs
            WHERE timestamp BETWEEN ? AND ?
        """, (start_str, end_str))
        log_count = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*) FROM parsed_logs
            WHERE timestamp BETWEEN ? AND ? AND log_level IN ('ERROR', 'CRITICAL', 'ALERT')
        """, (start_str, end_str))
        alert_count = cursor.fetchone()[0]

        time_buckets[label]["logs"] = log_count
        time_buckets[label]["alerts"] = alert_count

    conn.close()

    result = [
        {"time": label, "logs": time_buckets[label]["logs"], "alerts": time_buckets[label]["alerts"]}
        for label in time_labels
    ]
    return result

def getNoisySource(limit: int = 5):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT type, COUNT(*) as count
        FROM parsed_logs
        WHERE type IS NOT NULL AND type != ''
        GROUP BY type
        ORDER BY count DESC
        LIMIT ?
        """,
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()
    
    return [{"source": row[0], "count": row[1]} for row in rows]

def getSystemErrors():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT timestamp, message, type
        FROM parsed_logs
        WHERE log_level IN ('ERROR', 'CRITICAL', 'ALERT')
        ORDER BY timestamp DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
            "timestamp": row[0],
            "error": row[1],
            "source": row[2] if row[2] else "Unknown"
        })

    return results

def getAlerts():
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Fetch only rows where alert is explicitly '1' and log_level is 'ALERT'
    cursor.execute("""
        SELECT 
            id,
            log_level,
            message AS description,
            timestamp,
            type,
            CASE 
                WHEN log_level IN ('CRITICAL', 'ERROR', 'ALERT') THEN 'high'
                WHEN log_level = 'WARNING' THEN 'medium'
                ELSE 'low'
            END AS severity,
            'active' AS status
        FROM parsed_logs
        WHERE TRIM(alert) = '1' AND log_level = 'ALERT'
        ORDER BY datetime(timestamp) DESC
        LIMIT 50;
    """)

    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return alerts


