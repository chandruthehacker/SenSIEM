import re
from datetime import datetime, timedelta, timezone
import json

from backend.utils.database.database_operations import add_log_source_to_db, add_parsed_log_to_db, get_db_connection

def _default_parsed_log_dict(log: str, log_type: str, file_path: str, source_id: int):
    return {
        "timestamp": None,
        "log_level": None,
        "source": None,
        "host": None,
        "process": None,
        "message": log.strip() if log else None,
        "raw_log": log,
        "type": log_type,
        "file_path": file_path,
        "source_id": source_id,
        "event_id": None,
        "username": None,
        "status_code": None,
        "url": None,
        "method": None,
        "protocol": None,
        "src_ip": None,
        "dest_ip": None,
        "src_port": None,
        "dest_port": None,
        "rule": None,
        "signature": None,
        "action": None,
        "user_agent": None,
        "device": None,
        "mail_subject": None,
        "file_hash": None,
        "tags": None,
    }

def _format_timestamp(dt_obj: datetime) -> str | None:
    if dt_obj:
        return dt_obj.strftime("%m/%d/%Y %I:%M:%S %p")
    return None


def parse_syslog(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
        r"(?:\s+(?P<year>\d{4}))?\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<process>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
    )
    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        current_year = datetime.now().year
        try:
            timestamp_str = f"{groups['month']} {groups['day']} {groups['time']} {current_year}"
            parsed_ts = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")

            if parsed_ts > datetime.now() + timedelta(days=1):
                timestamp_str = f"{groups['month']} {groups['day']} {groups['time']} {current_year - 1}"
                parsed_ts = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
            
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass

        parsed_data["source"] = groups.get("process")
        parsed_data["host"] = groups.get("host")
        parsed_data["process"] = groups.get("process")
        parsed_data["message"] = groups.get("message", "").strip()
    
    return parsed_data

def parse_apache(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r'^(?P<ip>\S+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<day>\d{2})\/(?P<month>\w{3})\/(?P<year>\d{4}):(?P<time>\d{2}:\d{2}:\d{2})\s[+-]\d{4}\]\s+'
        r'"(?P<method>\w+)\s(?P<url>[^"]+)\s(?P<protocol_version>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<size>\S+)'
        r'(?:\s+"(?P<referrer>[^"]*)")?'
        r'(?:\s+"(?P<user_agent>[^"]*)")?$'
    )
    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        try:
            timestamp_str = f"{groups['day']}/{groups['month']}/{groups['year']}:{groups['time']}"
            parsed_ts = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass
        
        parsed_data["host"] = groups.get("ip")
        parsed_data["src_ip"] = groups.get("ip")
        parsed_data["username"] = groups.get("user") if groups.get("user") != '-' else None
        parsed_data["method"] = groups.get("method")
        parsed_data["url"] = groups.get("url")
        parsed_data["protocol"] = groups.get("protocol_version")
        parsed_data["status_code"] = groups.get("status")
        parsed_data["user_agent"] = groups.get("user_agent")
        parsed_data["message"] = f"Accessed {parsed_data['url']} with status {parsed_data['status_code']}"
        parsed_data["log_level"] = "INFO" if parsed_data["status_code"] and parsed_data["status_code"].startswith('2') else "WARNING"
        if parsed_data["status_code"] and parsed_data["status_code"].startswith(('4','5')):
            parsed_data["log_level"] = "ERROR"

    return parsed_data

def parse_auth(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<process>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
    )
    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        current_year = datetime.now().year
        try:
            timestamp_str = f"{groups['month']} {groups['day']} {groups['time']} {current_year}"
            parsed_ts = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")

            if parsed_ts > datetime.now() + timedelta(days=1):
                timestamp_str = f"{groups['month']} {groups['day']} {groups['time']} {current_year - 1}"
                parsed_ts = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
            
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass

        parsed_data["host"] = groups.get("host")
        parsed_data["process"] = groups.get("process")
        parsed_data["message"] = groups.get("message", "").strip()

        message_lower = parsed_data["message"].lower()
        if "accepted password for" in message_lower or "session opened for user" in message_lower:
            parsed_data["log_level"] = "INFO"
            parsed_data["action"] = "LOGIN_SUCCESS"
            username_match = re.search(r'(?:for|user)\s+(?P<username>\S+)', message_lower)
            if username_match:
                parsed_data["username"] = username_match.group("username").strip()
            ip_match = re.search(r'from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message_lower)
            if ip_match:
                parsed_data["src_ip"] = ip_match.group("ip")
            if "port" in message_lower:
                port_match = re.search(r'port\s+(?P<port>\d+)', message_lower)
                if port_match:
                    parsed_data["src_port"] = port_match.group("port")
            parsed_data["tags"] = "auth,login_success"

        elif "failed password for" in message_lower or "invalid user" in message_lower:
            parsed_data["log_level"] = "WARNING" if "invalid user" in message_lower else "ERROR"
            parsed_data["action"] = "LOGIN_FAILURE"
            username_match = re.search(r'(?:for|user)\s+(?P<username>\S+)', message_lower)
            if username_match:
                parsed_data["username"] = username_match.group("username").strip()
            ip_match = re.search(r'from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message_lower)
            if ip_match:
                parsed_data["src_ip"] = ip_match.group("ip")
            parsed_data["tags"] = "auth,login_failure"

        elif "session closed for user" in message_lower:
            parsed_data["log_level"] = "INFO"
            parsed_data["action"] = "LOGOUT_SUCCESS"
            username_match = re.search(r'for user\s+(?P<username>\S+)', message_lower)
            if username_match:
                parsed_data["username"] = username_match.group("username").strip()
            parsed_data["tags"] = "auth,logout_success"
        
        if parsed_data["process"] == "sudo":
            parsed_data["tags"] = (parsed_data["tags"] + ",sudo") if parsed_data["tags"] else "sudo"
            
    return parsed_data

def parse_nginx(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r'^(?P<ip>\S+)\s+'
        r'\S+\s+'
        r'\S+\s+'
        r'\[(?P<day>\d{2})\/(?P<month>\w{3})\/(?P<year>\d{4}):(?P<time>\d{2}:\d{2}:\d{2})\s[+-]\d{4}\]\s+'
        r'"(?P<method>\w+)\s(?P<url>[^"]+)\s(?P<protocol_version>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<bytes_sent>\S+)\s+'
        r'"(?P<referrer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"$'
    )
    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        try:
            timestamp_str = f"{groups['day']}/{groups['month']}/{groups['year']}:{groups['time']}"
            parsed_ts = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass
        
        parsed_data["host"] = groups.get("ip")
        parsed_data["src_ip"] = groups.get("ip")
        parsed_data["method"] = groups.get("method")
        parsed_data["url"] = groups.get("url")
        parsed_data["protocol"] = groups.get("protocol_version")
        parsed_data["status_code"] = groups.get("status")
        parsed_data["user_agent"] = groups.get("user_agent")
        parsed_data["message"] = f"Accessed {parsed_data['url']} with status {parsed_data['status_code']}"
        parsed_data["log_level"] = "INFO" if parsed_data["status_code"] and parsed_data["status_code"].startswith('2') else "WARNING"
        if parsed_data["status_code"] and parsed_data["status_code"].startswith(('4','5')):
            parsed_data["log_level"] = "ERROR"

    return parsed_data

def parse_windows_event_log(log: str, log_type: str, file_path: str, source_id: int):
    # Pattern for "MM/DD/YYYY HH:MM:SS AM/PM SomeSource EventID Level Message"
    pattern = re.compile(
        r"^(?P<month>\d{1,2})\/(?P<day>\d{1,2})\/(?P<year>\d{4})\s+"
        r"(?P<time>\d{1,2}:\d{2}:\d{2}\s(?:AM|PM))\s+"
        r"(?P<source_name>[^\s]+)\s+"
        r"(?P<event_id>\d+)\s+"
        r"(?P<level_text>[^\s]+)\s+"
        r"(?P<message>.*)$"
    )
    # Pattern for "LogName: ... Date: YYYY-MM-DDTHH:MM:SS.sssZ ..."
    alt_pattern = re.compile(
        r'LogName:\s*(?P<log_name>\S+)\s+Source:\s*(?P<source_name>[\w-]+(?:-[\w-]+)*)\s+Date:\s*(?P<timestamp_iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+'
        r'EventID:\s*(?P<event_id>\d+)\s+TaskCategory:\s*(?P<task_category>\S+)\s+Level:\s*(?P<level_text>\S+)\s+Keywords:\s*(?P<keywords>\S+)\s+'
        r'User:\s*(?P<username>\S+)\s+Computer:\s*(?P<host>\S+)\s+Description:\s*(?P<message>.*)'
    )

    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        try:
            dt_str = f"{groups['month']}/{groups['day']}/{groups['year']} {groups['time']}"
            parsed_ts = datetime.strptime(dt_str, "%m/%d/%Y %I:%M:%S %p")
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass # Keep timestamp None if parsing fails (will try alt_pattern if this fails)

        if parsed_data["timestamp"] is not None: # Only assign if first pattern matched successfully
            parsed_data["source"] = groups.get("source_name")
            parsed_data["event_id"] = groups.get("event_id")
            parsed_data["message"] = groups.get("message", "").strip()
            
            level_text = groups.get("level_text", "").lower()
            if "error" in level_text or "failure" in level_text:
                 parsed_data["log_level"] = "ERROR"
            elif "warning" in level_text:
                 parsed_data["log_level"] = "WARNING"
            elif "success" in level_text or "information" in level_text:
                 parsed_data["log_level"] = "INFO"
            
            parsed_data["tags"] = "win_event"
    
    # If the first pattern didn't match or timestamp parsing failed for it, try the alternative
    if parsed_data["timestamp"] is None:
        alt_match = alt_pattern.match(log)
        if alt_match:
            alt_groups = alt_match.groupdict()
            try:
                parsed_ts = datetime.fromisoformat(alt_groups["timestamp_iso"].replace('Z', '+00:00'))
                parsed_data["timestamp"] = _format_timestamp(parsed_ts)
            except ValueError:
                pass
            parsed_data["source"] = alt_groups.get("source_name")
            parsed_data["host"] = alt_groups.get("host")
            parsed_data["event_id"] = alt_groups.get("event_id")
            parsed_data["username"] = alt_groups.get("username") if alt_groups.get("username") not in ('-', 'N/A') else None
            parsed_data["message"] = alt_groups.get("message", "").strip()
            parsed_data["log_level"] = alt_groups.get("level_text", "INFO").upper()
            parsed_data["tags"] = f"win_event,{alt_groups.get('log_name')},{alt_groups.get('task_category')}"

    return parsed_data

def parse_firewall(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<action>(?:ALLOW|DENY|DROP|ACCEPT|BLOCK))\s+"
        r"(?P<protocol>\S+)\s+"
        r"(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<src_port>\d+)\s+->\s+"
        r"(?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<dest_port>\d+)"
        r'(?:\s+RULE_ID=(?P<rule_id>\S+))?'
        r'(?:\s+(?P<extra_message>.*))?$'
    )
    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        current_year = datetime.now().year
        try:
            timestamp_str = f"{groups['month']} {groups['day']} {groups['time']} {current_year}"
            parsed_ts = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")

            if parsed_ts > datetime.now() + timedelta(days=1):
                timestamp_str = f"{groups['month']} {groups['day']} {groups['time']} {current_year - 1}"
                parsed_ts = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
            
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass

        parsed_data["host"] = groups.get("host")
        parsed_data["action"] = groups.get("action")
        parsed_data["protocol"] = groups.get("protocol")
        parsed_data["src_ip"] = groups.get("src_ip")
        parsed_data["dest_ip"] = groups.get("dest_ip")
        parsed_data["src_port"] = groups.get("src_port")
        parsed_data["dest_port"] = groups.get("dest_port")
        parsed_data["rule"] = groups.get("rule_id")
        parsed_data["message"] = f"{parsed_data['action']} {parsed_data['protocol']} {parsed_data['src_ip']}:{parsed_data['src_port']} -> {parsed_data['dest_ip']}:{parsed_data['dest_port']}"
        if parsed_data["rule"]:
            parsed_data["message"] += f" (Rule: {parsed_data['rule']})"
        if groups.get('extra_message'):
            parsed_data["message"] += f" - {groups['extra_message'].strip()}"

        if parsed_data["action"] in ["DENY", "DROP", "BLOCK"]:
            parsed_data["log_level"] = "WARNING"
        else:
            parsed_data["log_level"] = "INFO"

        parsed_data["tags"] = f"firewall,{parsed_data['action'].lower()},{parsed_data['protocol'].lower()}"

    return parsed_data

def parse_ids_ips(log: str, log_type: str, file_path: str, source_id: int):
    pattern1 = re.compile(
        r"^(?P<timestamp>\d{2}\/\d{2}\/\d{4}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
        r'\[\*\*\]\s+(?P<alert_type>\S+)\s+(?P<protocol>\S+)\s+\[\*\*\]\s+'
        r'(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<src_port>\d+)\s+->\s+'
        r'(?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<dest_port>\d+)\s+'
        r'(?:\(msg="(?P<message_content>[^"]+)"\))?.*$'
    )
    
    pattern2 = re.compile(
        r'^\[\*\*\]\s+\[(?P<generator_id>\d+):(?P<signature_id>\d+):(?P<signature_rev>\d+)\]\s+'
        r'(?P<signature_name>[^\[]+?)\s+'
        r'(?:\[Classification:\s(?P<classification>[^\]]+)\]\s+)?'
        r'(?:\[Priority:\s(?P<priority>\d+)\]\s+)?'
        r'\{(?P<protocol>\S+)\}\s+'
        r'(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<src_port>\d+)\s+->\s+'
        r'(?P<dest_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<dest_port>\d+)'
        r'(?:\s+\(msg="(?P<message_content>[^"]+)"\))?.*$'
    )

    match1 = pattern1.match(log)
    match2 = pattern2.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match1:
        groups = match1.groupdict()
        try:
            parsed_ts = datetime.strptime(groups["timestamp"], "%m/%d/%Y-%H:%M:%S.%f")
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass

        parsed_data["log_level"] = "ALERT"
        parsed_data["protocol"] = groups.get("protocol")
        parsed_data["src_ip"] = groups.get("src_ip")
        parsed_data["dest_ip"] = groups.get("dest_ip")
        parsed_data["src_port"] = groups.get("src_port")
        parsed_data["dest_port"] = groups.get("dest_port")
        parsed_data["message"] = groups.get("message_content", "").strip() or f"IDS/IPS Alert: {groups.get('alert_type')}"
        parsed_data["action"] = "ALERT"
        parsed_data["tags"] = f"ids_ips,alert,{groups.get('alert_type', '').lower()}"

    elif match2:
        groups = match2.groupdict()
        parsed_data["timestamp"] = _format_timestamp(datetime.now()) # Fallback to current time for logs without explicit timestamp
        parsed_data["signature"] = f"{groups.get('signature_id')}:{groups.get('signature_rev')} - {groups.get('signature_name', '').strip()}"
        parsed_data["action"] = "ALERT"
        parsed_data["protocol"] = groups.get("protocol")
        parsed_data["src_ip"] = groups.get("src_ip")
        parsed_data["dest_ip"] = groups.get("dest_ip")
        parsed_data["src_port"] = groups.get("src_port")
        parsed_data["dest_port"] = groups.get("dest_port")
        parsed_data["message"] = groups.get("message_content", "").strip() or groups.get("signature_name", "").strip()
        if groups.get("classification"):
            parsed_data["message"] += f" (Classification: {groups['classification']})"

        priority = int(groups.get("priority", 3))
        if priority <= 1:
            parsed_data["log_level"] = "CRITICAL"
        elif priority == 2:
            parsed_data["log_level"] = "ERROR"
        else:
            parsed_data["log_level"] = "WARNING"

        parsed_data["tags"] = f"ids_ips,alert,{groups.get('classification', '').lower().replace(' ', '_')}"
    
    return parsed_data

def parse_vpn(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<year>\d{4})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<process>[a-zA-Z0-9_\-\.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
    )
    alt_pattern = re.compile(
        r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<year>\d{4})\s+"
        r"(?P<host>\S+)\s*(?P<message>.*)$"
    )

    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
    else:
        match = alt_pattern.match(log)
        if match:
            groups = match.groupdict()
        else:
            return parsed_data

    if match:
        try:
            timestamp_str = f"{groups['month']} {groups['day']} {groups['time']} {groups['year']}"
            parsed_ts = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass

        parsed_data["host"] = groups.get("host")
        parsed_data["process"] = groups.get("process")
        parsed_data["message"] = groups.get("message", "").strip()

        message_lower = parsed_data["message"].lower()
        if "connected from" in message_lower or "established between" in message_lower or "authenticated" in message_lower:
            parsed_data["log_level"] = "INFO"
            parsed_data["action"] = "VPN_CONNECT"
            ip_match = re.search(r'(?:from|between|client\/)?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(?P<port>\d+))?', message_lower)
            if ip_match:
                parsed_data["src_ip"] = ip_match.group("ip")
                if ip_match.group("port"): parsed_data["src_port"] = ip_match.group("port")
            user_match = re.search(r'ike_sa\s+(?P<user>\S+)\[\d+\]', message_lower)
            if user_match: parsed_data["username"] = user_match.group("user")
            
            parsed_data["tags"] = "vpn,connect"

        elif "disconnected" in message_lower or "closed" in message_lower:
            parsed_data["log_level"] = "INFO"
            parsed_data["action"] = "VPN_DISCONNECT"
            parsed_data["tags"] = "vpn,disconnect"

        elif "auth failed" in message_lower or "authentication failed" in message_lower:
            parsed_data["log_level"] = "WARNING"
            parsed_data["action"] = "VPN_AUTH_FAIL"
            parsed_data["tags"] = "vpn,auth_fail"

    return parsed_data

def parse_cloud(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r"^(?P<timestamp_iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+"
        r"(?P<level>\S+)\s+"
        r"(?:User\s+(?P<username>\S+)\s+)?"
        r"(?:Action\s+(?P<action>\S+)\s+)?"
        r"(?:Resource:\s*(?P<resource>\S+)\s*)?"
        r"(?:Region:\s*(?P<region>\S+)\s*)?"
        r"(?P<message>.*)?$"
    )
    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        try:
            parsed_ts = datetime.fromisoformat(groups["timestamp_iso"].replace('Z', '+00:00'))
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass

        parsed_data["log_level"] = groups.get("level", "INFO").upper()
        parsed_data["username"] = groups.get("username")
        parsed_data["action"] = groups.get("action")
        
        extracted_message = groups.get("message", "").strip()
        if extracted_message:
            s3_delete_match = re.search(r"deleted S3 bucket '(?P<bucket_name>[^']+)' from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", extracted_message)
            if s3_delete_match:
                parsed_data["message"] = f"User {parsed_data['username'] or 'N/A'} deleted S3 bucket '{s3_delete_match.group('bucket_name')}' from {s3_delete_match.group('ip')}"
                parsed_data["src_ip"] = s3_delete_match.group('ip')
            else:
                parsed_data["message"] = extracted_message
        else:
             msg_parts = []
             if groups.get("action"): msg_parts.append(f"Action: {groups['action']}")
             if groups.get("username"): msg_parts.append(f"User: {groups['username']}")
             if groups.get("resource"): msg_parts.append(f"Resource: {groups['resource']}")
             parsed_data["message"] = " ".join(msg_parts) if msg_parts else log.strip()


        parsed_data["tags"] = "cloud"
        if parsed_data["action"]:
            parsed_data["tags"] = (parsed_data["tags"] + f",{parsed_data['action'].lower()}")

    return parsed_data

def parse_json_log(log: str, log_type: str, file_path: str, source_id: int):
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)
    try:
        log_json = json.loads(log)

        timestamp_keys = ["timestamp", "time", "@timestamp"]
        parsed_ts_obj = None
        for key in timestamp_keys:
            if key in log_json and isinstance(log_json[key], str):
                try:
                    parsed_ts_obj = datetime.fromisoformat(log_json[key].replace('Z', '+00:00'))
                    break
                except ValueError:
                    pass
            elif key in log_json and isinstance(log_json[key], (int, float)):
                try:
                    parsed_ts_obj = datetime.fromtimestamp(log_json[key])
                    break
                except ValueError:
                    pass
        parsed_data["timestamp"] = _format_timestamp(parsed_ts_obj)

        parsed_data["log_level"] = log_json.get("level", log_json.get("severity", "INFO")).upper()
        parsed_data["message"] = log_json.get("message", log_json.get("msg", log_json.get("text", log.strip()))).strip()
        parsed_data["host"] = log_json.get("host", log_json.get("hostname"))
        parsed_data["source"] = log_json.get("source", log_json.get("app_name", log_json.get("service_name")))
        parsed_data["process"] = log_json.get("process", log_json.get("prog"))
        parsed_data["username"] = log_json.get("user", log_json.get("username"))
        parsed_data["action"] = log_json.get("action")
        parsed_data["src_ip"] = log_json.get("src_ip", log_json.get("client_ip"))
        parsed_data["dest_ip"] = log_json.get("dest_ip", log_json.get("server_ip"))
        parsed_data["url"] = log_json.get("url", log_json.get("request_url"))
        parsed_data["method"] = log_json.get("method", log_json.get("request_method"))
        parsed_data["status_code"] = str(log_json.get("status", log_json.get("status_code"))) if log_json.get("status") else None
        parsed_data["user_agent"] = log_json.get("user_agent")
        parsed_data["protocol"] = log_json.get("protocol")
        parsed_data["file_hash"] = log_json.get("file_hash")
        parsed_data["mail_subject"] = log_json.get("mail_subject")
        
        if isinstance(log_json.get("tags"), list):
            parsed_data["tags"] = ",".join(log_json["tags"])
        elif isinstance(log_json.get("tags"), str):
            parsed_data["tags"] = log_json["tags"]
        
    except json.JSONDecodeError:
        parsed_data["log_level"] = "ERROR"
        parsed_data["message"] = f"JSON parsing failed: {log.strip()}"
        parsed_data["tags"] = "json_parse_error"
    except Exception as e:
        parsed_data["log_level"] = "ERROR"
        parsed_data["message"] = f"Error during JSON log processing: {e} - {log.strip()}"
        parsed_data["tags"] = "json_process_error"
        
    return parsed_data

def parse_dns(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r"^(?P<day>\d{1,2})-(?P<month>\w{3})-(?P<year>\d{4})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:#(?P<src_port>\d+))?\s+"
        r"(?:\((?P<query_domain>\S+)\))?:\s+"
        r"(?P<action>(?:query|response)):?\s+"
        r"(?P<domain>\S+)\s+"
        r"(?P<query_type>\S+)"
        r"(?:\s+(?P<response_ip_or_flags>.*))?$"
    )
    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        try:
            timestamp_str = f"{groups['day']}-{groups['month']}-{groups['year']} {groups['time']}"
            if '.' in groups['time']:
                parsed_ts = datetime.strptime(timestamp_str, "%d-%b-%Y %H:%M:%S.%f")
            else:
                parsed_ts = datetime.strptime(timestamp_str, "%d-%b-%Y %H:%M:%S")
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass
        
        parsed_data["host"] = groups.get("host")
        parsed_data["src_ip"] = groups.get("src_ip")
        parsed_data["src_port"] = groups.get("src_port")
        parsed_data["action"] = groups.get("action").upper()
        parsed_data["protocol"] = "DNS"
        
        dns_query_domain = groups.get('query_domain') or groups.get('domain')
        dns_query_type = groups.get('query_type')

        parsed_data["message"] = f"DNS {parsed_data['action']}: {dns_query_domain} {dns_query_type}"
        
        response_part = groups.get("response_ip_or_flags", "").strip()
        if response_part and not response_part.startswith('+'):
            parsed_data["dest_ip"] = response_part.split(' ')[0]
            parsed_data["message"] += f" -> {parsed_data['dest_ip']}"
        
        parsed_data["log_level"] = "INFO"
        parsed_data["tags"] = f"dns,{parsed_data['action'].lower()}"

    return parsed_data

def parse_antivirus(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s+"
        r"(?P<level>\S+)\s+"
        r"(?:Threat detected:\s*)?(?P<threat_name>\S+)\s+"
        r"path=(?P<file_path_detected>\S+)\s+"
        r"action=(?P<action_av>\S+)"
        r"(?:\s+user=(?P<username>\S+))?"
        r"(?P<message_rest>.*)?$"
    )
    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        try:
            parsed_ts = datetime.strptime(groups["timestamp"], "%Y-%m-%d %H:%M:%S")
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass

        parsed_data["log_level"] = groups.get("level", "INFO").upper()
        parsed_data["action"] = groups.get("action_av", "").replace('_', ' ').title()
        parsed_data["username"] = groups.get("username")
        
        parsed_data["message"] = f"Threat '{groups['threat_name']}' detected in {groups['file_path_detected']}. Action: {parsed_data['action']}"
        parsed_data["signature"] = groups.get("threat_name")
        parsed_data["file_hash"] = None
        parsed_data["device"] = None

        if "DETECTED" in parsed_data["action"].upper() or "BLOCKED" in parsed_data["action"].upper():
            parsed_data["log_level"] = "CRITICAL"
            parsed_data["tags"] = "antivirus,threat_detected"
        else:
            parsed_data["log_level"] = "INFO"
            parsed_data["tags"] = "antivirus,scan"

    return parsed_data

def parse_zeek(log: str, log_type: str, file_path: str, source_id: int):
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    try:
        fields = log.strip().split('\t')
        
        if len(fields) < 20:
            raise ValueError("Not enough fields for a typical Zeek conn.log entry.")

        parsed_ts = datetime.fromtimestamp(float(fields[0]))
        parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        parsed_data["src_ip"] = fields[2]
        parsed_data["src_port"] = fields[3]
        parsed_data["dest_ip"] = fields[4]
        parsed_data["dest_port"] = fields[5]
        parsed_data["protocol"] = fields[6]
        
        service = fields[7] if len(fields) > 7 and fields[7] != '-' else None
        conn_state = fields[10] if len(fields) > 10 and fields[10] != '-' else None
        
        parsed_data["message"] = (
            f"Connection from {parsed_data['src_ip']}:{parsed_data['src_port']} "
            f"to {parsed_data['dest_ip']}:{parsed_data['dest_port']} via {parsed_data['protocol']}"
        )
        if service:
            parsed_data["message"] += f" (Service: {service})"
        if conn_state:
            parsed_data["message"] += f" State: {conn_state}"

        if conn_state in ['S0', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'RSTH']:
            parsed_data["log_level"] = "WARNING"
            parsed_data["tags"] = "zeek,connection_issue"
        else:
            parsed_data["log_level"] = "INFO"
            parsed_data["tags"] = "zeek,connection"
        
        if service:
            parsed_data["tags"] = (parsed_data["tags"] + f",{service}") if parsed_data["tags"] else service

    except (ValueError, IndexError) as e:
        parsed_data["log_level"] = "ERROR"
        parsed_data["message"] = f"Zeek conn.log parsing failed: {e} - {log.strip()}"
        parsed_data["tags"] = "zeek_parse_error"

    return parsed_data

def parse_email(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<process>[a-zA-Z0-9_\-\./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<queue_id>\S+):\s*"
        r"(?P<message>.*)$"
    )
    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        current_year = datetime.now().year
        try:
            timestamp_str = f"{groups['month']} {groups['day']} {groups['time']} {current_year}"
            parsed_ts = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")

            if parsed_ts > datetime.now() + timedelta(days=1):
                timestamp_str = f"{groups['month']} {groups['day']} {groups['time']} {current_year - 1}"
                parsed_ts = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
            
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass

        parsed_data["host"] = groups.get("host")
        parsed_data["process"] = groups.get("process")
        extracted_message = groups.get("message", "").strip()
        parsed_data["message"] = extracted_message

        msg_lower = extracted_message.lower()

        sender_match = re.search(r'from=<\s*(?P<sender>[^>]+)>', msg_lower)
        if sender_match: parsed_data["username"] = sender_match.group("sender")
        recipient_match = re.search(r'to=<\s*(?P<recipient>[^>]+)>', msg_lower)
        if recipient_match: parsed_data["dest_ip"] = recipient_match.group("recipient")

        if "status=sent" in msg_lower:
            parsed_data["action"] = "EMAIL_SENT"
            parsed_data["log_level"] = "INFO"
            status_code_match = re.search(r'status=sent\s+\((?P<status_code>\d{3})\s', msg_lower)
            if status_code_match: parsed_data["status_code"] = status_code_match.group("status_code")
            parsed_data["tags"] = "email,sent"
        elif "status=bounced" in msg_lower or "undeliverable" in msg_lower:
            parsed_data["action"] = "EMAIL_BOUNCE"
            parsed_data["log_level"] = "WARNING"
            parsed_data["tags"] = "email,bounce"
        elif "reject" in msg_lower:
            parsed_data["action"] = "EMAIL_REJECT"
            parsed_data["log_level"] = "ERROR"
            parsed_data["tags"] = "email,reject"
        else:
            parsed_data["action"] = "EMAIL_EVENT"
            parsed_data["log_level"] = "INFO"

        subject_match = re.search(r'subject=[\'"]?(?P<subject>[^\'"]+)[\'"]?', msg_lower)
        if subject_match:
            parsed_data["mail_subject"] = subject_match.group("subject").strip()
        
    return parsed_data

def parse_waf(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r'^\[(?P<day>\d{2})/(?P<month>\w{3})/(?P<year>\d{4}):(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s(?P<tz_offset>[+-]\d{4})\]\s'
        r'(?:\[client\s(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s)?'
        r'ModSecurity:\s(?P<log_level_raw>\w+)\.?\s(?P<main_message>.*?)\s*'
        r'(?:\[file\s"(?P<file>[^"]+)"\]\s)?'
        r'(?:\[line\s"(?P<line>\d+)"\]\s)?'
        r'(?:\[id\s"(?P<rule_id>\d+)"\]\s)?'
        r'(?:\[msg\s"(?P<msg>[^"]+)"\]\s)?'
        r'(?:\[data\s"(?P<data>[^"]+)"\]\s)?'
        r'(?:\[tag\s"(?P<tag>[^"]+)"\]\s)?'
        r'(?:\[hostname\s"(?P<hostname>[^"]+)"\]\s)?'
        r'(?:\[uri\s"(?P<uri>[^"]+)"\])?.*$'
    )

    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()

        # --- Timestamp Parsing ---
        try:
            date_time_str = (
                f"{groups['day']}/{groups['month']}/{groups['year']}:"
                f"{groups['hour']}:{groups['minute']}:{groups['second']}"
            )
            # CORRECTED LINE: Use datetime.datetime.strptime
            parsed_ts = datetime.datetime.strptime(date_time_str, "%d/%b/%Y:%H:%M:%S")
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except (ValueError, TypeError):
            parsed_data["log_level"] = 'ERROR'
            parsed_data["message"] = f"WAF: Timestamp parsing failed for: {log}"
            # CORRECTED LINE: Use datetime.datetime.now()
            parsed_data["timestamp"] = _format_timestamp(datetime.datetime.now())
            parsed_data["tags"].append('timestamp_parse_error')


        # --- Log Level ---
        log_level_raw = groups.get("log_level_raw", "INFO").upper()
        if log_level_raw == "WARNING":
            parsed_data["log_level"] = "WARNING"
        elif log_level_raw in ['ALERT', 'CRITICAL', 'ERROR', 'NOTICE', 'INFO', 'DEBUG']:
            parsed_data["log_level"] = log_level_raw
        else:
            parsed_data["log_level"] = "INFO"

        # --- Basic Fields ---
        parsed_data["host"] = groups.get("hostname")
        parsed_data["url"] = groups.get("uri")
        parsed_data["rule"] = groups.get("rule_id")
        parsed_data["event_id"] = groups.get("rule_id")
        parsed_data["src_ip"] = groups.get("src_ip")

        # --- Message Extraction ---
        message_content = (groups.get("msg") or groups.get("main_message") or "").strip()
        if message_content:
            parsed_data["message"] = message_content
        else:
            parsed_data["message"] = "WAF event detected (message unparsed, check raw_log)."
            parsed_data["tags"].append('message_parse_error')

        # --- Action Determination ---
        message_lower = parsed_data["message"].lower()
        if "blocked" in message_lower or "deny" in message_lower or "denied" in message_lower:
            parsed_data["action"] = "BLOCK"
        elif "detected" in message_lower or "warning" in message_lower or "alert" in message_lower:
            parsed_data["action"] = "DETECT"
        else:
            parsed_data["action"] = "UNKNOWN"

        # --- Signature ---
        if groups.get("msg"):
            parsed_data["signature"] = groups["msg"].strip()
        elif "xss" in message_lower:
            parsed_data["signature"] = "Cross-Site Scripting (XSS) Attack"
        elif "sql injection" in message_lower or "sqli" in message_lower:
            parsed_data["signature"] = "SQL Injection Attempt"
        elif "lfi" in message_lower:
            parsed_data["signature"] = "Local File Inclusion"
        elif "rfi" in message_lower:
            parsed_data["signature"] = "Remote File Inclusion"
        else:
            parsed_data["signature"] = parsed_data["message"]

        # --- Tags ---
        if isinstance(parsed_data["tags"], str):
             parsed_data["tags"] = [parsed_data["tags"]]

        if groups.get('tag'):
            for t_part in groups['tag'].lower().split('/'):
                cleaned_tag = t_part.replace('_', '')
                if cleaned_tag and cleaned_tag not in parsed_data["tags"]:
                    parsed_data["tags"].append(cleaned_tag)

        if parsed_data["action"] != "UNKNOWN" and parsed_data["action"].lower() not in parsed_data["tags"]:
            parsed_data["tags"].append(parsed_data["action"].lower())

        if "xss" in message_lower and "xss" not in parsed_data["tags"]:
            parsed_data["tags"].append("xss")
        if ("sql" in message_lower or "injection" in message_lower) and "sqli" not in parsed_data["tags"]:
            parsed_data["tags"].append("sqli")
        if "malware" in message_lower and "malware" not in parsed_data["tags"]:
            parsed_data["tags"].append("malware")

    else:
        parsed_data["log_level"] = 'ERROR'
        parsed_data["message"] = f"Failed to parse WAF log with defined pattern: {log}"
        parsed_data["tags"].append('parse_failure')
        # CORRECTED LINE: Use datetime.datetime.now()
        parsed_data["timestamp"] = _format_timestamp(datetime.datetime.now())

    return parsed_data

def parse_database(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<timezone>\S+)\s+"
        r"(?:\[(?P<pid>\d+)\])?\s*"
        r"(?:(?P<username>\S+)@(?P<dbname>\S+)\s+)?"
        r"(?P<level>\S+):\s*"
        r"(?:duration:\s*(?P<duration>\d+(?:\.\d+)?)\s*ms\s+)?(?:statement:\s*)?"
        r"(?P<message>.*)$"
    )
    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        try:
            ts_str = groups["timestamp"]
            if '.' in ts_str:
                parsed_ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
            else:
                parsed_ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass
        
        parsed_data["log_level"] = groups.get("level", "INFO").upper()
        parsed_data["username"] = groups.get("username")
        parsed_data["process"] = "database"
        parsed_data["message"] = groups.get("message", "").strip()
        
        if "statement:" in log and parsed_data["message"].startswith("statement:"):
            parsed_data["message"] = parsed_data["message"].replace("statement:", "", 1).strip()
            parsed_data["action"] = "DB_QUERY"
            parsed_data["tags"] = "database,query"
        elif "error:" in log.lower() or parsed_data["log_level"] == "ERROR":
            parsed_data["action"] = "DB_ERROR"
            parsed_data["tags"] = "database,error"
        
        if groups.get("duration"):
            parsed_data["message"] = f"Duration: {groups['duration']}ms - {parsed_data['message']}"

    return parsed_data

def parse_proxy(log: str, log_type: str, file_path: str, source_id: int):
    pattern = re.compile(
        r"^(?P<timestamp>\d+\.\d+)\s+"
        r"(?P<duration>\d+)\s+"
        r"(?P<src_ip>\S+)\s+"
        r"(?P<action_status>\S+)\/(?P<status_code>\d{3})\s+"
        r"(?P<bytes>\d+)\s+"
        r"(?P<method>\S+)\s+"
        r"(?P<url>\S+)\s+"
        r"\S+\s+"
        r"(?P<destination_host>\S+)\s+"
        r"(?P<content_type>\S+)$"
    )
    match = pattern.match(log)
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)

    if match:
        groups = match.groupdict()
        try:
            parsed_ts = datetime.fromtimestamp(float(groups["timestamp"]))
            parsed_data["timestamp"] = _format_timestamp(parsed_ts)
        except ValueError:
            pass
        
        parsed_data["src_ip"] = groups.get("src_ip")
        parsed_data["action"] = groups.get("action_status").split('/')[0]
        parsed_data["status_code"] = groups.get("status_code")
        parsed_data["method"] = groups.get("method")
        parsed_data["url"] = groups.get("url")
        parsed_data["host"] = groups.get("destination_host")
        parsed_data["protocol"] = parsed_data["url"].split("://")[0].upper() if parsed_data["url"] and "://" in parsed_data["url"] else "HTTP"

        parsed_data["message"] = f"Proxy {parsed_data['action']}/{parsed_data['status_code']}: {parsed_data['method']} {parsed_data['url']}"
        parsed_data["log_level"] = "INFO" if parsed_data["status_code"] and parsed_data["status_code"].startswith('2') else "WARNING"
        if parsed_data["status_code"] and parsed_data["status_code"].startswith(('4','5')):
            parsed_data["log_level"] = "ERROR"

        parsed_data["tags"] = f"proxy,{parsed_data['action'].lower()},{parsed_data['status_code']}"
        if groups.get("duration"): parsed_data["duration_ms"] = int(groups["duration"]) # Assuming these are added back to schema
        if groups.get("bytes"): parsed_data["bytes_transferred"] = int(groups["bytes"]) # Assuming these are added back to schema

    return parsed_data

def parse_invalid_log(log: str, log_type: str, file_path: str, source_id: int):
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)
    parsed_data["log_level"] = "UNKNOWN"
    parsed_data["message"] = f"Unparsed or invalid log format: {log.strip()}"
    parsed_data["timestamp"] = _format_timestamp(datetime.now())
    parsed_data["tags"] = "unparsed"
    return parsed_data

def parse_unsupported_log_type(log: str, log_type: str, file_path: str, source_id: int):
    parsed_data = _default_parsed_log_dict(log, log_type, file_path, source_id)
    parsed_data["log_level"] = "UNSUPPORTED"
    parsed_data["message"] = f"Log type '{log_type}' is currently unsupported: {log.strip()}"
    parsed_data["timestamp"] = _format_timestamp(datetime.now())
    parsed_data["tags"] = "unsupported_type"
    return parsed_data


LOG_TYPE_DISPATCH = {
    "syslog": parse_syslog,
    "apache": parse_apache,
    "auth": parse_auth,
    "nginx": parse_nginx,
    "win_evt": parse_windows_event_log,
    "firewall": parse_firewall,
    "ids_ips": parse_ids_ips,
    "vpn": parse_vpn,
    "cloud": parse_cloud,
    "dns": parse_dns,
    "antivirus": parse_antivirus,
    "zeek": parse_zeek,
    "email": parse_email,
    "waf": parse_waf,
    "database": parse_database,
    "proxy": parse_proxy,
    "json": parse_json_log,
}


def parser(payloads):
    for payload in payloads:
        try:
            log_type = payload.get("type")
            log_line = payload.get("log")
            source = payload.get("source")
            source_id = payload.get("source_id")

            if not log_type or not log_line:
                continue

            parser_func = LOG_TYPE_DISPATCH.get(log_type.lower())
            if parser_func:
                parsed = parser_func(log_line, log_type, source, source_id)
                if parsed:
                    add_parsed_log_to_db(parsed)
            else:
                print(f"[WARNING] Unsupported log type: {log_type} for log: {log_line[:100]}...")
        except Exception as e:
            print(f"[ERROR] Failed to process payload: {e} for payload: {payload}")

def ingest_logs(log_text: str, log_type: str, source_path: str):
    logs = log_text.strip().splitlines()
    payloads = []

    # Ensure log source exists in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM log_sources WHERE path=? AND log_type=?", (source_path, log_type))
    result = cursor.fetchone()
    conn.close()

    if not result:
        add_log_source_to_db(source_path, log_type)

    # Get source_id after ensuring it exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM log_sources WHERE path=? AND log_type=?", (source_path, log_type))
    source_id_result = cursor.fetchone()
    conn.close()

    source_id = source_id_result[0] if source_id_result else None

    for line in logs:
        if not line.strip():
            continue
        payloads.append({
            "source": source_path,
            "log": line.strip(),
            "type": log_type,
            "source_id": source_id
        })

    for payload in payloads:
        try:
            parser_func = LOG_TYPE_DISPATCH.get(payload["type"].lower())
            if parser_func:
                parsed = parser_func(payload["log"], payload["type"], payload["source"], payload["source_id"])
                if parsed:
                    add_parsed_log_to_db(parsed)
            else:
                print(f"[WARNING] Unsupported log type: {payload['type']}")
        except Exception as e:
            print(f"[ERROR] Failed to process log: {e} | Log line: {payload.get('log')}")
