import os
import re

patterns = {
        "windows_event": r"<Event[^>]*xmlns=\"http://schemas\.microsoft\.com/win/2004/08/events/event\">|"
                         r"(?:Log Name|LogName):\s+\S+.*?(?:Source|Provider Name):\s+\S+.*?(?:Event ID|EventID):\s+\d+",

        "ids_ips": r"\[\*\*\] \[(?:\d+:\d+:\d+|\s*GID:\d+\s*\]\s*\[SID:\d+\s*\])\s*\](?:\s+\S+)?\s*(?:ET\s+\S+\s+)?(?:POLICY|INFO|ATTACK|SCAN|INDICATOR|DETECTION|SUSPICIOUS)\b|\bSURICATA\s+STREAM_|\b(?:SNORT|SURICATA|ZEEK)\b(?:\s+\[\d+\])?:\s+(?:alert|drop|reject|pass)\s+.*"
                   r"|\b(?:malicious|exploit|injection|xss|sql)\b",

        "cloud": r"\"eventSource\":\s*\"[^\"]+\.amazonaws\.com\"|\"resource\":\s*\"projects/[^/]+/logs/[^\"]+\"|\"category\":\"[^\"]*Security\"|\"clientIPAddress\":|"
                 r"\"operationName\":\s*\"[^\"]+\"|\"logGroup\":\s*\"[^\"]+\"|\b(?:aws|azure|gcp)\b.*(?:cloudtrail|monitor|logging|activity|resource|event)\b",

        "firewall": r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+kernel:\s+\[UFW\s+AUDIT\](?=.*IN=\S+\s+OUT=\S+.*SRC=\d{1,3}(?:\.\d{1,3}){3}\s+DST=\d{1,3}(?:\.\d{1,3}){3}\s+.*PROTO=\w+).*|"
                    r"\b(IN|OUT)=(?:DROP|ACCEPT|REJECT)\s+.*?\s+SRC=\d{1,3}(?:\.\d{1,3}){3}\s+DST=\d{1,3}(?:\.\d{1,3}){3}\s+.*PROTO=\w+|"
                    r"\%ASA-\d-\d{6}:\s+Built\s+inbound\s+TCP\s+connection|\b(?:fwid|firewall)\b.*(?:blocked|dropped|accepted)\b",

        "vpn": r"\b(OpenVPN|strongSwan|IPsec|WireGuard)\b.*(?:connection|auth|peer|client|server)\b|"
               r"openvpn\[\d+\]:|ipsec\[\d+\]:|charon\[\d+\]:|wg-quick\[\d+\]:|\b(?:VPN|ikev2)\b.*(?:established|phase \d+)",

        "dns": r"\bnamed\[\d+\]:\s+client\s+\d{1,3}(?:\.\d{1,3}){3}(?:#\d+)?\s+\([^\)]+\):\s+query:\s+\S+\s+IN\s+(?:A|AAAA|PTR|MX|CNAME)\b|"
               r"\b(?:unbound|dnsmasq|pdns)\b.*(?:client|query|response)\b.*(?:from|to)\s+\d{1,3}(?:\.\d{1,3}){3}(?:#\d+)?|DNSSEC",

        "antivirus": r"\bWindows\s+Defender:\s+(?:Threat\s+detected|Real-time\s+protection\s+detected)\s+malware\b|"
                     r"\b(virus|malware|infected|detected|quarantined|scan|update|threat|trojan)\b.*\b(?:(?:ClamAV|McAfee|Symantec|Sophos|ESET|Kaspersky)|AV)\b",

        "apache": r'^\S+ \S+ \S+ \[(?:\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}|\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4}) \S+\] "\S+ \S+ HTTP/\d\.\d" \d{3} \d+ (?:(?:"[^"]*")|-) "(?:[^"]*)"(?: "[^"]*")?|'
                  r'^\[\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2}\.\d+ \d{4}\] \[[^\]]+\] \[client \S+\]',

        "nginx": r'^\S+ \S+ \S+ \[[^\]]+\] "\S+ \S+ HTTP/\d\.\d" \d{3} \d+ "[^"]*"(?: "|-)? "[^"]*"|'
                 r'^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[[^\]]+\] \d+#\d+: \*?\d+ ([^ ]+, )?client: \S+, server: \S+, request: "\S+ \S+ HTTP/\d\.\d", host: "\S+"(?:, referrer: "\S+")?, (?:upstream: "\S+", )?(?:response: "\S+", )?request_time: \S+,\s*(?:upstream_response_time: \S+, )?(?:bytes_sent: \d+, )?(?:status: \d+)',

        "auth": r"\b(sshd|sudo|CRON|USER|PAM|login|su|gdm|kdm)\b.*(session opened|authentication failure|invalid user|Accepted password for|Failed password for|disconnected from|new session)",
        
        "syslog": r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+(?:\[\d+\])?:\s+",
        
        "zeek": r"\bzeek\b|\bconn\.log\b|\bdns\.log\b|\bhttp\.log\b|\bssl\.log\b",
        
        "email": r"postfix/.*?:|smtpd:|status=bounced|status=sent|status=deferred|from=<[^>]+>",
        
        "waf": r"\bModSecurity\b.*(Warning|Alert|Access denied)|\bWAF\b.*(blocked|triggered)|\bRULE_ID\b",
        
        "database": r"(?:mysql|postgres|mongodb|sql)\b.*(connection|query|authentication|access denied|failed)",
        
        "proxy": r"\b(squid|http_proxy|proxy)\b.*(CONNECT|GET|POST|blocked|allowed|denied)"
    }



def log_type_find(content: str) -> str:
    def check_pattern(pattern_str: str) -> bool:
        return re.search(pattern_str, content, re.IGNORECASE | re.MULTILINE)

    for log_type, pattern in patterns.items():
        if check_pattern(pattern):
            return log_type

    return "unknown"

def specific_log_type_find(content: str, type: str) -> str:
    def check_pattern(pattern_str: str) -> bool:
        return re.search(pattern_str, content, re.IGNORECASE | re.MULTILINE)
    
    if check_pattern(patterns[type]):
        return type
    return "unknown"
     
def is_log_file(file_path: str) -> bool:
    if not isinstance(file_path, str):
        return False

    if not os.path.exists(file_path):
        return False
    if not os.path.isfile(file_path):
        return False
    if not os.access(file_path, os.R_OK):
        return False

    log_patterns = [
        re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+[\w\-/.]+(?:\[\d+\])?:"),
        re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\s+(INFO|DEBUG|ERROR|WARN|TRACE)"),
        re.compile(r'^\d{1,3}(?:\.\d{1,3}){3} - - \[\d{2}/[A-Za-z]+/\d{4}:'),
        re.compile(r'^\{.*?"timestamp"\s*:\s*".+?".*?"level"\s*:\s*".+?".*?\}'),
        re.compile(r'^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:,\d+)?\s+(INFO|DEBUG|ERROR|WARN|TRACE)')
    ]

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in range(50):
                line = f.readline()
                if not line:
                    break
                for pattern in log_patterns:
                    if pattern.match(line):
                        return True
        return False
    except Exception:
        return False

