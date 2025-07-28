from io import StringIO
import ipaddress
import os
from backend.utils.log_finder import log_type_find



def is_valid_ip(ip: str) -> bool:
    if ip == "localhost":
        return True
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    
def is_valid_port(port: int) -> bool:
    return 1 <= port <= 65535

def is_valid_path(path: str) -> bool:

    if not os.path.exists(path):
        return False
    if not os.path.isfile(path):
        return False
    if not os.access(path, os.R_OK):
        return False
    
    return True

def is_log_content_valid(text: str) -> dict:

    f = StringIO(text)
    log_type = "unknown"

    for _ in range(50):
        line = f.readline()
        if not line:
            break
        result = log_type_find(line)
        if result != "unknown":
            log_type = result
            break
    if result=="unknown":
        return {"result": "error", "message": "Invalid log content", "type": log_type}
    
    return {"result": "success", "message": "Valid log content", "type": log_type}
