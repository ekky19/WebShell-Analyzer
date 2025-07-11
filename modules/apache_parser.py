import os
import re
import urllib.parse
import json
from collections import defaultdict
from modules.keyword_manager.keyword_utils import load_keyword_config, extract_keyword_groups
from datetime import datetime
from modules.logger_helper import get_logger
from modules.shared import parse_log_timestamp 

logger = get_logger()

# === 1. Set server type ===
SERVER_TYPE = "apache"

# === 2. Load JSON config ===
config_data = load_keyword_config("modules/keyword_manager/keyword_config.json")
KEYWORD_GROUPS = extract_keyword_groups(config_data, SERVER_TYPE)

# Updated:
LOG_DIR = os.path.join("input", "apache")


def highlight_keywords(text, keyword_list, highlight_class="mark"):
    decoded = urllib.parse.unquote_plus(text)
    for kw in keyword_list:
        try:
            pattern = re.compile(kw, re.IGNORECASE)
            decoded = pattern.sub(lambda m: f'<mark class="{highlight_class}">{m.group(0)}</mark>', decoded)
        except re.error:
            continue
    return decoded

def parse_apache_log_line(line):
    parts = re.match(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<uri>[^\s]+) \S+" (?P<status>\d{3}) (?P<size>\d+|-) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"',
        line
    )
    if not parts:
        logger.debug(f"[ApacheParser] Failed regex match → {line.strip()}")
        return None

    data = parts.groupdict()
    timestamp_raw = data["datetime"]  # e.g. '06/Jun/2025:06:12:45 +0000'
    timestamp_str = timestamp_raw.split()[0]  # strip timezone

    timestamp_obj = parse_log_timestamp(timestamp_str)
    if not timestamp_obj:
        logger.warning(f"[ApacheParser] Invalid timestamp: {timestamp_str} from log → {line.strip()}")

    return {
        "timestamp": timestamp_str,
        "timestamp_obj": timestamp_obj,
        "c_ip": data["ip"],
        "cs_method": data["method"],
        "uri": data["uri"],
        "status": data["status"],
        "size": data["size"],
        "referer": data["referer"],
        "user_agent": data["user_agent"],
        "raw": line.strip()
    }

def detect_iocs(entry, keyword_groups):
    iocs = set()
    decoded_line = urllib.parse.unquote_plus(entry["raw"])

    for category, patterns in keyword_groups.items():
        for pattern in patterns:
            try:
                if re.search(pattern, decoded_line, re.IGNORECASE):
                    iocs.add(category)
            except re.error:
                continue
    return list(iocs)

def parse_apache_logs(log_dir=LOG_DIR):
    ioc_records = []

    if not os.path.exists(log_dir):
        logger.warning(f"Apache log directory not found: {log_dir}")
        print(f"[!] Apache log directory not found: {log_dir}")
        return []

    log_files = [f for f in os.listdir(log_dir) if f.endswith(".log")]
    if not log_files:
        logger.info(f"No Apache log files found in: {log_dir}")
        print(f"[*] No Apache log files found in: {log_dir}")
        return []

    try:
        with open(os.path.join("c2 list", "known_c2.txt"), "r") as f:
            known_c2 = set(ip.strip() for ip in f if ip.strip())
        logger.debug(f"Loaded {len(known_c2)} known C2 IPs.")
    except FileNotFoundError:
        known_c2 = set()
        logger.warning("C2 list file not found. Continuing without known C2 highlighting.")

    all_keywords = sum(KEYWORD_GROUPS.values(), [])

    for filename in log_files:
        path = os.path.join(log_dir, filename)
        logger.info(f"Parsing Apache log file: {filename}")
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, 1):
                entry = parse_apache_log_line(line)
                if not entry:
                    logger.debug(f"Line {line_number} in {filename} could not be parsed.")
                    continue

                iocs = detect_iocs(entry, KEYWORD_GROUPS)
                if not iocs:
                    continue  # Only log entries with IOCs

                uri_disp = highlight_keywords(entry["uri"], all_keywords)
                user_agent_disp = highlight_keywords(entry["user_agent"], all_keywords)
                referer_disp = highlight_keywords(entry["referer"], all_keywords)

                src_ip = entry["c_ip"]
                if src_ip in known_c2:
                    logger.debug(f"Known C2 IP matched: {src_ip}")
                    src_ip = f'<mark class="c2">{src_ip}</mark>'

                ioc_record = {
                    "timestamp": entry["timestamp"],
                    "timestamp_obj": entry["timestamp_obj"],
                    "username": "-",
                    "src_ip": src_ip,
                    "query": "-",
                    "uri": uri_disp,
                    "log_file": filename,
                    "http_method": entry["cs_method"],
                    "user_agent": user_agent_disp,
                    "referer": referer_disp,
                    "flags": iocs
                }

                logger.debug(f"IOC detected in {filename} line {line_number}: {iocs}")
                ioc_records.append(ioc_record)

    logger.info(f"Total IOC records extracted: {len(ioc_records)}")
    return ioc_records
