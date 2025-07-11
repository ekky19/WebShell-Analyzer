import os
import re
import urllib.parse
import json
from collections import defaultdict
from modules.keyword_manager.keyword_utils import load_keyword_config, extract_keyword_groups
from modules.logger_helper import get_logger

logger = get_logger()

# === 1. Set server type ===
SERVER_TYPE = "iis"  # or "nginx", "apache", etc.

# === 2. Load JSON config ===
config_data = load_keyword_config("modules/keyword_manager/keyword_config.json")
KEYWORD_GROUPS = extract_keyword_groups(config_data, SERVER_TYPE)

# === 3. Dynamic IOC detection using categories ===
def scan_log_entry(entry, keyword_groups):
    matches = []
    for category, patterns in keyword_groups.items():
        for pattern in patterns:
            try:
                if re.search(pattern, entry, re.IGNORECASE):
                    matches.append({"category": category, "pattern": pattern})
            except re.error:
                continue
    return matches

LOG_DIR = "IIS_LOGS"

def highlight_keywords(text, keyword_list, highlight_class="mark"):
    decoded = urllib.parse.unquote_plus(text)
    for kw in keyword_list:
        try:
            pattern = re.compile(kw, re.IGNORECASE)
            decoded = pattern.sub(lambda m: f'<mark class="{highlight_class}">{m.group(0)}</mark>', decoded)
        except re.error:
            continue
    return decoded

def parse_log_line(line):
    parts = line.strip().split()
    if len(parts) < 10 or not parts[0][0].isdigit():
        return None
    try:
        date, time, s_ip, cs_method, uri_stem, uri_query, s_port, cs_username, c_ip, user_agent, referer = parts[:11]
        return {
            "timestamp": f"{date} {time}",
            "s_ip": s_ip,
            "cs_method": cs_method,
            "uri_stem": uri_stem,
            "uri_query": uri_query,
            "s_port": s_port,
            "cs_username": cs_username,
            "c_ip": c_ip,
            "user_agent": user_agent,
            "referer": referer,
            "raw": line.strip()
        }
    except ValueError:
        return None

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

def parse_iis_logs(iis_log_dir):
    ioc_records = []

    if not os.path.exists(iis_log_dir):
        print(f"[!] IIS log directory not found: {iis_log_dir}")
        logger.error(f"IIS log directory not found: {iis_log_dir}")
        return []

    log_files = [f for f in os.listdir(iis_log_dir) if f.endswith(".log")]
    if not log_files:
        print(f"[*] No IIS log files found in: {iis_log_dir}")
        logger.warning(f"No IIS log files found in: {iis_log_dir}")
        return []

    try:
        with open(os.path.join("c2 list", "known_c2.txt"), "r") as f:
            known_c2 = set(ip.strip() for ip in f if ip.strip())
            logger.debug(f"Loaded {len(known_c2)} known C2 entries.")
    except FileNotFoundError:
        known_c2 = set()
        logger.warning("known_c2.txt not found. Continuing without C2 matching.")

    for filename in log_files:
        path = os.path.join(iis_log_dir, filename)
        skipped = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                entry = parse_log_line(line)
                if not entry:
                    skipped += 1
                    logger.debug(f"Skipping unparsable line in {filename}")
                    continue

                iocs = detect_iocs(entry, KEYWORD_GROUPS)
                if not iocs:
                    logger.debug(f"Detected IOCs {iocs} in {filename}: {entry['uri_stem']}?{entry['uri_query']}")
                    continue

                query_decoded = urllib.parse.unquote_plus(entry["uri_query"])
                uri_decoded = urllib.parse.unquote_plus(entry["uri_stem"])
                user_agent_decoded = urllib.parse.unquote_plus(entry["user_agent"])

                all_keywords = sum(KEYWORD_GROUPS.values(), [])

                query_disp = highlight_keywords(query_decoded, all_keywords)
                uri_disp = highlight_keywords(uri_decoded, all_keywords)
                user_agent_disp = highlight_keywords(user_agent_decoded, all_keywords)

                src_ip = entry["c_ip"]
                if src_ip in known_c2:
                    src_ip = f'<mark class="c2">{src_ip}</mark>'
                    logger.info(f"Known C2 IP detected: {entry['c_ip']} in {filename}")

                ioc_records.append({
                    "timestamp": entry["timestamp"],
                    "username": entry["cs_username"],
                    "src_ip": src_ip,
                    "query": query_disp,
                    "uri": uri_disp,
                    "log_file": filename,
                    "http_method": entry["cs_method"],
                    "user_agent": user_agent_disp,
                    "referer": entry["referer"],
                    "flags": iocs
                })
       # Log summary once per file
        file_ioc_count = len([rec for rec in ioc_records if rec["log_file"] == filename])
        logger.info(f"Parsed log file: {filename}")
        logger.info(f" → Extracted {file_ioc_count} IOCs")
        logger.debug(f" → Skipped lines: {skipped}")

    logger.info(f"Total IOC records extracted: {len(ioc_records)}")
    return ioc_records