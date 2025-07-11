# shared.py module
# unify IOC loading for all analyzers
# Automatically add correlated MFT hits to HTML report
# load_ioc_events() loads your findings.json (from any parser) , Automatically attaches timestamp_obj as a datetime for correlation


import os
import json
from datetime import datetime
from modules.logger_helper import get_logger

logger = get_logger()

# Attempts multiple formats for parsing log timestamps
def parse_log_timestamp(ts_str):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(ts_str, fmt)
            #logger.debug(f"[TimestampParse] Successfully parsed '{ts_str}' with format '{fmt}'")
            return parsed
        except Exception:
            continue
    logger.warning(f"[TimestampParse] Failed to parse timestamp: '{ts_str}' with all known formats")
    return None

# Loads and attaches timestamp_obj to each IOC record
def load_ioc_events(filepath="reports/findings.json"):
    if not os.path.exists(filepath):
        logger.warning(f"[load_ioc_events] File not found: {filepath}")
        return []

    with open(filepath, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except Exception as e:
            logger.error(f"[load_ioc_events] Failed to load JSON: {e}")
            return []

    valid_records = []
    for entry in data:
        ts = entry.get("timestamp")
        entry["timestamp_obj"] = parse_log_timestamp(ts) if ts else None

        if entry["timestamp_obj"]:
            valid_records.append(entry)
        else:
            logger.warning(f"[TimestampCheck] Invalid or missing timestamp → raw: {entry.get('timestamp')}, source: {filepath}")


    logger.info(f"[load_ioc_events] Loaded {len(valid_records)} valid IOC records from {filepath}")
    return valid_records
