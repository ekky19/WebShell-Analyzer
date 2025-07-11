import re
import os
import csv
import urllib.parse
from datetime import datetime, timedelta
from modules.shared import load_ioc_events
from modules.keyword_manager.keyword_utils import load_keyword_config
from modules.logger_helper import get_logger
from urllib.parse import unquote, urlparse

logger = get_logger()

def extract_filename_from_uri(uri):
    # Strip any HTML tags if accidentally passed in
    clean_uri = re.sub(r"<[^>]+>", "", uri)
    #logger.debug(f"[FilenameExtract] Cleaned URI (HTML removed): {clean_uri}")

    # Decode and strip query string
    decoded = urllib.parse.unquote(clean_uri).split("?", 1)[0]
    #logger.debug(f"[FilenameExtract] Decoded and stripped URI: {decoded}")

    # Extract filename
    filename = os.path.basename(decoded)
    logger.debug(f"[FilenameExtract] Extracted filename: {filename}")
    return filename




def get_mft_settings(server_type):
    config = load_keyword_config("modules/keyword_manager/keyword_config.json")
    settings = config.get(server_type, {}).get("mft_settings", {})
    extensions = settings.get("web_extensions", [".php", ".asp", ".aspx", ".jsp"])
    window_seconds = settings.get("time_window_seconds", 500)
    return extensions, timedelta(seconds=window_seconds)

def parse_mft_csv(file_path, server_type="iis"):
    logger.info(f"Parsing MFT file: {file_path}")
    web_extensions, _ = get_mft_settings(server_type)
    logger.debug(f"web_extensions for MFT checking: {web_extensions}")
    results = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = (line.replace("\x00", "") for line in f)
        reader = csv.DictReader(lines)
        for row in reader:
            parent = row.get("ParentPath", "").strip().replace("\\", "/")
            name = row.get("FileName", "").strip()
            ext = row.get("Extension", "").strip().lstrip(".").lower()

            # Build full_path carefully (avoid trailing dot if no ext)
            if ext:
                full_path = f"{parent}/{name}.{ext}".lower()
            else:
                full_path = f"{parent}/{name}".lower()

            logger.debug(f"Appending correlated entry with full_path: '{full_path}'")

            # Normalize extensions to lowercase and check exact extension match
            # web_extensions assumed to have dot, e.g. ['.php', '.asp']
            if ext and f".{ext}" in [e.lower() for e in web_extensions]:
                created_0x10 = parse_mft_time(row.get("Created0x10"))
                results.append({
                    "full_path": full_path,
                    "created_0x10": created_0x10,
                    "flags": [],
                    "entry_number": row.get("EntryNumber"),
                    "source_file": os.path.basename(file_path),
                    # Optionally keep parts for correlation use
                    "ParentPath": parent,
                    "FileName": name,
                    "Extension": ext
                })
                logger.debug(f"Added MFT entry: {full_path} created at {created_0x10}")
    return results

def correlate_with_logs(mft_entries, ioc_events, server_type="iis", log_filename=""):
    _, time_window = get_mft_settings(server_type)
    seen = set()
    correlated = []

    logger.info(f"Starting correlation using {len(mft_entries)} MFT entries and {len(ioc_events)} log events")

    for mft in mft_entries:
        mft_time = mft.get("created_0x10")

        # Use full_path if available, else reconstruct for safety
        full_path = mft.get("full_path")
        if not full_path:
            parent_path = mft.get("ParentPath", "")
            file_name = mft.get("FileName", "")
            extension = mft.get("Extension", "")
            full_path = os.path.normpath(f"{parent_path}\\{file_name}.{extension}").lower()
            mft["full_path"] = full_path  # Update for logging

        for log in ioc_events:
            uri_raw = log.get("uri", "").strip()
            if not uri_raw:
                continue

            log_time = log.get("timestamp_obj")
            if not log_time or not mft_time:
                logger.warning(
                    f"Missing timestamp → log_time: {log_time}, mft_time: {mft_time}, "
                    f"log_source: {log.get('log_file')}, uri: {log.get('uri')}, MFT file: {full_path}"
                )
                continue

            uri_cleaned = re.sub(r"<.*?>", "", uri_raw).lower()
            uri_filename = extract_filename_from_uri(uri_raw).lower()

            logger.debug(f"Checking URI: {uri_cleaned}")
            logger.debug(f"Extracted filename: {uri_filename}")
            logger.debug(f"Against MFT path: {full_path}")

            match_types = []

            try:
                diff = abs((mft_time - log_time).total_seconds())
                logger.debug(f"Time diff: {diff}s → log_time: {log_time}, mft_time: {mft_time}")
                if diff <= time_window.total_seconds():
                    match_types.append("TIME")
            except Exception as e:
                logger.error(f"Time comparison failed: {e}")

            # Use exact filename equality instead of 'in' substring check
            if uri_filename and uri_filename == os.path.basename(full_path):
                match_types.append("FILENAME")
                logger.debug(f"Potential filename match — URI filename: {uri_filename}, MFT file basename: {os.path.basename(full_path)}")

            if match_types:
                match_key = (full_path, uri_filename, log.get("src_ip"))
                if match_key in seen:
                    continue
                seen.add(match_key)

                logger.info(
                    f"Match found! MFT file: {full_path}, IP: {log.get('src_ip')}, Match type: {match_types}"
                )

                correlated.append({
                    "matched_file": full_path,
                    "entry_number": mft.get("entry_number"),
                    "created_0x10": mft_time.strftime("%Y-%m-%d %H:%M:%S") if mft_time else None,
                    "flags": log.get("flags"),
                    "src_ip": log.get("src_ip"),
                    "username": log.get("username"),
                    "log_source": log.get("log_file", log_filename).split("\\")[-1].split("/")[-1],
                    "correlation": " and ".join(match_types)
                })

    print(f"[*] Correlated {len(correlated)} MFT entries.")
    logger.info(f"Correlated {len(correlated)} MFT entries.")
    return correlated

def parse_mft_time(ts):
    if not ts:
        return None
    try:
        # Add more timestamp formats if needed
        for fmt in ("%d/%m/%Y %H:%M", "%d/%m/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(ts.strip(), fmt)
            except Exception:
                continue
        logger.warning(f"Failed to parse created_0x10 timestamp with known formats: {ts}")
    except Exception as e:
        logger.warning(f"Failed to parse created_0x10 timestamp: {ts}, error: {e}")
    return None

