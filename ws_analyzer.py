import json 
import os
import re
import argparse
import logging
from datetime import datetime
from colorama import Fore, Style
from jinja2 import Template
from jinja2 import Environment, FileSystemLoader
from tabulate import tabulate
from modules.iis_parser import parse_iis_logs
from modules.apache_parser import parse_apache_logs
from modules.nginx_parser import parse_nginx_logs
from modules.mft_analyzer import parse_mft_csv, correlate_with_logs
from modules.shared import load_ioc_events
from modules.logger_helper import get_logger

logger = get_logger()

REPORT_DIR = "reports"

def get_template_path(server_type):
    if server_type == "apache":
        template_path = os.path.join("template", "IOC_Report_apache.html")
    elif server_type == "nginx":
        template_path = os.path.join("template", "IOC_Report_nginx.html")
    elif server_type == "iis":
        template_path = os.path.join("template", "IOC_Report_iis.html")
    else:
        template_path = os.path.join("template", "IOC_Report.html")  # fallback

    logger.debug(f"Selected template path for '{server_type}': {template_path}")
    return template_path


def get_args():
    parser = argparse.ArgumentParser(description="WebShell Analyzer")
    parser.add_argument('--type', choices=['iis', 'apache', 'nginx', 'yara'], required=True,
                        help='Specify the web server type to analyze')
    args = parser.parse_args()
    #logger.debug(f"Selected server type: {args.type}")
    return args


def generate_reports(ioc_records, mft_hits, template_path):
    logger.info("Generating summary and HTML reports...")
    os.makedirs(REPORT_DIR, exist_ok=True)
    

    
    # Save summary as .txt
    with open(os.path.join(REPORT_DIR, "summary.txt"), "w") as f:
        logger.debug("Writing summary.txt report...")
        f.write(tabulate(
            [
                (
                    rec["timestamp"],
                    rec["username"],
                    rec["src_ip"],
                    rec["uri"],
                    rec["http_method"],
                    rec["log_file"]
                )
                for rec in ioc_records
            ],
            headers=["Timestamp", "Username", "IP Address", "URI", "HTTP Method", "Log File"]
        ))
    
    

    # Load HTML template
    with open(template_path, "r", encoding="utf-8") as tpl:
        template = Template(tpl.read())

    # Render HTML with both IOC and MFT data
    logger.debug(f"Loading and rendering HTML template: {template_path}")
    html_output = template.render(records=ioc_records, mft_hits=mft_hits, show_flags_first=True)

    # Write final HTML report
    with open(os.path.join(REPORT_DIR, "IOC_Report.html"), "w", encoding="utf-8") as f:
        logger.debug("Writing final IOC_Report.html...")
        f.write(html_output)
        

def main():
    print(Fore.CYAN + "[*] Starting WebShell Analyzer..." + Style.RESET_ALL)
    logger.info("WebShell Analyzer started.")
    args = get_args()
    server_type = args.type
    logger.debug(f"Server type selected: {server_type}")
    template_path = get_template_path(server_type)


    if server_type == "iis":
        ioc_records = parse_iis_logs("input/iis/access")
    elif server_type == "apache":
        ioc_records = parse_apache_logs("input/apache")
    elif server_type == "nginx":
        ioc_records = parse_nginx_logs("input/nginx")
    else:
        print("[!] Unsupported web server type selected.")
        return
        
    print(f"[?] Total IOCs detected in logs: {len(ioc_records)}")    

    os.makedirs(REPORT_DIR, exist_ok=True)
    
    for rec in ioc_records:
        try:
            rec["timestamp_obj"] = datetime.strptime(rec["timestamp"], "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            logger.warning(f"Failed to convert timestamp for log entry: {rec.get('timestamp')} → {e}")
            rec["timestamp_obj"] = None
            
    null_ts = sum(1 for rec in ioc_records if rec["timestamp_obj"] is None)
    logger.warning(f"{null_ts} log entries have invalid or missing timestamps.")
    
    if null_ts > 0:
        print(Fore.YELLOW + f"[!] {null_ts} log entries have invalid or missing timestamps." + Style.RESET_ALL)

    # Remove timestamp_obj before saving to JSON
    for rec in ioc_records:
        if "timestamp_obj" in rec:
            del rec["timestamp_obj"]


    # ✅ Save findings.json AFTER the loop
    with open(os.path.join(REPORT_DIR, "findings.json"), "w", encoding="utf-8") as f:
        json.dump(ioc_records, f, indent=2)


    print(Fore.YELLOW + f"[*] Found {len(ioc_records)} suspicious entries" + Style.RESET_ALL)
    logger.info(f"Parsed {len(ioc_records)} suspicious log entries.")
    print("[+] Saved findings.json for MFT correlation.")
    logger.debug("Saved findings.json to reports directory.")

    # === MFT Correlation ===
    mft_dir = "input/mft"
    if not os.path.exists(mft_dir) or not any(f.endswith(".csv") for f in os.listdir(mft_dir)):
        print(Fore.YELLOW + "[!] No MFT CSV files found. Skipping MFT correlation." + Style.RESET_ALL)
        logger.warning("No MFT CSV files found. Skipping MFT correlation.")
        mft_hits=[]
        generate_reports(ioc_records, mft_hits, template_path)
        return

    mft_files = [f for f in os.listdir(mft_dir) if f.endswith(".csv")]
    if len(mft_files) != 1:
        print(Fore.RED + f"[!] Expected 1 MFT file in '{mft_dir}', found {len(mft_files)}. Aborting." + Style.RESET_ALL)
        logger.error(f"Expected 1 MFT CSV file but found {len(mft_files)}. Aborting.")
        return

    mft_path = os.path.join(mft_dir, mft_files[0])
    mft_entries = parse_mft_csv(mft_path, server_type=server_type)
    logger.debug(f"Parsed {len(mft_entries)} MFT entries from {mft_path}")

    ioc_records = load_ioc_events(os.path.join(REPORT_DIR, "findings.json"))
    mft_matches = correlate_with_logs(mft_entries, ioc_records, server_type=server_type)
    logger.info(f"MFT correlation completed with {len(mft_matches)} hits.")

    if mft_matches:
        print(Fore.MAGENTA + f"[+] MFT Correlation Hits: {len(mft_matches)}" + Style.RESET_ALL)

    with open(os.path.join(REPORT_DIR, "mft_hits.json"), "w", encoding="utf-8") as f:
        json.dump(mft_matches, f, indent=2)
        logger.debug("Saved mft_hits.json to reports directory.")

    with open(os.path.join(REPORT_DIR, "mft_hits.json"), "r", encoding="utf-8") as f:
        mft_hits = json.load(f)

    generate_reports(ioc_records, mft_hits, template_path)

    print(Fore.GREEN + "[+] Reports generated in 'reports/' folder" + Style.RESET_ALL)
    logger.info("Report generation complete. Output in 'reports/' folder.")
    

if __name__ == "__main__":
    main()
