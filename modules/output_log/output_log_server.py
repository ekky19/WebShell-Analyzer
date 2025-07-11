from flask import Blueprint, jsonify, request, render_template
import os
import sys

# Blueprint setup: template_folder points to your templates dir relative to this file
output_log_bp = Blueprint('output_logs', __name__, template_folder='templates')

# Prioritize external logs for live updates, fall back to bundled if missing
external_path = os.path.join(os.getcwd(), "reports", "output.log")

try:
    bundled_path = os.path.join(sys._MEIPASS, "reports", "output.log")
except AttributeError:
    bundled_path = None

if os.path.exists(external_path):
    LOG_FILE_PATH = external_path
elif bundled_path and os.path.exists(bundled_path):
    LOG_FILE_PATH = bundled_path
else:
    LOG_FILE_PATH = None  # File doesn't exist



LINES_PER_PAGE = 100000000

@output_log_bp.route('/output_logs')
def get_logs():
    
    if not os.path.exists(LOG_FILE_PATH):
        return jsonify({"error": "Log file not found"}), 404

    with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
        lines = f.readlines()

     # Strip trailing newlines for clean display
    lines = [line.rstrip('\n') for line in lines]

    return jsonify({
        "total_lines": len(lines),
        "output_logs": lines
    })


@output_log_bp.route('/output_log_viewer')
def log_viewer():
    # read log file
    if not os.path.exists(LOG_FILE_PATH):
        logs = []
    else:
        with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
            logs = [line.rstrip('\n') for line in f.readlines()]

    return render_template('output_log_report.jinja2', logs=logs, per_page=LINES_PER_PAGE)

