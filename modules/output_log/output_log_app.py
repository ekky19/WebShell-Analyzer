import sys
import os

# 🧠 Set up correct template path for PyInstaller .exe and during development
if getattr(sys, 'frozen', False):
    base_dir = sys._MEIPASS
    sys.path.insert(0, os.path.join(base_dir, "modules"))
    template_path = os.path.join(base_dir, "templates")
else:
    base_dir = os.path.dirname(__file__)
    sys.path.insert(0, os.path.abspath(os.path.join(base_dir, "..")))
    template_path = os.path.join(base_dir, "templates")

from output_log.output_log_server import output_log_bp
from flask import Flask
import webbrowser

app = Flask(__name__, template_folder=template_path)
app.register_blueprint(output_log_bp)

if __name__ == "__main__":
    print("[+] Flask app is starting on http://127.0.0.1:5001")
    webbrowser.open("http://127.0.0.1:5001/output_log_viewer")
    app.run(debug=True, port=5001, use_reloader=False)
