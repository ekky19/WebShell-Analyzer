from flask import Flask, jsonify, request, send_from_directory
import json
import os
import sys
import webbrowser

# === Detect base path (bundled vs normal) ===
try:
    BASE_DIR = sys._MEIPASS
except AttributeError:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=BASE_DIR)

# === Set paths ===
CONFIG_FOLDER = os.path.join(os.getcwd(), "modules", "keyword_manager")
CONFIG_WRITABLE = os.path.join(CONFIG_FOLDER, "keyword_config.json")
CONFIG_DEFAULT = os.path.join(BASE_DIR, "keyword_config.json")
EDITOR_FILE = os.path.join(BASE_DIR, "keyword_editor.html")

# === Ensure config path exists ===
if not os.path.exists(CONFIG_FOLDER):
    os.makedirs(CONFIG_FOLDER)

# === If not present, copy bundled config to writable location ===
if not os.path.exists(CONFIG_WRITABLE):
    try:
        with open(CONFIG_DEFAULT, 'r', encoding='utf-8') as src, \
             open(CONFIG_WRITABLE, 'w', encoding='utf-8') as dst:
            dst.write(src.read())
        print("[+] Copied default config to modules/keyword_manager/keyword_config.json")
    except Exception as e:
        print(f"[!] Failed to copy config: {e}")

# === Choose config file path ===
def get_config_path():
    return CONFIG_WRITABLE

# === ROUTES ===

@app.route('/')
def serve_editor():
    return send_from_directory(BASE_DIR, 'keyword_editor.html')

@app.route('/api/config', methods=['GET'])
def load_config():
    try:
        with open(get_config_path(), 'r', encoding='utf-8') as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({"error": f"Failed to load config: {e}"}), 500

@app.route('/api/config', methods=['POST'])
def save_config():
    data = request.get_json()
    try:
        with open(CONFIG_WRITABLE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return jsonify({"status": "success", "message": "Configuration saved successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to save: {e}"}), 500

@app.route("/api/delete_category", methods=["POST"])
def delete_category():
    data = request.json
    server = data.get("server")
    category = data.get("category")

    try:
        with open(get_config_path(), 'r', encoding='utf-8') as f:
            config = json.load(f)

        if server in config and category in config[server]:
            del config[server][category]
            with open(CONFIG_WRITABLE, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            return jsonify({"status": "success", "message": f"✅ Category '{category}' deleted."})
        else:
            return jsonify({"status": "error", "message": "❌ Category not found."}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error: {e}"}), 500

# === LAUNCH ===

if __name__ == '__main__':
    print("[+] Keyword Editor is starting at http://127.0.0.1:5003")
    webbrowser.open("http://127.0.0.1:5003")
    app.run(debug=True, port=5003, use_reloader=False)
