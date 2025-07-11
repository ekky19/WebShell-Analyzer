# keyword_utils.py

import json

def load_keyword_config(path="modules/keyword_manager/keyword_config.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def extract_keyword_groups(config_data, server_type):
    server_data = config_data.get(server_type, {})
    keyword_groups = {}
    for category, info in server_data.items():
        keyword_groups[category] = info.get("keywords", [])
    return keyword_groups
