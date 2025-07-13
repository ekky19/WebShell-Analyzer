# WebShell Analyzer

<img width="1915" height="1020" alt="webshell menu" src="https://github.com/user-attachments/assets/3da12f3d-0710-46f5-a028-b233f3a4c628" />



**WebShell Analyzer** is a cross-platform, offline forensic toolkit for SOC analysts, and IR teams. It detects and investigates webshells, suspicious commands, and C2 traffic by parsing web server logs (IIS, Apache, Nginx), correlating findings with MFT data, and scanning web roots with YARA rules — all with automated reporting.

Developed by:
https://www.linkedin.com/in/ekremozdemir19/

---

## ✨ Key Features

* **Multi-Server Log Analysis:**
  Detects webshell activity and suspicious access patterns in IIS, Apache, and Nginx logs.
* **YARA-Based Webshell Scanning:**
  Standalone YARA scanner for webroot files using customizable rule sets.

  <img width="1887" height="894" alt="yara report1" src="https://github.com/user-attachments/assets/7fb345da-7f03-4858-bbe5-0184ab0f01b7" />
  
* **File System Correlation:**
  Matches suspicious activity in logs with MFT file events (CSV format) for deeper investigation.
* **C2 Threat Intelligence:**
  Flags traffic to known C2 IPs/domains via an updatable local feed.
* **Keyword Manager GUI:**
  An interface for editing detection keywords, supporting categories and custom server types.

  <img width="1912" height="1022" alt="keyword_manager" src="https://github.com/user-attachments/assets/f88367aa-e343-460f-ae36-b035a72538f6" />
  
* **Automated Reporting:**
  Generates HTML reports with color-coded highlights, detailed IOC breakdown, and summary stats.

  <img width="1908" height="901" alt="webshell report1" src="https://github.com/user-attachments/assets/248e95a8-bb97-465a-86e1-d1056b1fbbf6" />

* **False Positive Reduction:**
  Regex boundaries, static resource whitelisting, and easy keyword/category tuning.
  
  <img width="1906" height="970" alt="output_log_viewer" src="https://github.com/user-attachments/assets/9dd61e7d-7a70-4538-be1f-21af1e66bfb9" />


---

## 🚀 Getting Started

1. **Place your input files:**

   * **Web server logs:**

     * IIS: `input/iis/`
     * Apache: `input/apache/`
     * Nginx: `input/nginx/`
   * **Webroot files (for YARA scan):** `input/webroot/`
   * **MFT CSV:** `input/mft/`

2. **Double-click or run `start_menu.py`** to open the main interface.

3. **(Optional) Edit keywords and categories:**

---

## 🛠️ Main Scripts

| File                        | Purpose                             |
| --------------------------- | ----------------------------------- |
| `start_menu.py`             | Main menu interface for all tasks   |
| `ws_analyzer.py`            | Webshell and log analyzer engine    |
| `run_webshell_analyzer.bat` | Launch log/MFT analysis             |
| `run_yara_scan.bat`         | Standalone YARA scanner for webroot |

---

## 📊 Reporting & Output

* **All output reports** are saved to the `reports/` folder.
* **HTML reports** use enhanced, color-coded templates for visibility.
* **YARA scan** uses a fancy card layout for single-file scans, and table layout for multi-file.

---

## 🗂️ Project Structure (Important Folders)

```
input/
├── iis/           # IIS logs (.log)
├── apache/        # Apache logs
├── nginx/         # Nginx logs
├── mft/           # MFT CSV files
├── webroot/       # Files for YARA scan

modules/
├── iis_parser.py
├── apache_parser.py
├── nginx_parser.py
├── mft_analyzer.py
├── logger_helper.py
├── yara_scanner.py
├── yara_webshell_rules/
├── ...

template/
├── IOC_Report.html
├── yara_single_result.jinja2
├── yara_result.jinja2

c2 list/
├── known_c2.txt
├── c2_updater.py

reports/
```

---

## 🧠 False Positive Mitigation

* Ignores common static files (`.png`, `.jpg`, `.css`, etc.)
* Regex with word boundaries to avoid partial matches (`dir` ≠ `redirect`)
* Customizable and extendable via the keyword manager GUI

---

## 🌍 C2 Threat Feed

* **C2 detection:**
  Compares log IPs with those in `c2 list/known_c2.txt`
* **Feed update:**
  Use `update_c2_list.bat` for the latest known C2 addresses

---

## 🧪 YARA Webshell Scanner

* **Place files** to scan in `input/webroot/`
* **Run:**
  `run_yara_scan.bat` (Windows) or via start_menu.py
* **Custom rules:**
  Add to `modules/yara_webshell_rules/`
* **Auto-chooses** result template based on number of files

---

## 📝 Customization

* **Keyword/IOC lists:**
  Fully managed with GUI editor, supports category, server type, and per-rule explanations.
* **All detection logic** and feed lists are fully user-tunable for your environment.

---

## ❗ Known Issues

* Nginx to MFT correlation is currently not functioning as intended and will be resolved in the next release.

---

## 🛡️ Example Detection Categories

* `cmd`, `powershell`, `eval(`, `wget`, `curl`
* `base64`, `char(`, `frombase64string`
* `whoami`, `hostname`, `net user`
* `.php`, `.jsp`, `c99`, `r57`, `saveToFile`

---

## 🤝 Contributing

PRs, bug reports, and suggestions welcome!
Please open an issue for enhancements or to share new YARA rules/threat feeds.

---

## 📄 License

This project is licensed for **personal and non-commercial use only**.  
For commercial use, please contact me for permission: [ekremozdemir99@gmail.com]


---


