import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import threading
import os
import re
import shutil

# --- ANSI color support ---
ANSI_COLORS = {
    '30': '#222222', '31': '#f87171', '32': '#6ee7b7', '33': '#facc15',
    '34': '#6366f1', '35': '#f472b6', '36': '#67e8f9', '37': '#fff',
    '90': '#a3a3a3', '91': '#fb7185', '92': '#bef264', '93': '#fde68a',
    '94': '#60a5fa', '95': '#f9a8d4', '96': '#5eead4', '97': '#f1f5f9'
}
ansi_escape = re.compile(r'\x1b\[(\d+)m')

def insert_ansi_colored(text, text_widget):
    pos = 0
    last_fg = None
    for match in ansi_escape.finditer(text):
        start, end = match.span()
        segment = text[pos:start]
        if segment:
            if last_fg:
                text_widget.insert(tk.END, segment, last_fg)
            else:
                text_widget.insert(tk.END, segment)
        code = match.group(1)
        if code == '0':
            last_fg = None
        elif code in ANSI_COLORS:
            last_fg = f"ansi_fg_{code}"
            try:
                text_widget.tag_config(last_fg, foreground=ANSI_COLORS[code])
            except tk.TclError:
                pass
        pos = end
    segment = text[pos:]
    if segment:
        if last_fg:
            text_widget.insert(tk.END, segment, last_fg)
        else:
            text_widget.insert(tk.END, segment)


def archive_logs_to_folder():
    from datetime import datetime

    def log(msg, tag=None):
        terminal.config(state=tk.NORMAL)
        terminal.insert(tk.END, msg + '\n', tag)
        terminal.see(tk.END)
        terminal.config(state=tk.DISABLED)

    def worker():
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
            archive_dir = os.path.join("archived logs", timestamp)
            os.makedirs(archive_dir, exist_ok=True)
            log(f"[*] Archiving to: {archive_dir}", "INFO")

            # Move files from /reports
            if os.path.isdir("reports"):
                for f in os.listdir("reports"):
                    src = os.path.join("reports", f)
                    if os.path.isfile(src):
                        dst = os.path.join(archive_dir, f)
                        shutil.move(src, dst)
                        log(f"[✓] Moved {src} → {dst}", "GREEN")

            # Move files from /input and subdirs
            if os.path.isdir("input"):
                for root, _, files in os.walk("input"):
                    for f in files:
                        src = os.path.join(root, f)
                        rel = os.path.relpath(src, "input").replace("\\", "_")
                        dst = os.path.join(archive_dir, rel)
                        shutil.move(src, dst)
                        log(f"[✓] Moved {src} → {dst}", "GREEN")

            log("\n[✓] All files moved successfully.", "SUCCESS")
        except Exception as e:
            log(f"[!] Error: {e}", "ERROR")

    terminal.config(state=tk.NORMAL)
    terminal.delete("1.0", tk.END)
    terminal.insert(tk.END, "[*] Running Archive Logs...\n\n", "INFO")
    terminal.config(state=tk.DISABLED)
    threading.Thread(target=worker, daemon=True).start()


def run_yara_scanner():
    terminal.config(state=tk.NORMAL)
    terminal.delete("1.0", tk.END)
    terminal.insert(tk.END, "[*] Running YARA Webroot Scanner...\n\n")
    terminal.config(state=tk.DISABLED)

    def worker():
        try:
            exe_path = os.path.join("modules", "yara_scanner.exe")
            proc = subprocess.Popen(
                [exe_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False  # ✅ Don't use shell=True here
            )
            for line in iter(proc.stdout.readline, b''):
                decoded = line.decode('utf-8', errors='replace')

                terminal.config(state=tk.NORMAL)

                # Custom color highlights
                if "Match:" in decoded:
                    terminal.tag_config("MATCH", foreground="#00f7ff", font=("Consolas", 12, "bold"))
                    terminal.insert(tk.END, decoded, "MATCH")
                elif "HTML report saved to" in decoded:
                    terminal.tag_config("REPORT_HTML", foreground="#ffcc00")
                    terminal.insert(tk.END, decoded, "REPORT_HTML")
                elif "TXT report saved to" in decoded:
                    terminal.tag_config("REPORT_TXT", foreground="#b0f72f")
                    terminal.insert(tk.END, decoded, "REPORT_TXT")
                else:
                    insert_ansi_colored(decoded, terminal)

                terminal.see(tk.END)
                terminal.config(state=tk.DISABLED)

            proc.stdout.close()
            proc.wait()
            terminal.config(state=tk.NORMAL)
            terminal.insert(tk.END, f"\n[✓] Scan Complete.\n", "SUCCESS")
            terminal.tag_config("SUCCESS", foreground="#7fff7f")
            terminal.config(state=tk.DISABLED)

        except Exception as e:
            terminal.config(state=tk.NORMAL)
            terminal.insert(tk.END, f"[!] Failed to run YARA Scanner: {e}\n", "ERROR")
            terminal.tag_config("ERROR", foreground="#ff5555")
            terminal.config(state=tk.DISABLED)

    threading.Thread(target=worker, daemon=True).start()



buttons = [
    ("Webshell\nAnalyzer",   "run_webshell_analyzer.bat",              "#6366f1", "#fff", "Run Webshell Analyzer", True),
    ("YARA\nScan",           "run_yara",                      "#f59e42", "#222", "Scan webroot files with YARA", False),
    ("Keyword\nManager",     "modules/keyword_manager/keyword_editor_server.exe", "#f472b6", "#fff", "Open keyword manager", False),
    ("Output\nLog",          "modules/output_log/output_log_app.exe",  "#3b82f6", "#fff", "Show output logs", False),
    ("Update\nC2 List",      "c2 list/c2_updater.exe",                "#facc15", "#222", "Update known C2 list", False),
    ("Compile\nAll",        "compile_all", "#8e44ad", "#000", "Compile all components", False),
    ("Cleanup\nBuilds", "cleanup", "#94a3b8", "#000", "Delete all .spec, /dist and /build folders", False),
    ("Archive\nLogs", "archive_logs", "#6ee7b7", "#222", "Archive all logs", False),
]

def shade(hex_color, percent):
    hex_color = hex_color.lstrip('#')
    rgb = [int(hex_color[i:i+2], 16) for i in (0, 2, 4)]
    rgb = [max(0, min(255, int(v * percent))) for v in rgb]
    return "#%02x%02x%02x" % tuple(rgb)

def run_bat_in_terminal(bat_path, arg=None):
    if not os.path.exists(bat_path):
        messagebox.showerror("File Not Found", f"Could not find {bat_path}")
        return
    terminal.config(state=tk.NORMAL)
    terminal.delete("1.0", tk.END)
    terminal.insert(tk.END, f"Running: {bat_path}\n\n" if not arg else f"Running: {bat_path} {arg}\n\n")
    terminal.config(state=tk.DISABLED)

    def worker():
        cmd = ["cmd.exe", "/c", bat_path]
        if arg:
            cmd.append(arg)
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1
            )
        except Exception as e:
            terminal.config(state=tk.NORMAL)
            terminal.insert(tk.END, f"Failed to run {bat_path}: {e}\n")
            terminal.config(state=tk.DISABLED)
            return
        for line in iter(proc.stdout.readline, b''):
            decoded = line.decode('utf-8', errors='replace')
            terminal.config(state=tk.NORMAL)
            insert_ansi_colored(decoded, terminal)
            terminal.see(tk.END)
            terminal.config(state=tk.DISABLED)
        proc.stdout.close()
        proc.wait()
        terminal.config(state=tk.NORMAL)
        terminal.insert(tk.END, f"\n[Process exited with code {proc.returncode}]\n")
        terminal.config(state=tk.DISABLED)
    threading.Thread(target=worker, daemon=True).start()

def run_webshell_analyzer_gui(bat_path):
    def start_with_choice(choice):
        win.destroy()
        run_bat_in_terminal(bat_path, choice)
    win = tk.Toplevel(root)
    win.title("Select Web Server Type")
    win.geometry("350x220+420+320")
    tk.Label(win, text="Select Web Server Type to Analyze:", font=("Segoe UI", 13)).pack(padx=18, pady=18)
    opts = [("IIS", "#9ac6f8"), ("Apache", "#feb49a"), ("NGINX", "#a1f2b2")]
    for val, clr in opts:
        tk.Button(win, text=val, width=20, bg=clr, font=("Segoe UI", 12, "bold"),
                  command=lambda v=val.lower(): start_with_choice(v)).pack(pady=6)

def make_cmd(label, path, needs_menu):
    if needs_menu:
        return lambda: run_webshell_analyzer_gui(path)        
    elif label.strip().lower().startswith("cleanup"):
        return cleanup_pyinstaller_files
        
    elif label.strip().lower().startswith("compile"):
        return compile_executable
        
    elif label.strip().lower().startswith("yara"):
        return run_yara_scanner 
        
    elif label.strip().lower().startswith("archive"):
        return archive_logs_to_folder
   
    elif label.strip().lower().startswith("output") or label.strip().lower().startswith("keyword"):
        def run_exe():
            if os.path.exists(path):
                terminal.config(state=tk.NORMAL)
                terminal.delete("1.0", tk.END)
                terminal.insert(tk.END, f"Running: {path}\n\n")
                terminal.config(state=tk.DISABLED)

                def worker():
                    try:
                        proc = subprocess.Popen(
                            [path],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT
                        )
                        for line in iter(proc.stdout.readline, b''):
                            decoded = line.decode('utf-8', errors='replace')
                            terminal.config(state=tk.NORMAL)
                            insert_ansi_colored(decoded, terminal)
                            terminal.see(tk.END)
                            terminal.config(state=tk.DISABLED)
                        proc.stdout.close()
                        proc.wait()
                        terminal.config(state=tk.NORMAL)
                        terminal.insert(tk.END, f"\n[Process exited with code {proc.returncode}]\n")
                        terminal.config(state=tk.DISABLED)
                    except Exception as e:
                        terminal.config(state=tk.NORMAL)
                        terminal.insert(tk.END, f"Failed to run {path}: {e}\n")
                        terminal.config(state=tk.DISABLED)
                threading.Thread(target=worker, daemon=True).start()
            else:
                messagebox.showerror("Executable Not Found", f"{path} not found.")
        return run_exe

    else:
        return lambda: run_bat_in_terminal(path)

def cleanup_pyinstaller_files():
    confirm = messagebox.askyesno("Confirm Cleanup", "Are you sure you want to delete all .spec, dist, and build folders?")
    if not confirm:
        terminal.config(state=tk.NORMAL)
        terminal.insert(tk.END, "[!] Cleanup cancelled.\n")
        terminal.config(state=tk.DISABLED)
        return

    terminal.config(state=tk.NORMAL)
    terminal.insert(tk.END, "[*] Cleaning up PyInstaller build files...\n")

    # Delete all .spec files in current folder
    terminal.insert(tk.END, "[*] Deleting all .spec files...\n")
    for f in os.listdir("."):
        if f.endswith(".spec"):
            try:
                os.remove(f)
                terminal.insert(tk.END, f"    - Deleted {f}\n")
            except Exception as e:
                terminal.insert(tk.END, f"    - Failed to delete {f}: {e}\n")

    # Delete top-level /dist and /build folders
    terminal.insert(tk.END, "[*] Deleting top-level /dist and /build folders...\n")
    for folder in ["dist", "build"]:
        if os.path.isdir(folder):
            try:
                shutil.rmtree(folder)
                terminal.insert(tk.END, f"    - Deleted /{folder}\n")
            except Exception as e:
                terminal.insert(tk.END, f"    - Failed to delete /{folder}: {e}\n")

    # Delete all nested /dist and /build folders recursively
    terminal.insert(tk.END, "[*] Deleting all nested /dist and /build folders...\n")
    for root, dirs, _ in os.walk(".", topdown=False):
        for d in dirs:
            if d.lower() in ["dist", "build"]:
                path = os.path.join(root, d)
                try:
                    shutil.rmtree(path)
                    terminal.insert(tk.END, f"    - Deleted {path}\n")
                except Exception as e:
                    terminal.insert(tk.END, f"    - Failed to delete {path}: {e}\n")

    terminal.insert(tk.END, "\n[✓] Cleanup complete.\n")
    terminal.config(state=tk.DISABLED)


def compile_executable():
    import subprocess, threading, tkinter as tk
    from tkinter import messagebox

    def run_compile(target):
        compile_map = {
            "Webshell Analyzer": {
                "message": "[*] Building ws_analyzer.exe...\n",
                "command": ["pyinstaller", "--onefile", "--distpath", ".", "ws_analyzer.py"]
            },
            "Output Log Viewer": {
                "message": "[*] Building output_log_app.exe into /modules/output_log...\n",
                "command": [
                    "pyinstaller", "--onefile",
                    "--hidden-import", "flask",
                    "--hidden-import", "flask.templating",
                    "--hidden-import", "flask.blueprints",
                    "--add-data", "modules/output_log/templates/output_log_report.jinja2;templates",
                    "--add-data", "modules/output_log/output_log_server.py;.",
                    "--distpath", "modules/output_log",
                    "modules/output_log/output_log_app.py"
                ]
            },
            "Keyword Editor": {
                "message": "[*] Building keyword_editor_server.exe into /modules/keyword_manager...\n",
                "command": [
                    "pyinstaller", "--onefile",
                    "--hidden-import", "flask",
                    "--add-data", "modules/keyword_manager/keyword_editor.html;.",
                    "--add-data", "modules/keyword_manager/keyword_config.json;.",
                    "--distpath", "modules/keyword_manager",
                    "modules/keyword_manager/keyword_editor_server.py"
                ]
            },
            "C2 Updater": {
                "message": "[*] Building c2_updater.exe into /c2 list...\n",
                "command": [
                    "pyinstaller", "--onefile",
                    "--hidden-import", "requests",
                    "--distpath", "c2 list",
                    "c2 list/c2_updater.py"
                ]
            },
            "All": {
                "message": "[*] Compiling all components...\n",
                "command": None  # handled below
            }
        }

        if target == "All":
            terminal.config(state=tk.NORMAL)
            terminal.delete("1.0", tk.END)
            terminal.insert(tk.END, compile_map["All"]["message"])
            terminal.config(state=tk.DISABLED)

            def worker_all():
                for key in compile_map:
                    if key == "All":
                        continue
                    info = compile_map[key]
                    terminal.config(state=tk.NORMAL)
                    terminal.insert(tk.END, info["message"])
                    terminal.config(state=tk.DISABLED)
                    subprocess.run(info["command"])
                terminal.config(state=tk.NORMAL)
                terminal.insert(tk.END, "\n[✓] All components compiled.\n")
                terminal.config(state=tk.DISABLED)

            threading.Thread(target=worker_all, daemon=True).start()
            return

        if target not in compile_map:
            messagebox.showerror("Unknown Component", f"No build logic for: {target}")
            return

        info = compile_map[target]
        terminal.config(state=tk.NORMAL)
        terminal.delete("1.0", tk.END)
        terminal.insert(tk.END, info["message"])
        terminal.config(state=tk.DISABLED)

        def worker():
            subprocess.run(info["command"])
            terminal.config(state=tk.NORMAL)
            terminal.insert(tk.END, "\n[✓] Build complete.\n")
            terminal.config(state=tk.DISABLED)

        threading.Thread(target=worker, daemon=True).start()

    # -- Fancy popup window --
    win = tk.Toplevel(root)
    win.title("Select Module to Compile")
    win.geometry("395x435+450+320")
    win.configure(bg="#1a1a1a")
    win.resizable(False, False)
    win.attributes('-topmost', 1)

    # Card shadow
    shadow = tk.Frame(win, bg="#bdbdbd", bd=0, highlightthickness=0)
    shadow.place(x=32, y=44, width=320, height=340)

    # Card container
    card = tk.Frame(win, bg="#fff", bd=0, relief="flat", highlightthickness=0)
    card.place(x=20, y=30, width=320, height=340)

    title = tk.Label(card, text="Choose an executable to compile:", font=("Segoe UI", 14, "bold"),
                     bg="#fff", fg="#1f2937")
    title.pack(pady=(24, 28))

    options = [
        ("Webshell Analyzer", "#6366f1"),
        ("Output Log Viewer", "#3b82f6"),
        ("Keyword Editor", "#f472b6"),
        ("C2 Updater", "#facc15"),
        ("All", "#a1f2b2"),
    ]
    btn_width = 248
    btn_height = 38

    def on_enter(e, btn, clr):
        btn.config(bg=clr, fg="#fff", font=("Segoe UI", 12, "bold"))

    def on_leave(e, btn):
        btn.config(bg="#f4f4f6", fg="#222", font=("Segoe UI", 12, "bold"))

    # Use .place for exact same size buttons
    for i, (name, color) in enumerate(options):
        btn = tk.Label(
            card, text=name,
            font=("Segoe UI", 12, "bold"),
            bg="#f4f4f6", fg="#222",
            width=1, height=1,  # not used (we'll set via .place)
            bd=0, relief="flat",
            highlightthickness=0,
            anchor="center", cursor="hand2"
        )
        y = 70 + i * (btn_height + 15)
        btn.place(x=(320-btn_width)//2, y=y, width=btn_width, height=btn_height)
        btn.bind("<Enter>", lambda e, b=btn, c=color: on_enter(e, b, c))
        btn.bind("<Leave>", lambda e, b=btn: on_leave(e, b))
        btn.bind("<Button-1>", lambda e, n=name: [win.destroy(), run_compile(n)])

    win.lift()


   
# === UI Setup ===

root = tk.Tk()
root.title("\U0001F680 WebShell Toolkit Menu")
root.configure(bg="#eaf0fa")
root.geometry("1150x650+160+60")
root.minsize(800, 450)
root.rowconfigure(1, weight=1)
root.columnconfigure(0, weight=1)

title = tk.Label(root, text="\U0001F6E0️ WebShell Toolkit Menu", font=("Segoe UI", 22, "bold"), bg="#eaf0fa", fg="#1f2937")
title.grid(row=0, column=0, sticky="ew", pady=(18, 0), padx=0)

terminal = scrolledtext.ScrolledText(root, font=("Consolas", 12), bg="#181818", fg="#d7ffd7")
terminal.grid(row=1, column=0, sticky="nsew", padx=32, pady=(12, 8))
terminal.insert(tk.END, "[ Output of each tool appears here ]\n")
terminal.config(state=tk.DISABLED)

terminal.tag_config("INFO", foreground="#60a5fa")
terminal.tag_config("SUCCESS", foreground="#22c55e")
terminal.tag_config("ERROR", foreground="#ef4444")
terminal.tag_config("GREEN", foreground="#6ee7b7")

button_frame = tk.Frame(root, bg="#eaf0fa")
button_frame.grid(row=2, column=0, sticky="ew", padx=26, pady=(0,18))
button_frame.columnconfigure(tuple(range(len(buttons))), weight=1)

def on_enter(e, btn, color):
    btn['bg'] = shade(color, 1.18)
    btn['cursor'] = "hand2"
    btn['bd'] = 3

def on_leave(e, btn, color):
    btn['bg'] = color
    btn['bd'] = 2

def on_press(e, btn, color):
    btn['bg'] = shade(color, 0.9)

def on_release(e, btn, color):
    btn['bg'] = shade(color, 1.18)

for i, (label, path, color, fgcolor, tip, needs_menu) in enumerate(buttons):
    cmd = make_cmd(label, path, needs_menu)
    btn = tk.Button(
        button_frame, text=label, font=("Segoe UI", 13, "bold"),
        bg=color, fg=fgcolor, command=cmd,
        bd=2, activebackground=shade(color, 1.1),
        relief="ridge", wraplength=100, justify="center",
        highlightthickness=0, highlightbackground="#bbb"
    )
    btn.grid(row=0, column=i, padx=8, pady=4, sticky="ewns")
    btn.bind("<Enter>", lambda e, b=btn, c=color: on_enter(e, b, c))
    btn.bind("<Leave>", lambda e, b=btn, c=color: on_leave(e, b, c))
    btn.bind("<ButtonPress-1>", lambda e, b=btn, c=color: on_press(e, b, c))
    btn.bind("<ButtonRelease-1>", lambda e, b=btn, c=color: on_release(e, b, c))

root.mainloop()
