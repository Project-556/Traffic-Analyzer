import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from threading import Thread
from sys import executable
import queue
from subprocess import run
import json
from os import path

def worker(input_text, result_queue, explain):

    if not explain:
        proc = run(
            [executable, path.join(path.dirname(path.abspath(__file__)), "main.py"),
            "--input", input_text, "--returns"],
            capture_output=True,
            text=True
        )
    else:
        proc = run(
            [executable, path.join(path.dirname(path.abspath(__file__)), "main.py"),
            "--input", input_text, "--returns", "--explain"],
            capture_output=True,
            text=True
        )


    if proc.returncode != 0:
        # pass structured error instead of crashing UI
        result_queue.put({
            "error": True,
            "message": f"Sorry to say but something went wrong. It was output as \n{proc.stderr}"
        })
        return

    try:
        print(proc.stdout)
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        result_queue.put({
            "error": True,
            "message": f"Invalid JSON output: {e}",
            "raw": proc.stdout
        })
        return

    result_queue.put(data)


def launch_gui():
    result_queue = queue.Queue()

    def show_splash(root):
        splash = tk.Toplevel(root)
        splash.overrideredirect(True)
        splash.geometry("300x150+500+300")

        ttk.Label(
            splash,
            text="Analyzer 1.0.0 stable\nLoading...",
            font=("Segoe UI", 12),
            anchor="center"
        ).pack(expand=True, fill="both", padx=20, pady=20)

        # Close splash after 1.5 seconds
        root.after(1500, splash.destroy)


    def browse_file():
        path = filedialog.askopenfilename()
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    def on_run():
        output_label.config(text="Running...")

        pathw = entry.get()
        if not path.exists(pathw):
            result_queue.put({
                "error": True,
                "message" : "Please Check the path if it exist."
            })
        elif (not path.isfile(pathw)):
            result_queue.put({
                "error": True,
                "message": "Sorry to say, but the path given is not a file"
            })

        t = Thread(
            target=worker,
            args=(entry.get(), result_queue, explain),
            daemon=True
        )
        t.start()
        for w in side_frame.winfo_children():
            w.destroy()

        check_result()

    def toggle_explain():
        explain.set(not explain.get())

    def check_result():
        try:
            result = result_queue.get_nowait()
        except queue.Empty:
            root.after(50, check_result)
            return

        if result.get("error"):
            output_label.config(text="Error occurred")

            error_btn = ttk.Button(
                side_frame,
                text="View Error",
                command=lambda: show_popup(
                    "Analyzer Error",
                    result.get("message", "Unknown error")
                )
            )
            error_btn.pack(pady=5, anchor="nw")

            return
        output_label.config(text="*Completed")
        populateTable(result)
    # SAFE: back on main thread

    def show_popup(title, content):
        win = tk.Toplevel(root)
        win.title(title)
        win.geometry("500x300")

        text = tk.Text(win, wrap="word")
        text.insert("1.0", content)
        text.config(state="disabled")
        text.pack(expand=True, fill="both", padx=10, pady=10)

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=5)
    def parse_alerts(alerts):
        parsed = []

        if not isinstance(alerts, list):
            return parsed

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            parsed.append({
                "type": alert.get("type", "unknown"),
                "severity": alert.get("severity", "info"),
                "message": alert.get("message", "")
            })

        return parsed


    def populateTable(result):
        resultTable.delete(*resultTable.get_children())

        for key, value in result.items():
            if key == "alerts":
                parsed_alerts = parse_alerts(value)

                for alert in parsed_alerts:
                    for k, v in alert.items():
                        resultTable.insert("", "end", values=(k, v))
            else:
                if key != "explain":
                    resultTable.insert("", "end", values=(key, value))
                else:
                    explaination(value)

    def explaination(message: str):
        if explain:
            explain_btn = ttk.Button(side_frame, 
                                     text="Explaination", 
                                     command=lambda: show_popup(
                                         "Exaplaination",
                                         message
                                     ))
            explain_btn.pack(pady=7, padx=4, anchor="center")


    root = tk.Tk()
    root.withdraw()
    show_splash(root)
    root.after(1500, root.deiconify)
    root.title("Analyzer 1.0.0")
    root.geometry("400x250")

    frame = ttk.Frame(root, padding=20)
    frame.pack(expand=True, fill="both")

    explain = tk.BooleanVar(value=True)

    entry = ttk.Entry(frame, width=30)
    entry.pack(pady=5)

    ttk.Button(frame, text="Run", command=on_run).pack(pady=5)
    ttk.Checkbutton(frame, text="Explain", command=toggle_explain).pack(padx=4, pady=5)
    ttk.Button(frame, text="Browse File", command=browse_file).pack(pady=1, padx =7, anchor="w")

    output_label = ttk.Label(frame, text="")
    output_label.pack(pady=10)

    side_frame = ttk.Frame(frame)
    side_frame.pack(side="left", fill="y", padx=(0, 10))


    resultTable = ttk.Treeview(root, columns=("Key", "Value"), show="headings")

    resultTable.heading("Key", text="Key")
    resultTable.heading("Value", text="Value")

    resultTable.column("Key", width=200, anchor="w")
    resultTable.column("Value", width=400, anchor="w")

    resultTable.pack(fill="both", expand=True)

    root.mainloop()

launch_gui()
