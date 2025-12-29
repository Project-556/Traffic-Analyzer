import argparse
import json
import os
from google import genai
from dotenv import load_dotenv
import sys
from time import time


def mark(label):
    print(f"[{time():.2f}] {label}", flush=True)

mark("Program start")
#-------------------- OUTPUT CONFIG -----------------
sys.stdout.reconfigure(line_buffering=True)

# -------------------- ENV SETUP --------------------
load_dotenv()
mark("Env loaded")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
mark("GenAI client ready")
client = genai.Client(api_key=GOOGLE_API_KEY)

# -------------------- CONFIG --------------------
SEVERITY_SCORE = {
    "low": 10,
    "medium": 40,
    "high": 90
}

RULES_PATH = "data/rules.json"
OUTPUT_DIR = "data/output"
OUTPUT_FILE = "data/output.json"
output: dict
with open(OUTPUT_FILE, "r") as f:
    output = json.load(f)
mark("Files loaded")

# -------------------- UTILS --------------------

def analyze(logs, rules):
    alerts = []

    # Apply only first rule for now
    if rules:
        rule = rules[0]
        for entry in logs:
            port = entry.get('port', 0)
            if port > rule.get('port_range', [1, 1024])[1]:
                alerts.append({
                    "severity": rule.get('severity', 'HIGH'),
                    "message": f"{rule['name']} detected: port {port} from {entry.get('source_ip')}"
                })
    return alerts

def load_rules(path):
    try:
        with open(path, 'r') as f:
            rules = json.load(f)
        return rules
    except Exception as e:
        print(f"Error loading rules: {e}")
        return []

def decide_action(score: int) -> str:
    if score >= 80:
        return "BLOCK"
    elif score >= 40:
        return "FLAG"
    return "ALLOW"


def print_alert(alert: dict):
    print("\n[!] ALERT DETECTED")
    print(f"Rule     : {alert['rule']}")
    print(f"Severity : {alert['severity'].upper()}")
    print(f"Score    : {alert['score']}")
    print(f"Action   : {alert['action']}")
    output["alerts"] = alert


def generate_explanation(alert: dict) -> str:
    print("[TrafficWall] Generating AI explanation...")

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=f"""
        You are a cybersecurity analysis assistant.

        Explain WHY this security alert was triggered.

        Rules:
        - Simple language
        - No assumptions
        - Under 4 sentences
        - Beginner SOC analyst level

        Alert:
        Rule: {alert['rule']}
        Severity: {alert['severity']}
        Message: {alert['message']}"""
            )
    
    output["explain"] = response.text
    return response.text


# -------------------- MAIN --------------------
def main():
    mark("Entered main()")
    parser = argparse.ArgumentParser(description="Traffic Wall")
    parser.add_argument("--input", required=True, help="Path to sample_logs.json")
    parser.add_argument("--explain", action="store_true", help="AI explanation")
    parser.add_argument("--fast-demo", action="store_true", help="Optimized demo mode")
    parser.add_argument("--return" ,action="store_true", help="Returnn Output")
    args = parser.parse_args()

    # ---------- Load rules ----------
    print("[TrafficWall] Loading detection rules...")
    rules = load_rules(RULES_PATH)
    print("[TrafficWall] Rules loaded ✔")

    # ---------- Load logs ----------
    print("[TrafficWall] Reading input logs...", flush=True)
    try:
        with open(args.input, "r") as f:
            logs = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load input file: {e}")
        output["error"] = f"[ERROR] Failed to load input file: {e}"
        return

    if args.fast_demo:
        logs = logs[:20]
        print("[TrafficWall] Fast-demo mode enabled (limited dataset)", flush=True)

    print(f"[TrafficWall] Logs loaded: {len(logs)} entries", flush=True)

    # ---------- Analyze ----------
    print("[TrafficWall] Running traffic analysis...", flush=True)
    alerts = analyze(logs, rules)

    if not alerts:
        print("[TrafficWall] No threats detected ✔", flush=True)
        alert = {"rules": "None",
                 "severity": "LOW",
                 "message": "[TrafficWall] No threats detected ✔",
                 "score": 0}
        output["alerts"] = alert
        output["decision"] = "ALLOW"
        with open(OUTPUT_FILE, "w") as f:
            json.dump(output, f, indent=3)
        return

    output_data = {
        "alerts": [],
        "final_score": 0,
        "decision": "ALLOW",
        "explain": None,
        "error": None
    }

    total_score = 0

    # ---------- Process alerts ----------
    for idx, alert in enumerate(alerts, start=1):
        print(f"[TrafficWall] Processing alert {idx}/{len(alerts)}", flush=True)

        severity = alert["severity"].lower()
        score = SEVERITY_SCORE.get(severity, 0)
        action = decide_action(score)

        output["decision"] = action
        alert_obj = {
            "rule": alert.get("rule", "Unknown"),
            "severity": severity,
            "message": alert.get("message", ""),
            "score": score,
            "action": action
        }

        print_alert(alert_obj)

        total_score += score
        output_data["alerts"].append(alert_obj)

        if args.explain:
            explanation = generate_explanation(alert_obj)
            print("\n[AI Explanation]")
            print(explanation)
            output_data["explain"] = explanation

    # ---------- Final decision ----------
    output_data["final_score"] = total_score
    output_data["decision"] = decide_action(total_score)

    # ---------- Save output ----------
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output_data, f, indent=3)

    print("\n[TrafficWall] Analysis complete ✔", flush=True)
    print("Final Decision:", output_data["decision"], flush=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=3)
    if args.returns:
        return output


# -------------------- ENTRY --------------------
if __name__ == "__main__":
    print("[TrafficWall] Initializing analysis engine...", flush=True)
    main()
