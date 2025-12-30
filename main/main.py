import argparse
import json
import os
from google import genai
from dotenv import load_dotenv
import sys
from time import time

parser = argparse.ArgumentParser(description="Traffic Wall")
parser.add_argument("--input", required=True, help="Path to sample_logs.json")
parser.add_argument("--explain", action="store_true", help="AI explanation")
parser.add_argument("--fast-demo", action="store_true", help="Optimized demo mode")
parser.add_argument("--returns" ,action="store_true", help="Returnn Output")
args = parser.parse_args()

returning = args.returns
def mark(label):
    global returning
    if not returning:
        print(f"[{time():.2f}] {label}", flush=True)

mark("Program start")
#-------------------- OUTPUT CONFIG -----------------
sys.stdout.reconfigure(line_buffering=True, encoding="utf-8")

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
    global returning
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
    global returning
    mark("Entered main()")

    # ---------- Load rules ----------
    mark("[TrafficWall] Loading detection rules...")
    rules = load_rules(RULES_PATH)
    mark("[TrafficWall] Rules loaded ✔")

    # ---------- Load logs ----------
    mark("[TrafficWall] Reading input logs...")
    try:
        with open(args.input, "r") as f:
            logs = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load input file: {e}")
        output["error"] = f"[ERROR] Failed to load input file: {e}"
        return
    except Exception.with_traceback as e:
        print("Something occured: ", e)

    if args.fast_demo:
        logs = logs[:20]
        mark("[TrafficWall] Fast-demo mode enabled (limited dataset)")

    mark(f"[TrafficWall] Logs loaded: {len(logs)} entries")

    # ---------- Analyze ----------
    mark("[TrafficWall] Running traffic analysis...")
    alerts = analyze(logs, rules)

    if not alerts:
        output_data = {
            "alerts": [],
            "final_score": 0,
            "decision": "ALLOW",
            "explain": None,
            "error": None
        }
        if args.returns:
            print(json.dumps(output_data))
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
        mark(f"[TrafficWall] Processing alert {idx}/{len(alerts)}", flush=True)

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

        if not args.returns:
            print_alert(alert_obj)

        total_score += score
        output_data["alerts"].append(alert_obj)

        if args.explain:
            explanation = generate_explanation(alert_obj)
            mark("\n[AI Explanation]")
            mark(explanation)
            output_data["explain"] = explanation

    # ---------- Final decision ----------
    output_data["final_score"] = total_score
    output_data["decision"] = decide_action(total_score)

    # ---------- Save output ----------
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output_data, f, indent=3)

    # ---------- Final decision ----------
    output_data["final_score"] = total_score
    output_data["decision"] = decide_action(total_score)

    # ---------- Save output ----------
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output_data, f, indent=3)

    # ---------- Machine output ----------
    if not args.returns:
        print(json.dumps(output_data))
        return

    # ---------- Human output ----------
    mark("\n[TrafficWall] Analysis complete ✔")
    mark(f"Final Decision: {output_data["decision"]}")



# -------------------- ENTRY --------------------
if __name__ == "__main__":
    mark("[TrafficWall] Initializing analysis engine...")
    main()
