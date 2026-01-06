# Traffic Wall


A rule-based, explainable security tool that flags suspicious network activity and provides human-readable explanations.

---

## Overview
TrafficGuard is a lightweight, rule-based security tool designed to: 
- Detect suspicious network activity using simple, pre-defined rules that can be changed
- Explain why each alert was triggered in a clear, understandable way
- Allow easy customization of rules through a JSON file
- Be usable via a simple command-line interface (CLI)

This approach ensures transparency and simplicity while providing essential security monitoring functionality.

---

## Core Features
- Rule-based detection (max 5 rules)
- CLI-based usage
- JSON-based rule definitions
- Human-readable explanations (to be generated later using Google Gemini)

---

## Rules (Example)
1. Flag connections to ports outside allowed range (1-1024)  
2. Detect repeated connections from the same IP in a short period  
3. Flag unknown destination IPs  
4. Flag suspicious ports commonly used by malware (e.g., 4444)  
5. Detect unusual protocol usage  

*Rules are configurable in `rules/rules.json`.*

---

## Folder Structure
traffic_guard/<br>
├── main<br>
│ └── main.py<br>
│ └── GUI.py<br>
│ └── docs.md<br>
├── data<br>
│ └── output.json<br>
│ └── sample_logs.json<br>
│ └── rules.json
└── README.md<br>
└── LICENSE.txt<br>
---

# Tech Stack
- **Language**: Python 3.14
- **Framework**: Tkinter
- **AI**: Google Gemini API (google-genai)

## Note
This project is being developed **during the TechSprint hackathon**, following all rules for online participation. Detection is deterministic and rule-based; Google Gemini will only be used to generate easily-readable explanations for alerts if host is online.
