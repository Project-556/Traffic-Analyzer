# ui/tui.py
import subprocess
import json
import time
import threading
from sys import executable

from textual.app import App, ComposeResult
from textual.widgets import (
    Header,
    Footer,
    Static,
    DataTable,
    ProgressBar,
)
from textual.containers import Horizontal, Vertical


ENGINE_PATH = "main/main.py"
LOG_FILE = "data/sample_logs.json"
output: dict


class TrafficWallApp(App):
    CSS = """
    Screen {
        background: black;
    }

    #title {
        text-style: bold;
        padding: 1;
    }

    #decision {
        text-style: bold;
        padding: 1;
    }
    """

    # (left as-is, even though unused)
    with open("data/output.json", "r") as f:
        output = json.load(f)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        yield Static("🚨 TrafficWall — Security Dashboard", id="title")

        self.progress = ProgressBar(total=100)
        yield self.progress

        with Horizontal():
            self.alert_table = DataTable(zebra_stripes=True)
            self.alert_table.add_columns("Severity", "Rule")
            yield self.alert_table

            self.details = Static("Waiting for analysis…")
            yield self.details

        self.decision = Static("Final Decision: —", id="decision")
        yield self.decision

        yield Footer()

    def on_mount(self):
        thread = threading.Thread(target=self.run_engine, daemon=True)
        thread.start()

    def run_engine(self):
        # Fake progress while engine runs
        for _ in range(30):
            time.sleep(0.05)
            self.call_from_thread(self.progress.advance, 1)  # FIX

        try:
            result = subprocess.run(
                [
                    executable,
                    ENGINE_PATH,
                    "--input",
                    LOG_FILE,
                    "--return",
                ],
                capture_output=True,
                text=True,
            )
        except Exception as e:
            self.call_from_thread(self.details.update, f"[ERROR] {e}")  # FIX
            return

        for _ in range(70):
            time.sleep(0.01)
            self.call_from_thread(self.progress.advance, 1)  # FIX

        # FIX: parse JSON from stdout
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            self.call_from_thread(
                self.details.update,
                f"[ERROR] Invalid JSON from engine\n{e}",
            )
            return

        self.call_from_thread(self.load_results, data)  # FIX

    def load_results(self, data):
        self.progress.update(progress=100)

        alerts = data.get("alerts", [])

        # FIX: alerts is a list
        if not alerts:
            self.details.update("No alerts detected.")
            self.decision.update("Final Decision: ALLOW")
            return

        for alert in alerts:
            self.alert_table.add_row(
                alert.get("severity", "").upper(),
                alert.get("rule", ""),
            )

        first = alerts[0]
        self.details.update(
            f"""
            Rule     : {first.get('rule')}
            Severity : {first.get('severity', '').upper()}
            Score    : {first.get('score')}
            Action   : {first.get('action')}
            """.strip()
        )

        self.decision.update(
            f"Final Decision: {data.get('decision', 'UNKNOWN')}"
        )


if __name__ == "__main__":
    TrafficWallApp().run()
