import sqlite3
import os
import numpy as np
from sklearn.ensemble import IsolationForest
from rich.console import Console
from rich.table import Table
from rich import box

DB_FILE = "data/profiles.db"
console = Console()

def load_profiles():
    if not os.path.exists(DB_FILE):
        console.print("[red][ERROR] profiles.db not found.[/red]")
        return [], []
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT mac, avg_ttl, avg_tcp_window, avg_packet_length, packet_count FROM device_profiles")
    rows = c.fetchall()
    conn.close()
    if len(rows) < 2:
        console.print("[yellow][WARN] Need at least 2 profiles.[/yellow]")
        return [], []
    macs = [r[0] for r in rows]
    features = [[r[1], r[2], r[3], r[4]] for r in rows]
    return macs, features

def run_anomaly_detection(contamination=0.2):
    console.print("[bold]PacketMirror — Anomaly Detection (Isolation Forest)[/bold]")
    macs, features = load_profiles()
    if not macs:
        return
    X = np.array(features)
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    predictions = model.fit_predict(X)
    scores = model.decision_function(X)
    table = Table(show_header=True, header_style="bold")
    table.add_column("MAC Address", style="cyan")
    table.add_column("Anomaly Score", justify="right")
    table.add_column("Status", justify="center")
    anomaly_count = 0
    for i, mac in enumerate(macs):
        score = round(scores[i], 4)
        if predictions[i] == -1:
            status = "[red]ANOMALY[/red]"
            anomaly_count += 1
        else:
            status = "[green]NORMAL[/green]"
        table.add_row(mac, str(score), status)
    console.print(table)
    console.print(f"Summary: {len(macs)} devices | {anomaly_count} anomalies detected")

if __name__ == "__main__":
    run_anomaly_detection()