import threading
from flask import Flask, render_template, jsonify
import psutil
import time
from datetime import timedelta

app = Flask(__name__)

# ─── Thread-safe lock for shared state ───
# All writes from the log-processing thread and reads from the
# Flask request thread MUST be wrapped in this lock.
metrics_lock = threading.Lock()

# This will be updated by your main.py loop
metrics_data = {
    "banned_ips": [],
    "global_rps": 0,
    "top_ips": [], # List of tuples: [("1.2.3.4", 50), ("5.6.7.8", 12)]
    "mean": 0.0,
    "stddev": 0.0,
    "start_time": time.time()
}

@app.route('/')
def index():
    with metrics_lock:
        uptime = str(timedelta(seconds=int(time.time() - metrics_data['start_time'])))
    return render_template('index.html', uptime=uptime)

@app.route('/api/stats')
def stats():
    """Returns a JSON snapshot of all metrics.
    
    - top_ips is serialized as [{ip: "...", count: N}] to prevent
      the frontend from seeing raw arrays/tuples that cause 'undefined'.
    - banned_count is pre-computed so JS doesn't call .length on null.
    """
    with metrics_lock:
        # Build the snapshot under the lock to avoid partial reads
        top_ips_safe = []
        for entry in metrics_data["top_ips"]:
            if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                top_ips_safe.append({"ip": str(entry[0]), "count": int(entry[1])})
            elif isinstance(entry, dict):
                top_ips_safe.append(entry)

        banned_list = list(metrics_data["banned_ips"]) if metrics_data["banned_ips"] else []

        snapshot = {
            "cpu": psutil.cpu_percent(),
            "memory": psutil.virtual_memory().percent,
            "global_rps": metrics_data["global_rps"],
            "top_ips": top_ips_safe,
            "banned_ips": banned_list,
            "banned_count": len(banned_list),
            "mean": round(metrics_data["mean"], 2),
            "stddev": round(metrics_data["stddev"], 2),
        }
    return jsonify(snapshot)

def run_dashboard():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
