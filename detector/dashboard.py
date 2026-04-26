from flask import Flask, render_template, jsonify
import psutil
import time
from datetime import timedelta

app = Flask(__name__)

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
    uptime = str(timedelta(seconds=int(time.time() - metrics_data['start_time'])))
    return render_template('index.html', uptime=uptime)

@app.route('/api/stats')
def stats():
    return jsonify({
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "global_rps": metrics_data["global_rps"],
        "top_ips": metrics_data["top_ips"],
        "banned_ips": metrics_data["banned_ips"], # The actual list
        "mean": round(metrics_data["mean"], 2),
        "stddev": round(metrics_data["stddev"], 2)
    })

def run_dashboard():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
