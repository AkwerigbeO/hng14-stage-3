# HNG Stage 3 Anomaly Detection Engine

A Dockerized anomaly detection stack for the HNG DevOps Stage 3 task. It runs Nextcloud behind Nginx, tails JSON access logs in real time, learns recent traffic patterns, detects per-IP and global anomalies, blocks abusive IPs with `iptables`, and sends Slack notifications.

Blog post: [Multi-Layered Defense: Building an Intelligent, Dual-Trigger Firewall](https://dev.to/okeoghene_akwerigbe_a07a5/multi-layered-defense-building-an-intelligent-dual-trigger-firewall-27kc)

Server IP: [http://16.61.57.72/](http://16.61.57.72/)

Live metrics dashboard: [http://metrics.okeakwerigbe.name.ng/](http://metrics.okeakwerigbe.name.ng/)

GitHub repo: [https://github.com/AkwerigbeO/hng14-stage-3](https://github.com/AkwerigbeO/hng14-stage-3)

## Architecture

The stack has three Docker services:

- `nginx`: reverse proxy in front of Nextcloud. It writes JSON access logs to `/var/log/nginx/hng-access.log`.
- `nextcloud`: the required pre-built image, `kefaslungu/hng-nextcloud`.
- `detector`: Python daemon that tails the Nginx log, updates metrics, detects anomalies, blocks IPs, unbans expired bans, and serves the dashboard on port `5000`.

The shared log volume is the required Docker named volume `HNG-nginx-logs`. Nginx mounts it read/write. Nextcloud and the detector mount it read-only.

On the EC2 host, a host-level Nginx/virtual-host config routes `metrics.okeakwerigbe.name.ng` to the detector dashboard on `127.0.0.1:5000`. The container Nginx remains dedicated to serving Nextcloud by IP.

## Language Choice

The daemon is written in Python because the standard library gives direct, auditable building blocks for this task: `collections.deque` for sliding windows, `statistics` for mean/stddev calculations, and `subprocess` for `iptables` commands. Flask and psutil are used only for the live metrics UI.

## Sliding Window

The running detector keeps two 60-second deque windows:

- `global_window`: one timestamp per request across all traffic.
- `ip_windows[ip]`: one timestamp per request for each source IP.

On every log line, the detector appends the current timestamp and evicts old entries from the left while they are older than `now - 60`. Because the oldest entries are always on the left, eviction is efficient and the window is a true rolling 60 seconds, not a per-minute bucket.

Current rates are computed from the live deque sizes:

```python
global_rps = len(global_window) / 60
ip_rps = len(ip_windows[ip]) / 60
```

Error surge tracking uses a separate per-IP deque for 4xx/5xx responses over the same 60-second window.

## Baseline

The baseline uses completed per-second request counts from a rolling 30-minute window:

- Window size: `1800` per-second samples.
- Recalculation interval: every `60` seconds.
- Effective mean floor: `0.1 req/s`.
- Effective stddev floor: `0.05`.
- Error baseline floor: `0.1 errors/s`.

The detector also keeps per-hour slots. When the current hour has at least 300 per-second samples, that current-hour slot becomes the preferred baseline. Until then, the detector uses the rolling 30-minute window. Baseline state is persisted in `detector/baseline_data.json` so the daemon can recover learned traffic after a restart.

## Detection Logic

Per-IP and global detection use the configured dual trigger:

- Z-score trigger: current rate exceeds the baseline by more than `3.0` standard deviations.
- Rate multiplier trigger: current rate is more than `5x` the effective baseline mean.

Per-IP anomalies are blocked with an `iptables` DROP rule in the `DOCKER-USER` chain and announced to Slack. Global anomalies send a Slack alert only.

If an IP's 4xx/5xx rate rises above `3x` the baseline error rate, the detector tightens that IP's effective thresholds by half for the current decision.

## Blocking And Unban Schedule

Bans use this backoff schedule from `detector/config.yaml`:

| Offense | Duration |
| --- | --- |
| 1st | 10 minutes |
| 2nd | 30 minutes |
| 3rd | 2 hours |
| 4th+ | Permanent |

The unbanner runs continuously in the same daemon process. It reads the audit log at `/app/audit/audit.log`, releases expired bans, removes all matching `DOCKER-USER` rules for that IP, and sends a Slack unban notification. The host directory `detector/audit/` is mounted into the container so the audit history survives restarts.

## Dashboard

The dashboard refreshes every 3 seconds and shows:

- Banned IPs
- Global requests per second
- Top 10 source IPs
- CPU and memory usage
- Effective mean and stddev
- Detector uptime
- Live traffic vs baseline chart

## Setup From A Fresh VPS

1. Install Docker and Docker Compose.

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker
```

2. Clone the repository.

```bash
git clone https://github.com/AkwerigbeO/hng14-stage-3.git
cd hng14-stage-3
```

3. Configure secrets.

```bash
cp .env.example .env
nano .env
```

Set:

```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
HOME_IP=your.trusted.ip.address
```

4. Create the required named Docker volume.

```bash
docker volume create HNG-nginx-logs
```

5. Start the stack.

```bash
docker compose up -d --build
```

6. Verify services.

```bash
docker compose ps
docker logs log-detector -f
sudo iptables -L DOCKER-USER -n
```

7. Optional EC2 dashboard routing.

If the dashboard domain is served by host-level Nginx, proxy it to Flask on port `5000`:

```nginx
server {
    listen 80;
    server_name metrics.okeakwerigbe.name.ng;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Project Structure

```text
detector/
  main.py
  monitor.py
  baseline.py
  detector.py
  blocker.py
  unbanner.py
  notifier.py
  dashboard.py
  config.yaml
  requirements.txt
nginx/
  nginx.conf
docs/
  architecture.png
screenshots/
README.md
```

## Screenshots

Required screenshots should be stored in `screenshots/` before final submission:

- `Tool-running.png`
- `Ban-slack.png`
- `Unban-slack.png`
- `Global-alert-slack.png`
- `Iptables-banned.png`
- `Audit-log.png`
- `Baseline-graph.png`
