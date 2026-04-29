# 🛡️ Multi-Layered Defense: Intelligent Dual-Trigger Firewall

> A Dockerized, real-time security stack that monitors live Nginx traffic, detects anomalous behavior using statistical analysis (Z-Score + Rate Multiplier), auto-blocks malicious IPs via `iptables`, and sends instant Slack alerts — protecting a self-hosted Nextcloud instance.

📖 **Read the full blog post:** [Multi-Layered Defense: Building an Intelligent, Dual-Trigger Firewall](https://dev.to/okeoghene_akwerigbe_a07a5/multi-layered-defense-building-an-intelligent-dual-trigger-firewall-27kc)

🌐 **Server IP:** [http://16.61.57.72/](http://16.61.57.72/)

📊 **Live metrics dashboard:** [metrics.okeakwerigbe.name.ng](http://metrics.okeakwerigbe.name.ng/)

---

## 📋 Table of Contents

* [Overview](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#overview)
* [Architecture](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#architecture)
* [Language Choice](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#language-choice)
* [How the Sliding Window Works](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#how-the-sliding-window-works)
* [How the Baseline Works](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#how-the-baseline-works)
* [How the Dual-Trigger System Works](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#how-the-dual-trigger-system-works)
* [Automated Escalation Ladder](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#automated-escalation-ladder)
* [Observability &amp; Alerts](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#observability--alerts)
* [Project Structure](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#project-structure)
* [Prerequisites](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#prerequisites)
* [Setup &amp; Deployment](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#setup--deployment)
* [Environment Variables](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#environment-variables)
* [Screenshots](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#screenshots)
* [Tech Stack](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#tech-stack)
* [Author](https://claude.ai/chat/655b3bc3-51b9-40e9-afc0-dbd8b3fd3962#author)

---

## Overview

In modern DevOps, a simple rate-limiter isn't enough. Hard-coded thresholds block legitimate users during viral traffic surges and let slow-and-low bot attacks slip through undetected.

This project solves that with a **Python-based Anomaly Detection Engine** that adapts to your real traffic patterns. It uses a **Dual-Trigger System** — a statistical Z-Score brain for detecting stealthy crawlers, and a volumetric Rate Multiplier as an emergency brake for brute-force floods — to protect the server in real time without adding any latency to the application.

---

## Architecture

The system is composed of three Docker services sharing a named volume for Nginx logs:

```
┌─────────────────────────┐
│        Internet         │
└──────────┬──────────────┘
           │ HTTP / HTTPS
┌──────────▼──────────────┐
│   Nginx (Reverse Proxy) │  ← writes JSON access logs
│      port 80 / 443      │
└──────────┬──────────────┘
           │ HNG-nginx-logs (shared named volume)
┌──────────▼──────────────┐
│   Anomaly Detector      │  ← tails logs, evaluates every IP
│   (Python Engine)       │
│                         │
│  ┌─────────────────┐    │
│  │  Monitor Thread │    │  ← tails log line-by-line
│  └────────┬────────┘    │
│           │             │
│  ┌────────▼────────┐    │
│  │ Detector Thread │    │  ← Z-Score & Rate Multiplier
│  └──────┬────┬─────┘    │
│         │    │          │
│  ┌──────▼─┐ ┌▼────────┐ │
│  │Blocker │ │Notifier │ │  ← iptables DROP + Slack alert
│  └──────┬─┘ └─────────┘ │
│  ┌──────▼─┐              │
│  │Unbanner│              │  ← timed + escalating bans
│  └────────┘              │
└─────────────────────────┘
           │ proxied to
┌──────────▼──────────────┐
│  Nextcloud (App Layer)  │
│  kefaslungu/hng-nextcloud│
└─────────────────────────┘
```

The detector runs with `network_mode: host` and `privileged: true` so it can read real source IPs and manage the host firewall directly via `iptables`.

---

## Language Choice

The engine is written in **Python 3** for three reasons:

1. **Deque and statistics primitives are built-in.** Python's `collections.deque` with a `maxlen` parameter gives us a time-bounded sliding window in a single line. The `statistics` module provides `mean` and `stdev` without any extra dependencies, keeping the implementation transparent and auditable.
2. **Subprocess calls to `iptables` are trivial.** Python's `subprocess.run()` makes it straightforward to issue kernel firewall commands and check their return codes without needing OS-level bindings.
3. **Rapid iteration.** The detection logic — particularly the baseline recalculation and per-hour slot preference — changed several times during development. Python's dynamic typing and short feedback loop made that iteration fast.

---

## How the Sliding Window Works

The engine tracks request rates using two independent `collections.deque` objects — one **per-IP** and one **global** — each representing the last 60 seconds of traffic.

**Structure:** Each entry pushed onto a deque is a `(timestamp, count)` tuple, where `timestamp` is a Unix epoch float and `count` is always `1` (one entry per request). The deques are not bounded by `maxlen`; instead, eviction is time-based and handled explicitly on every evaluation cycle.

**Eviction logic:** Before calculating any rate, the engine calls an eviction pass that pops entries from the **left** of the deque (the oldest end) as long as the entry's timestamp is older than `now - 60`. Because entries are appended in chronological order, this left-pop loop terminates as soon as it hits an entry still within the window:

```python
now = time.time()
while ip_window[ip] and ip_window[ip][0][0] < now - 60:
    ip_window[ip].popleft()
```

**Rate calculation:** After eviction, the current rate for an IP is simply the number of entries remaining in its deque divided by 60:

```python
current_rate = len(ip_window[ip]) / 60.0
```

This gives a true sliding average in requests-per-second — not a discretized per-minute bucket — so the engine responds smoothly to ramp-up attacks that try to stay just below a fixed threshold.

The global deque follows the same pattern but aggregates all IPs together, allowing the engine to distinguish between a single aggressive source and a distributed flood from many IPs simultaneously.

---

## How the Baseline Works

The baseline is a  **rolling 30-minute window of per-second request counts** , used to compute the mean and standard deviation that power the Z-Score trigger.

**Window structure:** The engine maintains a `deque` of per-second count slots. Every second, the monitor thread appends the count of requests seen in that second. Entries older than 1,800 seconds (30 minutes) are evicted from the left on each recalculation cycle, keeping the window strictly bounded.

**Recalculation interval:** The baseline is recalculated every **60 seconds** in a dedicated background thread. On each cycle it:

1. Evicts stale slots from the 30-minute deque.
2. Computes `mean` and `stdev` over the remaining slots using `statistics.mean()` and `statistics.stdev()`.
3. Persists the result to `baseline_data.json` so state survives a daemon restart.

**Per-hour slot preference:** The engine also maintains per-hour accumulators. If the current hour's slot has accumulated at least 5 minutes of data (300 data points), the engine uses that hour's mean and stdev as the effective baseline instead of the full 30-minute window. This means the baseline adapts faster during predictable intra-day traffic patterns (e.g., a morning traffic spike won't inflate the effective mean used during the quiet night period).

**Floor values:** To prevent division-by-zero and avoid spuriously high Z-Scores during near-zero traffic periods (e.g., the middle of the night), the baseline enforces a minimum floor:

```python
effective_mean = max(computed_mean, 0.1)   # floor at 0.1 req/s
effective_stdev = max(computed_stdev, 0.05) # floor at 0.05 to keep denominator stable
```

These floors ensure the detector does not block the first legitimate user who arrives after a long quiet period just because their single request produces a very high Z-Score against a near-zero baseline.

---

## How the Dual-Trigger System Works

Every IP address hitting the server is simultaneously evaluated by two independent triggers:

### Trigger A — The Statistical Brain (Z-Score)

Designed to catch **stealthy, slow-burn attacks** — crawlers and scrapers that deliberately stay below naive rate limits.

The engine tracks a rolling **Baseline Mean** (historical average requests/sec) and **Standard Deviation** (normal traffic fluctuation). Every new request is scored with:

```
Z = (current_rate - baseline_mean) / standard_deviation
```

Statistically, 99.7% of all normal activity falls within a Z-Score of ±3.0. If an IP generates a Z-Score above  **4.0** , the math proves it is not a normal user — it's a statistical anomaly, and the engine fires.

### Trigger B — The Volumetric Shield (Rate Multiplier)

Designed as a  **fail-safe for sudden flood attacks** . The Z-Score needs a few seconds of data to warm up; this trigger acts before the math even has time to finish.

Configured with a  **3× multiplier** :

* If the baseline is `1.0 req/sec`, any IP exceeding `3.0 req/sec` trips this trigger immediately.
* It acts as an emergency brake, stopping brute-force floods at the kernel level in real time.

Both triggers run simultaneously. Either one firing is sufficient to block an IP.

---

## Automated Escalation Ladder

An automated **Unbanner** worker manages a progressive backoff schedule so persistent offenders face increasingly severe consequences:

| Offense | Ban Duration                     |
| ------- | -------------------------------- |
| 1st     | 10 minutes                       |
| 2nd     | 30 minutes                       |
| 3rd     | 2 hours                          |
| 4th+    | **Permanent**(999,999 min) |

Blocks are applied to the **`DOCKER-USER` iptables chain** — because Docker aggressively rewrites `INPUT` chain rules, causing standard firewall blocks to be bypassed. Inserting a `DROP` rule in `DOCKER-USER` intercepts traffic at the lowest possible kernel level before it ever reaches the container.

---

## Observability & Alerts

**Live Dashboard**
A web dashboard plots a real-time sliding window of current Requests Per Second vs. the Baseline Mean — making traffic spikes instantly visible.

**Banned IP Panel**
A "Currently Banned" panel shows all IPs in the iptables penalty box with offense count and remaining ban time.

**Slack Webhooks**
Every block event fires a JSON payload to a configured Slack channel with:

* The offending IP address
* Which trigger fired (Z-Score or Rate Multiplier)
* The ban duration applied

---

## Project Structure

```
hng14-stage-3/
├── detector/               # Python anomaly detection engine
│   ├── Dockerfile
│   ├── detector.py         # Main engine: monitor, detect, block, notify
│   ├── audit.log           # Persisted ban/unban history
│   └── baseline_data.json  # Persisted learned traffic baseline
├── nginx/
│   └── nginx.conf          # Reverse proxy config with JSON log format
├── Screenshots/            # Project screenshots
├── docker-compose.yml      # Orchestrates all three services
├── .env.example            # Environment variable template
└── .gitignore
```

---

## Prerequisites

* A Linux host with Docker & Docker Compose installed
* A Slack Incoming Webhook URL
* The external Docker named volume `HNG-nginx-logs` created before starting

---

## Setup & Deployment

**1. Clone the repository**

```bash
git clone https://github.com/AkwerigbeO/hng14-stage-3.git
cd hng14-stage-3
```

**2. Configure environment variables**

```bash
cp .env.example .env
# Edit .env and fill in your Slack webhook URL and trusted home IP
nano .env
```

**3. Create the shared log volume**

```bash
docker volume create HNG-nginx-logs
```

**4. Build and start all services**

```bash
docker compose up -d --build
```

**5. Verify the stack is running**

```bash
docker compose ps
docker logs log-detector -f
```

---

## Environment Variables

Copy `.env.example` to `.env` and configure the following:

| Variable              | Description                                              |
| --------------------- | -------------------------------------------------------- |
| `SLACK_WEBHOOK_URL` | Your Slack Incoming Webhook URL for ban/unban alerts     |
| `HOME_IP`           | Your trusted IP address — this IP will never be blocked |

> ⚠️ Never commit your `.env` file. It is already listed in `.gitignore`.

---

## Screenshots

Screenshots are available in the [`/Screenshots`](https://claude.ai/chat/Screenshots) directory, including:

* The Python detector tailing live Nginx logs
* Z-Score and Rate Multiplier trigger output in the terminal
* The live metrics dashboard
* Slack alert notifications

---

## Tech Stack

| Layer            | Technology                               |
| ---------------- | ---------------------------------------- |
| Reverse Proxy    | Nginx (JSON access logs)                 |
| App              | Nextcloud (`kefaslungu/hng-nextcloud`) |
| Detection Engine | Python 3                                 |
| Firewall         | Linux `iptables`(DOCKER-USER chain)    |
| Alerting         | Slack Incoming Webhooks                  |
| Containerization | Docker & Docker Compose                  |

---

## Author

**Okeoghene Akwerigbe**

* Blog post: [Multi-Layered Defense: Building an Intelligent, Dual-Trigger Firewall](https://dev.to/okeoghene_akwerigbe_a07a5/multi-layered-defense-building-an-intelligent-dual-trigger-firewall-27kc)

---

*Built as part of the HNG Internship — Stage 3 DevOps track.*
