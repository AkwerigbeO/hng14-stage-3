from collections import defaultdict, deque


class TrafficMonitor:
    """Reusable 60-second deque monitor for global and per-IP traffic."""

    def __init__(self, window_seconds=60):
        self.window_seconds = window_seconds
        self.global_window = deque()
        self.ip_windows = defaultdict(deque)

    def add_request(self, ip, timestamp):
        self.global_window.append(timestamp)
        self.ip_windows[ip].append(timestamp)
        self.cleanup(timestamp)

    def cleanup(self, now):
        cutoff = now - self.window_seconds
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()

        for ip in list(self.ip_windows.keys()):
            while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
                self.ip_windows[ip].popleft()
            if not self.ip_windows[ip]:
                del self.ip_windows[ip]

    def global_rps(self):
        return len(self.global_window) / self.window_seconds

    def ip_rps(self, ip):
        return len(self.ip_windows.get(ip, ())) / self.window_seconds
