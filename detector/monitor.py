from collections import deque
from datetime import datetime, timedelta

class TrafficMonitor:
    def __init__(self):
        self.global_window = deque()
        self.ip_windows = {} # Dictionary: { ip: deque() }

    def add_request(self, ip, timestamp):
        now = timestamp
        # 1. Add to Global
        self.global_window.append(now)
        # 2. Add to IP-specific
        if ip not in self.ip_windows:
            self.ip_windows[ip] = deque()
        self.ip_windows[ip].append(now)

        self._cleanup(now)

    def _cleanup(self, now):
        cutoff = now - timedelta(seconds=60)
        # Clean global
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()
        # Clean IPs
        for ip in list(self.ip_windows.keys()):
            while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
                self.ip_windows[ip].popleft()
            if not self.ip_windows[ip]:
                del self.ip_windows[ip]
