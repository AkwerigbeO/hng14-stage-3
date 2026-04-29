from collections import defaultdict, deque
from statistics import mean, stdev


class BaselineManager:
    """Small reusable 30-minute baseline helper.

    The running daemon keeps this logic inside AnomalyDetector so it can update
    windows, hourly slots, and detection decisions atomically. This class mirrors
    the same baseline rules for isolated tests or future refactors.
    """

    def __init__(self, window_seconds=1800, min_hour_samples=300):
        self.window_seconds = window_seconds
        self.min_hour_samples = min_hour_samples
        self.history = deque(maxlen=window_seconds)
        self.hourly = defaultdict(list)
        self.effective_mean = 0.1
        self.effective_stddev = 0.05

    def add_count(self, count, hour):
        value = float(count)
        self.history.append(value)
        self.hourly[hour].append(value)
        self.hourly[hour] = self.hourly[hour][-3600:]

    def recalculate(self, current_hour):
        data = self.hourly[current_hour] if len(self.hourly[current_hour]) >= self.min_hour_samples else list(self.history)
        if not data:
            return self.effective_mean, self.effective_stddev

        self.effective_mean = max(mean(data), 0.1)
        self.effective_stddev = max(stdev(data) if len(data) > 1 else 0.05, 0.05)
        return self.effective_mean, self.effective_stddev

    def get_z_score(self, current_rate):
        return (current_rate - self.effective_mean) / self.effective_stddev
