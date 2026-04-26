import numpy as np
from collections import deque
import time

class BaselineManager:
    def __init__(self):
        # 30-minute window of per-second counts (1800 seconds)
        self.history = deque([0] * 1800, maxlen=1800)
        self.effective_mean = 0.0
        self.effective_stddev = 0.0
        self.floor_mean = 5.0  # Prevents division by zero or overly sensitive alerts

    def add_count(self, count):
        """Adds the current second's request count to the history."""
        self.history.append(count)

    def recalculate(self):
        """
        Computes mean and stddev. 
        Requirements: Recalculate every 60 seconds.
        """
        data = list(self.history)
        self.effective_mean = max(np.mean(data), self.floor_mean)
        self.effective_stddev = np.std(data)
        return self.effective_mean, self.effective_stddev

    def get_z_score(self, current_rate):
        """Calculates how many standard deviations the current rate is from the mean."""
        if self.effective_stddev == 0:
            return 0
        return (current_rate - self.effective_mean) / self.effective_stddev
