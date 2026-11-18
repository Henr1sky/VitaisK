"""An error-rate baseline using one-minute buckets and exponentially weighted moments."""
from collections import OrderedDict
from dataclasses import dataclass
from math import sqrt

from ..events import Severity


@dataclass
class Rate:
    bucket: int
    count: int = 0
    samples: int = 0
    mean: float = 0.0
    square_mean: float = 0.0
    alerted: bool = False


class ErrorRates:
    def __init__(self, window, z_threshold, max_groups, saved=None):
        self.weight = 2 / (max(2, window // 60) + 1)
        self.z_threshold = z_threshold
        self.max_groups = max_groups
        self.rates = OrderedDict()
        if saved:
            for host, source, state in saved[-max_groups:]:
                self.rates[(host, source)] = Rate(**state)

    def snapshot(self):
        return [[host, source, vars(rate)] for (host, source), rate in self.rates.items()]

    def observe(self, event):
        if event.severity < Severity.ERROR:
            return None
        bucket = int(event.ts // 60)
        key = (event.host, event.source)
        rate = self.rates.setdefault(key, Rate(bucket))
        self.rates.move_to_end(key)
        if len(self.rates) > self.max_groups:
            self.rates.popitem(last=False)
        if bucket < rate.bucket:
            return None
        if bucket > rate.bucket:
            missing = bucket - rate.bucket - 1
            decay = (1 - self.weight) ** missing
            rate.mean = (rate.mean * (1 - self.weight) + rate.count * self.weight) * decay
            rate.square_mean = (
                rate.square_mean * (1 - self.weight) + rate.count**2 * self.weight
            ) * decay
            rate.samples += missing + 1
            rate.bucket, rate.count, rate.alerted = bucket, 0, False

        rate.count += 1
        if rate.samples < 6 or rate.count < 8 or rate.alerted:
            return None
        deviation = sqrt(max(1.0, rate.square_mean - rate.mean**2))
        z_score = (rate.count - rate.mean) / deviation
        if z_score < self.z_threshold:
            return None
        rate.alerted = True
        return rate.count, rate.bucket * 60, z_score
