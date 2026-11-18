"""Regression tests for overlapping collectors and correlation field boundaries."""
from unittest import TestCase

from vitaisk.engine.pipeline import Pipeline
from vitaisk.events import make_event
from vitaisk.rules.loader import load_rules


def ssh(ts, category="ssh_failed", user="example", collector="authlog"):
    return make_event(
        ts=ts, source="auth", host="host", category=category, severity="WARN",
        message=category, src_ip="192.0.2.3", user=user,
        extra={"collector": collector},
    )


class DetectionTests(TestCase):
    def setUp(self):
        self.pipeline = Pipeline(load_rules())

    def test_same_record_seen_by_journal_and_authlog_only_counts_once(self):
        for ts in (2, 4, 6, 8):
            self.assertFalse(list(self.pipeline.process(ssh(ts))))
            self.assertFalse(list(self.pipeline.process(ssh(ts, collector="journal"))))

        alerts = list(self.pipeline.process(ssh(10)))
        self.assertEqual([(alert.rule_id, alert.event_count) for alert in alerts],
                         [("ssh-brute-force", 5)])

    def test_login_after_failures_requires_same_user(self):
        for ts in (2, 4, 6, 8, 10):
            list(self.pipeline.process(ssh(ts)))

        wrong_user = ssh(11, "ssh_login", user="another")
        self.assertFalse(list(self.pipeline.process(wrong_user)))

        login = ssh(12, "ssh_login")
        alerts = list(self.pipeline.process(login))
        self.assertEqual([(alert.rule_id, alert.event_count) for alert in alerts],
                         [("ssh-fail-then-success", 6)])
