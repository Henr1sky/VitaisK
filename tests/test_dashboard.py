"""Regressions for dashboard filters, severity, and selection during collection."""
from unittest import TestCase

from vitaisk.config import Config
from vitaisk.dashboard import Dashboard, PulseSample, ViewFilter, pulse_trace
from vitaisk.engine.pipeline import Pipeline
from vitaisk.events import Severity, make_event
from vitaisk.rules.loader import load_rules
from vitaisk.watch import KeyReader


def ssh(timestamp, *, host="host", address="192.0.2.1", message="SSH failure"):
    return make_event(
        ts=timestamp, source="auth", host=host, category="ssh_failed", severity="INFO",
        message=message, src_ip=address, user="example",
    )


class DashboardTests(TestCase):
    def test_filters_include_contributing_source_and_use_alert_severity(self):
        pipeline = Pipeline(load_rules())
        for port in range(20):
            firewall = make_event(
                ts=100 + port / 5, source="firewall", host="host", category="firewall_block",
                severity="WARN", src_ip="192.0.2.1", dst_ip="192.0.2.2", dst_port=1000 + port,
                protocol="TCP", message="Firewall record",
            )
            list(pipeline.process(firewall))
        self.assertFalse(list(pipeline.process(ssh(105, address="192.0.2.9"))))
        self.assertFalse(list(pipeline.process(ssh(106, host="different"))))
        event = ssh(107)
        alerts = tuple(pipeline.process(event))
        self.assertEqual([alert.rule_id for alert in alerts], ["inbound-scan-then-ssh-fail"])
        self.assertEqual(alerts[0].sources_matched, ["auth", "firewall"])

        options = {"view": "anomalies", "min_level": "ERROR", "sources": ("firewall",),
                   "grep": "ssh", "ip": "192.0.2.1", "ignore": ("debug",)}
        self.assertTrue(ViewFilter(Config(), **options).matches(event, alerts))
        for field, value in (("min_level", "CRITICAL"), ("sources", ("kernel",)),
                             ("grep", "invalid"), ("ip", "192.0.2.9"), ("ignore", ("FAIL",))):
            with self.subTest(field=field):
                self.assertFalse(ViewFilter(Config(), **{**options, field: value}).matches(event, alerts))
        self.assertFalse(ViewFilter(Config(), view="anomalies").matches(event, ()))
        self.assertFalse(ViewFilter(Config(), view="important").matches(event, ()))
        self.assertTrue(ViewFilter(Config(), view="all").matches(event, ()))
        event.src_ip = "2001:0db8::1"
        self.assertTrue(ViewFilter(Config(), view="all", ip="2001:db8::1").matches(event, ()))

    def test_browsing_keeps_selection_stable_until_return_to_live(self):
        config = Config()
        dashboard = Dashboard(config, ViewFilter(config, view="all"))
        recent = [(ssh(101), ()), (ssh(102), ())]
        dashboard.handle("down", recent)
        recent.append((ssh(103), ()))
        dashboard.handle("enter", recent)
        self.assertEqual(dashboard.details[0].ts, 101)
        dashboard.handle("esc", recent)
        dashboard.handle("home", recent)
        dashboard.handle("enter", recent)
        self.assertEqual(dashboard.details[0].ts, 103)

    def test_trace_colors_each_sample_instead_of_coloring_whole_history(self):
        samples = [PulseSample(1), PulseSample(3, Severity.WARN), PulseSample(1, Severity.ERROR)]
        trace = pulse_trace(samples, 3)
        self.assertEqual([span.style for span in trace.spans[:3]],
                         ["bright_green", "bright_yellow", "bright_red"])

    def test_terminal_decodes_split_arrows_and_utf8_input(self):
        reader = KeyReader()
        self.assertEqual(list(reader.feed(b"\x1b[")), [])
        self.assertEqual(list(reader.feed(b"A")), ["up"])
        self.assertEqual(list(reader.feed(b"\xc3")), [])
        self.assertEqual(list(reader.feed(b"\xa7\r")), ["ç", "enter"])
