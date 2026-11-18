"""Load bundled rules and user overrides through the same validation path."""
from importlib.resources import files
from pathlib import Path

import re

import yaml

from ..events import Event, SOURCES, Severity
from ..utils import config_dir

_MATCH_KEYS = {"source", "category", "contains", "equals", "regex"}
_RULE_KEYS = _MATCH_KEYS | {"id", "group_by", "threshold", "window", "severity", "followed_by", "distinct", "suggested_actions", "match_window"}
_FIELDS = set(Event.__dataclass_fields__)
_GROUP_FIELDS = _FIELDS - {"extra"}


def _strings(value):
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and bool(item) for item in value
    )


def _match_valid(match):
    if "source" in match and match["source"] not in SOURCES:
        return False
    if "category" in match and not (
        isinstance(match["category"], str) and match["category"] or _strings(match["category"])
    ):
        return False
    if "contains" in match and not _strings(match["contains"]):
        return False
    if "regex" in match:
        if not isinstance(match["regex"], str) or not match["regex"]:
            return False
        re.compile(match["regex"], re.IGNORECASE)
    equals = match.get("equals", {})
    return isinstance(equals, dict) and set(equals) <= _FIELDS and bool(set(match) & _MATCH_KEYS)


def _validate(rule):
    if not isinstance(rule, dict) or rule.keys() - _RULE_KEYS:
        raise ValueError("invalid rule fields")
    if not isinstance(rule.get("id"), str) or not rule["id"].strip() or not _match_valid(rule):
        raise ValueError("invalid rule id or match")
    threshold = rule.get("threshold", 1)
    window = rule.get("window", 0)
    groups = rule.get("group_by", [])
    if type(threshold) is not int or threshold < 1 or type(window) is not int or window < 0:
        raise ValueError(f"{rule['id']}: invalid threshold or window")
    if not isinstance(groups, list) or (groups and not _strings(groups)) or set(groups) - _GROUP_FIELDS:
        raise ValueError(f"{rule['id']}: invalid group_by")
    distinct = rule.get("distinct")
    if distinct is not None and (not isinstance(distinct, str) or distinct not in _GROUP_FIELDS):
        raise ValueError(f"{rule['id']}: invalid distinct field")
    if "suggested_actions" in rule and not _strings(rule["suggested_actions"]):
        raise ValueError(f"{rule['id']}: invalid suggested actions")
    terminal = rule.get("followed_by")
    if terminal is not None and (
        not isinstance(terminal, dict) or terminal.keys() - _MATCH_KEYS or not _match_valid(terminal)
    ):
        raise ValueError(f"{rule['id']}: invalid followed_by")
    match_window = rule.get("match_window")
    if match_window is not None and (
        terminal is None or type(match_window) is not int or not 0 < match_window <= window
    ):
        raise ValueError(f"{rule['id']}: invalid match_window")
    if (threshold > 1 or terminal is not None) and not window:
        raise ValueError(f"{rule['id']}: a positive window is required")
    try:
        Severity.parse(rule.get("severity", "WARN"))
    except (AttributeError, KeyError, ValueError) as exc:
        raise ValueError(f"{rule['id']}: invalid severity") from exc


def load_rules(directory: Path | None = None):
    directory = directory if directory is not None else config_dir() / "rules.d"
    paths = [files(__package__).joinpath("builtin.yaml")]
    paths.extend(sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")]))
    rules = {}
    for path in paths:
        try:
            entries = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(entries, list):
                raise ValueError("expected a list of rules")
            seen = set()
            for rule in entries:
                _validate(rule)
                if rule["id"] in seen:
                    raise ValueError(f"duplicate id {rule['id']}")
                for match in (rule, rule.get("followed_by") or {}):
                    if "contains" in match:
                        match["contains"] = [token.casefold() for token in match["contains"]]
                seen.add(rule["id"])
                rules[rule["id"]] = rule
        except (ValueError, re.error, yaml.YAMLError) as exc:
            raise ValueError(f"{path}: {exc}") from exc
    return rules
