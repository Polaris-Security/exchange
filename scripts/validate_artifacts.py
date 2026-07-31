#!/usr/bin/env python3
"""Validate every Exchange Artifact in this repository.

Run by CI on every pull request; run it locally before opening one:

    python scripts/validate_artifacts.py

Two classes of check, and the second is the interesting one:

* **Shape** — does this parse into something a Polaris deployment can import at all?
  Mirrors `exchange/services/artifact.py::read_rule_artifact` on the consuming side, so an
  artifact that lands here is one that will import rather than erroring on someone's box.

* **Safety** — is there anything in here that must not be in a public repo, or that is
  *deployment-local* and would therefore mean something different on an importing manager?
  This is a backstop behind human review, not a replacement for it.

Exit code 0 = clean, 1 = at least one error.
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
import uuid as uuid_module
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

ROOT = Path(__file__).resolve().parent.parent

KIND_DIRS = {"search_rule": "rules", "playbook": "playbooks"}
VALID_KINDS = set(KIND_DIRS)
VALID_STATUSES = {"active", "deprecated", "withdrawn"}

# Mirrors correlations.models.SEARCH_OPERATOR_CHOICES / SEARCH_COUNT_OP_CHOICES.
VALID_OPERATORS = {"equals", "contains", "gte", "lte", "cidr"}
VALID_COUNT_OPS = {"gte", "lte"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_CORRELATION_KEYS = {
    "host.name", "source.ip", "user.name", "file.hash.sha256", "process.name", "none",
}
VALID_TIME_WINDOW_MODES = {"inside", "outside"}

# Wazuh reserves ids at or above this for local rules. Such an id names a *different* rule on
# every manager, so an artifact carrying one matches confidently and wrongly downstream.
CUSTOM_RULE_ID_FLOOR = 100000

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Addresses that are examples by standard, not someone's infrastructure.
DOC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),    # RFC 5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"), # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # RFC 5737 TEST-NET-3
]
EXAMPLE_DOMAINS = ("example.com", "example.org", "example.net", "example.invalid")


class Problems:
    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, path, message):
        self.errors.append(f"{path}: {message}")

    def warn(self, path, message):
        self.warnings.append(f"{path}: {message}")


def _walk_strings(node, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk_strings(value, f"{path}.{key}" if path else str(key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk_strings(value, f"{path}[{index}]")
    elif isinstance(node, str):
        yield path, node


def _is_documentation_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    if address.is_private or address.is_loopback or address.is_unspecified:
        return True
    return any(address in network for network in DOC_NETWORKS)


def check_envelope(artifact, rel, problems, seen_uuids):
    artifact_uuid = artifact.get("uuid")
    if not artifact_uuid:
        problems.error(rel, "missing 'uuid'")
    else:
        try:
            uuid_module.UUID(str(artifact_uuid))
        except (ValueError, AttributeError, TypeError):
            problems.error(rel, f"'uuid' is not a UUID: {artifact_uuid!r}")
        else:
            if str(artifact_uuid) in seen_uuids:
                problems.error(
                    rel,
                    f"duplicate uuid {artifact_uuid} — already used by "
                    f"{seen_uuids[str(artifact_uuid)]}. One detection, one artifact: "
                    "revise the existing file instead of adding a second.",
                )
            else:
                seen_uuids[str(artifact_uuid)] = rel

    revision = artifact.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        problems.error(rel, f"'revision' must be a positive integer, got {revision!r}")

    kind = artifact.get("kind")
    if kind not in VALID_KINDS:
        problems.error(rel, f"unknown 'kind' {kind!r} (expected one of {sorted(VALID_KINDS)})")
    else:
        expected_dir = KIND_DIRS[kind]
        if not rel.startswith(f"{expected_dir}/"):
            problems.error(rel, f"a {kind!r} artifact belongs under {expected_dir}/")

    status = artifact.get("status", "active")
    if status not in VALID_STATUSES:
        problems.error(rel, f"unknown 'status' {status!r} (expected one of {sorted(VALID_STATUSES)})")
    elif status != "active" and not (artifact.get("status_reason") or "").strip():
        problems.error(rel, f"'status: {status}' needs a 'status_reason' — consumers show it to their operators")

    if not (artifact.get("name") or "").strip():
        problems.error(rel, "missing 'name'")

    return kind


def check_search_rule(spec, rel, problems):
    severity = spec.get("severity", "medium")
    if severity not in VALID_SEVERITIES:
        problems.error(rel, f"unknown severity {severity!r}")

    key = spec.get("correlation_key", "none")
    if key not in VALID_CORRELATION_KEYS:
        problems.error(rel, f"unknown correlation_key {key!r}")

    mode = spec.get("time_window_mode", "inside")
    if mode not in VALID_TIME_WINDOW_MODES:
        problems.error(rel, f"unknown time_window_mode {mode!r}")

    legs = spec.get("legs") or []
    if not legs:
        problems.error(rel, "a search_rule must carry at least one leg")

    for index, leg in enumerate(legs):
        if not isinstance(leg, dict):
            problems.error(rel, f"leg {index} is not a mapping")
            continue

        count_op = leg.get("count_operator", "gte")
        if count_op not in VALID_COUNT_OPS:
            problems.error(rel, f"leg {index}: unknown count_operator {count_op!r}")
        if count_op == "lte" and key != "none":
            # Mirrors the consuming side: a terms aggregation cannot enumerate which keys went
            # silent, so there is no key universe to evaluate per-key absence against.
            problems.error(
                rel,
                f"leg {index}: an absence firing (count_operator 'lte') requires "
                "correlation_key 'none' — importing deployments reject the combination",
            )

        conditions = leg.get("conditions") or []
        if not conditions:
            problems.warn(rel, f"leg {index} has no conditions — it will match every document")

        for position, condition in enumerate(conditions):
            where = f"leg {index} condition {position}"
            if not isinstance(condition, dict):
                problems.error(rel, f"{where} is not a mapping")
                continue

            operator = condition.get("operator")
            if operator not in VALID_OPERATORS:
                problems.error(rel, f"{where}: unknown operator {operator!r}")

            field = condition.get("field_name")
            if not field:
                problems.error(rel, f"{where}: missing field_name")

            value = str(condition.get("value", ""))
            if field == "rule.id":
                for token in re.findall(r"\d+", value):
                    if int(token) >= CUSTOM_RULE_ID_FLOOR:
                        problems.error(
                            rel,
                            f"{where}: rule.id {token} is in Wazuh's local range (>= "
                            f"{CUSTOM_RULE_ID_FLOOR}). That id names a different rule on every "
                            "manager, so this artifact would match confidently and wrongly "
                            "elsewhere. Express the detection in terms of fields instead.",
                        )

    for index, test in enumerate(spec.get("tests") or []):
        if not isinstance(test, dict):
            problems.error(rel, f"test {index} is not a mapping")
            continue
        if not (test.get("name") or "").strip():
            problems.error(rel, f"test {index}: missing name")
        if not isinstance(test.get("samples") or [], list):
            problems.error(rel, f"test {index}: 'samples' must be a list")

    if not (spec.get("tests") or []):
        problems.warn(
            rel,
            "no rule tests — tests are what let a stranger verify this detection "
            "rather than trust it",
        )


def check_playbook(spec, rel, problems):
    if not (spec.get("subject_slug") or "").strip():
        problems.error(rel, "a playbook must name a 'subject_slug'")

    items = spec.get("items") or []
    if not items:
        problems.error(rel, "a playbook must carry at least one item")

    for index, item in enumerate(items):
        if not isinstance(item, dict):
            problems.error(rel, f"item {index} is not a mapping")
            continue
        if not (item.get("title") or "").strip():
            problems.error(rel, f"item {index}: missing title")


def check_no_leaks(artifact, rel, problems):
    """Public repo, permanent history. A backstop behind human review, not a replacement."""
    cidr_values = {
        str(condition.get("value") or "")
        for leg in (artifact.get("spec") or {}).get("legs") or []
        for condition in leg.get("conditions") or []
        if condition.get("operator") == "cidr"
    }

    for path, text in _walk_strings(artifact):
        if text in cidr_values:
            continue  # a CIDR is ordinary detection content, not a leaked address

        for match in EMAIL_RE.findall(text):
            if match.lower().endswith(EXAMPLE_DOMAINS):
                continue
            problems.error(
                rel,
                f"{path}: email address {match!r}. If it is genuinely part of the detection, "
                "say so in the pull request so a maintainer can merge past this.",
            )

        for match in IPV4_RE.findall(text):
            if _is_documentation_ip(match):
                continue
            problems.error(
                rel,
                f"{path}: public IP literal {match!r}. If it is a known-bad indicator rather "
                "than someone's infrastructure, say so in the pull request.",
            )


def validate_file(path: Path, problems: Problems, seen_uuids: dict) -> None:
    rel = str(path.relative_to(ROOT))

    try:
        artifact = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        problems.error(rel, f"not valid YAML: {exc}")
        return

    if not isinstance(artifact, dict):
        problems.error(rel, "did not parse to a mapping")
        return

    kind = check_envelope(artifact, rel, problems, seen_uuids)

    spec = artifact.get("spec")
    if not isinstance(spec, dict):
        problems.error(rel, "missing or malformed 'spec'")
        return

    if kind == "search_rule":
        check_search_rule(spec, rel, problems)
    elif kind == "playbook":
        check_playbook(spec, rel, problems)

    check_no_leaks(artifact, rel, problems)


def main() -> int:
    problems = Problems()
    seen_uuids: dict[str, str] = {}

    paths = sorted(
        p
        for directory in KIND_DIRS.values()
        for p in (ROOT / directory).glob("*.yml")
    ) + sorted(
        p
        for directory in KIND_DIRS.values()
        for p in (ROOT / directory).glob("*.yaml")
    )

    for path in paths:
        validate_file(path, problems, seen_uuids)

    for warning in problems.warnings:
        print(f"warning: {warning}")

    if problems.errors:
        print()
        for error in problems.errors:
            print(f"error: {error}")
        print(f"\n{len(problems.errors)} error(s) in {len(paths)} artifact(s).")
        return 1

    print(f"{len(paths)} artifact(s) validated, {len(problems.warnings)} warning(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
