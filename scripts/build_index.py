#!/usr/bin/env python3
"""Rebuild index.json from the artifact files.

`index.json` is the only thing a consuming deployment fetches to *browse* — one small file
rather than a walk of the whole repo. Individual artifacts are fetched on import.

It is generated, never hand-edited: CI rebuilds it on every merge to main, so an edit by hand
is simply overwritten.

Each entry carries what the catalog needs to render and filter a row without downloading the
artifact — crucially `required_fields`, which lets a deployment answer "will this work on my
data?" against its own live OpenSearch field mapping *before* fetching anything.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "index.json"

ARTIFACT_DIRS = ("rules", "playbooks")

# Wazuh document field a correlation key resolves to. Mirrors
# correlations.services.search_compiler.CORRELATION_KEY_TO_WAZUH_FIELD — the rule must be able
# to read the field it aggregates on, so it counts as required.
CORRELATION_KEY_TO_WAZUH_FIELD = {
    "host.name": "agent.name",
    "source.ip": "data.srcip",
    "user.name": "data.dstuser",
    "file.hash.sha256": "data.sha256",
    "process.name": "data.audit.comm",
}


def derive_required_fields(spec: dict) -> list:
    """Every raw Wazuh field path this rule must be able to read to work at all.

    Derived from the rule's own legs rather than declared by its author, so compatibility
    metadata cannot drift from what the rule actually does.
    """
    fields = set()

    wazuh_key_field = CORRELATION_KEY_TO_WAZUH_FIELD.get(spec.get("correlation_key"))
    if wazuh_key_field:
        fields.add(wazuh_key_field)

    for leg in spec.get("legs") or []:
        for name in (leg.get("distinct_field"), leg.get("novelty_field")):
            if name:
                fields.add(name)
        for condition in leg.get("conditions") or []:
            if condition.get("field_name"):
                fields.add(condition["field_name"])

    return sorted(fields)


def entry_for(path: Path) -> dict | None:
    try:
        artifact = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        print(f"skipping {path.name}: not valid YAML ({exc})", file=sys.stderr)
        return None

    if not isinstance(artifact, dict) or not artifact.get("uuid"):
        print(f"skipping {path.name}: no uuid", file=sys.stderr)
        return None

    spec = artifact.get("spec") or {}
    kind = artifact.get("kind")

    # Trust the file's own required_fields only if present; otherwise derive. A search rule's
    # is always re-derived, so a stale hand-edited list cannot mislead the compatibility filter.
    if kind == "search_rule":
        required_fields = derive_required_fields(spec)
    else:
        required_fields = list(artifact.get("required_fields") or [])

    return {
        "uuid": str(artifact["uuid"]),
        "revision": artifact.get("revision", 1),
        "kind": kind,
        "status": artifact.get("status", "active"),
        "status_reason": artifact.get("status_reason", ""),
        "name": artifact.get("name", ""),
        "description": artifact.get("description", ""),
        "tags": list(artifact.get("tags") or []),
        "attack_techniques": list(artifact.get("attack_techniques") or []),
        "required_fields": required_fields,
        "path": str(path.relative_to(ROOT)),
    }


def main() -> int:
    entries = []
    for directory in ARTIFACT_DIRS:
        for pattern in ("*.yml", "*.yaml"):
            for path in sorted((ROOT / directory).glob(pattern)):
                entry = entry_for(path)
                if entry:
                    entries.append(entry)

    entries.sort(key=lambda e: (e["kind"], e["name"].lower(), e["uuid"]))

    INDEX.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {INDEX.name} with {len(entries)} artifact(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
