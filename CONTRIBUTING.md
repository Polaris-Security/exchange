# Contributing

## The one rule that shapes everything else

**Artifacts are repo-owned, not publisher-owned.** Anyone may open a pull request revising
anyone's artifact. The original publisher is credited, not privileged.

This exists so one detection has *one* canonical artifact. If improving someone's rule meant
forking it into a new one, the commons would fill with near-identical detections that importers
cannot choose between, and every fix would have to be made several times. Found a false positive
in someone's second leg? PR the fix into their file.

## Identity

An artifact's identity is the `uuid` **inside the file**. Not its path, not its filename, not its
git SHA — all three move, and consuming deployments track artifacts by UUID so that upstream
reorganisation never breaks a mirror.

Two consequences:

- **Never change a `uuid`.** Changing it orphans every deployment mirroring that artifact.
- **Always bump `revision`** when you change anything else. Consumers compare revisions to decide
  whether they have work to do; an edit that doesn't bump is an edit nobody receives.

Renaming or moving a file is fine — the UUID carries the identity.

## Publishing from Polaris (the easy path)

In your deployment: open a Scheduled Search Rule or playbook → **Publish to Exchange**.

It assembles the artifact, derives its `required_fields` from the rule's own legs, scans the
exact outgoing payload against your own tenants' identifiers, makes you confirm each finding,
and opens the pull request under your own GitHub account. Publishing the same artifact again
later produces a *revision*, not a competing artifact.

## Publishing by hand

1. Fork this repo.
2. Add or edit a file under `rules/` or `playbooks/`. Filenames are for humans:
   `rules/<slug>-<first-8-of-uuid>.yml`.
3. Generate a fresh UUID for a new artifact (`python -c "import uuid; print(uuid.uuid4())"`), or
   keep the existing one and bump `revision` for a change.
4. Validate locally: `python scripts/validate_artifacts.py`
5. Open a pull request.

The schema lives in [`schema/artifact.schema.json`](schema/artifact.schema.json), and
`rules/ssh-brute-force-*.yml` is a worked example of every field.

## What CI enforces

`validate_artifacts.py` runs on every pull request and **fails** on:

- malformed YAML, a missing or non-UUID `uuid`, a non-positive `revision`
- an unknown `kind` or `status`
- a duplicate `uuid` across the repo
- a `search_rule` with no legs, or a condition with an unknown operator or no `field_name`
- a `playbook` with no items, an item with no title, or no `subject_slug`
- **a `rule.id` condition at or above `100000`** — see below
- **an email address or a public IP literal anywhere in the artifact**

The last two are the ones people trip over, so they're worth understanding rather than working
around.

### Why custom `rule.id` is rejected

Wazuh reserves ids ≥ `100000` for local rules. A leg matching `rule.id = 100234` means whatever
*your* manager assigned; on an importing manager that integer names something else entirely.
The artifact doesn't fail there — it matches, confidently, and produces plausible-looking
incidents about the wrong events. Nothing downstream can detect this, which is exactly why it is
blocked at the door.

If you need to share a detection built on a custom rule, express it in terms of the underlying
fields (`data.*`, `decoder.name` where it ships with Wazuh, `rule.groups` from the stock
ruleset) rather than the id.

### Why IPs and email addresses are rejected

They are almost always someone's real infrastructure, and this repo is public and permanent.

If an address is genuinely part of the detection — a known-bad C2, a public threat-intel
indicator — say so in the pull request and a maintainer can merge past the check. Private ranges
in a CIDR condition (`10.0.0.0/8`) are fine and not flagged; a bare literal is.

## Review

A maintainer looks for:

- **Is it portable?** Would this work on a Wazuh deployment that isn't yours?
- **Is it honest about volume?** A rule that fires constantly is worse than no rule. Say what
  you've seen it do on real data.
- **Does it leak?** Especially in `spec.tests[].samples` — those are usually pasted from a real
  match, and are the single likeliest place for a customer hostname to hide.
- **Are the tests meaningful?** A `search_rule` with tests is far more adoptable than one
  without: they're what let a stranger verify your detection rather than trust it.

## Retracting

Never delete the file. Set `status` to `deprecated` (superseded — consumers are told, the rule
keeps running) or `withdrawn` (harmful — consumers **auto-disable it on their next sync**), give
a `status_reason`, and bump `revision`.
