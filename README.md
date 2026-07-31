# Polaris Knowledge Exchange

A commons for security-operations knowledge, shared between independent [Polaris](https://github.com/ReyhZhao/Polaris)
deployments. One SOC works out which raw Wazuh fields matter, what threshold separates signal
from noise, and which leg combination catches an attack without drowning the analysts — and
every other SOC gets to start from there instead of from scratch.

Its unit is the **Exchange Artifact**: one versioned, self-contained, deployment-agnostic YAML
file. Two kinds today:

| Kind | Lives in | What it is |
|---|---|---|
| `search_rule` | `rules/` | A Scheduled Search Rule bundled with its Rule Tests |
| `playbook` | `playbooks/` | A response procedure (a task template) |

## Using it

You don't clone this repo. A Polaris deployment reads it directly — set
`KNOWLEDGE_EXCHANGE_REPO=Polaris-Security/exchange` and the Knowledge Exchange page lists
everything here, filtered against **your own** OpenSearch field mapping so you can see which
artifacts will actually work on your data.

**Reading needs no credentials.** Browsing and importing hit `raw.githubusercontent.com`
anonymously. Only *publishing* authenticates, using the operator's own GitHub account.

Nothing you import fires on its own. An imported rule lands **mirrored** — present and inert —
and stays that way until a human enables it, after a **Backtest** has dry-run it against that
deployment's own recent data and reported the volume it would have produced *per tenant*.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: artifacts here are **repo-owned, not
publisher-owned**. Anyone may open a pull request revising anyone's artifact, and one detection
has one canonical artifact rather than a family of near-duplicates. The original publisher is
credited, not privileged.

The easiest way to contribute is from inside Polaris — "Publish to Exchange" on any rule or
playbook assembles the artifact, scans it for anything belonging to your own tenants, and opens
the pull request under your GitHub account.

## What must never be in here

This is a **public** repository, and git history outlives any deletion. Before anything lands:

- **No customer data.** No real hostnames, internal addressing, usernames, domains, email
  addresses, or ticket references. The likeliest place for these to hide is a rule test's
  sample documents, because they are usually pasted from a real match.
- **No deployment-local Wazuh identifiers.** A `rule.id` at or above `100000` is local to one
  manager. On an importing deployment that integer names a *different* rule, so the artifact
  will match confidently and wrongly, and nothing downstream can tell. The same goes for
  custom `decoder.name` and `rule.groups` values.

CI rejects both automatically, but CI is a backstop, not the reviewer.

## Retraction

Artifacts are **never deleted** — a missing file is indistinguishable from a botched merge or a
path rename, and consuming deployments are built to treat it as exactly that (an accident, not a
signal). To take one out of service, set its `status` in the file:

- `deprecated` — superseded or obsolete. Consumers are notified; the rule keeps running.
- `withdrawn` — harmful or wrong. Consumers **auto-disable it immediately**, without waiting
  for anyone to read a notification.

Always give a `status_reason`.

## Layout

```
rules/            search_rule artifacts
playbooks/        playbook artifacts
index.json        generated on merge — do not edit by hand
schema/           the artifact contract
scripts/          index builder + validator (run by CI)
```

`index.json` is what deployments actually fetch to browse. It is rebuilt from the artifact files
on every merge to `main`; editing it by hand achieves nothing.

## Licence

Artifacts in this repository are Apache-2.0 (see [LICENSE](LICENSE)). Contributing means you are
fine with that.
