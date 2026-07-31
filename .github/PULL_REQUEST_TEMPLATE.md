<!--
Publishing from inside Polaris fills most of this in for you.
Artifacts are repo-owned: revising someone else's file is welcome and is the preferred way to
fix a detection, rather than adding a near-duplicate.
-->

## What this is

<!-- What does it detect, or what procedure does it describe? When should another SOC adopt it? -->

- **Artifact UUID:**
- **Revision:**
- [ ] New artifact (fresh UUID)
- [ ] Revision of an existing artifact (same UUID, `revision` bumped)
- [ ] Retraction (`status` set to `deprecated` or `withdrawn`, with a `status_reason`)

## Volume

<!--
The single most useful thing you can tell an adopter. A rule that fires constantly is worse
than no rule.
-->

What have you seen this do on real data? Roughly how often does it fire, over what estate?

## Portability

- [ ] No `rule.id` in Wazuh's local range (>= 100000)
- [ ] No custom `decoder.name` or `rule.groups` from a local ruleset
- [ ] Works on a stock Wazuh deployment, not just mine

## Leak check

<!--
This repository is public and git history outlives deletion. Sample documents are the likeliest
hiding place, because they are usually pasted from a real match.
-->

- [ ] No real hostnames, internal addressing, usernames, or domains — **including in
      `spec.tests[].samples`**
- [ ] No customer or organisation names, no ticket references
- [ ] Any IP or email literal that remains is a deliberate threat indicator, explained below

## Tests

- [ ] Includes rule tests (`spec.tests`), or explains below why not

<!-- Tests are what let a stranger verify your detection rather than trust it. -->
