# ATT&CK coverage matrix

At-a-glance breadth: which MITRE ATT&CK techniques this repo's detections cover, laid
out on the tactics they belong to. This is the first thing to look at — it shows the
shape of the coverage and, just as importantly, the **honest gaps**.

## The grid

Columns are ATT&CK **tactics**; each cell is a technique with its detection status.
✅ = detection built **and verified firing** end-to-end · ⬜ = in scope but not covered.

| Credential Access | Discovery | Persistence |
|---|---|---|
| ✅ **T1558.003** Kerberoasting<br>`rule 100010` | ✅ **T1087.002** Account Discovery: Domain<br>`rule 100013` | ⬜ **T1558.001** Golden Ticket<br>*(enabled by DCSync, not detected — see gaps)* |
| ✅ **T1558.004** AS-REP Roasting<br>`rule 100011` | ✅ **T1069.002** Permission Groups Discovery<br>`rule 100013` (same burst) | |
| ✅ **T1003.006** DCSync<br>`rule 100012` | ⬜ **T1482** Domain Trust Discovery<br>*(part of the burst, not keyed on)* | |
| ⬜ **T1110.002** Password Cracking<br>*(offline, off-host — no telemetry by design)* | | |

## Summary

- **5 techniques detected end-to-end**, across **2 tactics** (Credential Access,
  Discovery), via **4 custom Wazuh rules** (`100010`–`100013`), each backed by a
  portable Sigma rule.
- Every detection is paired 1:1 with a **real attack** in the
  [ad-attack-chain](../../ad-attack-chain) repo and **verified firing** — see
  [`../validation.md`](../validation.md).

## Honest gaps (what I do *not* claim to cover)

- **T1110.002 Password Cracking** — happens offline on the attacker's box; there is no
  host telemetry to detect, by design. Listed for completeness, not coverage.
- **T1558.001 Golden Ticket** — DCSync recovers the `krbtgt` hash that *enables*
  forging a Golden Ticket, but forging is offline and *using* one is a separate
  detection problem (anomalous TGT lifetimes, RC4 TGS-REQ patterns). Out of scope here.
- **T1482 Domain Trust Discovery** — BloodHound enumerates trusts as part of the same
  read burst, so rule `100013` catches the *activity* but isn't specifically keyed on
  trust queries. I count it as "swept up," not "targeted."

Calling these out is deliberate: a coverage matrix that's all ✅ is a red flag. Knowing
where your visibility ends is part of the job.

## How to reproduce the ATT&CK Navigator layer

For a colour-coded Navigator view, the covered technique IDs are:
`T1558.003, T1558.004, T1003.006, T1087.002, T1069.002`. Paste them into a new layer
at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
and score them to render the same grid visually.
