# ATT&CK coverage matrix

At-a-glance breadth: which MITRE ATT&CK techniques this repo's detections cover, laid
out on the tactics they belong to. This is the first thing to look at. It shows the
shape of the coverage and, just as importantly, the **known gaps**.

## The grid

Columns are ATT&CK **tactics**; each cell is a technique with its detection status.
Entries with a rule number are built **and verified firing** end-to-end. Entries marked *Not covered* are in scope but have no detection.

| Credential Access | Discovery | Initial Access | Persistence |
|---|---|---|---|
| **T1558.003** Kerberoasting<br>`rule 100010` | **T1087.002** Account Discovery: Domain<br>`rule 100013` | **T1190** Exploit Public-Facing App (web SQLi)<br>`rule 100014` | *Not covered:* **T1558.001** Golden Ticket<br>*(enabled by DCSync, not detected)* |
| **T1558.004** AS-REP Roasting<br>`rule 100011` | **T1069.002** Permission Groups Discovery<br>`rule 100013` (same burst) | **T1190** Exploit Public-Facing App (web XSS)<br>`rule 100015` | |
| **T1003.006** DCSync<br>`rule 100012` | *Not covered:* **T1482** Domain Trust Discovery<br>*(part of the burst, not keyed on)* | | |
| *Not covered:* **T1110.002** Password Cracking<br>*(offline, off-host: no telemetry by design)* | | | |

## Summary

- **6 techniques detected end-to-end**, across **3 tactics** (Credential Access,
  Discovery, Initial Access), via **6 custom Wazuh rules** (`100010`–`100015`), each
  backed by a portable Sigma rule.
- The web rules (`100014`/`100015`, T1190) close the red→blue loop for the
  [web pentest](https://github.com/manlikefelo/webapp-pentest-juiceshop) the same way `100010`–`100013` do for
  the AD attacks.
- Every detection is paired 1:1 with a **real attack** in the
  [ad-attack-chain](https://github.com/manlikefelo/ad-attack-chain) repo and **verified firing**, see
  [`../validation.md`](../validation.md).

## Known gaps

- **T1110.002 Password Cracking**: happens offline on the attacker's box; there is no
  host telemetry to detect, by design. Listed for completeness, not coverage.
- **T1558.001 Golden Ticket**: DCSync recovers the `krbtgt` hash that *enables*
  forging a Golden Ticket, but forging is offline and *using* one is a separate
  detection problem (anomalous TGT lifetimes, RC4 TGS-REQ patterns). Out of scope here.
- **T1482 Domain Trust Discovery**: BloodHound enumerates trusts as part of the same
  read burst, so rule `100013` catches the *activity* but isn't specifically keyed on
  trust queries. I count it as "swept up," not "targeted."

Calling these out is deliberate: a coverage matrix that's all is a red flag. Knowing
where your visibility ends is part of the job.

## How to reproduce the ATT&CK Navigator layer

For a colour-coded Navigator view, the covered technique IDs are:
`T1558.003, T1558.004, T1003.006, T1087.002, T1069.002, T1190`. Paste them into a new layer
at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
and score them to render the same grid visually.
