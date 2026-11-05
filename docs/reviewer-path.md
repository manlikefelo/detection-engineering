# Repo guide

The fastest route through this repo, in the order that best shows detection thinking.

### 1. The coverage, at a glance (30 sec)
Open **[`coverage-matrix.md`](coverage-matrix.md)**. The ATT&CK grid shows the breadth:
5 techniques across 2 tactics, and, deliberately, the **gaps I don't claim to
cover**. A coverage matrix that's all green is a warning sign; this one isn't.

### 2. One detection, end to end (90 sec)
Open **[`detections/03-dcsync/`](../detections/03-dcsync/)**: the sharpest example:
- the **[Sigma rule](../detections/03-dcsync/dcsync_replication_rights.yml)** (portable source of truth),
- the **[doc](../detections/03-dcsync/README.md)** explaining the 4662 + replication-GUID logic and the auditing prerequisite,
- the deployed **Wazuh rule 100012**,
- and the **[verified alert JSON](https://github.com/manlikefelo/ad-attack-chain/blob/main/engagement/03-dcsync/evidence/wazuh_alert_100012.json)** proving it fired on the real attack.

That's the full loop: attack → log → rule → alert.

### 3. The tuning log: read this one (60 sec)
Open **[`tuning-log.md`](tuning-log.md)**. Two *real* false positives, why each fired,
and how I suppressed or managed it, including the trade-off reasoning. This is the
part that separates someone who *writes* a rule from someone who *runs* detections in
production, and it taught me the most.

---

**What this repo shows:** I can author portable Sigma detections, deploy them in a
real SIEM, validate them against live attacks, tune out false positives with clear
reasoning, and assess where my coverage ends. Paired with
[ad-attack-chain](https://github.com/manlikefelo/ad-attack-chain), it's a complete purple-team demonstration:
I ran the attack, and I catch it.
