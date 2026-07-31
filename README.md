# Detection Engineering — Sigma + Wazuh 🔵

The blue-team half of a purple-team pair. In my [ad-attack-chain](../ad-attack-chain)
repo I compromised an Active Directory domain; **here I detect every one of those
attacks** — written as portable **Sigma** rules (the source of truth) and deployed as
**Wazuh** rules in my single-node SIEM, each **verified firing end-to-end** against
the real attack.

> **The purple-team story:** I attacked in repo A, and here's how I catch myself in
> repo B. Detecting the exact attacks you launched — on the same telemetry, mapped to
> the same ATT&CK IDs — is the demonstration that turns "I ran some tools" into "I
> understand both sides of the event."

---

## What's here

```
detections/
  01-kerberoasting/            Sigma + doc  → Wazuh rule 100010  (T1558.003)
  02-asrep-roasting/           Sigma + doc  → Wazuh rule 100011  (T1558.004)
  03-dcsync/                   Sigma + doc  → Wazuh rule 100012  (T1003.006)
  04-bloodhound-enumeration/   Sigma + doc  → Wazuh rule 100013  (T1087.002)
  05-web-attacks/              Sigma + doc  → Wazuh rules 100014/100015 (T1190)
wazuh/local_rules.xml          the deployed rules (what actually runs in my SIEM)
docs/coverage-matrix.md        ATT&CK grid + honest gaps
docs/tuning-log.md             2 real false positives I hit and suppressed  ⭐
validation.md                  proof each rule fired on a real attack + metrics
```

## Sigma as the source of truth

Each detection is authored as a **Sigma** rule — the portable, vendor-neutral
detection format — and then expressed as the **Wazuh** rule that runs in my lab. Sigma
is the thing worth reviewing: it's tool-agnostic, so the same logic could be converted
to Splunk, Elastic, or Sentinel. The Wazuh XML is the deployment detail.

## Detections at a glance

| # | Technique (ATT&CK) | Event(s) | Signal | Sigma | Wazuh |
|---|--------------------|----------|--------|-------|-------|
| 01 | Kerberoasting (T1558.003) | 4769 | RC4 (`0x17`) TGS for an SPN | [yml](detections/01-kerberoasting/kerberoasting_rc4_tgs.yml) | 100010 |
| 02 | AS-REP Roasting (T1558.004) | 4768 | `preAuthType 0` | [yml](detections/02-asrep-roasting/asrep_roasting_no_preauth.yml) | 100011 |
| 03 | DCSync (T1003.006) | 4662 | replication right by a non-DC | [yml](detections/03-dcsync/dcsync_replication_rights.yml) | 100012 |
| 04 | Enumeration burst (T1087.002) | 4661/4662 | rate: >15 reads / 60s | [yml](detections/04-bloodhound-enumeration/bloodhound_directory_read_burst.yml) | 100013 |
| 05 | Web SQLi / XSS (T1190) | Apache access log | injection patterns in the URI (URL-encoding aware) | [yml](detections/05-web-attacks/web_sqli_xss.yml) | 100014/100015 |

**Quantified result:** 6 detections covering 6 ATT&CK techniques across 3 tactics,
all verified firing, with 3 documented tuning cases (2 false positives + 1 false
negative from URL-encoding).

## The part hiring managers ask about

- **[`docs/tuning-log.md`](docs/tuning-log.md)** — two *real* false positives I hit
  (the DCSync rule catching the DC's own replication; the enumeration rule catching
  legitimate bulk reads), why each happened, and how I tuned it. This is where the
  actual craft of detection engineering lives.
- **[`docs/coverage-matrix.md`](docs/coverage-matrix.md)** — the ATT&CK grid *and* the
  honest gaps I don't claim to cover.

## Deploy

```bash
# copy the rules into the Wazuh manager and restart it
docker cp wazuh/local_rules.xml wazuh-lab-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec wazuh-lab-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```
The lab itself (DC + Sysmon + Wazuh) is built in [security-homelab](../security-homelab).
Note the **auditing prerequisite** for the 4662 rules in [`validation.md`](validation.md).

## Skills demonstrated

Sigma rule authoring · Wazuh custom rules/decoders · Windows event analysis (4768/
4769/4661/4662) · ATT&CK mapping · **detection tuning & false-positive analysis** ·
purple-team validation (attack → log → rule → alert) · honest coverage assessment.

## Read next
- **[`docs/reviewer-path.md`](docs/reviewer-path.md)** — a 3-minute guided tour.
