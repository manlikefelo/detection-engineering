# Validation — every detection fired on a real attack

Detection rules only count if they fire on the real thing. Each rule here was
validated by **replaying the matching attack from KALI01** against DC01 (agent id
001), letting the Wazuh manager evaluate it, and confirming the alert in Discover.
The captured alert documents live in the [ad-attack-chain](../ad-attack-chain)
repo's per-phase `evidence/` folders (linked below).

## Results

| Rule | Technique | Attack replayed | Verified alert | Evidence |
|------|-----------|-----------------|----------------|----------|
| **100010** | T1558.003 Kerberoasting | `impacket-GetUserSPNs` → RC4 TGS for `svc_sql` | ✅ 4769 / `0x17` / `svc_sql`, src 10.10.10.40 | [alert shot](../ad-attack-chain/engagement/01-kerberoasting/evidence/05-wazuh-kerberoast-alert.png) |
| **100011** | T1558.004 AS-REP Roasting | `impacket-GetNPUsers -no-pass` for `b.otieno` | ✅ 4768 / `preAuthType 0` / RC4 (fired 2×) | [alert JSON](../ad-attack-chain/engagement/02-asrep-roasting/evidence/wazuh_alert_100011.json) |
| **100012** | T1003.006 DCSync | `impacket-secretsdump -just-dc` as `b.otieno` | ✅ 4662 / replication GUID `1131f6aa…` / subject `b.otieno` (fired 2×) | [alert JSON](../ad-attack-chain/engagement/03-dcsync/evidence/wazuh_alert_100012.json) |
| **100013** | T1087.002 Discovery | `bloodhound-python -c All` | ✅ 4662 read burst, `frequency 15` tripped (fired 2×) | [alert JSON](../ad-attack-chain/engagement/04-bloodhound/evidence/wazuh_alert_100013.json) |

## Metrics

- **Detections built & verified:** 4 Wazuh rules, 4 Sigma rules.
- **ATT&CK techniques covered end-to-end:** 5 (see [`docs/coverage-matrix.md`](docs/coverage-matrix.md)).
- **Tactics covered:** 2 (Credential Access, Discovery).
- **True-positive rate on replay:** 4/4 attacks alerted.
- **False positives found & tuned:** 2 documented in [`docs/tuning-log.md`](docs/tuning-log.md).

## Notes on validating detections honestly

- **`wazuh-logtest` dry-runs don't prove a Windows rule.** Hand-built JSON fed to
  logtest decodes as generic `json` and never enters the `windows` group, so it won't
  match rules that key on `win.eventdata.*`. Only a **real agent-sourced event**
  decodes correctly — so the live attack replay *is* the test, not a substitute for it.
- **4662-based rules need auditing enabled first.** DCSync (100012) and the
  enumeration burst (100013) only produce events if the DC has **Directory Service
  Access** auditing on plus a **SACL** on the domain root. I enabled both on DC01;
  without them these rules are silent no matter how correct the logic is. That
  prerequisite is a detection-engineering lesson worth stating plainly.
