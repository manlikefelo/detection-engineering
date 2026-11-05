# Detection 04: Directory Enumeration Burst / BloodHound (T1087.002)

Detects the attack in [ad-attack-chain: Phase 04](https://github.com/manlikefelo/ad-attack-chain/tree/main/engagement/04-bloodhound).

| | |
|---|---|
| **ATT&CK** | Discovery / Account Discovery: Domain (**T1087.002**), Permission Groups Discovery: Domain (**T1069.002**) |
| **Log source** | Windows Security (DC), Wazuh `windows_eventchannel` decoder |
| **Key events** | **4661 / 4662**, object-access reads, in volume |
| **Signal type** | **Rate** (frequency + timeframe), not a single event |
| **Sigma** | [`bloodhound_directory_read_burst.yml`](bloodhound_directory_read_burst.yml) |
| **Deployed Wazuh rule** | `100013` (level 8, `frequency=15` / `timeframe=60`): [`../../wazuh/local_rules.xml`](../../wazuh/local_rules.xml) |

## Detection logic (plain English)

BloodHound/SharpHound collection reads huge swathes of the directory (users, groups,
ACLs, trusts) producing a **burst** of 4661/4662 object-access events from a single
account in seconds. There's no one "smoking-gun" event; the signal is the *rate*. So
this rule counts 4661/4662 per user over a 60-second window and fires when the count
exceeds 15.

**This is deliberately the noisiest rule in the set**, and I call that out honestly:
threshold detections trade precision for coverage. It's the opposite design from the
sharp single-event rules (01–03) and the one most in need of environment tuning.

## Expected alert

`rule.id:100013` returns the enumeration burst, multiple 4662s from `a.mokaya` /
`b.otieno` inside the window, source `10.10.10.40`. Captured alert JSON:
[`wazuh_alert_100013.json`](https://github.com/manlikefelo/ad-attack-chain/blob/main/engagement/04-bloodhound/evidence/wazuh_alert_100013.json).

## Known false positives & tuning

- **Legitimate bulk readers** (vulnerability scanners, identity-governance tooling,
  AD-audit/backup agents, and admins running big reports) can all trip the threshold.
  This is the concrete false positive I hit and tuned; the full write-up (why it fired,
  how I raised the threshold and scoped by account) is in
  [`../../docs/tuning-log.md`](../../docs/tuning-log.md).
- Tuning levers: raise `frequency`, shorten/lengthen `timeframe`, and whitelist known
  service accounts by `subjectUserName`.
