# Detection 03 — DCSync (T1003.006)

Detects the attack in [ad-attack-chain → Phase 03](https://github.com/manlikefelo/ad-attack-chain/tree/main/engagement/03-dcsync).

| | |
|---|---|
| **ATT&CK** | Credential Access → OS Credential Dumping: DCSync (**T1003.006**) |
| **Log source** | Windows Security (DC), Wazuh `windows_eventchannel` decoder |
| **Key event** | **4662** — an operation was performed on an AD object |
| **Key fields** | `properties` contains a replication extended-right GUID · `subjectUserName` |
| **Sigma** | [`dcsync_replication_rights.yml`](dcsync_replication_rights.yml) |
| **Deployed Wazuh rule** | `100012` (level 12 — the highest here) — [`../../wazuh/local_rules.xml`](../../wazuh/local_rules.xml) |

## Detection logic (plain English)

DCSync impersonates a DC and asks a real DC to **replicate** account secrets. That
touches the domain object using two control-access rights, identified in the 4662 by
their GUIDs:

- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes-All

The rule fires on: *event 4662 AND `properties` contains either GUID*. The Sigma
source refines this by **excluding machine accounts and SYSTEM** (real DC-to-DC
replication), so only a *non-DC* principal exercising replication rights alerts — the
true DCSync signature.

> ⚠️ **Auditing prerequisite (learned the hard way):** 4662 only logs if the DC has
> **Directory Service Access** auditing enabled *and* a **SACL** on the domain root
> auditing those replication GUIDs. Neither is on by default — I enabled both on DC01.
> This is documented as a detection-engineering gotcha, not an afterthought.

## Expected alert

`rule.id:100012` returns the DCSync with the replication GUID in `properties` and
`subjectUserName: b.otieno` (a non-DC helpdesk account) from source `10.10.10.40`.
Captured alert JSON:
[`wazuh_alert_100012.json`](https://github.com/manlikefelo/ad-attack-chain/blob/main/engagement/03-dcsync/evidence/wazuh_alert_100012.json).

## Known false positives & tuning

- **Legitimate DC-to-DC replication** is the main FP — the Sigma filter drops machine
  accounts (`$`) and `S-1-5-18` (SYSTEM) to remove it.
- **Entra/Azure AD Connect** sync accounts replicate legitimately; whitelist the
  specific service account by name.
- This false-positive class is written up in detail in
  [`../../docs/tuning-log.md`](../../docs/tuning-log.md).
