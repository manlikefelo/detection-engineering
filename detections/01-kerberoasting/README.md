# Detection 01: Kerberoasting (T1558.003)

Detects the attack in [ad-attack-chain: Phase 01](https://github.com/manlikefelo/ad-attack-chain/tree/main/engagement/01-kerberoasting).

| | |
|---|---|
| **ATT&CK** | Credential Access / Kerberoasting (**T1558.003**) |
| **Log source** | Windows Security (DC), Wazuh `windows_eventchannel` decoder |
| **Key event** | **4769**: Kerberos service ticket (TGS) requested |
| **Key fields** | `ticketEncryptionType = 0x17` (RC4) · `serviceName` (the SPN account) |
| **Sigma** | [`kerberoasting_rc4_tgs.yml`](kerberoasting_rc4_tgs.yml) |
| **Deployed Wazuh rule** | `100010` (level 10): [`../../wazuh/local_rules.xml`](../../wazuh/local_rules.xml) |

## Detection logic (plain English)

When any account with a Service Principal Name is Kerberoasted, the DC logs a **4769**
for the TGS request. The ticket is encrypted with the service account's password key,
and the crackable case is **RC4 (`0x17`)**, modern accounts should use AES
(`0x11`/`0x12`). So the rule fires on: *event 4769 AND encryption type 0x17*. The
Sigma version additionally filters out machine accounts (names ending in `$`) and
`krbtgt`, which legitimately appear with RC4 in some environments.

## Expected alert

Filtering `rule.id:100010` in Wazuh Discover returns the Kerberoast, with
`data.win.eventdata.serviceName: svc_sql`, `ticketEncryptionType: 0x17`, and the
attacker's source IP (`10.10.10.40`, KALI01). Screenshots:
[attack](https://github.com/manlikefelo/ad-attack-chain/blob/main/engagement/01-kerberoasting/evidence/02-getuserspns-svc_sql.png)
→ [alert](https://github.com/manlikefelo/ad-attack-chain/blob/main/engagement/01-kerberoasting/evidence/05-wazuh-kerberoast-alert.png).

## Known false positives & tuning

- **Legacy apps/appliances that still negotiate RC4** for service tickets will match.
  Tune by whitelisting those specific `serviceName`s once inventoried.
- **Un-migrated service accounts** that haven't moved to AES: the fix is to migrate
  them (see the attack repo's remediation), which also removes the false positive.
- See the cross-detection write-up in [`../../docs/tuning-log.md`](../../docs/tuning-log.md).
