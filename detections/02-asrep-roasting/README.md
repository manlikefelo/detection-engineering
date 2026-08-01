# Detection 02 — AS-REP Roasting (T1558.004)

Detects the attack in [ad-attack-chain → Phase 02](https://github.com/manlikefelo/ad-attack-chain/tree/main/engagement/02-asrep-roasting).

| | |
|---|---|
| **ATT&CK** | Credential Access → AS-REP Roasting (**T1558.004**) |
| **Log source** | Windows Security (DC), Wazuh `windows_eventchannel` decoder |
| **Key event** | **4768** — Kerberos authentication ticket (TGT) requested |
| **Key fields** | `preAuthType = 0` (pre-auth disabled) · `ticketEncryptionType = 0x17` (RC4) |
| **Sigma** | [`asrep_roasting_no_preauth.yml`](asrep_roasting_no_preauth.yml) |
| **Deployed Wazuh rule** | `100011` (level 10) — [`../../wazuh/local_rules.xml`](../../wazuh/local_rules.xml) |

## Detection logic (plain English)

A normal interactive logon shows **pre-auth type 2** (the client proves it knows the
password with an encrypted timestamp). **Pre-auth type 0** means the DC issued the TGT
*without* that proof — which only happens for accounts flagged
`DoesNotRequirePreAuth`. That's exactly the account state AS-REP roasting abuses, so
the rule fires on: *event 4768 AND preAuthType 0*. This needs no attacker credentials,
which is what makes it a pre-access technique worth alerting on loudly.

## Expected alert

`rule.id:100011` returns the roast with `preAuthType: 0`, `ticketEncryptionType: 0x17`,
`targetUserName: b.otieno`, source `10.10.10.40`. Real captured alert JSON:
[`wazuh_alert_100011.json`](https://github.com/manlikefelo/ad-attack-chain/blob/main/engagement/02-asrep-roasting/evidence/wazuh_alert_100011.json).

## Known false positives & tuning

- **Legitimately pre-auth-disabled accounts** (rare legacy interop) will fire every
  time they authenticate. The right response is to *inventory* them
  (`Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'`), fix the ones that
  shouldn't be, and whitelist any that genuinely must stay — but keep alerting,
  because the population should be tiny and stable.
- See [`../../docs/tuning-log.md`](../../docs/tuning-log.md).
