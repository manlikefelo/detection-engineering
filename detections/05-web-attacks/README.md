# Detection 05: Web attacks: SQL injection & XSS (T1190)

Detects the attacks in [webapp-pentest-juiceshop](https://github.com/manlikefelo/webapp-pentest-juiceshop).

| | |
|---|---|
| **ATT&CK** | Initial Access → Exploit Public-Facing Application (**T1190**) |
| **Log source** | DVWA container Apache access log → docker json → Wazuh agent (UB01) |
| **Signal** | SQLi / XSS patterns in the HTTP request URI |
| **Sigma** | [`web_sqli_xss.yml`](web_sqli_xss.yml) |
| **Deployed Wazuh rules** | `100014` (SQLi, lvl 12), `100015` (XSS, lvl 10): [`../../wazuh/local_rules.xml`](../../wazuh/local_rules.xml) |

## Detection logic (plain English)

The UB01 agent tails the DVWA container's Apache access log. The `json` decoder exposes
each request line under `data.log`. Two rules match attack signatures in the request:
`UNION SELECT` / `information_schema` / `OR 1=1` / `sqlmap` for SQLi, and
`<script` / `<iframe` / `javascript:` / `onerror=` / `alert(` for XSS.

## The lesson that makes this detection real

The first version of the SQLi rule **missed the attack**: the XSS rule fired but the
SQLi one didn't. Real attack traffic is **URL-encoded**: the access log recorded
`UNION%20SELECT`, not `UNION SELECT`, so a literal-space pattern never matched. The fix
was a **PCRE2** pattern (`type="pcre2"`) that accepts `%20`/`+`/space between keywords.

**Detections must match the wire format, not the textbook form.** This, plus two
config errors that briefly took the rule engine offline (an unterminated XML comment,
and OS_Regex rejecting PCRE-style groups), is written up in
[`../../docs/tuning-log.md`](../../docs/tuning-log.md) as FP-3.

## Verified firing

Both rules fired end-to-end on replayed attacks, captured alert JSON in the pentest
repo: [SQLi alert](https://github.com/manlikefelo/webapp-pentest-juiceshop/blob/main/evidence/blue-detection/wazuh_alert_100014_sqli.json),
[XSS alert](https://github.com/manlikefelo/webapp-pentest-juiceshop/blob/main/evidence/blue-detection/wazuh_alert_100015_xss.json).
