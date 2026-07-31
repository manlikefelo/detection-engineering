# Tuning log — real false positives I hit and suppressed

Detection rules are never "done" the moment they fire on the attack. The harder,
more honest work is what happens next: the rule also fires on *benign* activity, and
you have to decide whether to suppress, refine, or accept it. This log records the
false positives I actually ran into building this lab, why each happened, and exactly
how I tuned it. The reasoning matters more than the YAML.

> Two of these (FP-1, FP-2) are the ones I'd talk through in an interview, because
> they show the two classic tuning trade-offs: a **rate rule that's too broad** and a
> **signature rule that catches legitimate system behaviour**.

---

## FP-1 — DCSync rule (100012) fired on the DC's own replication

**What fired.** Rule `100012` (DCSync, 4662 + replication GUID) alerted even when I
had run *no* attack — a hit with `subjectUserName` being the **DC computer account
(`DC01$`)** and, in other events, the SYSTEM SID `S-1-5-18`.

**Why it's a false positive.** A Domain Controller legitimately exercises
`DS-Replication-Get-Changes` / `-All` as part of *normal* operation — replication
health checks, and (in a multi-DC domain) DC-to-DC sync. The 4662 for the replication
GUID is identical whether it's an attacker's `secretsdump` or the DC doing its job.
Keying only on "event 4662 + replication GUID" therefore catches both. In a real
multi-DC environment this would be a *constant* stream of false positives.

**How I suppressed it.** The distinguishing fact is the **principal**: real
replication is done by **machine accounts** (names ending `$`) and **SYSTEM**
(`S-1-5-18`); DCSync-as-attack is done by a *user* account that is not a DC. So I
added exclusion filters:

```yaml
    filter_dc_accounts:
        SubjectUserName|endswith: '$'
    filter_system:
        SubjectUserSid: 'S-1-5-18'
    condition: selection and not 1 of filter_*
```

(See [`../detections/03-dcsync/dcsync_replication_rights.yml`](../detections/03-dcsync/dcsync_replication_rights.yml).)
After the filter, only a **non-DC user** exercising replication rights alerts — which
is the true DCSync signature. The attack from `b.otieno` (a user, not a `$` account)
still fires; `DC01$` / SYSTEM no longer do.

**Reasoning / trade-off.** This is a *safe* suppression: the excluded principals
genuinely can't be the attack I care about here. The residual risk — an attacker who
compromises a machine account or SYSTEM on a DC — is a different, later-stage problem
that other detections (and the fact that they're already on a DC) should cover. I'd
rather have a precise rule I trust than a noisy one analysts learn to ignore.

---

## FP-2 — BloodHound burst rule (100013) fired on legitimate bulk directory reads

**What fired.** Rule `100013` (4661/4662 read burst, `frequency=15` / `timeframe=60`)
fired during setup activity that had nothing to do with BloodHound — routine
administrative enumeration and a management console walking the directory tripped the
15-reads-in-60-seconds threshold.

**Why it's a false positive.** Enumeration is a **rate signal**, not a signature.
Plenty of *legitimate* things read the directory in bursts: admins running reports,
identity-governance / audit tooling, backup agents, vulnerability scanners, and even
the Wazuh/monitoring tooling itself. A pure "N reads in a window" rule can't tell
those apart from SharpHound — by design it's the broadest, least precise rule in the
set (I flagged this in the rule's own description).

**How I tuned it (rather than deleting it).** Three levers, in order of preference:

1. **Scope by account.** The real attack came from a specific user
   (`a.mokaya` / `b.otieno`) over the network. Known bulk-reader **service accounts
   get whitelisted** by `subjectUserName` so their normal behaviour doesn't alert.
2. **Raise the threshold** to sit above normal admin noise but below a full
   SharpHound sweep (which reads *far* more than 15 objects). In production I'd derive
   the number from a baseline of a quiet week, not guess it.
3. **Keep the level low (8).** I deliberately did **not** make this a high-severity,
   page-someone alert. It's a *hunting lead* — worth surfacing, not worth waking
   someone at 3am, precisely because its false-positive rate is inherently higher.

**Reasoning / trade-off.** I chose to **keep a noisier rule at low severity** rather
than suppress the behaviour entirely, because losing enumeration visibility is worse
than triaging the occasional benign burst. This is the honest opposite of FP-1: there
I could cleanly exclude the FP; here I can only *manage* it. Saying that plainly —
"this detection is a lead, not a verdict" — is itself part of good detection
engineering.

---

## What I'd do next (production hardening)

- **Port the Sigma filters into the deployed Wazuh rules.** The live lab rules are
  kept deliberately simple (the attacks come from a named user, so the extra filters
  aren't strictly needed to get a clean result); in a real SOC I'd carry FP-1's
  machine-account/SYSTEM exclusions and FP-2's account whitelist straight across.
- **Baseline before threshold-tuning.** Replace the guessed `frequency=15` with a
  value derived from real quiet-period data per environment.
- **Add allow-lists as data, not code.** Keep whitelisted service accounts in a
  maintained list so tuning doesn't mean editing rules.
