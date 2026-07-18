# Gap Analysis — Full Technique Breakdown

This document details the before/after evidence for each MITRE ATT&CK technique tested against the baseline Wazuh + Sysmon configuration.

---

## T1082 — System Information Discovery

**Tactic:** Discovery
**Atomic Test:** `Invoke-AtomicTest T1082` (multiple sub-tests: `systeminfo`, environment variable discovery, etc.)

**Before:** No alert. Wazuh's dashboard returned zero results when queried for `rule.mitre.id:"T1082"`, despite the command executing successfully on the endpoint.

**Root cause:** No existing Sysmon/Wazuh rule matched discovery-only commands like `systeminfo` — these are indistinguishable from routine administrative activity under the default ruleset.

**Fix:** Custom rule `100011` — regex match on command line for `systeminfo`, `hostname.exe`, `Get-ComputerInfo`, `wmic os get`, `wmic computersystem`.

**After:** Alert fired correctly:
```
rule.id: 100011
rule.description: Possible System Information Discovery Activity Detected
rule.level: 6
rule.mitre.id: T1082
rule.mitre.technique: System Information Discovery
rule.mitre.tactic: Discovery
```

---

## T1087.001 — Local Account Discovery

**Tactic:** Discovery
**Atomic Test:** `Invoke-AtomicTest T1087.001` (`net user`, `net localgroup`, etc.)

**Before:** An alert *did* fire, but under a generic rule:
```
rule.id: 92032
rule.description: Suspicious Windows cmd shell execution
rule.mitre.id: T1087, T1059.003
rule.mitre.technique: Account Discovery, Windows Command Shell
```
This rule triggers on any cmd.exe execution pattern, not specifically account discovery — it happened to catch this activity as a side effect, with generic (and only partially accurate) MITRE tagging.

**Fix:** Custom rule `100013` — regex match for `net user`, `net localgroup`, `net group`, `Get-LocalUser`, `Get-LocalGroup`.

**After:**
```
rule.id: 100013
rule.description: Possible Local Account Discovery Activity Detected
rule.level: 6
rule.mitre.id: T1087.001
rule.mitre.technique: Local Account
rule.mitre.tactic: Discovery
```
Note: the original generic rule (92032) still fires alongside the new specific one — this is intentional; the new rule adds precision without removing existing (if imperfect) coverage.

---

## T1016 — System Network Configuration Discovery

**Tactic:** Discovery
**Atomic Test:** `Invoke-AtomicTest T1016` (`ipconfig /all`, `nslookup`, `arp -a`, etc.)

**Before:** Interestingly, the raw Sysmon log itself correctly tagged the activity (`technique_id=T1016` visible in the raw Sysmon message field, via the Sysmon config's own naming), but the **Wazuh rule that actually fired mislabeled it**:
```
rule.id: 92032
rule.description: Suspicious Windows cmd shell execution
rule.mitre.id: T1087, T1059.003   <-- incorrect; this was T1016 activity
```
This revealed that Wazuh's default ruleset was not reading/using the MITRE tagging already present in the Sysmon log — it was applying a separate, less accurate classification of its own.

**Fix:** Custom rule `100012` — regex match for `nslookup`, `ipconfig /all`, `arp -a`, `route print`, `netstat -`.

**After:**
```
rule.id: 100012
rule.description: Possible Network Configuration Discovery Activity Detected
rule.level: 6
rule.mitre.id: T1016
rule.mitre.technique: System Network Configuration Discovery
rule.mitre.tactic: Discovery
```

---

## T1003.001 — LSASS Memory (Credential Dumping)

**Tactic:** Credential Access
**Atomic Test:** `Invoke-AtomicTest T1003.001` (multiple tool variants: ProcDump, comsvcs.dll, Mimikatz, NanoDump, pypykatz, Out-Minidump.ps1)

**Before:** This is the most significant finding of the project.

Windows Defender actively blocked several tool variants outright:
```
Exception calling "Start": "Access is denied"
This script contains malicious content and has been blocked by your antivirus software.
```
This is Defender performing **prevention** — stopping the tool from executing.

However, checking Wazuh's **archive index** (which logs all received events, not just those that trigger alerts) showed that attempts which *did* execute (e.g., the `Out-Minidump.ps1` / `rdrleakdiag` variants) were logged by Sysmon and received by Wazuh — but **no dedicated alert fired**. The only alert generated was the same generic rule as before:
```
rule.id: 92027
rule.description: Powershell process spawned powershell instance
rule.mitre.id: T1059.001
rule.mitre.technique: PowerShell
rule.mitre.tactic: Execution
```
This rule says nothing about credential access or LSASS — an analyst monitoring only the alerts index (not manually digging through archives) would have **no visibility into an active credential-dumping attempt** on this endpoint.

**Fix:** Custom rule `100010` — regex match for LSASS-dumping-specific keywords/tool signatures (`lsass.*dump`, `comsvcs.dll.*MiniDump`, `procdump.*lsass`, `rdrleakdiag`, `nanodump`, `mimikatz`, `pypykatz`, `Out-Minidump`), set to level 12 (high) given the severity of this technique in real-world attacks.

**After:**
```
rule.id: 100010
rule.description: Possible LSASS Credential Dumping Attempt Detected
rule.level: 12
rule.mitre.id: T1003.001
rule.mitre.technique: LSASS Memory
rule.mitre.tactic: Credential Access
```

**Why this matters:** distinguishing prevention from detection is a core SOC concept. A tool being blocked by AV does not mean a SOC has *visibility* into the attempt — logging and alerting on the attempt itself (regardless of whether it succeeded) is what enables an analyst to investigate, correlate with other activity, and respond. This gap — silent on one of the most common real-world credential theft techniques — was the most operationally significant finding of the project.

---

## Summary Table

| Technique | MITRE ID | Tactic | Before | After | Rule ID |
|---|---|---|---|---|---|
| System Information Discovery | T1082 | Discovery | No alert | Correctly tagged alert (level 6) | 100011 |
| Local Account Discovery | T1087.001 | Discovery | Generic/mislabeled alert | Correctly tagged alert (level 6) | 100013 |
| Network Configuration Discovery | T1016 | Discovery | Generic/mislabeled alert | Correctly tagged alert (level 6) | 100012 |
| LSASS Credential Dumping | T1003.001 | Credential Access | No alert (archive-only) | Correctly tagged alert (level 12) | 100010 |
