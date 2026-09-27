# Investigation Notes

## Investigation Objective

The objective of this investigation was to examine Windows DPAPI-related artifacts and determine whether the endpoint showed evidence of suspicious credential-related activity.

The investigation used PowerShell, Sysmon, and Wazuh to examine the Windows user profile, cryptographic locations, process activity, and endpoint telemetry.

The investigation was performed using an evidence-first approach. DPAPI artifacts and keyword matches were treated as investigation leads rather than automatic evidence of credential theft.

---

## 1. Host Identification

The endpoint identity was established before examining the artifacts.

Observed host information:

- Computer: `DESKTOP-9MMM37V`
- User: `desktop-9mmm37v\dell`
- Profile: `C:\Users\Dell`
- Domain: `WORKGROUP`
- Domain Role: `0`

The investigation evidence directory was created at:

`C:\DPAPILab\Evidence`

This directory was used to store the investigation output.

---

## 2. DPAPI User Profile

The following location was examined:

`C:\Users\Dell\AppData\Roaming\Microsoft\Protect`

The path existed.

The directory contained:

- `S-1-5-21-51198790-337801975-3228388354-1001`
- `CREDHIST`

The SID-named directory represents the user-specific DPAPI area.

`CREDHIST` was also present.

These observations confirm the existence of DPAPI-related artifacts within the user profile.

They do not establish that the artifacts were accessed maliciously.

---

## 3. DPAPI Artifact Evidence Collection

The contents of the DPAPI profile directory were collected using PowerShell and written to:

`DPAPI-Profile-Artifacts.txt`

The collected information included:

- Name
- Full path
- File length
- Creation time
- Last write time
- Last access time

This provided a basic filesystem view of the available DPAPI artifacts.

---

## 4. Machine Cryptographic Locations

The investigation examined:

`C:\ProgramData\Microsoft\Crypto`

The following directories were observed:

- `PCPKSP`
- `RSA`

The timestamps showed existing activity associated with these locations.

These directories were recorded as supporting evidence because they are part of the Windows cryptographic environment.

No malicious conclusion was assigned based only on their existence.

---

## 5. Registry Investigation

The investigation checked:

`HKCU:\Software\Microsoft\Cryptography`

The following path was also checked:

`HKCU:\Software\Microsoft\Protect`

The second path returned:

`False`

The result was documented as a negative finding.

The investigation did not assume that the absence of this specific registry path indicated malicious activity.

---

## 6. Sysmon Process Investigation

Sysmon Event ID `1` was used to investigate process creation activity.

The search looked for:

- `dpapi`
- `protect`
- `cryptprotect`
- `credential`
- `vault`
- `lsass`

Four process creation events matched the search.

Observed timestamps were:

- `27-09-2026 05:54:01`
- `27-09-2026 05:56:13`
- `27-09-2026 05:58:21`
- `27-09-2026 05:58:21`

The matching events were exported to:

`Sysmon-DPAPI-ProcessActivity.txt`

The keyword match was treated as a discovery mechanism.

It was not treated as proof that the processes were malicious.

---

## 7. Sysmon File Activity

Sysmon Event ID `11` was included in the initial search together with Event ID `1`.

The purpose was to identify process and file activity associated with the investigation keywords.

The results were written to:

`DPAPI-Timeline.txt`

The resulting timeline was treated as supporting evidence rather than a standalone detection.

---

## 8. Wazuh `net.exe` Event

A Wazuh event was identified for `net.exe`.

Observed values included:

- Image: `C:\Windows\SysWOW64\net.exe`
- Command Line: `net.exe accounts`
- Company: `Microsoft Corporation`
- Description: `Net Command`
- Integrity Level: `System`
- Original File Name: `net.exe`
- Parent Process: `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe`

The command line was recorded exactly as observed.

---

## 9. Why `net.exe` Required Investigation

The initial presence of `net.exe` could appear interesting because Windows `net.exe` can be used for different administrative and discovery operations.

However, the executable name alone does not identify malicious behavior.

The exact command was:

`net.exe accounts`

Therefore, the investigation focused on the complete process context.

The parent process was also:

`wazuh-agent.exe`

This parent-child relationship was documented rather than ignored.

---

## 10. Evidence Correlation

The investigation used the following correlation model:

**Process → Command Line → Parent Process → User → Integrity Level → Timestamp → Surrounding Events**

This is more reliable than searching for a single suspicious process name or keyword.

For the observed `net.exe` event, the available evidence confirms the process execution and command line.

The current evidence does not establish that the process was used for credential theft.

---

## 11. DPAPI Keyword Results

The Sysmon keyword search returned process creation events because the event messages contained one or more investigation terms.

The relevant search terms were:

- `dpapi`
- `protect`
- `cryptprotect`
- `credential`
- `vault`
- `lsass`

These terms are intentionally broad.

For example, a legitimate process can contain `credential` or `protect` in its command line or event message.

Therefore:

**Keyword match = investigation lead**

not:

**Keyword match = malicious activity**

---

## 12. Confirmed Findings

The investigation confirmed:

- A Windows DPAPI user profile exists.
- A user SID-named DPAPI directory exists.
- `CREDHIST` exists.
- Machine cryptographic directories exist.
- Sysmon produced four keyword-matching process creation events.
- Wazuh recorded `net.exe`.
- The exact command was `net.exe accounts`.
- The Wazuh event reported `wazuh-agent.exe` as the parent process.

---

## 13. Findings Not Established

The investigation did not establish:

- Credential extraction.
- DPAPI secret decryption by an attacker.
- Credential dumping.
- LSASS dumping.
- Malicious persistence.
- Account compromise.
- Confirmed malicious use of `net.exe`.
- Confirmed malicious use of DPAPI.

---

## 14. Investigation Limitations

The current evidence contains useful endpoint observations, but a stronger conclusion would require additional context.

Useful additional telemetry would include:

- Complete Sysmon Event ID `1` messages.
- Process hashes.
- Exact parent command lines.
- Windows Security events.
- User logon information.
- Network connections.
- File access telemetry.
- Additional Wazuh process events.
- Process activity immediately before and after the observed events.

Without this information, the investigation should remain limited to the evidence that was actually observed.

---

## 15. Analyst Assessment

The endpoint contains legitimate DPAPI-related artifacts and associated cryptographic directories.

The investigation also identified process telemetry matching DPAPI-related keywords and a Wazuh event involving `net.exe`.

The `net.exe` event is notable enough to document and correlate, but the observed command line and available context do not independently establish credential theft.

The investigation therefore remains evidence-based and does not classify normal DPAPI artifacts as malicious simply because they are related to credential protection.

---

## 16. Investigation Principle

The central principle demonstrated by this lab is:

**An artifact is not automatically an incident.**

A SOC analyst should establish:

- What happened?
- Which process performed the action?
- What was the exact command line?
- Which user context was involved?
- What was the parent process?
- When did it happen?
- What happened immediately before and after?
- Is the behavior expected?
- What evidence supports the conclusion?

This approach helps reduce false positives and produces a defensible investigation record.
