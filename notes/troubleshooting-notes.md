# Troubleshooting Notes

## Overview

This document records the issues and investigation decisions encountered during the Windows DPAPI artifact investigation.

The main challenge was interpreting DPAPI-related artifacts and process keyword matches without incorrectly treating normal Windows activity as credential theft.

---

## 1. `net.exe` Appeared in Wazuh

### Observation

Wazuh reported:

`C:\Windows\SysWOW64\net.exe`

The command line was:

`net.exe accounts`

### Initial Concern

The investigation was focused on DPAPI and credential-related activity, so the appearance of `net.exe` required investigation.

### Investigation

The following fields were reviewed:

- Process image
- Command line
- Parent process
- Integrity level
- User context
- Timestamp

The event showed:

`C:\Program Files (x86)\ossec-agent\wazuh-agent.exe`

as the parent process.

### Resolution

The event was documented as process activity rather than automatically classified as credential theft.

The exact command line and parent process were preserved for correlation.

---

## 2. DPAPI Artifacts Were Already Present

### Observation

The following path existed:

`C:\Users\Dell\AppData\Roaming\Microsoft\Protect`

It contained:

- A SID-named directory
- `CREDHIST`

### Problem

It would be easy to interpret the presence of DPAPI artifacts as evidence that credentials had been targeted.

### Resolution

The artifacts were treated as normal DPAPI-related evidence.

The investigation specifically avoided claiming credential theft based only on the existence of the directory or files.

---

## 3. Machine Cryptographic Directories Were Present

### Observation

The following path existed:

`C:\ProgramData\Microsoft\Crypto`

The observed entries were:

- `PCPKSP`
- `RSA`

### Resolution

These locations were documented as part of the endpoint's cryptographic environment.

Their existence was not treated as suspicious.

---

## 4. Registry Path Was Missing

### Observation

The investigation checked:

`HKCU:\Software\Microsoft\Protect`

The result was:

`False`

### Resolution

The missing path was recorded as a negative finding.

The investigation did not treat the result as an error because Windows systems do not necessarily expose every possible artifact path in the same way.

---

## 5. Sysmon Keyword Search Returned Multiple Events

### Observation

The Sysmon process search returned four events matching:

- `dpapi`
- `protect`
- `cryptprotect`
- `credential`
- `vault`
- `lsass`

### Problem

The search was intentionally broad.

A keyword can appear in a legitimate process message without the process performing malicious activity.

### Resolution

The events were exported to:

`Sysmon-DPAPI-ProcessActivity.txt`

The results were treated as leads for further investigation.

---

## 6. Keyword Matching Created an Interpretation Problem

### Observation

Searching for:

`credential`

or:

`protect`

can return legitimate activity.

### Problem

A SOC investigation can generate false positives when broad keywords are interpreted as detections.

### Resolution

The following distinction was used:

**Keyword match → investigate**

rather than:

**Keyword match → malicious**

This is especially important when investigating Windows security mechanisms.

---

## 7. Process Name Was Not Enough

### Observation

The Wazuh event showed:

`net.exe`

### Problem

Looking only at the process name does not explain what the process was doing.

### Resolution

The investigation reviewed:

- Exact image
- Exact command line
- Parent process
- Integrity level
- User context
- Timestamp

The command line was confirmed as:

`net.exe accounts`

This provided more useful context than the process name alone.

---

## 8. Parent Process Was Important

### Observation

The Wazuh event identified:

`C:\Program Files (x86)\ossec-agent\wazuh-agent.exe`

as the parent process.

### Resolution

The parent process was recorded as part of the investigation rather than focusing only on `net.exe`.

This reinforces the importance of process ancestry during endpoint investigations.

---

## 9. Evidence Collection Was Successful

The investigation created:

`C:\DPAPILab\Evidence`

The following evidence files were generated:

- `Host-Identity.txt`
- `DPAPI-Profile-Artifacts.txt`
- `DPAPI-Registry-Artifacts.txt`
- `DPAPI-Timeline.txt`
- `Sysmon-DPAPI-ProcessActivity.txt`
- `Investigation-Summary.txt`

These files provide a structured record of the investigation.

---

## 10. Investigation Should Not Force a Detection

### Observation

The lab produced DPAPI artifacts, keyword matches, and a `net.exe` process event.

### Problem

There was a risk of interpreting all of these observations as one malicious chain without sufficient supporting evidence.

### Resolution

The investigation separated:

- Confirmed artifacts
- Confirmed process activity
- Suspicious-looking observations
- Unconfirmed hypotheses

This prevented the investigation from overstating what the telemetry demonstrated.

---

## 11. What Additional Evidence Would Help

If the investigation were continued, the following evidence would be useful:

- Full Sysmon Event ID `1` details.
- Complete command lines.
- Parent command lines.
- Process hashes.
- User and logon information.
- Windows Security events.
- Network connections.
- File access events.
- Additional Wazuh telemetry.
- Events immediately before and after the observed process activity.

This would help determine whether the observed activity was expected endpoint behavior or part of a suspicious execution chain.

---

## Final Troubleshooting Lesson

The main lesson from this investigation is that endpoint telemetry must be interpreted in context.

A DPAPI directory does not prove credential theft.

A `credential` keyword does not prove credential access.

A `net.exe` process does not prove malicious activity.

A strong investigation correlates:

**Process + Command Line + Parent Process + User + Timestamp + Surrounding Telemetry**

The investigation should document what is confirmed, identify what remains unknown, and avoid conclusions that are not supported by the available evidence.
