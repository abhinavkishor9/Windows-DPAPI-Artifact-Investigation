# Windows DPAPI Artifact Investigation

## Overview

This lab investigates Windows Data Protection API (DPAPI) artifacts and related endpoint telemetry using PowerShell, Sysmon, and Wazuh.

The investigation focuses on identifying DPAPI-related artifacts within a Windows user profile, reviewing related process activity, and correlating endpoint events using process image, command line, parent process, user context, integrity level, and timestamp.

The investigation follows an evidence-first approach. The presence of a DPAPI artifact, a credential-related keyword, or a process such as `net.exe` is not treated as proof of malicious activity. Each observation must be correlated with additional evidence before reaching a conclusion.

---

## Lab Objectives

- Identify Windows DPAPI-related artifact locations.
- Examine the user's DPAPI profile directory.
- Identify relevant machine-level cryptographic locations.
- Review Sysmon process creation events for DPAPI-related activity.
- Review Sysmon file telemetry associated with the investigation.
- Investigate `net.exe` activity reported by Wazuh.
- Examine the exact command line associated with `net.exe`.
- Correlate process image, command line, parent process, user, integrity level, and timestamp.
- Preserve investigation evidence in structured files.
- Distinguish normal DPAPI artifacts from evidence of suspicious activity.
- Document confirmed findings, limitations, and unresolved questions.
- Practice an evidence-first SOC investigation methodology.

---

## Investigation Scenario

A Windows endpoint is being investigated for possible credential-related activity involving Windows DPAPI.

DPAPI is a legitimate Windows security mechanism used to protect sensitive information. Because DPAPI-related directories and files normally exist on Windows systems, their presence alone does not indicate compromise.

During the investigation, the endpoint was examined for DPAPI-related artifacts and associated process telemetry. Sysmon process creation events were searched using terms such as `dpapi`, `protect`, `credential`, `vault`, and `lsass`.

Wazuh also reported execution of `net.exe` with the command line `net.exe accounts`. Instead of treating the executable name as suspicious by itself, the event was examined using its command line, parent process, integrity level, and other available context.

The investigation therefore focuses on determining what the available evidence actually demonstrates rather than forcing a DPAPI or credential-theft detection.

---

## Host Information

- Hostname: `DESKTOP-9MMM37V`
- User: `desktop-9mmm37v\dell`
- User Profile: `C:\Users\Dell`
- Domain: `WORKGROUP`
- Domain Role: `0`
- Wazuh Agent ID: `001`
- Wazuh Agent Name: `DESKTOP-9MMM37V`
- Investigation Directory: `C:\DPAPILab\Evidence`

---

## DPAPI Artifact Investigation

The primary user-level DPAPI location investigated was:

`C:\Users\Dell\AppData\Roaming\Microsoft\Protect`

The directory existed and contained:

- A user SID-named directory
- `CREDHIST`

The observed SID-named directory was:

`S-1-5-21-51198790-337801975-3228388354-1001`

The presence of these artifacts confirms that DPAPI-related material exists within the user profile.

However, these artifacts are not sufficient to establish credential theft or malicious DPAPI access.

---

## Machine Cryptographic Artifacts

The investigation also examined:

`C:\ProgramData\Microsoft\Crypto`

The following entries were observed:

- `PCPKSP`
- `RSA`

These locations were documented as part of the Windows cryptographic environment.

Their presence alone was not treated as suspicious.

---

## Registry Investigation

The investigation checked:

`HKCU:\Software\Microsoft\Cryptography`

It also checked:

`HKCU:\Software\Microsoft\Protect`

The `HKCU:\Software\Microsoft\Protect` path returned `False`.

This was documented as a negative finding rather than treated as an investigation failure.

---

## Sysmon Investigation

Sysmon Event ID `1` process creation events were searched for the following terms:

- `dpapi`
- `protect`
- `cryptprotect`
- `credential`
- `vault`
- `lsass`

The search returned four matching process creation events.

Observed timestamps included:

- `27-09-2026 05:54:01`
- `27-09-2026 05:56:13`
- `27-09-2026 05:58:21`
- `27-09-2026 05:58:21`

These events demonstrate that process telemetry matched the investigation keywords.

They do not, by themselves, prove that a process was performing credential theft or malicious DPAPI operations.

---

## Wazuh `net.exe` Investigation

Wazuh reported a process event involving:

`C:\Windows\SysWOW64\net.exe`

The exact command line was:

`net.exe accounts`

Additional event information included:

- Company: `Microsoft Corporation`
- Description: `Net Command`
- Integrity Level: `System`
- Original File Name: `net.exe`
- Parent Process: `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe`

The command line was particularly important because the investigation should focus on what `net.exe` actually executed rather than treating every occurrence of `net.exe` as malicious.

The parent process was also reviewed because process ancestry can provide important context.

---

## Evidence Assessment

### Confirmed

- The endpoint contains a DPAPI user-profile directory.
- A user SID-named DPAPI directory exists.
- `CREDHIST` exists within the DPAPI location.
- Machine-level cryptographic directories exist.
- Sysmon process creation events matched DPAPI-related investigation keywords.
- Wazuh recorded execution of `net.exe`.
- The observed `net.exe` command line was `net.exe accounts`.
- The Wazuh event identified `wazuh-agent.exe` as the parent process.

### Not Confirmed

The available evidence does not establish:

- Credential theft.
- DPAPI secret extraction.
- Malicious DPAPI decryption.
- LSASS credential dumping.
- Confirmed account compromise.
- Malicious persistence.
- Confirmed attacker activity.

---

## MITRE ATT&CK Mapping

The investigation has potential relevance to credential-access techniques involving Windows credential stores and protected credentials.

Potentially relevant techniques include:

- **T1555 - Credentials from Password Stores**
- **T1555.004 - Credentials from Password Stores: Windows Credential Manager**
- **T1003 - OS Credential Dumping**

These techniques are included as investigative considerations rather than confirmed detections.

The presence of DPAPI artifacts or credential-related keywords is not sufficient to claim that any of these techniques were successfully executed.

Further behavioral evidence would be required.

---

## Investigation Methodology

The investigation followed this correlation sequence:

1. Identify the artifact or event.
2. Determine whether the artifact can be expected on a normal Windows system.
3. Identify the associated process.
4. Review the exact command line.
5. Identify the parent process.
6. Review user and integrity context.
7. Correlate timestamps.
8. Review surrounding endpoint activity.
9. Separate confirmed facts from assumptions.
10. Document limitations.

This approach helps prevent normal Windows activity from being incorrectly classified as malicious.

---

## Evidence Collected

The investigation generated the following evidence files:

- `Host-Identity.txt`
- `DPAPI-Profile-Artifacts.txt`
- `DPAPI-Registry-Artifacts.txt`
- `DPAPI-Timeline.txt`
- `Sysmon-DPAPI-ProcessActivity.txt`
- `Investigation-Summary.txt`

---

## Key Takeaway

A DPAPI artifact is evidence that DPAPI-related material exists on the endpoint. It is not automatically evidence of credential theft.

Similarly, `net.exe` is a legitimate Windows executable. Its presence should be investigated using the exact command line, parent process, user context, timestamp, and surrounding telemetry.

The main lesson from this lab is:

**Follow the evidence, not the assumption.**
