# Windows-DPAPI-Artifact-Investigation
# Overview
DPAPI (Data Protection API) is a Windows security mechanism used to protect sensitive data such as stored credentials, browser secrets, certificates, and application secrets.

From a DFIR perspective, the important point is that DPAPI-protected data is tied to Windows user or machine protection context. An investigator may therefore examine DPAPI-related artifacts to determine:

Which users or applications may have stored protected data.
Whether DPAPI-related files or registry artifacts exist.
Which Windows profile was involved.
Whether suspicious processes accessed DPAPI-related locations.
Whether credential-access activity occurred around the same time.
Whether the evidence supports a confirmed compromise or only suspicious access.

This lab investigates Windows Data Protection API (DPAPI) artifacts and related endpoint telemetry using PowerShell, Sysmon, and Wazuh.

The investigation focuses on identifying DPAPI-related artifacts within a Windows user profile, reviewing related process activity, and correlating endpoint events using process image, command line, parent process, user context, integrity level, and timestamp.

The investigation follows an evidence-first approach. The presence of a DPAPI artifact, a credential-related keyword, or a process such as `net.exe` is not treated as proof of malicious activity. Each observation must be correlated with additional evidence before reaching a conclusion.

---

## Lab Objectives

The objectives of this lab are to:

- Investigate Windows DPAPI-related artifacts from a user profile and determine what they reveal about the endpoint.
- Identify and document DPAPI-related directories, files, and cryptographic locations associated with the Windows user and system.
- Use PowerShell to collect relevant filesystem and registry evidence without modifying the underlying artifacts.
- Analyze Sysmon process creation telemetry for activity associated with DPAPI, credential, protection, vault, and LSASS-related keywords.
- Investigate `net.exe` activity reported by Wazuh and determine what the exact command line reveals about the process execution.
- Correlate the process image, command line, parent process, user context, integrity level, and timestamp for relevant endpoint events.
- Distinguish normal Windows security artifacts from activity that may require further investigation.
- Understand the limitations of keyword-based searches and identify how they can produce legitimate matches and false positives.
- Build a chronological view of relevant process and artifact activity using Sysmon and Wazuh telemetry.
- Preserve investigation findings in structured evidence files for later review and reproducibility.
- Apply an evidence-first investigation methodology by separating confirmed observations from assumptions and unconfirmed hypotheses.
- Determine whether the collected telemetry is sufficient to support a conclusion of suspicious DPAPI activity or credential theft.
  
---

## Lab Scenario

A Windows endpoint is being investigated for possible credential-related activity involving the **Data Protection API (DPAPI)**. The investigation begins after identifying DPAPI-related artifacts within the user's profile and process telemetry containing terms associated with credential protection and Windows authentication.

The endpoint under investigation is:

- **Hostname:** `DESKTOP-9MMM37V`
- **User:** `desktop-9mmm37v\dell`
- **Profile:** `C:\Users\Dell`
- **Domain:** `WORKGROUP`
- **Wazuh Agent:** `001`

The investigation focuses on the following areas:

- Windows DPAPI user-profile artifacts under `AppData\Roaming\Microsoft\Protect`.
- Machine-level cryptographic locations under `ProgramData\Microsoft\Crypto`.
- Relevant registry locations associated with Windows cryptographic functionality.
- Sysmon process creation and file telemetry.
- Wazuh process telemetry from the endpoint.

During the investigation, Sysmon process creation events are searched for terms such as `dpapi`, `protect`, `cryptprotect`, `credential`, `vault`, and `lsass`. Several matching events are identified and recorded for further correlation.

A separate Wazuh event identifies the execution of:

`C:\Windows\SysWOW64\net.exe`

with the command line:

`net.exe accounts`

The event also provides additional process context, including the integrity level and parent process:

`C:\Program Files (x86)\ossec-agent\wazuh-agent.exe`

The investigation therefore requires more than simply identifying `net.exe` or a DPAPI-related keyword. The analyst must correlate the **process, command line, parent process, user, timestamp, and surrounding endpoint activity** to determine whether the activity is expected or requires further investigation.

The scenario is deliberately designed around an evidence-first approach. DPAPI artifacts are expected to exist on Windows systems, and tools such as `net.exe` have legitimate administrative uses. Therefore, the presence of an artifact or keyword match should not automatically be interpreted as credential theft.

The investigation should ultimately determine:

- What DPAPI-related artifacts are present?
- What process activity occurred around the investigation?
- What was the exact command executed by `net.exe`?
- What process launched it?
- What user and integrity context were involved?
- Which findings are confirmed by telemetry?
- Which findings remain inconclusive?
- Is there sufficient evidence to associate the observed activity with malicious credential access?

The expected outcome is a documented investigation that distinguishes **observable evidence from assumptions**, rather than forcing a malicious conclusion when the available telemetry does not support one.

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

## Evidence Collected

The investigation generated the following evidence files:

- `Host-Identity.txt`
- `DPAPI-Profile-Artifacts.txt`
- `DPAPI-Registry-Artifacts.txt`
- `DPAPI-Timeline.txt`
- `Sysmon-DPAPI-ProcessActivity.txt`
- `Investigation-Summary.txt`

---

