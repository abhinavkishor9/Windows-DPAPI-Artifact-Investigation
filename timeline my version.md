# Investigation Timeline

## 27 September 2026

### 05:54:01

A Sysmon Event ID `1` process creation event matched the DPAPI investigation keyword search.

The search included terms such as:

- `dpapi`
- `protect`
- `cryptprotect`
- `credential`
- `vault`
- `lsass`

**Assessment:** Process activity matched the investigation search criteria. Malicious activity was not established from the keyword match alone.

---

### 05:56:13

A second Sysmon Event ID `1` process creation event matched the investigation keyword search.

The event was included in the investigation output written to:

`Sysmon-DPAPI-ProcessActivity.txt`

**Assessment:** Relevant process telemetry identified. Additional context required.

---

### 05:58:21

A Sysmon Event ID `1` process creation event matched the investigation keyword search.

**Assessment:** Relevant process telemetry identified. The keyword match alone does not establish malicious activity.

---

### 05:58:21

A second Sysmon Event ID `1` process creation event matched the investigation keyword search at the same timestamp.

**Assessment:** Relevant process telemetry identified. Additional process context would be required for behavioral interpretation.

---

## DPAPI User Profile Investigation

### Investigation Activity

The following path was examined:

`C:\Users\Dell\AppData\Roaming\Microsoft\Protect`

The directory existed.

Observed entries included:

- `S-1-5-21-51198790-337801975-3228388354-1001`
- `CREDHIST`

**Assessment:** DPAPI-related user-profile artifacts confirmed.

---

## Machine Cryptographic Artifact Investigation

### Investigation Activity

The following path was examined:

`C:\ProgramData\Microsoft\Crypto`

Observed entries included:

- `PCPKSP`
- `RSA`

**Assessment:** Machine-level cryptographic artifacts confirmed.

---

## Registry Investigation

### Investigation Activity

The investigation checked:

`HKCU:\Software\Microsoft\Cryptography`

The following path was also checked:

`HKCU:\Software\Microsoft\Protect`

The result for the second path was:

`False`

**Assessment:** The specific registry path was not present and was documented as a negative finding.

---

## Wazuh `net.exe` Investigation

### Investigation Activity

Wazuh identified execution of:

`C:\Windows\SysWOW64\net.exe`

The exact command line was:

`net.exe accounts`

Additional process information included:

- Company: `Microsoft Corporation`
- Description: `Net Command`
- Integrity Level: `System`
- Original File Name: `net.exe`
- Parent Process: `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe`

**Assessment:** Confirmed process execution. The available evidence does not independently establish credential theft or malicious activity.

---

## Evidence Collection

### Investigation Activity

The investigation created:

`C:\DPAPILab\Evidence`

The directory was successfully verified.

Evidence files generated during the investigation included:

- `Host-Identity.txt`
- `DPAPI-Profile-Artifacts.txt`
- `DPAPI-Registry-Artifacts.txt`
- `DPAPI-Timeline.txt`
- `Sysmon-DPAPI-ProcessActivity.txt`
- `Investigation-Summary.txt`

**Assessment:** Investigation evidence was preserved in a structured location.

---

