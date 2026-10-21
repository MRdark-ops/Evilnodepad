# Evilnodepad


---

## Overview

Evilnodepad is a custom Windows loader written in C that implements EDR evasion techniques to inject a staged reverse shell into `notepad.exe` without triggering Microsoft Defender Antivirus.

The project also covers the **defender's perspective**: Sysmon artifact analysis, Sigma detection rules, and Wazuh SIEM integration.

---

## Evasion Techniques

| Technique | Target Layer | Effect |
|---|---|---|
| XOR shellcode encryption | Static detection | Breaks signatures, lowers entropy |
| Dynamic API resolution | Static detection | Empty IAT, no suspicious imports |
| AMSI bypass (`AmsiScanBuffer` patch) | AMSI | Returns `CLEAN` without scanning |
| ntdll unhooking | Behavioral detection | Overwrites EDR hooks in memory |
| Process injection into `notepad.exe` | Attribution | Shellcode runs under a legitimate process |

---

## Repository Structure

```
Evilnodepad/
├── loader.c                             # Final loader (all techniques)
├── detection/
│   ├── sigma/
│   │   ├── Evilnodepad_injection.yml      # T1055.003 — CreateRemoteThread
│   │   ├── Evilnodepad_network.yml        # T1071    — C2 from notepad.exe
│   │   └── Evilnodepad_recon.yml          # T1033    — post-exploitation recon
│   └── wazuh/
│       └── Evilnodepad_rules.xml          # Wazuh XML rules (levels 12–15)
├── report/
│   └── Evilnodepad_main.tex               # Full LaTeX report (French)
├── .gitignore
└── README.md
```

---

## Sigma Detection Rules

### Rule 1 — Process Injection via CreateRemoteThread (T1055.003)

```yaml
title: Memory injection via CreateRemoteThread into a legitimate process
id: f3a8d2c1-4b7e-4f9a-8c3d-1e5b2a6f0d9c
status: experimental
logsource:
  category: create_remote_thread
  product: windows
detection:
  selection:
    EventID: 8
    TargetImage|endswith:
      - '\notepad.exe'
      - '\explorer.exe'
      - '\svchost.exe'
  filter:
    SourceImage|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
  condition: selection and not filter
level: high
tags:
  - attack.defense_evasion
  - attack.t1055.003
```

### Rule 2 — C2 Communication from notepad.exe (T1071)

```yaml
title: Outbound network connection initiated by a text editor
id: 9c2e1b4a-7f3d-4a8b-b5c6-0d2f8e1a3c7b
status: experimental
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    EventID: 3
    Image|endswith: '\notepad.exe'
    Initiated: 'true'
  filter:
    DestinationIp|startswith:
      - '127.'
      - '::1'
  condition: selection and not filter
level: critical
tags:
  - attack.command_and_control
  - attack.t1071
```

### Rule 3 — Post-Exploitation Recon with High Integrity (T1033)

```yaml
title: Post-exploitation recon with elevated privileges
id: 2d7f4e8b-1a3c-4b9d-c6e0-5f2a8b1d3e7c
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    EventID: 1
    Image|endswith:
      - '\whoami.exe'
      - '\ipconfig.exe'
      - '\net.exe'
      - '\systeminfo.exe'
    IntegrityLevel: 'High'
  filter:
    ParentImage|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
  condition: selection and not filter
level: high
tags:
  - attack.discovery
  - attack.t1033
```

Convert to any SIEM with `pySigma`:
```bash
sigma convert -t wazuh         -r detection/sigma/Evilnodepad_injection.yml
sigma convert -t elasticsearch -r detection/sigma/Evilnodepad_network.yml
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Phase |
|---|---|---|
| Process Injection: Remote Thread | T1055.003 | Defense Evasion |
| Dynamic API Resolution | T1027.007 | Defense Evasion |
| AMSI Bypass | T1562.001 | Defense Evasion |
| Application Layer Protocol | T1071 | Command & Control |
| System Owner/User Discovery | T1033 | Discovery |

---

## Environment

- **Attacker**: Kali Linux — Metasploit Framework
- **Target**: Windows 11 — Microsoft Defender Antivirus (active)
- **Network**: Host-only adapter (`192.168.56.0/24`)
- **Compiler**: `gcc` (MinGW-w64, x86_64-w64-mingw32)

---

## Build

```bash
x86_64-w64-mingw32-gcc loader.c -o loader.exe -lntdll
```

