# Phase 02: On-Prem AD Build — Audit Policy & Sysmon

Logging infrastructure deployed before Phase 03 attacks begin. The purple team loop (attack → log → detect → KQL rule) requires both layers to be active before any attack runs — if the attack fires before logging is configured, the detection work in Phase 07 has nothing to query.

---

## Why Windows doesn't log by default

Three real reasons Microsoft defaulted to minimal logging:

**Performance.** A busy DC handles thousands of authentication requests per minute. Logging every subcategory by default would generate millions of events per hour, filling disks and degrading authentication performance.

**Noise.** Logging everything makes finding meaningful signal impossible. The intent is that admins enable exactly what their environment needs.

**Most Windows machines have no monitoring.** Aggressive default logging for an audience that doesn't read event logs wastes resources for no benefit.

The real-world consequence: on a default Windows DC, Kerberoasting leaves zero trace. This is why breached organisations often discover attackers were present for months — the logs that would have caught them were never turned on.

---

## Basic vs Advanced Audit Policy — the conflict

Windows has two audit policy systems:

- **Basic** (`secpol.msc`, 9 broad categories) — too coarse, too noisy
- **Advanced** (53 subcategories, controlled by `auditpol`) — surgical precision

**Critical:** if both are configured simultaneously, Basic overrides Advanced on reboot and silently wipes subcategory settings. Fix applied first:

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa -v SCENoApplyLegacyAuditPolicy -t REG_DWORD -d 1 -f
```

This tells Windows to honour Advanced Audit Policy subcategory settings and ignore Basic policy overrides permanently.

---

## Audit Policy — DC01

```powershell
# Kerberos — Kerberoasting, AS-REP Roasting, Golden/Silver Ticket detection
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Account Management — privilege escalation, backdoor accounts
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Directory Service — DCSync and ACL abuse detection
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Logon — lateral movement, Pass-the-Hash
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable

# Privilege Use — Mimikatz SeDebugPrivilege
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# Policy Change — attacker disabling logging
auditpol /set /subcategory:"Audit Policy Change" /success:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable

# Process Creation — attack tool detection
auditpol /set /subcategory:"Process Creation" /success:enable
```

---

## Audit Policy — CLIENT01

```powershell
# Logon — domain account authentication on the workstation
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable

# Process Creation — attack tools launching from the workstation
auditpol /set /subcategory:"Process Creation" /success:enable

# Credential Validation — NTLM authentication attempts
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Privilege Use — Mimikatz on the client side
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
```

---

## Event ID reference — attack technique mapping

| Event ID | What it records | Attack technique |
|---|---|---|
| 4768 | Kerberos TGT requested | AS-REP Roasting, Golden Ticket |
| 4769 | Kerberos service ticket requested | Kerberoasting, Silver Ticket |
| 4771 | Kerberos pre-auth failed | AS-REP Roasting, password spraying |
| 4776 | NTLM credential validation | Pass-the-Hash |
| 5136 | AD object attribute modified | ACL abuse, DCSync setup |
| 4662 | Operation on AD object | DCSync |
| 4624 | Successful logon | Lateral movement |
| 4625 | Failed logon | Brute force, password spraying |
| 4672 | Admin privileges at logon | Golden Ticket |
| 4728/4732 | Member added to security group | Privilege escalation |
| 4688 | Process created | Attack tool detection |
| 4673/4674 | Sensitive privilege use | Mimikatz SeDebugPrivilege |
| 4719 | Audit policy changed | Attacker disabling logging |

---

## Sysmon installation — DC01 and CLIENT01

Same script run on both machines:

```powershell
# Create directory
New-Item -ItemType Directory -Path "C:\Tools\Sysmon" -Force

# Download Sysmon from Microsoft Sysinternals
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
    -OutFile "C:\Tools\Sysmon.zip"
Expand-Archive -Path "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force

# Download SwiftOnSecurity config from GitHub
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# Install with config
& "C:\Tools\Sysmon\Sysmon64.exe" -accepteula -i "C:\Tools\Sysmon\sysmonconfig.xml"

# Verify
Get-Service Sysmon64 | Select-Object Name, Status, StartType
```

---

## Sysmon version and config

| Setting | Value |
|---|---|
| Version | Sysmon64 v15.21 |
| Config | SwiftOnSecurity sysmonconfig-export.xml |
| Config location | `C:\Tools\Sysmon\sysmonconfig.xml` |
| Status (DC01) | Running / Automatic |
| Status (CLIENT01) | Running / Automatic |
| Log location | Applications and Services Logs → Microsoft → Windows → Sysmon → Operational |

---

## Key Sysmon event IDs

| Sysmon Event ID | What it records | Attack relevance |
|---|---|---|
| 1 | Process created with full command line | Every attack tool that runs |
| 3 | Network connection | LDAP sweeps, C2 connections |
| 8 | Remote thread created | Process injection |
| 10 | Process accessed another process | lsass.exe access — primary Mimikatz signal |
| 11 | File created | Attack tools dropping to disk |
| 12/13 | Registry modified | Persistence mechanisms |
| 22 | DNS query | DNS-based C2 |

---

## Why both layers are needed

Audit Policy (Security log) and Sysmon are complementary — neither alone is sufficient:

- **Security log:** who authenticated, what AD objects changed. Blind to what processes ran.
- **Sysmon log:** what processes ran, what commands executed, what network connections were made. Blind to Kerberos ticket details and AD attribute changes.
- **Sentinel (Phase 07):** ingests both, correlates across them, runs KQL detection rules against the combined dataset.

Kerberoasting detection example: Security log provides Event 4769 (service ticket requested by john.smith). Sysmon provides Event 1 (SharpHound.exe launched by john.smith). Combined: a user who just ran SharpHound generated 15 service ticket requests in 2 seconds. That's the detection.

---

## Status

Audit Policy and Sysmon active on DC01 and CLIENT01. Verified via `auditpol /get /category:*` and `Get-Service Sysmon64`. Phase 02 is complete. Phase 03 attacks begin next.
