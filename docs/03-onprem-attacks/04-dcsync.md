# Phase 03: On-Prem Attacks — Attack #4: DCSync

**Technique:** DCSync — Domain credential extraction via replication protocol abuse
**MITRE ATT&CK:** T1003.006 — OS Credential Dumping: DCSync
**Privilege required:** DS-Replication-Get-Changes-All (Domain Admin holds this implicitly)
**Tools used:** impacket-secretsdump
**Attacking account:** adm.kavee (Domain Admin)
**Outcome:** Full NTDS.dit dump — every domain account hash extracted remotely without touching DC01 directly

---

## What DCSync Is

Domain controllers replicate their credential stores constantly — when a password changes on DC01, that change must propagate to every other DC in the domain. This replication uses Microsoft's **DRSUAPI (Directory Replication Service API)** protocol.

Two specific rights on the domain object control who can request replication:
- `DS-Replication-Get-Changes`
- `DS-Replication-Get-Changes-All`

Any account holding both can send a `DRSGetNCChanges` RPC call to a DC and request the full credential set for any user — NT hash, AES keys, Kerberos keys, everything. The DC treats it as a legitimate replication partner and complies.

DCSync is not a software vulnerability. It's a legitimate AD replication feature being abused. An attacker with Domain Admin (or an account explicitly granted replication rights) can extract the entire NTDS.dit remotely, over the network, without logging into the DC, without touching the database file, and without installing anything.

---

## Prerequisites

The previous attack chain built the path to this point:

- Attack #1 (Kerberoasting) → cracked svc.http and svc.sql passwords
- Attack #2 (AS-REP Roasting) → cracked svc.backup password
- Attack #3 (ACL Abuse) → cracked sarah.jones via GenericWrite
- **Attack #4 (DCSync)** → requires Domain Admin. `adm.kavee` is the Domain Admin account created in Phase 02. In a real attack chain, this privilege would have been reached through escalation from the above.

---

## The Attack

Single command. No staging, no preparation:

```bash
impacket-secretsdump kaveelab.internal/adm.kavee:'[REDACTED]'@192.168.112.10
```

**`impacket-secretsdump`** — multi-purpose credential extraction tool. When pointed at a DC with Domain Admin credentials, it automatically selects the DRSUAPI (DCSync) method. It connects, sends `DRSGetNCChanges` for every account, decrypts the transport layer, and presents the raw hashes.

**`kaveelab.internal/adm.kavee`** — domain and username authorising the replication request.

**`@192.168.112.10`** — DC01's IP. The target of the replication request.

---

## Output Structure

secretsdump returns four sections:

**Section 1 — Local SAM hashes:** local accounts on DC01 itself (not domain accounts). Separate credential set, different hashes.

**Section 2 — LSA Secrets:** machine account credentials DC01 uses to authenticate to the domain. Includes DC01's own Kerberos keys.

**Section 3 — Domain credentials via DRSUAPI:** the actual DCSync output. Every domain account, format:
```
username:RID:LMhash:NThash:::
```
The LM hash field is always `aad3b435b51404eeaad3b435b51404ee` — a fixed placeholder returned when LM hashing is disabled. Ignore it. The NT hash (4th field) is the real credential.

**Section 4 — Kerberos keys:** full AES256/AES128 key set per account. Required for forging AES-encrypted tickets on WS2025 (which enforces AES by default).

---

## Key Accounts Extracted

| Account | RID | What it enables |
|---|---|---|
| Administrator | 500 | Pass-the-Hash against any domain resource |
| krbtgt | 502 | Golden Ticket (Attack #5) — forge any TGT |
| adm.kavee | 1106 | Confirmed DA credential |
| svc.http | 1107 | Silver Ticket (Attack #6) — confirmed matches Kerberoasting result |
| svc.sql | 1108 | Silver Ticket (Attack #6) — confirmed matches |
| DC01$ | 1000 | Machine account — DC impersonation |
| CLIENT01$ | 1114 | Machine account |

NT hash values are stored in the private Notion journal only. Not in this repository.

---

## Notable Finding — Shared Hashes

john.smith, sarah.jones, and mike.brown returned identical NT hashes — meaning identical passwords. DCSync exposed this without cracking. No wordlist, no GPU time — identical hash strings in the output are visually obvious. This is a common real-world pattern where accounts are created with a standard default password that is never changed.

---

## What DC01 Logged — Event ID 4662

A cluster of Event 4662 entries fired rapidly — one per account being replicated.

| Field | Value | Significance |
|---|---|---|
| Subject Account | adm.kavee | Account performing replication |
| Object | DC=kaveelab,DC=internal | Domain object |
| Operation | Control Access | DS-Replication-Get-Changes-All being exercised |
| Source IP | 192.168.112.138 | ATTACKER01 — not a domain controller |

**The detection signal:** 4662 events from a non-DC source IP accessing replication GUIDs on the domain object. DC-to-DC replication is normal. A workstation or member server requesting replication is not.

---

## KQL Detection Rule

Stored at `scripts/kql-dcsync.kql`. Tests in Microsoft Sentinel in Phase 07.

Detection logic: cluster of Event 4662 entries from a non-DC source, accessing DS-Replication-Get-Changes-All GUID on the domain object, within a 1-minute window. Single 4662s are noise. A cluster from a non-DC IP is DCSync.

---

## What These Hashes Enable

**krbtgt hash → Attack #5 (Golden Ticket).** Forge a TGT for any user with any group memberships, valid indefinitely, without touching the KDC. The domain is owned until krbtgt is rotated twice (single rotation doesn't invalidate all existing tickets).

**svc.http and svc.sql hashes → Attack #6 (Silver Ticket).** Forge service tickets for those specific services, bypassing the KDC entirely.

**Administrator hash → Pass-the-Hash.** Authenticate as built-in Administrator on any domain resource without knowing the plaintext.

---

## Purple Team Loop

| Step | Status |
|---|---|
| DCSync executed from ATTACKER01 as adm.kavee | ✅ |
| Full NTDS.dit dump — every domain account hash extracted | ✅ |
| krbtgt hash obtained for Golden Ticket | ✅ |
| Shared password pattern identified across three accounts | ✅ |
| Event 4662 cluster confirmed on DC01 | ✅ |
| KQL detection rule written | ✅ |
| KQL tested in Microsoft Sentinel | ⏳ Phase 07 |
