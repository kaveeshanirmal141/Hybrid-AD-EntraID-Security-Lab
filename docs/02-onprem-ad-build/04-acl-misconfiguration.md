# Phase 02: On-Prem AD Build — ACL Misconfiguration

Final step of Phase 02. A deliberate GenericWrite ACE placed on sarah.jones granting john.smith write access to all her attributes. This simulates a real-world over-permissioned helpdesk delegation and directly enables Attack #3 (ACL/DACL Abuse) in Phase 03.

---

## What was configured

| Setting | Value |
|---|---|
| Principal | `john.smith` (KAVEELAB\john.smith) |
| Target object | `sarah.jones` (CN=Sarah Jones,OU=Accounts,OU=Tier2,OU=KaveeLab,DC=kaveelab,DC=internal) |
| Permission | Write all properties (GenericWrite) |
| ACE Type | Allow |
| Inherited From | None — explicit ACE, not inherited |
| Applies to | This object only |

---

## What GenericWrite enables on a user object

Three separate attack paths from one misconfigured permission:

**Targeted Kerberoasting** — set a fake SPN on sarah.jones, making her a Kerberoasting target on demand. Request a service ticket, take it offline, crack the password. No lockout, no noise.

**Logon script hijack** — modify `scriptPath` attribute to point at attacker-controlled content. Executes in sarah.jones's context the next time she logs in.

**Shadow Credentials** — write to `msDS-KeyCredentialLink` to add an attacker-controlled key. Authenticate as sarah.jones using certificate-based Kerberos without ever knowing or changing her password. No lockout, victim has no indication.

---

## Why this misconfiguration exists in real environments

An IT admin wanted to delegate the helpdesk team the ability to manage certain user attributes — password resets, department info updates. Instead of carefully scoping the exact rights needed, they granted GenericWrite because it was quick and it worked. The delegation was never audited afterward. These accumulate silently over years with no built-in AD alarm to flag them.

GenericWrite is not a suspicious permission on its face — it's a standard AD rights constant. The problem is scope: granting it on a specific user object, to a specific lower-tier account, creates a targeted, exploitable attack path that BloodHound will surface immediately.

---

## Setup method

Configured via ADUC GUI — Advanced Security Settings on sarah.jones → Add → Principal: john.smith → Type: Allow → Applies to: This object only → Write all properties checked.

Equivalent PowerShell in `scripts/Set-KavelabACLMisconfiguration.ps1`.

**Mistake made during setup:** initial ACE was created with `Applies to: This object and all descendant objects` instead of `This object only`. This caused Windows to auto-check `List contents`, `Read all properties`, and `Read permissions` in addition to `Write all properties`. Corrected by editing the ACE and changing scope back to `This object only` — extra checkboxes were artifacts of the wrong scope and cleared automatically on correction.

---

## Verification

```powershell
$dn = (Get-ADUser -Identity "sarah.jones").DistinguishedName
(Get-Acl -Path "AD:\$dn").Access |
    Where-Object { $_.IsInherited -eq $false } |
    Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType |
    Format-Table -AutoSize
```

Expected output includes a row:
- IdentityReference: `KAVEELAB\john.smith`
- ActiveDirectoryRights: includes `GenericWrite` / `WriteProperty`
- AccessControlType: `Allow`

---

## AdminSDHolder — why this works on sarah.jones

AD's built-in protection mechanism (AdminSDHolder + SDProp) automatically resets DACLs on privileged accounts every 60 minutes — Domain Admins, Enterprise Admins, etc. `sarah.jones` is a normal Tier2 user with `adminCount=0`. She has zero SDProp protection. The explicit ACE persists indefinitely with no automatic cleanup.

---

## Detection

Event ID `5136` (directory service object modified) fires when an object's `nTSecurityDescriptor` attribute is changed. The Sentinel KQL detection rule for this attack will query Event 5136 filtering for `nTSecurityDescriptor` modifications on user objects outside expected admin accounts. Built in Phase 07 after the attack is demonstrated.

---

## Status

Phase 02 complete. All preconditions for Phase 03 on-prem attacks are in place:

- [x] DC01 promoted, verified, DNS healthy, time sync correct
- [x] OU structure built — tiered model, all OUs protected
- [x] User accounts created — regular users, admin account, service accounts
- [x] SPNs registered on svc.http and svc.sql (Kerberoasting targets)
- [x] Pre-authentication disabled on svc.backup (AS-REP Roasting target)
- [x] Groups created with AGDLP nesting
- [x] GenericWrite ACE: john.smith → sarah.jones (ACL abuse target)

**Next:** MEMSRV01 and CLIENT01 build, Sysmon + audit logging, then Phase 03 attacks begin.
