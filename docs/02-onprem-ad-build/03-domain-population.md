# Phase 02: On-Prem AD Build — Domain Population

User accounts, service accounts, groups, SPNs, and deliberate misconfigurations created to enable the seven on-prem attack techniques in Phase 03. Everything here was built intentionally — nothing is random, every misconfiguration maps directly to a named attack technique.

---

## Design principle

An empty domain can't be attacked, administered, or learned from. But populating a domain randomly doesn't teach anything either. Every object created in this phase was designed with Phase 03's attack list in mind — the misconfigurations exist because they represent real conditions found in production environments, not because they were convenient to set up.

---

## OU structure (recap)

Full structure documented in `docs/02-onprem-ad-build/02-ou-structure.md`. Objects placed as follows:

```
KaveeLab
├── Tier0\Accounts     ← adm.kavee
├── Tier2\Accounts     ← john.smith, sarah.jones, mike.brown
├── ServiceAccounts    ← svc.http, svc.sql, svc.backup
└── Groups\Security    ← GG-Helpdesk, GG-Finance, GG-HR, DL-ServerAccess
```

---

## User accounts

### Admin account — Tier0\Accounts

| Attribute | Value |
|---|---|
| sAMAccountName | `adm.kavee` |
| UPN | `adm.kavee@kaveelab.internal` |
| Group membership | Domain Admins |
| Description | Personal admin account — Tier0 |
| Misconfiguration | None — this is the legitimate admin account |

The built-in `Administrator` account (RID 500) is not used for day-to-day administration. Real environments always separate the built-in account from personal admin accounts — the built-in account is left as an emergency break-glass credential only.

### Regular users — Tier2\Accounts

| sAMAccountName | Department | Title | Deliberate role in Phase 03 |
|---|---|---|---|
| `john.smith` | IT | Helpdesk Technician | Has GenericWrite ACL over sarah.jones — ACL abuse attack #3 |
| `sarah.jones` | HR | HR Coordinator | Victim of misconfigured ACL — target of ACL abuse |
| `mike.brown` | Finance | Finance Analyst | Normal account — realistic domain population |

---

## Service accounts — ServiceAccounts OU

All three service accounts have `PasswordNeverExpires` set — a common real-world misconfiguration on service accounts, and one that compounds the impact of a weak password since there's no forced rotation.

| sAMAccountName | SPN registered | Password | Pre-auth disabled | Attack technique |
|---|---|---|---|---|
| `svc.http` | Yes | Weak — crackable offline | No | Kerberoasting #1 |
| `svc.sql` | Yes | Weak — crackable offline | No | Kerberoasting #1 |
| `svc.backup` | No | Weak — crackable offline | **Yes** | AS-REP Roasting #2 |

### Why SPNs make svc.http and svc.sql Kerberoasting targets

Any authenticated domain user can request a Kerberos service ticket for any SPN — this is a legitimate Kerberos operation and generates only a standard Event 4769. That service ticket is encrypted with the service account's password hash. The attacker takes it offline, cracks the encryption, and recovers the password — no lockout, no network noise.

Defence in production: long random passwords (120+ characters) via Group Managed Service Accounts (gMSAs), which Windows rotates automatically. Not configured here intentionally — the attack has to work in Phase 03.

### Why disabled pre-authentication makes svc.backup an AS-REP Roasting target

With pre-authentication disabled, the KDC responds to any AS-REQ with an AS-REP containing data encrypted with svc.backup's password hash — without first verifying the requester knows the password. An attacker doesn't even need a domain account in some configurations. The encrypted AS-REP is taken offline and cracked.

The `DoesNotRequirePreAuth` flag is stored as bit `4194304` in the `UserAccountControl` attribute. A normal enabled account reads `512`. svc.backup reads `4194816` (512 + 4194304).

---

## SPNs registered

SPNs registered using `setspn -S` (not `-A`) — the `-S` flag checks for duplicates before adding. Duplicate SPNs silently break Kerberos by causing the KDC to fail to determine which account's key to use for ticket encryption.

```
svc.http:
  HTTP/memsrv01.kaveelab.internal
  HTTP/memsrv01

svc.sql:
  MSSQLSvc/memsrv01.kaveelab.internal:1433
  MSSQLSvc/memsrv01:1433
```

Both FQDN and NetBIOS short-name versions registered — clients may use either format when requesting service tickets.

---

## Groups — Groups\Security OU

Groups follow the AGDLP pattern: Accounts → Global groups → Domain Local groups → Permissions.

| Group | Scope | Members | Purpose |
|---|---|---|---|
| `GG-Helpdesk` | Global | john.smith | Represents the helpdesk team — who |
| `GG-Finance` | Global | mike.brown | Represents finance — who |
| `GG-HR` | Global | sarah.jones | Represents HR — who |
| `DL-ServerAccess` | Domain Local | GG-Helpdesk (nested) | Grants server access — where |

`DL-ServerAccess` contains `GG-Helpdesk` as a group, not individual users — AGDLP nesting in practice. Permissions will be granted to `DL-ServerAccess`; adding or removing users from `GG-Helpdesk` automatically changes their access without touching the permission itself.

---

## Verification commands run

```powershell
# All users with key attributes
Get-ADUser -Filter * -SearchBase "OU=KaveeLab,DC=kaveelab,DC=internal" `
    -Properties Department, Title, PasswordNeverExpires, DoesNotRequirePreAuth |
    Select-Object Name, SamAccountName, Enabled, Department, DoesNotRequirePreAuth, PasswordNeverExpires |
    Format-Table -AutoSize

# Domain Admins membership
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName

# SPNs
setspn -L svc.http
setspn -L svc.sql
setspn -L svc.backup   # should return nothing — no SPN, only pre-auth flag

# Pre-auth flag — svc.backup should show 4194816
Get-ADUser -Identity svc.backup -Properties UserAccountControl |
    Select-Object Name, UserAccountControl

# Group nesting
Get-ADGroupMember -Identity "DL-ServerAccess"
# ObjectClass should be 'group' (GG-Helpdesk), not 'user'

# Duplicate SPN check — should return no results
setspn -X
```

---

## Pending — not yet complete

The ACL misconfiguration (john.smith → GenericWrite over sarah.jones) is not yet applied and will be documented separately once completed. This is the final item before Phase 02 is closed and Phase 03 attack preparation begins.

---

## Status

Domain population complete and verified. OU structure, user accounts, admin account, service accounts, SPNs, pre-auth misconfiguration, and group nesting all confirmed correct via both ADUC and PowerShell. ACL misconfiguration pending.
