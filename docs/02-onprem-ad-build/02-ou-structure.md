# Phase 02: On-Prem AD Build — OU Structure

OU structure design and creation for `kaveelab.internal`. Built before any user, computer, or group objects were created — OU structure is infrastructure, not organisation, and changing it after objects live inside it is painful.

---

## Why OU structure matters before anything else

Every GPO link, every permission delegation, and every access control decision in this domain is anchored to an OU. An object's OU determines which policies apply to it and what rights others have over it. Getting the structure wrong before population means fixing it later under live conditions — a well-understood source of AD misconfigurations in real environments.

Default AD containers (`CN=Users`, `CN=Computers`) cannot have GPOs linked to them and handle permission delegation awkwardly. Every real object in this lab lives in a custom OU, not a default container.

---

## Design: Tiered Administration Model

The structure follows Microsoft's tiered administration model — Tier 0 for highest-privilege assets, Tier 1 for servers and server admins, Tier 2 for workstations and standard users. Tier boundaries are enforced structurally: an account in Tier2\Accounts should never have permissions over objects in Tier0.

This directly enables the ACL/DACL abuse attack technique in Phase 3 — that attack is fundamentally about finding places where tier boundaries broke down, where a lower-tier account gained inappropriate rights over a higher-tier object.

---

## Final OU tree

```
kaveelab.internal
└── KaveeLab                          ← top-level container, all lab objects live here
    ├── Tier0
    │   ├── Accounts                  ← Domain Admin level accounts only
    │   └── Servers                   ← DC01 moves here
    ├── Tier1
    │   ├── Accounts                  ← Server admin accounts
    │   └── Servers                   ← MEMSRV01 goes here when built
    ├── Tier2
    │   ├── Accounts                  ← Regular domain users
    │   └── Workstations              ← CLIENT01 goes here when joined
    ├── ServiceAccounts               ← All service accounts, always isolated
    └── Groups
        └── Security                  ← All security groups
```

---

## Design decisions

**Single top-level KaveeLab OU:** keeps all lab-built objects cleanly separated from default system containers. A GPO linked at the KaveeLab level applies across the entire lab environment. Makes the domain easy to read — anything under KaveeLab was deliberately created, anything outside it is a default system object.

**ServiceAccounts always isolated:** service accounts with SPNs registered are Kerberoasting targets by design in Phase 3. Isolating them in their own OU allows a separate, stricter password policy to be applied specifically to them (via Fine-Grained Password Policy), and makes them immediately identifiable without having to search across the domain.

**Groups OU with Security sub-OU:** distribution groups and security groups serve completely different purposes. Security groups carry actual permissions — distribution groups are mail-only and have no security function. Keeping them in a dedicated sub-OU rather than mixed into the Users container or scattered across the domain reflects standard practice and will matter when building out AGDLP group nesting in the next step.

**Accidental deletion protection enabled on all OUs:** each OU was created with "Protect object from accidental deletion" checked. This adds an explicit Deny Delete ACE for the Everyone group on each OU's ACL — even Domain Admins cannot delete or move a protected OU without first explicitly removing that Deny entry via the Object tab in ADUC (only visible with Advanced Features enabled). All OUs in this lab carry this protection.

---

## Equivalent PowerShell

The GUI steps above are equivalent to the script at `scripts/New-KavelabOUStructure.ps1`. Running that script against a fresh domain produces an identical result — useful for rebuilds.

---

## Mistakes made and corrected

ServiceAccounts and Groups were initially created at the `kaveelab.internal` root level rather than inside KaveeLab. Caught before any objects were placed inside them. Fix required:

1. Enabling Advanced Features in ADUC (View → Advanced Features) to expose the Object tab
2. Temporarily removing the deletion protection Deny ACE on each misplaced OU via Properties → Object tab → uncheck "Protect object from accidental deletion"
3. Moving each OU into KaveeLab via right-click → Move
4. Re-enabling the deletion protection on both OUs afterward

This is worth documenting explicitly — the ACL mechanic behind "accidental deletion protection" (an explicit Deny on Everyone) is the same class of permission that makes ACL abuse possible later. Deny always beats Allow in Windows ACLs regardless of account privilege level.

---

## Status

OU skeleton complete and verified in ADUC. No objects placed yet — next step is creating user accounts, service accounts, and groups on top of this structure.
