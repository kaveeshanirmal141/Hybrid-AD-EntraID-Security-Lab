# Phase 02: On-Prem AD Build — CLIENT01 Build & Domain Join

Domain-joined Windows 11 workstation. The simulated compromised endpoint — every Phase 03 attack originates from here as a low-privilege domain user, reflecting the realistic attacker starting position.

---

## Why CLIENT01 exists

Real attacks don't originate from the domain controller. An attacker lands on a workstation first — phishing, stolen VPN credentials, drive-by exploit. From CLIENT01, logged in as `john.smith` (a low-privilege helpdesk user), the attacker enumerates, escalates, and moves toward DC01. Running attack tools from DC01 against DC01 skips this entire realistic phase and teaches nothing about the actual attack perspective.

---

## Machine configuration

| Setting | Value |
|---|---|
| OS | Windows 11 Enterprise Evaluation |
| Hostname | CLIENT01 |
| Network | VMnet8 (NAT) — same subnet as DC01 |
| IP address | 192.168.112.20 (static) |
| Subnet mask | 255.255.255.0 |
| Default gateway | 192.168.112.2 |
| Preferred DNS | 192.168.112.10 (DC01) |
| Local account | localadmin |
| Domain | kaveelab.internal |
| OU | OU=Workstations,OU=Tier2,OU=KaveeLab,DC=kaveelab,DC=internal |

---

## OS edition — why Enterprise, not Home

Windows 11 Home cannot join a domain. The Domain radio button in System Properties is greyed out with an explicit "You cannot join a computer running this edition of Windows to a domain" message. This is a hard Microsoft product limitation — not a configuration issue.

First install attempt used Home edition. Discovered during domain join attempt. Reinstalled with Enterprise from Microsoft Evaluation Center. Enterprise was chosen over Pro because it includes all features present in real corporate domain environments.

---

## Pre-join decisions

**Microsoft account removed:** Windows 11 forces Microsoft account sign-in during setup. A Microsoft account on a domain-joined machine creates identity conflicts — Windows tries to reconcile the cloud identity with the domain identity. Local account only (`localadmin`), then domain join.

**DNS pointed at DC01:** Domain join works by querying DNS for `_ldap._tcp.dc._msdcs.kaveelab.internal` — the SRV record that locates the domain controller. If DNS points at `8.8.8.8`, this query returns nothing and the join fails with a misleading "domain not found" error. DC01 must be the configured DNS server before the join wizard runs.

**Static IP:** Domain-joined machines should have predictable addresses. DNS records for `CLIENT01.kaveelab.internal` need to remain stable.

**Computer name before joining:** Renaming after domain join creates unnecessary cleanup work. Set to `CLIENT01` before the join.

---

## What happens during a domain join — the six steps

**Step 1 — DNS SRV lookup:** CLIENT01 queries DC01's DNS for `_ldap._tcp.dc._msdcs.kaveelab.internal`. Answer: DC01 at 192.168.112.10, port 389.

**Step 2 — LDAP connection:** CLIENT01 opens an LDAP connection to DC01 on port 389, authenticates with the credentials entered in the join wizard.

**Step 3 — Computer account created:** DC01 creates `CLIENT01$` in AD. The `$` suffix always denotes a computer account. Lands in `CN=Computers` (default container) by default — moved to the correct OU afterward.

**Step 4 — Machine account password:** A 120-character randomly generated password is negotiated between CLIENT01 and DC01 for the `CLIENT01$` account. Never visible, rotates automatically every 30 days. This is how DC01 trusts CLIENT01 on the network.

**Step 5 — Secure channel established:** Netlogon establishes an encrypted secure channel between CLIENT01 and DC01. All Kerberos requests, Group Policy downloads, and domain authentication flow through this channel.

**Step 6 — Reboot:** The join is not complete until CLIENT01 reboots. On first post-join boot, Kerberos becomes active and Group Policy applies for the first time.

---

## Join method

Used the classic System Properties dialog: right-click Start → System → Advanced system settings → Computer Name tab → Change → Domain radio button → `kaveelab.internal`.

Credential prompt: `KAVEELAB\Administrator` (built-in Domain Admin) used successfully. `adm.kavee` was attempted first but failed at the credential prompt — likely a format issue at that specific dialog. `adm.kavee` login works correctly post-join.

---

## Post-join verification

```powershell
# Confirm domain account is active
whoami
# Returns: kaveelab\adm.kavee

# Confirm domain membership
(Get-WmiObject Win32_ComputerSystem).Domain
# Returns: kaveelab.internal

# Test secure channel — must run elevated
nltest /sc_verify:kaveelab.internal
# Returns:
# Flags: 800000b0 HAS_IP HAS_TIMESERV Authentication Service: Kerberos
# Trusted DC Name \\DC01.kaveelab.internal
# Trusted DC Connection Status = 0 0x0 NERR_Success
# Trust Verification Status = 0 0x0 NERR_Success
# The command completed successfully
```

All three checks passed. Kerberos confirmed as active authentication protocol — not NTLM.

---

## Moving CLIENT01 to the correct OU

Computer account landed in `CN=Computers` after join — the default container, which cannot have GPOs linked to it. Moved via ADUC:

Right-click `CLIENT01` in `CN=Computers` → Move → `KaveeLab → Tier2 → Workstations`

Final DN: `CN=CLIENT01,OU=Workstations,OU=Tier2,OU=KaveeLab,DC=kaveelab,DC=internal`

Any GPO linked to `Tier2\Workstations` will now apply to CLIENT01 correctly.

---

## Snapshot

VMware snapshot taken after domain join and OU move: `Phase02-Complete-Clean`. Taken before any attack tools run or audit policy configured — the clean rollback point for all Phase 03 work.
