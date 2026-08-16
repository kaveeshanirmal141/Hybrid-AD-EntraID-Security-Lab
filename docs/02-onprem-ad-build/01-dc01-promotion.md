# Phase 02: On-Prem AD Build DC01 Promotion

Forest root domain controller, built and promoted from a bare Windows Server 2025 install. This document covers the design decisions made before promotion, the promotion process itself, and the verification/troubleshooting done afterward to confirm DC01 is actually healthy rather than assuming the wizard's success message was the whole story.

Exact IP addressing, DSRM credentials, and other live values are kept in the private lab journal per project convention this document covers methodology and reasoning, not raw values.

---

## Environment

| Item | Value |
|---|---|
| VM | DC01 |
| OS | Windows Server 2025 Standard Evaluation (Desktop Experience) |
| Hypervisor | VMware Workstation |
| Network | VMnet8 (NAT) |
| Forest / domain name | `kaveelab.internal` |
| NetBIOS name | `KAVEELAB` |
| Forest / domain functional level | Windows Server 2025 |

---

OS edition/install type and the VMware NAT network design are lab-wide decisions, not DC-specific documented in `docs/01-environment-setup/01-vm-foundation.md`. This document picks up from there: DC01's own addressing, domain identity, and promotion.

---

## Decision: Static IP addressing

A domain controller cannot run on a DHCP lease clients locate DCs via DNS records that point at a fixed address, and a changing IP breaks that silently.

Process: checked the NAT network's actual DHCP pool via VMware's Virtual Network Editor -> DHCP Settings (not just the subnet ID, which is a different field and doesn't show the usable range), then assigned DC01 a static IP outside that pool to avoid a future lease collision.

DC01's own preferred DNS server was set to point at **itself**, even before the DNS role existed. This looks wrong until you understand the sequencing: DNS gets installed as part of the promotion wizard, not as a separate step, so DC01 has zero working DNS resolution until promotion completes. Pointing it at itself in advance means the config is already correct the moment DNS comes online no second change needed.

IPv6 was left enabled. Disabling it via the adapter checkbox is a common but incorrect "hardening" step several Windows components (Group Policy processing, DFSR/SYSVOL replication, some AD internals) are built assuming the IPv6 stack is present even when nothing is actively using it on an isolated network.

---

## Decision: Domain name `.internal`, not `.local`

The original plan used `lab.local` as a placeholder. Corrected before promotion:

- `.local` causes mDNS/Bonjour collisions on networks running zeroconf discovery.
- Public certificate authorities have refused to issue certificates for invalid TLDs like `.local` since a CA/Browser Forum decision in November 2015.
- Microsoft's own current guidance: use `.internal` instead of `.local` when not using a subdomain of a domain you actually own.

Settled on `kaveelab.internal` non-conflicting, never externally resolvable, satisfies the original requirement of never using a real org name or FQDN.

---

## Decision: Functional level Windows Server 2025

Set both forest and domain functional level to Windows Server 2025 (the highest available). Every DC expected to join this forest will also run Server 2025, so there's no reason to cap the functional level lower doing so would just disable newer schema and Kerberos hardening features for no benefit.

---

## The promotion process

Two steps, not one a common point of confusion:

1. **Install the AD DS role** (Server Manager -> Add Roles and Features) this only copies binaries. Nothing about the server changes yet.
2. **Run the promotion wizard** (triggered separately after role install finishes) this is the step that actually creates the forest, promotes the server, and critically **installs and configures DNS at the same time**, via the "DNS Server" checkbox on the Domain Controller Options screen. DNS is not a separate manual install for the first DC in a new forest.

Key screens:

- **Deployment Configuration** -> Add a new forest, root domain `kaveelab.internal`
- **Domain Controller Options** -> Forest/Domain functional level: Windows Server 2025; DNS Server: checked; Global Catalog: forced yes (first DC); DSRM password set here a local, non-domain credential used only for booting into Directory Services Restore Mode, unrelated to any domain account
- **DNS Options** -> warned that a DNS delegation can't be created because no authoritative parent zone exists. Expected and correct: `.internal` isn't a real, resolvable TLD, so there's no parent zone to delegate from. Left "Create DNS delegation" unchecked.
- **Additional Options** -> NetBIOS name auto-derived as `KAVEELAB`, left as-is
- **Paths** -> NTDS database, log files, and SYSVOL left at Windows defaults. Separating these onto different volumes is a production disk-failure-isolation practice; irrelevant on a single VM sharing one virtual disk.
- **Review Options** -> generates the equivalent `Install-ADDSForest` PowerShell worth reading before clicking Install, since it's the actual automation underneath the GUI wizard.

---

## Post-promotion verification

Ran a full verification pass rather than trusting the wizard's success message alone:

```powershell
Get-Service NTDS, DNS, Netlogon, kdc
Get-ADDomain
Get-ADForest
Resolve-DnsName kaveelab.internal
Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.kaveelab.internal
netdom query fsmo
dcdiag
```

Results:

- NTDS, DNS, Netlogon, and kdc services all running
- `DomainMode` / `ForestMode`: `Windows2025Domain` / `Windows2025Forest` functional levels landed correctly
- Forward lookup (`kaveelab.internal`) resolves correctly
- The SRV record (`_ldap._tcp.dc._msdcs.kaveelab.internal`) resolves to DC01 this is the specific record clients query to locate a domain controller, so a clean answer here confirms the DNS/AD integration works end to end, not just superficially
- All five FSMO roles (Schema Master, Domain Naming Master, PDC Emulator, RID Master, Infrastructure Master) correctly seated on DC01, confirmed via `netdom query fsmo` after `Get-ADDomain` showed an inconsistent-looking `InfrastructureMaster` field (turned out to be a display formatting difference, not a real role issue)

---

## Troubleshooting: DFSREvent failure in dcdiag

`dcdiag` initially reported `DC01 failed test DFSREvent`. Rather than assume this was boot noise, checked the actual source: **Event Viewer -> Applications and Services Logs -> DFS Replication**.

Important mechanical note: `dcdiag`'s DFSREvent and SystemLog tests scan a **trailing 24-hour window** of the event log, not current state. Re-running `dcdiag` will keep reporting "failed" for a full day after a transient event, regardless of whether the underlying issue actually resolved. The event log itself has to be checked directly to know current health.

Event sequence found:

1. **Error 1202** ("failed to contact domain controller to access configuration information, will retry") logged during the promotion process itself, before AD DS was fully up
2. **Warning 6016** ("failed to update configuration in AD DS, will retry") logged again right after the post-promotion reboot, before NTDS had finished starting
3. **Info 1206** ("successfully contacted domain controller to access configuration") recovery from step 1
4. **Info 4602** - "SYSVOL has been initialized." This is the definitive confirmation event for DFSR/SYSVOL.
5. **Info 6018** - "successfully updated configuration in Active Directory Domain Services," logged several minutes later with no further errors since

Conclusion: this was DFSR racing AD DS's own startup during the promotion + reboot cycle a well-documented pattern on freshly promoted DCs not a real replication problem. Confirmed via the presence of event 4602 and a clean, recent 6018 with nothing further logged afterward.

---

## Troubleshooting: Time source configuration

DC01 holds every FSMO role, including PDC Emulator. As the forest root PDC emulator, there's no domain above it to inherit time from, so by default it uses its own hardware clock as the domain's authoritative time source flagged by `dcdiag` as an `NtpClient` warning.

This matters beyond a cosmetic warning: Kerberos authentication embeds an encrypted timestamp in every ticket request as a defense against replay attacks, and the KDC (running on DC01) rejects any request outside a **5-minute clock skew tolerance** before even checking whether the password is correct. Once other machines join the domain, they inherit their time from DC01 by default, meaning any drift on DC01's clock (VM clocks drift more than physical hardware, especially across pauses/snapshots) propagates domain-wide and produces authentication failures that give no indication they're actually a time problem.

Fix applied:

```powershell
w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /reliable:yes /update
Restart-Service w32time
w32tm /resync /force
w32tm /query /status
```

First attempt was run without the `/reliable:yes /update` flags and silently failed to apply `w32tm /query /status` still showed `Source: Local CMOS Clock` afterward. Re-ran the full command with the missing flags plus a forced resync. Confirmed fixed:

- `Source: time.windows.com,0x8`
- `ReferenceId` resolved to a real external IP
- `Stratum: 5` correct and expected for a machine several hops from an atomic reference clock via NTP, not a downgrade from the earlier (incorrect) Stratum 1 self-reference

---

## Key concepts from this phase

- AD as three integrated pieces: a database (NTDS.dit), a trust protocol (Kerberos), and a policy engine (Group Policy/SYSVOL)
- Why AD has a hard dependency on DNS DC location happens via SRV records, not hardcoded IPs
- Forest = security boundary; domain = one replicated identity database within it
- Role installation and promotion are separate actions; DNS installs as part of promotion, not separately
- DSRM password is a local, non-domain recovery credential
- RID pool allocation and why fresh DCs can throw transient SAM/KDC errors immediately after boot
- DFSR's startup event sequence for SYSVOL initialization, and how to distinguish a real replication failure from boot-time noise
- Kerberos timestamp/replay-attack mechanics and why the whole domain inherits the PDC emulator's clock

---

## Status

DC01 verified healthy: AD DS and DNS running, forest/domain functional levels correct, all FSMO roles seated on DC01, SRV self-registration confirmed, SYSVOL/DFSR initialization confirmed via event log (not assumption), time source corrected and verified against an external NTP source.

**Next:** initial OU structure and test user accounts, or bring MEMSRV01 online and join it to the domain.
