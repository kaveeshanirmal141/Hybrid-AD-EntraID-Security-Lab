# Phase 01: Environment Setup VM Foundation

Base virtual machine inventory, install decisions, and network design for the lab, before any domain-specific configuration begins. Everything here applies to the lab as a whole, not to any single machine.

---

## VM inventory

| VM | OS | Role | Status |
|---|---|---|---|
| DC01 | Windows Server 2025 | Forest root domain controller | Built see `docs/02-onprem-ad-build/` |
| MEMSRV01 | Windows Server 2025 | Member server; later hosts Entra Connect and AD CS | Not yet built |
| CLIENT01 | Windows 11 | Domain-joined, later hybrid-joined client | Not yet built |
| ATTACKER01 | Kali Linux | Isolated offensive testing box | Not yet built |

---

## ISO source

Windows Server 2025 Evaluation, downloaded from Microsoft's official [Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025). 180-day evaluation license sufficient for lab purposes, rebuildable as needed.

---

## Decision: OS install - Standard, Desktop Experience

Four options are offered at install: Standard/Datacenter × Core/Desktop Experience.

- **Standard over Datacenter** Datacenter's extra features (unlimited guest VM licensing, Storage Spaces Direct, Shielded VMs) are host-virtualization-scale features a lab doesn't need. Most real-world servers in these roles run Standard no reason to practice against an unrepresentative setup.
- **Desktop Experience over Server Core** Core (no GUI) is the correct production hardening choice: smaller attack surface, fewer patchable components. But Core has no local access to AD Users and Computers, Group Policy Management, DNS Manager, or AD Sites and Services the tools that make AD's structure visible while still learning it. Desktop Experience now, with a deliberate rebuild on Core later as a hardening exercise once the fundamentals are solid, avoids learning "headless remote administration" and "what AD even is" at the same time. This isn't reversible without a full reinstall Core and Desktop Experience are separate images, not a toggle.

This convention applies to every Windows Server VM in the lab (DC01 built; MEMSRV01 to follow the same choice).

---

## Decision: VMware network - NAT (VMnet8), not Bridged or Host-only

- **Bridged** puts the lab directly on the home network unacceptable once ATTACKER01 is running offensive tooling against deliberately vulnerable machines.
- **Host-only** blocks outbound internet entirely, which breaks later requirements: Windows Update, and Entra Connect needing outbound connectivity to Microsoft cloud endpoints.
- **NAT** gives outbound internet with no inbound exposure from the LAN correct tradeoff. All lab VMs share this network so they can reach each other, which the domain requires anyway.

---

## Addressing methodology

Before assigning a static IP to any lab VM, check the network's actual DHCP pool: VMware Workstation -> **Edit -> Virtual Network Editor** -> select the VMnet -> **DHCP Settings** button specifically (the general NAT tab only shows the subnet ID, not the usable range a different field, easy to check the wrong one). Static IPs for any VM in this lab sit outside that pool to avoid a future lease collision.

Exact addressing for DC01 is documented in `docs/02-onprem-ad-build/` alongside the domain-specific reasoning (why a DC in particular can't run on DHCP). The same methodology applies when MEMSRV01, CLIENT01, and ATTACKER01 are built.

---

## Status

Network and VM install conventions established. DC01 built on top of this foundation see Phase 02. MEMSRV01, CLIENT01, and ATTACKER01 not yet created; same conventions apply when they are.
