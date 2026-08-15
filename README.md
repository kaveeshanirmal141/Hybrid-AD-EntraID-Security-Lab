# Hybrid AD / Entra ID Security Lab

A self-built hybrid identity environment (on-prem Active Directory bridged to Microsoft Entra ID) used to learn, attack, and defend real hybrid identity architecture from first principles. Everything here is built manually, not pulled from a pre-made vulnerable lab, so every misconfiguration exploited is one I created and understand.

## Disclaimer

This is a personal, isolated learning lab. Nothing in this repository is a hardening guide, a production reference, or a tool meant to be pointed at any system I do not own. All attacks are executed against infrastructure built specifically for this project, fully isolated from any production network. Do not deploy any configuration shown here as-is.

## Objective

Move past surface level tool running and build genuine systems level understanding of:

1. How on-prem Active Directory actually works (Kerberos, NTLM, trusts, delegation, ACLs)
2. How Microsoft Entra ID actually works (OAuth2/OIDC, Conditional Access, tokens)
3. How the two are bridged in a real hybrid deployment, and why that bridge is the single highest value target in the environment
4. How to attack that bridge with an understanding of why each technique works, not just which command to run
5. How to detect and respond to those same attacks, building a working (if small scale) SOC function around Microsoft Sentinel

## Architecture

```
On-prem Active Directory  --(Entra Connect / sync)-->  Microsoft Entra ID (cloud)
     Domain Controllers                                     Cloud directory
     Kerberos / NTLM auth                                   OAuth2 / OIDC tokens
                                                              Conditional Access
```

The bridge (Entra Connect, using Password Hash Sync initially, Pass-through Authentication later) is treated as its own tier of the architecture, not a footnote. Most of the interesting attack surface in this project lives in that bridge, not in either directory alone.

## Environment and Resources

**Hypervisor:** VMware Workstation, running on local hardware.

**On-prem virtual machines:**
- `DC01`: Windows Server (first domain controller, forest root)
- `MEMSRV01`: Windows Server (member server, later hosts Entra Connect and/or AD CS)
- `CLIENT01`: Windows 11 (domain joined, later hybrid joined)
- `ATTACKER01`: Kali Linux (isolated on the same lab network, used for the attack track)

**Cloud resources:**
- Azure free trial subscription ($200 credit, 30 day window) for the Entra ID tenant and Microsoft Sentinel
- Microsoft Entra ID P2 trial license (Conditional Access, Identity Protection, PIM)
- Microsoft Entra Connect (classic sync engine, not Cloud Sync, for the first build)

**SIEM / SOC tooling:**
- Microsoft Sentinel (SIEM and SOAR)
- Log Analytics Workspace (log ingestion)
- Sysmon and Windows Event Forwarding on-prem, forwarded into the same workspace
- KQL for custom detection rules

**Offensive tooling (used only inside the isolated lab network):**
- Mimikatz, Rubeus, Impacket, BloodHound, Certipy, PowerView

**Reference lab (secondary, used only after the custom build is attacked first):**
- GOAD (Game of Active Directory) by Orange Cyberdefense, used to cross check technique coverage against a known benchmark, not used as the primary learning environment

## Repository Structure

```
hybrid-ad-entra-lab/
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── 01-environment-setup/
│   ├── 02-onprem-ad-build/
│   ├── 03-onprem-attacks/
│   ├── 04-cloud-tenant-setup/
│   ├── 05-hybrid-bridge-setup/
│   ├── 06-hybrid-pivot-attacks/
│   └── 07-soc-detection/
├── screenshots/
│   └── (mirrors the docs/ phase folders above)
├── scripts/
│   └── (KQL queries, PowerShell, any automation used)
└── lab-config/
    └── (Ansible/Terraform/Vagrant files, no real credentials committed)
```

## Documentation Split

**Notion** is the real time working journal: daily logs, in-progress screenshots, actual values needed for my own reference while working, and the messy thinking that does not belong in a public repo.

**GitHub (this repo)** is the cleaned up, sanitized, versioned record of what was built and why. Domain names, IPs, and any captured hashes or tickets shown in write-ups here are either fake lab values or explicitly redacted. Nothing that could authenticate to anything real is ever committed.

## Build Order and Tracks

The project runs three tracks. Track A must lead, since Track B and Track C both depend on the environment existing first. Track C (detection) is stood up before Track B (attacks) actually starts firing, so every attack has a chance of being seen and logged, not just executed.

### Track A: Build

| Phase | What | Status |
|---|---|---|
| 1 | On-prem AD forest build (DC01 promoted, forest and domain established) | In progress |
| 2 | On-prem population (OUs, GPOs, service accounts, deliberately chosen weak configurations, documented as they are created) | Not started |
| 3 | Cloud tenant setup (Azure free trial, Entra ID tenant, Entra ID P2 trial license activated) | Not started |
| 4 | Hybrid bridge setup (Entra Connect installed, Password Hash Sync configured first, CLIENT01 hybrid joined) | Not started |

### Track B: Red Team / Attack Testing

11 core techniques across two phases, plus 2 stretch techniques if the project later expands to federation. Order matters: on-prem fundamentals are tested before any hybrid pivot, since the hybrid attacks depend on understanding the on-prem primitives first.

**Phase 3 on-prem attacks, in order:**
1. Kerberoasting
2. AS-REP Roasting
3. ACL / DACL abuse (privilege escalation through misconfigured permissions)
4. DCSync
5. Golden Ticket (built from the KRBTGT hash obtained via DCSync)
6. Silver Ticket
7. AD CS abuse (ESC1 and ESC8 certificate template misconfigurations)

**Phase 6 hybrid pivot attacks, in order:**
8. Entra Connect sync account (MSOL_) abuse, using its on-prem DCSync rights to extract KRBTGT and forge Golden Tickets directly from the sync server
9. Cloud sync connector account abuse (Directory Synchronization Accounts role), using its password reset rights over synced users for account takeover
10. Seamless SSO abuse, stealing the AZUREADSSOACC NTLM hash and forging a Silver Ticket against the SSO endpoint
11. Full pivot chain: compromise the sync server, create a backdoor synced account, authenticate into Entra ID, escalate to Global Admin, persist via a rogue guest account, and disable sync to cover the trail

**Stretch techniques (only if scope expands to AD FS federation):**
12. Password Hash Sync process injection for bulk NT hash harvesting
13. Golden SAML, forging SAML tokens using a stolen AD FS token-signing certificate

### Track C: SOC / Blue Team

This is a small, single-analyst SOC built around Microsoft Sentinel as the SIEM, correlating on-prem identity events with cloud identity events, specifically watching the seam between the two directories rather than treating them as separate monitoring problems.

Structure:
- Log Analytics Workspace as the central ingestion point
- On-prem: Sysmon and Windows Event Forwarding from DC01, MEMSRV01, and CLIENT01
- Cloud: Entra ID sign-in logs and audit logs ingested into the same workspace
- Detection engineering in KQL, with one rule authored and validated for every attack technique in Track B, so each red team test has a matching blue team check rather than attacks and detections being built separately

This makes the project a purple team loop by design: attack technique 1 through 11 above each gets its own detection rule in `docs/07-soc-detection/`, tested by re-running the attack and confirming the alert fires.

## Progress Tracker

- [ ] Track A, Phase 1: On-prem AD forest build
- [ ] Track A, Phase 2: On-prem population
- [ ] Track A, Phase 3: Cloud tenant setup
- [ ] Track A, Phase 4: Hybrid bridge setup
- [ ] Track B, Phase 3: On-prem attacks (7 techniques)
- [ ] Track B, Phase 6: Hybrid pivot attacks (4 core techniques)
- [ ] Track C: Detection rules matching all Track B techniques
- [ ] Stretch: AD FS federation and Golden SAML

## License

MIT. See `LICENSE`.
