# Phase 02: On-Prem AD Build — MEMSRV01 & AD CS

Member server added to the domain to host Active Directory Certificate Services (AD CS). Required for Attack #7 (AD CS Abuse — ESC1) and for the hybrid bridge phase (LDAPS on DC01, Entra Connect certificate auth).

---

## Machine Configuration

| Setting | Value |
|---|---|
| OS | Windows Server 2025 Standard Evaluation |
| Hostname | MEMSRV01 |
| Network | VMnet8 (NAT) |
| IP address | 192.168.112.30 (static) |
| Subnet mask | 255.255.255.0 |
| Default gateway | 192.168.112.2 |
| Preferred DNS | 192.168.112.10 (DC01) |
| Domain joined | kaveelab.internal |
| OU | OU=Servers,OU=Tier1,OU=KaveeLab,DC=kaveelab,DC=internal |
| Role installed | AD CS (Certification Authority + Web Enrollment) |
| CA name | KaveeLab-CA |
| CA type | Enterprise Root CA |

---

## Build Order

AD CS must be installed **after** domain join — Enterprise CA requires domain admin context and registers itself in AD during installation. Installing on a standalone machine and joining later creates an unsupported configuration.

1. Install Windows Server 2025
2. Set static IP (192.168.112.30), DNS pointing at DC01
3. Join to kaveelab.internal
4. Move computer object to correct OU
5. Install AD CS role

---

## Domain Join Note

On first login as `adm.kavee`, the account password had expired (set to require change at next logon during Phase 02). Password was changed to `AdminPass@2026!abc` at the login prompt. All subsequent operations on MEMSRV01 use this credential.

The "Run as different user" prompt does not work reliably for AD CS configuration on MEMSRV01 — logging in directly as `adm.kavee` is required for the Enterprise CA option to be selectable in the wizard.

---

## AD CS Installation

### Role Installation (GUI)

Server Manager → Manage → Add Roles and Features → Role-based installation → MEMSRV01

Role selected: **Active Directory Certificate Services**

Role services selected:
- **Certification Authority** — the CA engine that issues certificates
- **Certification Authority Web Enrollment** — HTTP interface at `/certsrv`, required for ESC8 attack (NTLM relay to web enrollment endpoint)

### Configuration Wizard

After role installation, the yellow flag in Server Manager → "Configure Active Directory Certificate Services":

| Setting | Value chosen | Reason |
|---|---|---|
| Credentials | KAVEELAB\adm.kavee | Domain Admin required for Enterprise CA |
| Setup Type | Enterprise CA | Integrates with AD, publishes templates domain-wide |
| CA Type | Root CA | First CA in the domain, self-signed |
| Private Key | Create new | No existing key to use |
| Cryptography | RSA 2048, SHA256 | Current standard, not legacy |
| CA Name | KaveeLab-CA | Lab naming convention |
| Validity Period | 5 years | Lab lifetime |
| Database | Default paths | No custom storage needed |

**Why Enterprise CA over Standalone CA:** Enterprise CA is AD-integrated. It publishes certificate templates to the domain, auto-enrolls domain members, and is automatically trusted by all domain-joined machines via Group Policy. Standalone CA has none of this — it would require manual trust distribution and doesn't support the template-based ESC1 attack scenario.

---

## Verification

```powershell
# Verify CA service is running
Get-Service certsvc | Select-Object Name, Status, StartType
# Expected: Running / Automatic

# Verify CA is reachable and registered in AD
certutil -ping
# Expected: Server "KaveeLab-CA" ICertRequest2 interface is alive (0ms)
#           CertUtil: -ping command completed successfully.
```

Browser on MEMSRV01: `http://localhost/certsrv` — web enrollment page loads.

---

## Auto-Enrollment on DC01

After KaveeLab-CA was deployed, DC01 automatically requested a Domain Controller certificate from the CA via auto-enrollment (triggered by `gpupdate /force` + `certutil -pulse`). This gave DC01 an SSL certificate enabling LDAPS on port 636.

```powershell
# Verify on DC01 after auto-enrollment
Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject, Issuer, NotAfter
# Expected: CN=DC01.kaveelab.internal, issued by CN=KaveeLab-CA, valid 5 years
```

NTDS service restart required after auto-enrollment for DC01 to load the new certificate and activate LDAPS:

```powershell
Restart-Service NTDS -Force
Test-NetConnection -ComputerName 192.168.112.10 -Port 636
# Expected: TcpTestSucceeded: True
```

---

## Vulnerable Template — KaveeLab-ESC1

A deliberately misconfigured certificate template was created to enable Attack #7 (ESC1). See `docs/03-onprem-attacks/07-adcs-esc1.md` for the attack documentation.

**Template created via certtmpl.msc on MEMSRV01:**

| Setting | Value | Security impact |
|---|---|---|
| Template name | KaveeLab-ESC1 | Lab identifier |
| Duplicated from | User | Base template with Client Authentication EKU |
| Subject Name tab | Supply in the request | **The misconfiguration** — requester controls identity |
| Domain Users — Enroll | Allow | Any domain user can request this certificate |
| Client Authentication EKU | Enabled (inherited from User) | Certificate can authenticate to AD via PKINIT |
| Manager Approval | Not required | Certificates issued immediately, no human review |

**Published via certsrv.msc:** KaveeLab-CA → Certificate Templates → New → Certificate Template to Issue → KaveeLab-ESC1

---

## Snapshot

VMware snapshot taken after AD CS installation and template creation: `Phase03-ADCS-Clean`
