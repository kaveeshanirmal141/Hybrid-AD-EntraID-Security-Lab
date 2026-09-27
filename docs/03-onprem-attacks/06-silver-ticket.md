# Phase 03: On-Prem Attacks — Attack #6: Silver Ticket

**Technique:** Silver Ticket — forged service ticket using service account hash
**MITRE ATT&CK:** T1558.002 — Steal or Forge Kerberos Tickets: Silver Ticket
**Privilege required:** Service account NT hash (from Attack #1 Kerberoasting or Attack #4 DCSync)
**Tools used:** impacket-ticketer, netexec
**Outcome:** Authenticated to DC01's CIFS service as Administrator using a forged ticket — KDC never involved, no KDC-side events generated

---

## What Silver Ticket Is

A Silver Ticket forges a Kerberos service ticket (TGS) directly, using the service account's own secret key. It skips the KDC entirely — no TGT exchange, no service ticket request. The forged ticket is presented directly to the target service, which decrypts it with its own key and grants access.

Compared to Golden Ticket:

| Property | Golden Ticket | Silver Ticket |
|---|---|---|
| Forged using | krbtgt hash | Service account hash |
| Ticket type | TGT (AS response) | Service ticket (TGS response) |
| Works against | Any service | One specific service |
| KDC involvement | None | None — service validates locally |
| WS2025 PAC check blocks it | Yes | No |
| KDC-side events | None | None |

The impacket output confirms ticket type: Golden Ticket produces `EncASRepPart`, Silver Ticket produces `EncTGSRepPart`. AS = Authentication Service (TGT). TGS = Ticket Granting Service (service ticket).

---

## Why WS2025 PAC Validation Doesn't Block Silver Ticket

The PAC_REQUESTOR check that blocked Golden Ticket on WS2025 only applies when the KDC processes a TGT. Silver Ticket never touches the KDC. The target service validates the ticket locally using its own key. No DC01 KDC validation step exists in the chain, so there is no PAC_REQUESTOR check to fail. Silver Ticket works on WS2025 when Golden Ticket does not.

---

## Hashes Used

Both came from Attack #4 (DCSync):

| Account | NT Hash | SPN Targeted |
|---|---|---|
| svc.http | [REDACTED — Notion only] | HTTP/memsrv01.kaveelab.internal |
| DC01$ | [REDACTED — Notion only] | cifs/dc01.kaveelab.internal |

NT hash values are stored in the private Notion journal only. Not in this repository.

---

## Ticket 1 — HTTP/memsrv01 (Proof of Concept)

```bash
impacket-ticketer \
    -nthash [svc.http NT hash] \
    -domain-sid S-1-5-21-2245599927-464017992-703701844 \
    -domain kaveelab.internal \
    -spn HTTP/memsrv01.kaveelab.internal \
    -user-id 500 \
    administrator
```

**`-nthash`** — svc.http's NT hash. This encrypts the ticket. The HTTP service on MEMSRV01 would decrypt it with svc.http's own key. Not the krbtgt key — the service account's key.

**`-spn HTTP/memsrv01.kaveelab.internal`** — the specific SPN this ticket is valid for. A Silver Ticket is bound to one SPN. Cannot be reused for any other service.

**`-user-id 500`** — the RID to embed in the PAC. Combined with the domain SID, constructs `S-1-5-21-2245599927-464017992-703701844-500` — the built-in Administrator's SID. RID 500 is always the built-in Administrator in every Windows domain.

**`administrator`** — the username embedded in the ticket. Can be any string. The service trusts the PAC SID, not just the name.

**Status:** ticket forged correctly. MEMSRV01 does not yet exist — will be demonstrated against a real HTTP service in Phase 05 when MEMSRV01 is built.

---

## Ticket 2 — CIFS/DC01 (Live Demonstration)

```bash
impacket-ticketer \
    -nthash [DC01$ NT hash] \
    -domain-sid S-1-5-21-2245599927-464017992-703701844 \
    -domain kaveelab.internal \
    -spn cifs/dc01.kaveelab.internal \
    -user-id 500 \
    administrator
```

**Why DC01$'s hash:** the CIFS service on DC01 runs under the machine account `DC01$`, not under a user service account. Each service uses the key of the account it runs under. CIFS on DC01 is owned by DC01$, so DC01$'s hash is required. Every machine account hash from DCSync is a Silver Ticket opportunity against that machine's services.

---

## Authentication to DC01

```bash
KRB5CCNAME=administrator.ccache nxc smb dc01.kaveelab.internal \
    --use-kcache \
    --shares
```

Output:

```
[+] KAVEELAB.INTERNAL\administrator from ccache
Share        Permissions
C$           (accessible)
ADMIN$       (accessible)
SYSVOL       READ
NETLOGON     READ
```

`[+] KAVEELAB.INTERNAL\administrator from ccache` — DC01's CIFS service decrypted the forged ticket using DC01$'s key, read the PAC claiming Administrator (SID -500), and authenticated successfully. No KDC contact. No Event 4769.

SYSVOL and NETLOGON accessible — the forged ticket claiming Administrator identity was granted read access to the domain's Group Policy and logon script shares.

---

## Event 4624 — The Only Log That Exists

Silver Ticket generates zero KDC-side events. The only evidence is a 4624 on the target machine.

| Field | Value | Significance |
|---|---|---|
| TargetUserSid | S-1-5-21-...-500 | Administrator SID — RID 500 confirms built-in Administrator |
| TargetUserName | administrator | Forged identity accepted |
| LogonType | 3 | Network logon |
| SubjectUserName | - | Silver Ticket fingerprint — no local subject exists |
| AuthenticationPackage | Kerberos | Kerberos ticket used, not NTLM |

**`SubjectUserName: -`** is the key anomaly. A legitimate Kerberos logon always has a subject (the account that initiated the session on the local machine). A Silver Ticket logon has no subject because authentication came entirely from the forged ticket — there is no preceding TGT exchange, no local session context, nothing that would create a subject on DC01.

---

## Detection Challenge

The 4624 event from a Silver Ticket is nearly identical to a legitimate Kerberos network logon. Without correlating it against the absence of a corresponding 4769 service ticket event (which the KDC never issued), the 4624 alone is hard to distinguish from legitimate traffic.

The detection requires cross-event correlation: a Kerberos 4624 logon to a DC with no matching 4769 preceding it from the same source IP within a short window. Silver Ticket produces the 4624 without the 4769 because the service ticket was forged, not requested.

---

## KQL Detection Rule

Stored at `scripts/kql-silver-ticket.kql`. Tests in Microsoft Sentinel in Phase 07.

---

## Purple Team Loop

| Step | Status |
|---|---|
| Silver Ticket forged for HTTP/memsrv01 (svc.http hash) | ✅ |
| Silver Ticket forged for cifs/dc01.kaveelab.internal (DC01$ hash) | ✅ |
| Authentication to DC01 CIFS via forged ticket | ✅ |
| No KDC events confirmed — no 4768, no 4769 | ✅ |
| Event 4624 on DC01 — SubjectUserName: -, Kerberos auth | ✅ |
| KQL detection rule written | ✅ |
| HTTP/memsrv01 Silver Ticket against real service | ⏳ Phase 05 (MEMSRV01 build) |
| KQL tested in Sentinel | ⏳ Phase 07 |
