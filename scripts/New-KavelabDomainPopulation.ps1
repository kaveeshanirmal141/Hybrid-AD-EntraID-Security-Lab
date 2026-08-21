# New-KavelabDomainPopulation.ps1
# Creates all user accounts, service accounts, SPNs, and groups for kaveelab.internal
# Run as Domain Admin on DC01 after OU structure is in place (New-KavelabOUStructure.ps1)
# Passwords here are intentionally weak for attack technique demonstration in Phase 03

#region --- Path Variables ---
$tier0Accounts = "OU=Accounts,OU=Tier0,OU=KaveeLab,DC=kaveelab,DC=internal"
$tier2Accounts = "OU=Accounts,OU=Tier2,OU=KaveeLab,DC=kaveelab,DC=internal"
$svcOU         = "OU=ServiceAccounts,OU=KaveeLab,DC=kaveelab,DC=internal"
$groupsOU      = "OU=Security,OU=Groups,OU=KaveeLab,DC=kaveelab,DC=internal"
#endregion

#region --- Admin Account (Tier0) ---
$adminPass = ConvertTo-SecureString "AdminPass@2026!" -AsPlainText -Force

New-ADUser -Name "Admin Kavee" `
    -SamAccountName "adm.kavee" `
    -UserPrincipalName "adm.kavee@kaveelab.internal" `
    -Path $tier0Accounts `
    -AccountPassword $adminPass `
    -Enabled $true `
    -Description "Personal admin account - Tier0"

Add-ADGroupMember -Identity "Domain Admins" -Members "adm.kavee"
Write-Host "[+] Admin account created and added to Domain Admins" -ForegroundColor Green
#endregion

#region --- Regular Users (Tier2) ---
$userPass = ConvertTo-SecureString "Password123!" -AsPlainText -Force

New-ADUser -Name "John Smith" `
    -SamAccountName "john.smith" `
    -UserPrincipalName "john.smith@kaveelab.internal" `
    -Path $tier2Accounts `
    -AccountPassword $userPass `
    -Enabled $true `
    -Department "IT" `
    -Title "Helpdesk Technician"

New-ADUser -Name "Sarah Jones" `
    -SamAccountName "sarah.jones" `
    -UserPrincipalName "sarah.jones@kaveelab.internal" `
    -Path $tier2Accounts `
    -AccountPassword $userPass `
    -Enabled $true `
    -Department "HR" `
    -Title "HR Coordinator"

New-ADUser -Name "Mike Brown" `
    -SamAccountName "mike.brown" `
    -UserPrincipalName "mike.brown@kaveelab.internal" `
    -Path $tier2Accounts `
    -AccountPassword $userPass `
    -Enabled $true `
    -Department "Finance" `
    -Title "Finance Analyst"

Write-Host "[+] Regular users created" -ForegroundColor Green
#endregion

#region --- Service Accounts ---
New-ADUser -Name "svc.http" `
    -SamAccountName "svc.http" `
    -UserPrincipalName "svc.http@kaveelab.internal" `
    -Path $svcOU `
    -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -Description "HTTP service account - Kerberoasting target"

New-ADUser -Name "svc.sql" `
    -SamAccountName "svc.sql" `
    -UserPrincipalName "svc.sql@kaveelab.internal" `
    -Path $svcOU `
    -AccountPassword (ConvertTo-SecureString "Service123!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -Description "SQL service account - Kerberoasting target"

New-ADUser -Name "svc.backup" `
    -SamAccountName "svc.backup" `
    -UserPrincipalName "svc.backup@kaveelab.internal" `
    -Path $svcOU `
    -AccountPassword (ConvertTo-SecureString "Backup2023!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -Description "Backup service account - AS-REP Roasting target"

Write-Host "[+] Service accounts created" -ForegroundColor Green
#endregion

#region --- SPN Registration ---
# -S flag checks for duplicates before adding (always use -S, never -A)
setspn -S "HTTP/memsrv01.kaveelab.internal" "svc.http"
setspn -S "HTTP/memsrv01" "svc.http"
setspn -S "MSSQLSvc/memsrv01.kaveelab.internal:1433" "svc.sql"
setspn -S "MSSQLSvc/memsrv01:1433" "svc.sql"

Write-Host "[+] SPNs registered on svc.http and svc.sql" -ForegroundColor Green
#endregion

#region --- Pre-Authentication Disable (AS-REP Roasting setup) ---
# Sets bit 4194304 in UserAccountControl
# svc.backup UAC will read 4194816 (512 normal account + 4194304 no preauth)
Set-ADAccountControl -Identity "svc.backup" -DoesNotRequirePreAuth $true

Write-Host "[+] Pre-authentication disabled on svc.backup" -ForegroundColor Yellow
Write-Host "    WARNING: This account is now an AS-REP Roasting target" -ForegroundColor Yellow
#endregion

#region --- Security Groups ---
New-ADGroup -Name "GG-Helpdesk" -GroupScope Global      -GroupCategory Security -Path $groupsOU
New-ADGroup -Name "GG-Finance"  -GroupScope Global      -GroupCategory Security -Path $groupsOU
New-ADGroup -Name "GG-HR"       -GroupScope Global      -GroupCategory Security -Path $groupsOU
New-ADGroup -Name "DL-ServerAccess" -GroupScope DomainLocal -GroupCategory Security -Path $groupsOU

# User membership
Add-ADGroupMember -Identity "GG-Helpdesk" -Members "john.smith"
Add-ADGroupMember -Identity "GG-Finance"  -Members "mike.brown"
Add-ADGroupMember -Identity "GG-HR"       -Members "sarah.jones"

# AGDLP nesting — GG-Helpdesk nested into DL-ServerAccess, not individual users
Add-ADGroupMember -Identity "DL-ServerAccess" -Members "GG-Helpdesk"

Write-Host "[+] Groups created and members added" -ForegroundColor Green
#endregion

#region --- Verification ---
Write-Host "`n--- Verification ---" -ForegroundColor Cyan

Write-Host "`n[Users in KaveeLab OU]"
Get-ADUser -Filter * -SearchBase "OU=KaveeLab,DC=kaveelab,DC=internal" `
    -Properties Department, DoesNotRequirePreAuth, PasswordNeverExpires |
    Select-Object Name, SamAccountName, Enabled, DoesNotRequirePreAuth |
    Format-Table -AutoSize

Write-Host "`n[SPNs on svc.http]"
setspn -L svc.http

Write-Host "`n[SPNs on svc.sql]"
setspn -L svc.sql

Write-Host "`n[svc.backup UserAccountControl - should be 4194816]"
Get-ADUser -Identity svc.backup -Properties UserAccountControl |
    Select-Object Name, UserAccountControl

Write-Host "`n[Domain Admins membership]"
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName

Write-Host "`n[DL-ServerAccess members - should show GG-Helpdesk as ObjectClass=group]"
Get-ADGroupMember -Identity "DL-ServerAccess"

Write-Host "`n[Duplicate SPN check - should return no results]"
setspn -X
#endregion
