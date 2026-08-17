# New-KavelabOUStructure.ps1
# Creates the full KaveeLab OU skeleton in kaveelab.internal
# Run as Domain Admin on DC01
# Safe to re-run only on a fresh domain — will error if OUs already exist

$domain = "DC=kaveelab,DC=internal"

# Top-level container
New-ADOrganizationalUnit -Name "KaveeLab" -Path $domain -ProtectedFromAccidentalDeletion $true

$kaveelab = "OU=KaveeLab,$domain"

# Tier OUs
foreach ($tier in @("Tier0","Tier1","Tier2")) {
    New-ADOrganizationalUnit -Name $tier -Path $kaveelab -ProtectedFromAccidentalDeletion $true
}

# Tier0 children
$tier0 = "OU=Tier0,$kaveelab"
New-ADOrganizationalUnit -Name "Accounts" -Path $tier0 -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Servers"  -Path $tier0 -ProtectedFromAccidentalDeletion $true

# Tier1 children
$tier1 = "OU=Tier1,$kaveelab"
New-ADOrganizationalUnit -Name "Accounts" -Path $tier1 -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Servers"  -Path $tier1 -ProtectedFromAccidentalDeletion $true

# Tier2 children
$tier2 = "OU=Tier2,$kaveelab"
New-ADOrganizationalUnit -Name "Accounts"     -Path $tier2 -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Workstations" -Path $tier2 -ProtectedFromAccidentalDeletion $true

# ServiceAccounts and Groups
New-ADOrganizationalUnit -Name "ServiceAccounts" -Path $kaveelab -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Groups"          -Path $kaveelab -ProtectedFromAccidentalDeletion $true

# Groups sub-OUs
$groups = "OU=Groups,$kaveelab"
New-ADOrganizationalUnit -Name "Security" -Path $groups -ProtectedFromAccidentalDeletion $true

Write-Host "OU structure created. Verify with:" -ForegroundColor Green
Write-Host 'Get-ADOrganizationalUnit -Filter * | Select-Object DistinguishedName | Sort-Object DistinguishedName'
