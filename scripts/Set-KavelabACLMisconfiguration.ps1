# Set-KavelabACLMisconfiguration.ps1
# Applies deliberate ACL misconfiguration for Phase 03 ACL/DACL Abuse attack (#3)
# Sets GenericWrite ACE on sarah.jones granting john.smith write access to all attributes
# Run as Domain Admin on DC01 after domain population is complete

# Get john.smith's SID — stored in the ACE, not his name
$johnSID = (Get-ADUser -Identity "john.smith").SID

# Get sarah.jones's Distinguished Name — the full LDAP address of her object
$sarahDN = (Get-ADUser -Identity "sarah.jones").DistinguishedName

# Pull the current ACL from sarah.jones's AD object
$acl = Get-Acl -Path "AD:\$sarahDN"

# Build the ACE
# - Principal:   john.smith's SID
# - Rights:      GenericWrite (write all non-protected attributes)
# - Type:        Allow
# - Inheritance: None (this object only — does not flow to child objects)
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.SecurityIdentifier]$johnSID,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
)

# Add the ACE to the existing DACL
$acl.AddAccessRule($ace)

# Write the modified DACL back to sarah.jones's object
Set-Acl -Path "AD:\$sarahDN" -AclObject $acl

Write-Host "[+] GenericWrite ACE written: john.smith -> sarah.jones" -ForegroundColor Yellow
Write-Host "    Attack paths now enabled:" -ForegroundColor Yellow
Write-Host "      - Targeted Kerberoasting (set SPN on sarah.jones)" -ForegroundColor Yellow
Write-Host "      - Logon script hijack (modify scriptPath attribute)" -ForegroundColor Yellow
Write-Host "      - Shadow Credentials (write msDS-KeyCredentialLink)" -ForegroundColor Yellow

# Verify
Write-Host "`n[Verification - explicit ACEs on sarah.jones]" -ForegroundColor Cyan
(Get-Acl -Path "AD:\$sarahDN").Access |
    Where-Object { $_.IsInherited -eq $false } |
    Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType |
    Format-Table -AutoSize
