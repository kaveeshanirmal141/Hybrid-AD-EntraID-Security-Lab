# Set-KavelabAuditAndSysmon.ps1
# Configures Advanced Audit Policy and installs Sysmon on DC01 or CLIENT01
# Run as local Administrator on each machine separately
# DC01 gets the full set; CLIENT01 gets the workstation subset

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("DC","Client")]
    [string]$Role
)

#region --- Prevent Basic Audit Policy from overriding Advanced subcategories ---
Write-Host "[*] Applying SCENoApplyLegacyAuditPolicy registry fix..." -ForegroundColor Cyan
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
    -v SCENoApplyLegacyAuditPolicy `
    -t REG_DWORD `
    -d 1 `
    -f | Out-Null
Write-Host "[+] Registry fix applied" -ForegroundColor Green
#endregion

#region --- Audit Policy ---
Write-Host "`n[*] Configuring Advanced Audit Policy for role: $Role" -ForegroundColor Cyan

# Common to both DC and Client
auditpol /set /subcategory:"Logon"                  /success:enable /failure:enable
auditpol /set /subcategory:"Logoff"                  /success:enable
auditpol /set /subcategory:"Special Logon"           /success:enable
auditpol /set /subcategory:"Process Creation"        /success:enable
auditpol /set /subcategory:"Credential Validation"   /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

if ($Role -eq "DC") {
    # DC-specific subcategories
    auditpol /set /subcategory:"Kerberos Authentication Service"   /success:enable /failure:enable
    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
    auditpol /set /subcategory:"Security Group Management"         /success:enable /failure:enable
    auditpol /set /subcategory:"User Account Management"           /success:enable /failure:enable
    auditpol /set /subcategory:"Directory Service Access"          /success:enable /failure:enable
    auditpol /set /subcategory:"Directory Service Changes"         /success:enable /failure:enable
    auditpol /set /subcategory:"Audit Policy Change"               /success:enable
    auditpol /set /subcategory:"Authentication Policy Change"      /success:enable
    Write-Host "[+] DC audit policy configured" -ForegroundColor Green
} else {
    Write-Host "[+] Client audit policy configured" -ForegroundColor Green
}

# Verify
Write-Host "`n[*] Current active subcategories:" -ForegroundColor Cyan
auditpol /get /category:* | Where-Object { $_ -match "Success|Failure" }
#endregion

#region --- Sysmon Installation ---
Write-Host "`n[*] Installing Sysmon..." -ForegroundColor Cyan

New-Item -ItemType Directory -Path "C:\Tools\Sysmon" -Force | Out-Null

# Download Sysmon
Write-Host "    Downloading Sysmon from Microsoft Sysinternals..."
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
    -OutFile "C:\Tools\Sysmon.zip"
Expand-Archive -Path "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force

# Download SwiftOnSecurity config
Write-Host "    Downloading SwiftOnSecurity config from GitHub..."
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# Install
Write-Host "    Installing Sysmon with SwiftOnSecurity config..."
& "C:\Tools\Sysmon\Sysmon64.exe" -accepteula -i "C:\Tools\Sysmon\sysmonconfig.xml"

# Verify
Write-Host "`n[*] Sysmon service status:" -ForegroundColor Cyan
Get-Service Sysmon64 | Select-Object Name, Status, StartType
#endregion

Write-Host "`n[+] Setup complete on role: $Role" -ForegroundColor Green
Write-Host "    Security log location:  Event Viewer -> Windows Logs -> Security" -ForegroundColor Gray
Write-Host "    Sysmon log location:    Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> Sysmon -> Operational" -ForegroundColor Gray
