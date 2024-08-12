###################################################################################
#
#    Script:    WINAudit.ps1
#    Version:   1.4
#    Author:    Dan Saunders
#    Contact:   dcscoder@gmail.com
#    Purpose:   Windows Security Configuration Audit Script (PowerShell)
#    Usage:     .\WINAudit.ps1
#
#    This program is free software: you can redistribute it and / or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <https://www.gnu.org/licenses/>.
#
###################################################################################

$Script = "WINAudit_"
$Version = "v1.4"

########## Startup ##########

Write-Host "

          ___      ____      ___ ________  ____    __     __                  __
          \  \    /    \    /  /|__    __||    \  |  |   /  \                |  | __  ________
           \  \  /  /\  \  /  /    |  |   |  \  \ |  |  / /\ \   __    __  __|  ||__||__    __|
            \  \/  /  \  \/  /   __|  |__ |  |\  \|  | /  __  \ |  |__|  ||  __ ||  |   |  |
             \____/    \____/   |________||__| \_____|/__/  \__\|________||_____||__|   |__|


		Script: WINAudit.ps1 - $Version - Author: Dan Saunders dcscoder@gmail.com`n`n"

Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please Note:

Hi $env:USERNAME, script running on $env:ComputerName, please do not touch!

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor yellow -BackgroundColor black

# Check Privileges
$Admin=[Security.Principal.WindowsIdentity]::GetCurrent()
if ((New-Object Security.Principal.WindowsPrincipal $Admin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $False)
{
    Write-Host "`n"
    Write-Warning "You have insufficient permissions. Run this script with local Administrator privileges."
    Write-Host "`n"
    exit
}

########## Admin ##########

# Destination
$Destination = $PSScriptRoot
# System Date/Time
$Timestamp = ((Get-Date).ToString('_yyyyMMdd_HHmmss'))
# Computer Name
$Endpoint = $env:ComputerName
# Triage
$Name = $Script+$Endpoint+$Timestamp
$Audit = $Name

# Stream Events
Start-Transcript $Destination\$Audit\WINAudit.log -Append | Out-Null

# Directory Structure
New-Item $Destination\$Audit\RawData -ItemType Directory | Out-Null
New-Item $Destination\$Audit\Reference -ItemType Directory | Out-Null

# Report
Write-Output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Security Configuration Report - $Script$Version
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" > $Destination\$Audit\WINAudit_Security_Configuration_Report.txt

########## Functions ##########

function Test-RegistryValue ($Key, $Value) {
	if (Get-ItemProperty -Path $Key -Name $Value -ErrorAction Ignore) {
		$True
    } else {
        $False
    }
}

########## General Information ##########
Write-Output "`n### General Information`n
Note: This data should be used to correlate registry audit findings and can be located within 'RawData'.`n" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt

Write-Output "`n### Recommended Manual Verification`n
Note: Additional checks should be carried out on general information located within 'RawData'. The below are some optional recommendations:`n
AntiVirus: Verify what endpoint protection solution is in-use, i.e. is an EDR in use, therefore Windows Defender is disabled.`n
Installed Programs: Verify no risky or potentially unwanted applications (PUA) are installed, i.e. an unauthorised remote access Trojans (RAT), not approved in the organisation acceptable use policy.`n
Hotfixes: Verify security fixes are being applied to the system, i.e. any recent critical security fixes.`n
Scheduled Tasks: Verify no cleartext credentials exist within scheduled tasks, i.e. an SQL server may have hardcoded credentials within a scheduled task to connect to a database.`n
Local Users: Verify when the password for the local user was last changed, i.e. a user accounts password may not be frequently rotated.`n
Local Groups: Verify standard users are assigned suitable group privileges, i.e. a user account may be assigned to local Administrators group.`n
Internet Connection: Verify sensitive servers do not allow outbound internet connections, i.e. a Domain Controller.`n" >> $Destination\$Audit\Reference\Recommended_Manual_Verification.txt

# System Information
Write-Output "General Checks: System" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
try
{
	systeminfo | Out-File $Destination\$Audit\RawData\System_Information.txt
}
catch
{

}

# Network Configuration
Write-Output "General Checks: Network" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
try
{
	ipconfig | Out-File $Destination\$Audit\RawData\IP_Configuration.txt
}
catch
{

}

# PowerShell Version
Write-Output "General Checks: PowerShell Version" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
try
{
	$PSVersionTable.PSVersion | Out-File $Destination\$Audit\RawData\PowerShell_Version.txt
}
catch
{

}

# PowerShell States
Write-Output "General Checks: PowerShell States" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
try
{
	Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShell* | Format-Table FeatureName, DisplayName, State | Out-File $Destination\$Audit\RawData\PowerShell_States.txt
}
catch
{

}

# Hotfixes
Write-Output "General Checks: Hotfixes" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
try
{
	Get-HotFix | Sort-Object InstalledOn -ErrorAction SilentlyContinue | Format-Table InstalledOn, HotFixID, InstalledBy, Description, Caption, FixComments, InstallDate, Name, Status | Out-File $Destination\$Audit\RawData\Security_Hotfixes.txt
}
catch
{

}

# AntiVirus
Write-Output "General Checks: AntiVirus" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
try
{
	Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Out-File $Destination\$Audit\RawData\AntiVirus_Product.txt
	Get-WmiObject -namespace root\Microsoft\SecurityClient -Class AntimalwareHealthStatus | Out-File $Destination\$Audit\RawData\Antimalware_Health_Status.txt
}
catch
{

}

# Installed Programs
Write-Output "General Checks: Installed Programs" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
try
{
	Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher | Out-File $Destination\$Audit\RawData\Installed_Programs.txt
}
catch
{

}

# Scheduled Tasks
Write-Output "General Checks: Scheduled Tasks" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
try
{
	schtasks /query /fo CSV /v > $Destination\$Audit\RawData\Scheduled_Tasks.csv
}
catch
{

}

# Local Users
Write-Output "General Checks: Local Users" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
try
{
	Get-LocalUser | Select * | Out-File $Destination\$Audit\RawData\Local_Users.txt
}
catch
{

}

# Local Administrators
Write-Output "General Checks: Local Administrators" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
try
{
	net localgroup administrators | Out-File $Destination\$Audit\RawData\Local_Administrators.txt
}
catch
{

}

# Internet Connection Test
Write-Output "General Checks: Internet Connection Test" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$OS = (Get-WMIObject win32_operatingsystem) | Select Name
if($OS[0] -like "*Server*") {
	Test-NetConnection "google.com" -Port "80" -WarningAction SilentlyContinue > $Destination\$Audit\Internet_Connection_Test.txt
	Test-NetConnection "google.com" -Port "443" -WarningAction SilentlyContinue >> $Destination\$Audit\Internet_Connection_Test.txt
}
else
{
	Write-Output "Information: Internet Connection Test not carried out, as system is not a Windows server." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

########## Registry Auditing ##########
Write-Output "`n### Registry Audit" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt

# WDigest Protocol
Write-Output "`nCheck: WDigest Protocol" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$WDigestKey = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest"
$WDigestValue = "UseLogonCredential"
$WDigestRecommended = "0"
if (Test-RegistryValue $WDigestKey $WDigestValue)
{
	$WDigestData = (Get-ItemPropertyValue -Path $WDigestKey -Name $WDigestValue -ea SilentlyContinue)
	if ($WDigestData -Eq "1") {
		Write-Output "Finding: WDigest '$WDigestValue' is set to '1'. WDigest protocol is enabled. `nBackground: Threat actors may use credential stealer tools to harvest cleartext credentials from memory (LSASS). `nRecommendation: Set registry key '$WDigestKey' value '$WDigestValue' to '$WDigestRecommended', to ensure cleartext credentials are not stored in memory (LSASS)." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($WDigestData -Eq "0") { 
		Write-Output "Information: WDigest '$WDigestValue' is set to '0'. WDigest protocol is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: WDigest '$WDigestValue' does not exist, therefore WDigest is not configured, this may pose a risk depending on OS version and security patching. `nBackground: Threat actors may use credential stealer tools to harvest cleartext credentials from memory (LSASS). `nRecommendation: Set registry key '$WDigestKey' value '$WDigestValue' to '$WDigestRecommended', to ensure cleartext credentials are not stored in memory (LSASS). `nCaveat: If this setting is not configured, Windows 7, Windows 8, Windows Server 2008 R2 and Windows Server 2012 all require Microsoft knowledge base KB2871997 is order to disable WDigest. WDigest is disabled by default in Windows 8.1 and Windows Server 2012 R2." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# LSA Protection
Write-Output "`nCheck: LSA Protection" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$LSAKey = "HKLM:\System\CurrentControlSet\Control\Lsa"
$LSAValue = "RunAsPPL"
$LSARecommended = "1"
if (Test-RegistryValue $LSAKey $LSAValue)
{
	$LSAData = (Get-ItemPropertyValue -Path $LSAKey -Name $LSAValue -ea SilentlyContinue)
	if ($LSAData -Eq "1") {
		Write-Output "Information: Local Security Authority (LSA) protection '$LSAValue' is set to '1'. LSA protection is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($LSAData -Eq "0") { 
		Write-Output "Finding: Local Security Authority (LSA) protection '$LSAValue' is set to '0'. LSA protection is disabled. `nBackground: Threat actors may use malicious binaries which are unsigned and often do not adhere to the Microsoft Security Development Lifecycle (SDL) to interact with protected processes. `nRecommendation: Set registry key '$LSAKey' value '$LSAValue' to '$LSARecommended', to ensure only legitimate binaries are permitted to interact with protected processes." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
}
    else
{
    Write-Output "Finding: Local Security Authority (LSA) protection '$LSAValue' does not exist, therefore LSA protection is disabled. `nBackground: Threat actors may use malicious binaries which are unsigned and often do not adhere to the Microsoft Security Development Lifecycle (SDL) to interact with protected processes. `nRecommendation: Set registry key '$LSAKey' value '$LSAValue' to '$LSARecommended', to ensure only legitimate binaries are permitted to interact with protected processes." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Credential Guard
Write-Output "`nCheck: Credential Guard" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$CredentialGuardKey = "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard"
$CredentialGuardValue = "LsaCfgFlags"
$CredentialGuardRecommended = "1"
if (Test-RegistryValue $CredentialGuardKey $CredentialGuardValue)
{
	$CredentialGuardData = (Get-ItemPropertyValue -Path $CredentialGuardKey -Name $CredentialGuardValue -ea SilentlyContinue)
	if ($CredentialGuardData -Eq "0") {
		Write-Output "Finding: Credential Guard '$CredentialGuardValue' is set to '0'. Credential Guard is disabled. `nBackground: Threat actors may use credential stealer tools to harvest credentials from the system. `nRecommendation: Set registry key '$CredentialGuardKey' value '$CredentialGuardValue' to '$CredentialGuardRecommended', to ensure Credential Guard is enabled with UEFI lock." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($CredentialGuardData -Eq "1") { 
		Write-Output "Information: Credential Guard '$CredentialGuardValue' is set to '1'. Credential Guard is enabled with UEFI lock." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	elseif ($CredentialGuardData -Eq "2") { 
		Write-Output "Finding: Credential Guard '$CredentialGuardValue' is set to '2'. Credential Guard is enabled without UEFI lock." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}
}
}
    else
{
    Write-Output "Finding: Credential Guard '$CredentialGuardValue' does not exist, therefore Credential Guard is disabled. `nBackground: Threat actors may use credential stealer tools to harvest credentials from the system. `nRecommendation: Set registry key '$CredentialGuardKey' value '$CredentialGuardValue' to '$CredentialGuardRecommended', to ensure Credential Guard is enabled with UEFI lock." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Credential Guard Virtualization Security
Write-Output "`nCheck: Credential Guard Virtualization Security" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$VirtualizationSecurityKey = "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard"
$VirtualizationSecurityValue = "EnableVirtualizationBasedSecurity"
$VirtualizationSecurityRecommended = "1"
if (Test-RegistryValue $VirtualizationSecurityKey $VirtualizationSecurityValue)
{
	$VirtualizationSecurityData = (Get-ItemPropertyValue -Path $VirtualizationSecurityKey -Name $VirtualizationSecurityValue -ea SilentlyContinue)
	if ($VirtualizationSecurityData -Eq "0") {
		Write-Output "Finding: Virtualization-based Security '$VirtualizationSecurityValue' is set to '0'. Virtualization-based Security is disabled. `nBackground: Threat actors may use credential stealer tools to harvest credentials from the system. `nRecommendation: Set registry key '$VirtualizationSecurityKey' value '$VirtualizationSecurityValue' to '$VirtualizationSecurityRecommended', to ensure Virtualization-based Security is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($VirtualizationSecurityData -Eq "1") { 
		Write-Output "Information: Virtualization-based Security '$VirtualizationSecurityValue' is set to '1'. Virtualization-based Security is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Virtualization-based Security '$VirtualizationSecurityValue' does not exist, therefore Virtualization-based Security is disabled. `nBackground: Threat actors may use credential stealer tools to harvest credentials from the system. `nRecommendation: Set registry key '$VirtualizationSecurityKey' value '$VirtualizationSecurityValue' to '$VirtualizationSecurityRecommended', to ensure Virtualization-based Security is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Credential Guard Platform Security Level
Write-Output "`nCheck: Credential Guard Platform Security Level" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$PlatformSecurityLevelKey = "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard"
$PlatformSecurityLevelValue = "RequirePlatformSecurityFeatures"
$PlatformSecurityLevelRecommended = "3"
if (Test-RegistryValue $PlatformSecurityLevelKey $PlatformSecurityLevelValue)
{
	$PlatformSecurityLevelData = (Get-ItemPropertyValue -Path $PlatformSecurityLevelKey -Name $PlatformSecurityLevelValue -ea SilentlyContinue)
	if ($PlatformSecurityLevelData -Eq "1") {
		Write-Output "Finding: Platform Security Level '$PlatformSecurityLevelValue' is set to '1'. Platform Security Level is enabled with Secure Boot only. `nBackground: Threat actors may use credential stealer tools to harvest credentials from the system. `nRecommendation: Set registry key '$PlatformSecurityLevelKey' value '$PlatformSecurityLevelValue' to '$PlatformSecurityLevelRecommended', to ensure Platform Security Level is enabled with Secure Boot and DMA protection." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($PlatformSecurityLevelData -Eq "3") { 
		Write-Output "Information: Platform Security Level '$PlatformSecurityLevelValue' is set to '3'. Platform Security Level is enabled with Secure Boot and DMA protection." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Platform Security Level '$PlatformSecurityLevelValue' does not exist, therefore Platform Security Level is disabled. `nBackground: Threat actors may use credential stealer tools to harvest credentials from the system. `nRecommendation: Set registry key '$PlatformSecurityLevelKey' value '$PlatformSecurityLevelValue' to '$PlatformSecurityLevelRecommended', to ensure Platform Security Level is enabled with Secure Boot and DMA protection." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Safe DLL Search Mode
Write-Output "`nCheck: Safe DLL Search Mode" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SafeDLLKey = "HKLM:\System\CurrentControlSet\Control\Session Manager"
$SafeDLLValue = "SafeDllSearchMode"
$SafeDLLRecommended = "1"
if (Test-RegistryValue $SafeDLLKey $SafeDLLValue)
{
	$SafeDLLData = (Get-ItemPropertyValue -Path $SafeDLLKey -Name $SafeDLLValue -ea SilentlyContinue)
	if ($SafeDLLData -Eq "1") {
		Write-Output "Information: Safe DLL Search Mode '$SafeDLLValue' is set to '1'. Safe DLL Search Mode is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SafeDLLData -Eq "0") { 
		Write-Output "Finding: Safe DLL Search Mode '$SafeDLLValue' is set to '0'. Safe DLL Search Mode is disabled. `nBackground: Threat actors may insert unauthorised DLL binaries into an applications working directoryfor malicious execution. `nRecommendation: Set registry key '$SafeDLLKey' value '$SafeDLLValue' to '$SafeDLLRecommended', to ensure %systemroot% is searched for the DLL prior to current or other working directories, reducing the risk of malicious DLL execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Safe DLL Search Mode '$SafeDLLValue' does not exist, therefore Safe DLL Search Mode is disabled. `nBackground: Threat actors may insert unauthorised DLL binaries into an applications working directoryfor malicious execution. `nRecommendation: Set registry key '$SafeDLLKey' value '$SafeDLLValue' to '$SafeDLLRecommended', to ensure %systemroot% is searched for the DLL prior to current or other working directories, reducing the risk of malicious DLL execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Remote Host Credential Delegation
Write-Output "`nCheck: Remote Host Credential Delegation" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$RemoteHostCredDelegationKey = "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation"
$RemoteHostCredDelegationValue = "AllowProtectedCreds"
$RemoteHostCredDelegationRecommended = "1"
if (Test-RegistryValue $RemoteHostCredDelegationKey $RemoteHostCredDelegationValue)
{
	$RemoteHostCredDelegationData = (Get-ItemPropertyValue -Path $RemoteHostCredDelegationKey -Name $RemoteHostCredDelegationValue -ea SilentlyContinue)
	if ($RemoteHostCredDelegationData -Eq "1") {
		Write-Output "Information: Remote Host Credential Delegation '$RemoteHostCredDelegationValue' is set to '1'. The host supports Restricted Admin or Remote Credential Guard mode." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($RemoteHostCredDelegationData -Eq "0") { 
		Write-Output "Finding: Remote Host Credential Delegation '$RemoteHostCredDelegationValue' is set to '0'. Restricted Administration and Remote Credential Guard mode are not supported. User will always need to pass their credentials to the host. `nBackground: Threat actors may use credential stealer tools to harvest credentials from the system. `nRecommendation: Set registry key '$RemoteHostCredDelegationKey' value '$RemoteHostCredDelegationValue' to '$RemoteHostCredDelegationRecommended', to ensure the host supports Restricted Admin or Remote Credential Guard mode, reducing the risk of credential theft." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Remote Host Credential Delegation '$RemoteHostCredDelegationValue' does not exist, therefore Restricted Administration and Remote Credential Guard mode are not supported. User will always need to pass their credentials to the host. `nBackground: Threat actors may use credential stealer tools to harvest credentials from the system. `nRecommendation: Set registry key '$RemoteHostCredDelegationKey' value '$RemoteHostCredDelegationValue' to '$RemoteHostCredDelegationRecommended', to ensure the host supports Restricted Admin or Remote Credential Guard mode, reducing the risk of credential theft." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Remote SAM Enumeration 
Write-Output "`nCheck: Remote SAM Enumeration" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$RemoteSAMEnumKey = "HKLM:\System\CurrentControlSet\Control\Lsa"
$RemoteSAMEnumValue = "RestrictRemoteSAM"
$RemoteSAMEnumRecommended = "1"
if (Test-RegistryValue $RemoteSAMEnumKey $RemoteSAMEnumValue)
{
	$RemoteSAMEnumData = (Get-ItemPropertyValue -Path $RemoteSAMEnumKey -Name $RemoteSAMEnumValue -ea SilentlyContinue)
	if ($RemoteSAMEnumData -Eq "1") {
		Write-Output "Information: Remote SAM Enumeration '$RemoteSAMEnumValue' is set to '1'. Remote SAM Enumeration Restriction is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($RemoteSAMEnumData -Eq "0") { 
		Write-Output "Finding: Remote SAM Enumeration '$RemoteSAMEnumValue' is set to '0'. Remote SAM Enumeration Restriction is disabled. `nBackground: Threat actors may attempt remote calls to SAM databases and active directories to enumerate users and groups. `nRecommendation: Set registry key '$RemoteSAMEnumKey' value '$RemoteSAMEnumValue' to '$RemoteSAMEnumRecommended', to restrict clients which are permitted to make remote calls, to only those users and groups which are defined within the rules." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
}
    else
{
    Write-Output "Finding: Remote SAM Enumeration '$RemoteSAMEnumValue' does not exist, therefore Remote SAM Enumeration Restriction is disabled. `nBackground: Threat actors may attempt remote calls to SAM databases and active directories to enumerate users and groups. `nRecommendation: Set registry key '$RemoteSAMEnumKey' value '$RemoteSAMEnumValue' to '$RemoteSAMEnumRecommended', to restrict clients which are permitted to make remote calls, to only those users and groups which are defined within the rules." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Anonymous Enumeration 
Write-Output "`nCheck: Anonymous Enumeration " >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$RestrictAnonKey = "HKLM:\System\CurrentControlSet\Control\Lsa"
$RestrictAnonValue = "RestrictAnonymous"
$RestrictAnonRecommended = "1"
if (Test-RegistryValue $RestrictAnonKey $RestrictAnonValue)
{
	$RemoteSAMEnumData = (Get-ItemPropertyValue -Path $RestrictAnonKey -Name $RestrictAnonValue -ea SilentlyContinue)
	if ($RemoteSAMEnumData -Eq "1") {
		Write-Output "Information: Restrict Anonymous Enumeration '$RestrictAnonValue' is set to '1'. Restrict Anonymous Enumeration is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($RemoteSAMEnumData -Eq "0") { 
		Write-Output "Finding: Restrict Anonymous Enumeration '$RestrictAnonValue' is set to '0'. Restrict Anonymous Enumeration is disabled. `nBackground: Threat actors may attempt to list account names and enumeration all shared resources including shares. `nRecommendation: Set registry key '$RestrictAnonKey' value '$RestrictAnonValue' to '$RestrictAnonRecommended', to prevent anonyomous logon user sessions and subsequent enumeration." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
}
    else
{
    Write-Output "Finding: Restrict Anonymous Enumeration '$RestrictAnonValue' does not exist, therefore anonymous logon users (null session connections) is enabled. `nBackground: Threat actors may attempt to list account names and enumeration all shared resources including shares. `nRecommendation: Set registry key '$RestrictAnonKey' value '$RestrictAnonValue' to '$RestrictAnonRecommended', to prevent anonyomous logon user sessions and subsequent enumeration." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
}

# Anonymous SAM Enumeration 
Write-Output "`nCheck: Anonymous SAM Enumeration" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$RestrictAnonSAMKey = "HKLM:\System\CurrentControlSet\Control\Lsa"
$RestrictAnonSAMValue = "RestrictAnonymousSAM"
$RestrictAnonSAMRecommended = "1"
if (Test-RegistryValue $RestrictAnonSAMKey $RestrictAnonSAMValue)
{
	$RemoteSAMEnumData = (Get-ItemPropertyValue -Path $RestrictAnonSAMKey -Name $RestrictAnonSAMValue -ea SilentlyContinue)
	if ($RemoteSAMEnumData -Eq "1") {
		Write-Output "Information: Restrict Anonymous SAM Enumeration '$RestrictAnonSAMValue' is set to '1'. Restrict Anonymous SAM Enumeration is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($RemoteSAMEnumData -Eq "0") { 
		Write-Output "Finding: Restrict Anonymous SAM Enumeration '$RestrictAnonSAMValue' is set to '0'. Restrict Anonymous SAM Enumeration is disabled. `nBackground: Threat actors may attempt to list SAM account names. `nRecommendation: Set registry key '$RestrictAnonSAMKey' value '$RestrictAnonSAMValue' to '$RestrictAnonSAMRecommended', to prevent anonyomous logon user sessions enumerating SAM accounts." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
}
    else
{
    Write-Output "Finding: Restrict Anonymous SAM Enumeration '$RestrictAnonSAMValue' does not exist, therefore anonymous logon users (null session connections) for SAM enumeration is enabled. `nBackground: Threat actors may attempt to list SAM account names. `nRecommendation: Set registry key '$RestrictAnonSAMKey' value '$RestrictAnonSAMValue' to '$RestrictAnonSAMRecommended', to prevent anonyomous logon user sessions enumerating SAM accounts." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Link Local Multicast Name Resolution (LLMNR)
Write-Output "`nCheck: Link Local Multicast Name Resolution (LLMNR)" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$LLMNRKey = "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient"
$LLMNRValue = "EnableMulticast"
$LLMNRRecommended = "0"
if (Test-RegistryValue $LLMNRKey $LLMNRValue)
{
	$LLMNRData = (Get-ItemPropertyValue -Path $LLMNRKey -Name $LLMNRValue -ea SilentlyContinue)
	if ($LLMNRData -Eq "1") {
		Write-Output "Finding: Link Local Multicast Name Resolution (LLMNR) '$LLMNRValue' is set to '1'. LLMNR is enabled.`nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials, due to insecure LLMNR protocols. This is achieved by impersonating a system when LLMNR sends a resolution query, resulting in LLMNR sending credentials. `nRecommendation: Set registry key '$LLMNRKey' value '$LLMNRValue' to '$LLMNRRecommended', to prevent LLMNR abuse." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($LLMNRData -Eq "0") { 
		Write-Output "Information: Link Local Multicast Name Resolution (LLMNR) '$LLMNRValue' is set to '0'. LLMNR is disabled."  >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: Link Local Multicast Name Resolution (LLMNR) '$LLMNRValue' does not exist, therefore LLMNR is enabled. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials, due to insecure LLMNR protocols. This is achieved by impersonating a system when LLMNR sends a resolution query, resulting in LLMNR sending credentials. `nRecommendation: Set registry key '$LLMNRKey' value '$LLMNRValue' to '$LLMNRRecommended', to prevent LLMNR abuse." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# NetBIOS Name Service (NBT-NS)
Write-Output "`nCheck: NetBIOS Name Service (NBT-NS)" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$NBTNSKey = "HKLM:\System\CurrentControlSet\Services\NetBT\Parameters"
$NBTNSValue = "NodeType"
$NBTNSRecommended = "2"
if (Test-RegistryValue $NBTNSKey $NBTNSValue)
{
	$NBTNSData = (Get-ItemPropertyValue -Path $NBTNSKey -Name $NBTNSValue -ea SilentlyContinue)
	if ($NBTNSData -Eq "1") {
		Write-Output "Finding: NetBIOS Name Service (NBT-NS) '$NBTNSValue' is set to '1'. B-node = Broadcast. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials, due to insecure name resolution methods. `nRecommendation: Set registry key '$NBTNSKey' value '$NBTNSValue' to '$NBTNSRecommended', to ensure NetBIOS Name Service (NBT-NS) is using a secure name resolution method." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($NBTNSData -Eq "2") { 
		Write-Output "Information: NetBIOS Name Service (NBT-NS) '$NBTNSValue' is set to '2'. P-node = Peer-to-peer: for environments with WINS servers only." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	elseif ($NBTNSData -Eq "4") { 
		Write-Output "Finding: NetBIOS Name Service (NBT-NS) '$NBTNSValue' is set to '4'. M-node = Mixed: broadcast first, then use WINS servers. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials, due to insecure name resolution methods. `nRecommendation: Set registry key '$NBTNSKey' value '$NBTNSValue' to '$NBTNSRecommended', to ensure NetBIOS Name Service (NBT-NS) is using a secure name resolution method." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	elseif ($NBTNSData -Eq "8") { 
		Write-Output "Finding: NetBIOS Name Service (NBT-NS) '$NBTNSValue' is set to '8'. H-node = Hybrid: use WINS servers first, then use broadcast. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials, due to insecure name resolution methods. `nRecommendation: Set registry key '$NBTNSKey' value '$NBTNSValue' to '$NBTNSRecommended', to ensure NetBIOS Name Service (NBT-NS) is using a secure name resolution method." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt

	}
}
}
}
    else
{
    Write-Output "Finding: NetBIOS Name Service (NBT-NS) 'NodeType' does not exist, therefore NetBIOS Name Service (NBT-NS) is set to broadcast by default. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials, due to insecure name resolution methods. `nRecommendation: Set registry key '$NBTNSKey' value '$NBTNSValue' to '$NBTNSRecommended', to ensure NetBIOS Name Service (NBT-NS) is using a secure name resolution method." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Cached Domain Credentials
Write-Output "`nCheck: Cached Domain Credentials" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DomainCredsKey = "HKLM:\System\CurrentControlSet\Control\Lsa"
$DomainCredsValue = "DisableDomainCreds"
$DomainCredsRecommended = "1"
if (Test-RegistryValue $DomainCredsKey $DomainCredsValue)
{
	$DomainCredsData = (Get-ItemPropertyValue -Path $DomainCredsKey -Name $DomainCredsValue -ea SilentlyContinue)
	if ($DomainCredsData -Eq "1") {
		Write-Output "Information: Cached Domain Credentials '$DomainCredsValue' is set to '1'. Cached Domain Credentials in Credential Manager is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DomainCredsData -Eq "0") { 
		Write-Output "Finding: Cached Domain Credentials '$DomainCredsValue' is set to '0'. Cached Domain Credentials in Credential Manager is enabled. `nBackground: Threat actors may use credential stealer tools to harvest cached domain credentials stored on the local system. `nRecommendation: Set registry key '$DomainCredsKey' value '$DomainCredsValue' to '$DomainCredsRecommended', to ensure credentials are not stored on the local system within Credential Manager." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
}
    else
{
    Write-Output "Finding: Cached Domain Credentials '$DomainCredsValue' does not exist, therefore Cached Domain Credentials in Credential Manager is enabled. `nBackground: Threat actors may use credential stealer tools to harvest cached domain credentials stored on the local system within the Credential Manager. `nRecommendation: Set registry key '$DomainCredsKey' value '$DomainCredsValue' to '$DomainCredsRecommended', to ensure credentials are not stored on the local system within Credential Manager." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Cached Domain Credentials Count
Write-Output "`nCheck: Cached Domain Credentials Count" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DomainCredsCountKey = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$DomainCredsCountValue = "CachedLogonsCount"
$DomainCredsCountRecommended = "0"
$DomainCredsCountAltRecommended = "3"
if (Test-RegistryValue $DomainCredsCountKey $DomainCredsCountValue)
{
	$DomainCredsCountData = (Get-ItemPropertyValue -Path $DomainCredsCountKey -Name $DomainCredsCountValue -ea SilentlyContinue)
	if ($DomainCredsCountData -Ge "1") { 
		Write-Output "Finding: Cached Domain Credentials Count '$DomainCredsCountValue' is set to $DomainCredsCountData. Cached Domain Credentials (hashes) from previous interactive logons is enabled. `nBackground: Threat actors may use credential stealer tools to harvest cached domain credentials stored on the local system and perform offline brute-force attacks. `nRecommendation: Set registry key '$DomainCredsCountKey' value '$DomainCredsCountValue' to '$DomainCredsCountRecommended', to ensure cached domain credentials (hashes) are not stored on the local system. `nCaveat: By default this registry value is set to '10'. If there are operational requirements to have some credentials cached in case the domain is unresponsive, reduce the number to '$DomainCredsCountAltRecommended'." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DomainCredsCountData -Eq "0") { 
		Write-Output "Information: Cached Domain Credentials Count '$DomainCredsCountValue' is set to $DomainCredsCountData. Cached Domain Credentials (hashes) from previous interactive logons is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: Cached Domain Credentials Count '$DomainCredsCountValue' does not exist, therefore Cached Domain Credentials (hashes) from previous interactive logons is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Non Admin Safe Mode Block
Write-Output "`nCheck: Non Admin Safe Mode Block" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SafeModeKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$SafeModeValue = "SafeModeBlockNonAdmins"
$SafeModeRecommended = "1"
if (Test-RegistryValue $SafeModeKey $SafeModeValue)
{
	$SafeModeData = (Get-ItemPropertyValue -Path $SafeModeKey -Name $SafeModeValue -ea SilentlyContinue)
	if ($SafeModeData -Eq "1") {
		Write-Output "Information: Non Admin Safe Mode Block '$SafeModeValue' is set to '1'. Non Admin Safe Mode Block is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SafeModeData -Eq "0") { 
		Write-Output "Finding: Non Admin Safe Mode Block '$SafeModeValue' is set to '0'. Non Admin Safe Mode Block is disabled. `nBackground: Threat actors with standard user credentials that can boot into Microsoft Windows using Safe Mode, Safe Mode with Networking or Safe Mode with Command Prompt options may be able to bypass system protections. `nRecommendation: Set registry key '$SafeModeKey' value '$SafeModeValue' to '$SafeModeRecommended', to ensure Non Admin Safe Mode Block is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
}
    else
{
    Write-Output "Finding: Non Admin Safe Mode Block '$SafeModeValue' does not exist, therefore Non Admin Safe Mode Block is disabled. `nBackground: Threat actors with standard user credentials that can boot into Microsoft Windows using Safe Mode, Safe Mode with Networking or Safe Mode with Command Prompt options may be able to bypass system protections. `nRecommendation: Set registry key '$SafeModeKey' value '$SafeModeValue' to '$SafeModeRecommended', to ensure Non Admin Safe Mode Block is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Command Line Process Auditing
Write-Output "`nCheck: Command Line Process Auditing" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$CmdlineProcKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$CmdlineProcValue = "ProcessCreationIncludeCmdLine_Enabled"
$CmdlineProcRecommended = "1"
if (Test-RegistryValue $CmdlineProcKey $CmdlineProcValue)
{
	$CmdlineProcData = (Get-ItemPropertyValue -Path $CmdlineProcKey -Name $CmdlineProcValue -ea SilentlyContinue)
	if ($CmdlineProcData -Eq "1") {
		Write-Output "Information: Command line process auditing '$CmdlineProcValue' is set to '1'. Command line process auditing is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($CmdlineProcData -Eq "0") { 
		Write-Output "Finding: Command line process auditing '$CmdlineProcValue' is set to '0'. Command line process auditing is disabled. `nBackground: Process auditing by default does not include command line capture, therefore this limits visibility and detection opportunities. `nRecommendation: Set registry key '$CmdlineProcKey' value '$CmdlineProcValue' to '$CmdlineProcRecommended', to ensure process auditing includes command line. Monitor Windows EID 4688 for enhanced visibility." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
}
    else
{
    Write-Output "Finding: Command line process auditing '$CmdlineProcValue' does not exist, therefore command line process auditing is disabled. `nBackground: Process auditing by default does not include command line capture, therefore this limits visibility and detection opportunities. `nRecommendation: Set registry key '$CmdlineProcKey' value '$CmdlineProcValue' to '$CmdlineProcRecommended', to ensure process auditing includes command line. Monitor Windows EID 4688 for enhanced visibility." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# SMBv1
Write-Output "`nCheck: SMBv1" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SMB1Key = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
$SMB1Value = "SMB1"
$SMB1Recommended = "0"
if (Test-RegistryValue $SMB1Key $SMB1Value)
{
	$SMB1Data = (Get-ItemPropertyValue -Path $SMB1Key -Name $SMB1Value -ea SilentlyContinue)
	if ($SMB1Data -Eq "1") {
		Write-Output "Finding: '$SMB1Value' is installed. '$SMB1Value' is enabled. `nBackground: Threat actors may attempt to abuse the highly vulnerable SMB version 1 service. `nRecommendation: Set registry key '$SMB1Key' value '$SMB1Value' to '$SMB1Recommended', to ensure SMB version 1 is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SMB1Data -Eq "0") { 
		Write-Output "Information: '$SMB1Value' is installed. '$SMB1Value' is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: '$SMB1Value' does not exist, therefore '$SMB1Value' is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# SMBv2
Write-Output "`nCheck: SMBv2" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SMB2Key = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
$SMB2Value = "SMB2"
if (Test-RegistryValue $SMB2Key $SMB2Value)
{
	$SMB2Data = (Get-ItemPropertyValue -Path $SMB2Key -Name $SMB2Value -ea SilentlyContinue)
	if ($SMB2Data -Eq "1") {
		Write-Output "Information: '$SMB2Value' is installed. '$SMB2Value' is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SMB2Data -Eq "0") { 
		Write-Output "Information: '$SMB2Value' is installed. '$SMB2Value' is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: '$SMB2Value' does not exist, therefore '$SMB2Value' is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# SMB Require Security Signature Client
Write-Output "`nCheck: SMB Require Security Signature Client" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SMBRequireSSClientKey = "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"
$SMBRequireSSClientValue = "RequireSecuritySignature"
$SMBRequireSSClientRecommended = "1"
if (Test-RegistryValue $SMBRequireSSClientKey $SMBRequireSSClientValue)
{
	$SMBRequireSSClientData = (Get-ItemPropertyValue -Path $SMBRequireSSClientKey -Name $SMBRequireSSClientValue -ea SilentlyContinue)
	if ($SMBRequireSSClientData -Eq "1") {
		Write-Output "Information: SMB Require Security Signature Client '$SMBRequireSSClientValue' is set to '1'. SMB packet signing requirement is enabled for clients - Microsoft network client: Digitally sign communications (always)." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SMBRequireSSClientData -Eq "0") { 
		Write-Output "Finding: SMB Require Security Signature Client '$SMBRequireSSClientValue' is set to '0'. SMB packet signing requirement is disabled for clients. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials via an NTLM relay attack, due to insecure SMB security signatures. `nRecommendation: Set registry key '$SMBRequireSSClientKey' value '$SMBRequireSSClientValue' to '$SMBRequireSSClientRecommended', to ensure SMB Require Security Signature is enabled for clients. `nCaveat: The EnableSecuritySignature registry setting for SMB2+ client and SMB2+ server is ignored. Therefore, this setting does nothing unless you're using SMB1. SMB 2.02 and later signing is controlled solely by being required or not. This setting is used when either the server or client requires SMB signing. Only if both have signing set to 0 will signing not occur." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: SMB Require Security Signature Client '$SMBRequireSSClientValue' does not exist, therefore SMB packet signing requirement is disabled for clients. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials via an NTLM relay attack, due to insecure SMB security signatures. `nRecommendation: Set registry key '$SMBRequireSSClientKey' value '$SMBRequireSSClientValue' to '$SMBRequireSSClientRecommended', to ensure SMB Require Security Signature is enabled for clients. `nCaveat: The EnableSecuritySignature registry setting for SMB2+ client and SMB2+ server is ignored. Therefore, this setting does nothing unless you're using SMB1. SMB 2.02 and later signing is controlled solely by being required or not. This setting is used when either the server or client requires SMB signing. Only if both have signing set to 0 will signing not occur." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# SMB Require Security Signature Server
Write-Output "`nCheck: SMB Require Security Signature Server" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SMBRequireSSServerKey = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
$SMBRequireSSServerValue = "RequireSecuritySignature"
$SMBRequireSSServerRecommended = "1"
if (Test-RegistryValue $SMBRequireSSServerKey $SMBRequireSSServerValue)
{
	$SMBRequireSSServerData = (Get-ItemPropertyValue -Path $SMBRequireSSServerKey -Name $SMBRequireSSServerValue -ea SilentlyContinue)
	if ($SMBRequireSSServerData -Eq "1") {
		Write-Output "Information: SMB Require Security Signature Server '$SMBRequireSSServerValue' is set to '1'. SMB packet signing requirement is enabled for servers - Microsoft network client: Digitally sign communications (always)." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SMBRequireSSServerData -Eq "0") { 
		Write-Output "Finding: SMB Require Security Signature Server '$SMBRequireSSServerValue' is set to '0'. SMB packet signing requirement is disabled for servers. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials via an NTLM relay attack, due to insecure SMB security signatures. `nRecommendation: Set registry key '$SMBRequireSSServerKey' value '$SMBRequireSSServerValue' to '$SMBRequireSSServerRecommended', to ensure SMB Require Security Signature is enabled for servers. `nCaveat: The EnableSecuritySignature registry setting for SMB2+ client and SMB2+ server is ignored. Therefore, this setting does nothing unless you're using SMB1. SMB 2.02 and later signing is controlled solely by being required or not. This setting is used when either the server or client requires SMB signing. Only if both have signing set to 0 will signing not occur." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: SMB Require Security Signature Server '$SMBRequireSSServerValue' does not exist, therefore SMB packet signing requirement is disabled for servers. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials via an NTLM relay attack, due to insecure SMB security signatures. `nRecommendation: Set registry key '$SMBRequireSSServerKey' value '$SMBRequireSSServerValue' to '$SMBRequireSSServerRecommended', to ensure SMB Require Security Signature is enabled for servers. `nCaveat: The EnableSecuritySignature registry setting for SMB2+ client and SMB2+ server is ignored. Therefore, this setting does nothing unless you're using SMB1. SMB 2.02 and later signing is controlled solely by being required or not. This setting is used when either the server or client requires SMB signing. Only if both have signing set to 0 will signing not occur." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# SMB Enable Security Signature Client
Write-Output "`nCheck: SMB Enable Security Signature Client" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SMBEnableSSClientKey = "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"
$SMBEnableSSClientValue = "EnableSecuritySignature"
$SMBEnableSSClientRecommended = "1"
if (Test-RegistryValue $SMBEnableSSClientKey $SMBEnableSSClientValue)
{
	$SMBEnableSSClientData = (Get-ItemPropertyValue -Path $SMBEnableSSClientKey -Name $SMBEnableSSClientValue -ea SilentlyContinue)
	if ($SMBEnableSSClientData -Eq "1") {
		Write-Output "Information: SMB Enable Security Signature Client '$SMBEnableSSClientValue' is set to '1'. SMB packet signing enablement is enabled for clients - Microsoft network server: Digitally sign communications (if client agrees)." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SMBEnableSSClientData -Eq "0") { 
		Write-Output "Finding: SMB Enable Security Signature Client '$SMBEnableSSClientValue' is set to '0'. SMB packet signing enablement is disabled for clients. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials via an NTLM relay attack, due to insecure SMB security signatures. `nRecommendation: Set registry key '$SMBEnableSSClientKey' value '$SMBEnableSSClientValue' to '$SMBEnableSSClientRecommended', to ensure SMB Enable Security Signature is enabled for clients. `nCaveat: The EnableSecuritySignature registry setting for SMB2+ client and SMB2+ server is ignored. Therefore, this setting does nothing unless you're using SMB1. SMB 2.02 and later signing is controlled solely by being required or not. This setting is used when either the server or client requires SMB signing. Only if both have signing set to 0 will signing not occur." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: SMB Enable Security Signature Client '$SMBEnableSSClientValue' does not exist, therefore SMB packet signing enablement is disabled for clients. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials via an NTLM relay attack, due to insecure SMB security signatures. `nRecommendation: Set registry key '$SMBEnableSSClientKey' value '$SMBEnableSSClientValue' to '$SMBEnableSSClientRecommended', to ensure SMB Enable Security Signature is enabled for clients. `nCaveat: The EnableSecuritySignature registry setting for SMB2+ client and SMB2+ server is ignored. Therefore, this setting does nothing unless you're using SMB1. SMB 2.02 and later signing is controlled solely by being required or not. This setting is used when either the server or client requires SMB signing. Only if both have signing set to 0 will signing not occur." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# SMB Enable Security Signature Server
Write-Output "`nCheck: SMB Enable Security Signature Server" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SMBEnableSSServerKey = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
$SMBEnableSSServerValue = "EnableSecuritySignature"
$SMBEnableSSServerRecommended = "1"
if (Test-RegistryValue $SMBEnableSSServerKey $SMBEnableSSServerValue)
{
	$SMBEnableSSServerData = (Get-ItemPropertyValue -Path $SMBEnableSSServerKey -Name $SMBEnableSSServerValue -ea SilentlyContinue)
	if ($SMBEnableSSServerData -Eq "1") {
		Write-Output "Information: SMB Enable Security Signature Server '$SMBEnableSSServerValue' is set to '1'. SMB packet signing enablement is enabled for servers - Microsoft network server: Digitally sign communications (if server agrees)." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SMBEnableSSServerData -Eq "0") { 
		Write-Output "Finding: SMB Enable Security Signature Server '$SMBEnableSSServerValue' is set to '0'. SMB packet signing enablement is disabled for servers. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials via an NTLM relay attack, due to insecure SMB security signatures. `nRecommendation: Set registry key '$SMBEnableSSServerKey' value '$SMBEnableSSServerValue' to '$SMBEnableSSServerRecommended', to ensure SMB Enable Security Signature is enabled for servers. `nCaveat: The EnableSecuritySignature registry setting for SMB2+ client and SMB2+ server is ignored. Therefore, this setting does nothing unless you're using SMB1. SMB 2.02 and later signing is controlled solely by being required or not. This setting is used when either the server or client requires SMB signing. Only if both have signing set to 0 will signing not occur." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: SMB Enable Security Signature Server '$SMBEnableSSServerValue' does not exist, therefore SMB packet signing enablement is disabled for servers. `nBackground: Threat actors may attempt Man-In-The-Middle attacks to harvest credentials via an NTLM relay attack, due to insecure SMB security signatures. `nRecommendation: Set registry key '$SMBEnableSSServerKey' value '$SMBEnableSSServerValue' to '$SMBEnableSSServerRecommended', to ensure SMB Enable Security Signature is enabled for servers. `nCaveat: The EnableSecuritySignature registry setting for SMB2+ client and SMB2+ server is ignored. Therefore, this setting does nothing unless you're using SMB1. SMB 2.02 and later signing is controlled solely by being required or not. This setting is used when either the server or client requires SMB signing. Only if both have signing set to 0 will signing not occur." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Printer Spooler CVE-2021-34527 [PrintNightmare]
Write-Output "`nCheck: Printer Spooler CVE-2021-34527 [PrintNightmare]" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$PrintNightmareKey = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$PrintNightmare1Value = "UpdatePromptSettings"
$PrintNightmare2Value = "NoWarningNoElevationOnInstall"
$PrintNightmareRecommended = "0"
if (Test-RegistryValue $PrintNightmareKey $PrintNightmare1Value)
{
	$PrintNightmare1Data = (Get-ItemPropertyValue -Path $PrintNightmareKey -Name $PrintNightmare1Value -ea SilentlyContinue)
	if ($PrintNightmare1Data -Eq "1") {
		Write-Output "Finding: Printer Spooler [PrintNightmare] '$PrintNightmare1Value' is set to '1'. Printer Spooler [PrintNightmare] is vulnerable. `nBackground: Threat actors may use attempt to exploit CVE-2021-34527 [PrintNightmare] a remote code execution (RCE) vulnerability in the Printer Spooler service. `nRecommendation: Set registry key '$PrintNightmareKey' value '$PrintNightmare1Value' to '$PrintNightmareRecommended', to prevent updating Point and Print drivers. Microsoft knowledge base KB5005010. `nCaveat: If either $PrintNightmare1Value or $PrintNightmare2Value are set to '1' then the system is vulnerable to CVE-2021-34527 [PrintNightmare]." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($PrintNightmare1Data -Eq "0") { 
		Write-Output "Information: Printer Spooler [PrintNightmare] '$PrintNightmare1Value' is set to '0'. Printer Spooler [PrintNightmare] is not vulnerable." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	elseif ($PrintNightmare1Data -Eq "2") { 
		Write-Output "Information: Printer Spooler [PrintNightmare] '$PrintNightmare1Value' is set to '2'. Printer Spooler [PrintNightmare] is not vulnerable. `nBackground: Threat actors may use attempt to exploit CVE-2021-34527 [PrintNightmare] a remote code execution (RCE) vulnerability in the Printer Spooler service. `nRecommendation: Set registry key '$PrintNightmareKey' value '$PrintNightmare1Value' to '$PrintNightmareRecommended', to prevent updating Point and Print drivers. Microsoft knowledge base KB5005010. `nCaveat: If either $PrintNightmare1Value or $PrintNightmare2Value are not set to '0', then the system is vulnerable to CVE-2021-34527 [PrintNightmare]." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}
}
}
    else
{
    Write-Output "Information: Printer Spooler [PrintNightmare] '$PrintNightmare1Value' does not exist, therefore Printer Spooler [PrintNightmare] is not vulnerable." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
if (Test-RegistryValue $PrintNightmareKey $PrintNightmare2Value)
{
	$PrintNightmare2Data = (Get-ItemPropertyValue -Path $PrintNightmareKey -Name $PrintNightmare2Value -ea SilentlyContinue)
	if ($PrintNightmare2Data -Eq "1") {
		Write-Output "Finding: Printer Spooler [PrintNightmare] '$PrintNightmare2Value' is set to '1'. Printer Spooler [PrintNightmare] is vulnerable. `nBackground: Threat actors may use attempt to exploit CVE-2021-34527 [PrintNightmare] a remote code execution (RCE) vulnerability in the Printer Spooler service. `nRecommendation: Set registry key '$PrintNightmareKey' value '$PrintNightmare2Value' to '$PrintNightmareRecommended', to prevent installing Point and Print drivers. Microsoft knowledge base KB5005010. `nCaveat: If either $PrintNightmare1Value or $PrintNightmare2Value are not set to '0', then the system is vulnerable to CVE-2021-34527 [PrintNightmare]." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($PrintNightmare2Data -Eq "0") { 
		Write-Output "Information: Printer Spooler [PrintNightmare] '$PrintNightmare2Value' is set to '0'. Printer Spooler [PrintNightmare] is not vulnerable." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: Printer Spooler [PrintNightmare] '$PrintNightmare2Value' does not exist, therefore Printer Spooler [PrintNightmare] is not vulnerable." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Printer Spooler CVE-2021-34481
Write-Output "`nCheck: Printer Spooler CVE-2021-34481" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$PrinterSpoolerRCEKey = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
$PrinterSpoolerRCEValue = "RestrictDriverInstallationToAdministrators"
$PrinterSpoolerRCERecommended = "1"
if (Test-RegistryValue $PrinterSpoolerRCEKey $PrinterSpoolerRCEValue)
{
	$PrinterSpoolerRCEData = (Get-ItemPropertyValue -Path $PrinterSpoolerRCEKey -Name $PrinterSpoolerRCEValue -ea SilentlyContinue)
	if ($PrinterSpoolerRCEData -Eq "1") {
		Write-Output "Information: Printer Spooler Driver Restriction '$PrinterSpoolerRCEValue' is set to '1'. Printer Spooler Driver Restriction is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($PrinterSpoolerRCEData -Eq "0") { 
		Write-Output "Finding: Printer Spooler Driver Restriction '$PrinterSpoolerRCEValue' is set to '0'. Printer Spooler Driver Restriction is disabled. `nBackground: Threat actors may use attempt to exploit CVE-2021-34481 a remote code execution (RCE) vulnerability in the Printer Spooler service. `nRecommendation: Set registry key '$PrinterSpoolerRCEKey' value '$PrinterSpoolerRCEValue' to '$PrinterSpoolerRCERecommended', to prevent non-administrator users from installing Point and Print drivers. Microsoft knowledge base KB5005652." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: Printer Spooler Driver Restriction '$PrinterSpoolerRCEValue' does not exist, therefore Printer Spooler Driver Restriction is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Hijack Execution Flow Unquoted Path
Write-Output "`nCheck: Hijack Execution Flow Unquoted Path" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$ServicesKey = "HKLM:\System\CurrentControlSet\Services"
$SafeServiceCount = 0
$VulnerableServiceCount = 0
$Services = (Get-ChildItem $ServicesKey | ForEach-Object {Get-ItemProperty $_.PsPath})
foreach ($Service in $Services) {
    $ServiceImagePath = $Service.ImagePath -split ".exe"
    if(($ServiceImagePath[0] -like "* *") -and ($ServiceImagePath[0] -notlike '"*') -and ($ServiceImagePath[0] -notlike "\*")) {
		$VulnerableServiceCount++
		$Service | Format-List -Property DisplayName,ImagePath,PsPath >> $Destination\$Audit\RawData\Vulnerable_Service_Unquoted_File_Paths.txt}
	else {
		$SafeServiceCount++
	}
}
if ($VulnerableServiceCount -Ge "1") {
	Write-Output "Finding: $VulnerableServiceCount Windows services with vulnerable unquoted file paths were identified. `nBackground: Threat actors may attempt to hijack vulnerable file paths lacking surrounding quotations, by placing a malicious payload in a higher level directory of the file path, which Windows will resolve and execute. `nRecommendation: Review Services identified with vulnerable unquoted file paths and modify to contain quotations, to ensure the Service cannot be exploited for persistence purposes." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
else
{
	Write-Output "Information: $SafeServiceCount Windows services were identified, none were found to be lacking surrounding quotations, therefore are not vulnerable." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Legacy PowerShell
Write-Output "`nCheck: Legacy PowerShell" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$PSInstallKey = "HKLM:\Software\Microsoft\PowerShell\1\PowerShellEngine"
$PSInstallValue = "PowerShellVersion"
if (Test-RegistryValue $PSInstallKey $PSInstallValue)
{
	$PSInstallData = (Get-ItemPropertyValue -Path $PSInstallKey -Name $PSInstallValue -ea SilentlyContinue)
	if ($PSInstallData -Match "1.0") {
		Write-Output "Finding: PowerShell version 1.0 is installed. Logging and AMSI not supported for legacy version. `nBackground: Threat actors may leverage legacy PowerShell versions for defense evasion to avoid updated PowerShell logging and AMSI protection. `nRecommendation: Either disable or/and uninstall PowerShell version 1.0 or create a software restriction policy preventing the binary from executing, to prevent legacy PowerShell abuse." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($PSInstallData -Match "2.0") { 
		Write-Output "Finding: PowerShell version 2.0 is installed. Logging and AMSI not supported for legacy version. `nBackground: Threat actors may leverage legacy PowerShell versions for defense evasion to avoid updated PowerShell logging and AMSI protection. `nRecommendation: Either disable or/and uninstall PowerShell version 2.0 or create a software restriction policy preventing the binary from executing, to prevent legacy PowerShell abuse." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: Legacy PowerShell versions not installed." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# PowerShell Module Logging
Write-Output "`nCheck: PowerShell Module Logging" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$PSModuleLogKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$PSModuleLogValue = "EnableModuleLogging"
$PSModuleRecommended = "1"
$PSModuleLogNamesKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
if (Test-RegistryValue $PSModuleLogKey $PSModuleLogValue)
{
	$PSModuleLogData = (Get-ItemPropertyValue -Path $PSModuleLogKey -Name $PSModuleLogValue -ea SilentlyContinue)
	if ($PSModuleLogData -Eq "1") {
		Write-Output "Information: PowerShell Module Logging '$PSModuleLogValue' is set to '1'. PowerShell Module Logging is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		# Fetch Module Names
		Get-ItemProperty -Path $PSModuleLogNamesKey -Name * -ea SilentlyContinue | Out-File $Destination\$Audit\RawData\PowerShell_Module_Logging.txt}}
	elseif ($PSModuleLogData -Eq "0") { 
		Write-Output "Finding: PowerShell Module Logging '$PSModuleLogValue' is set to '0'. PowerShell Module Logging is disabled. `nBackground: PowerShell Module Logging auditing is not configured by default, therefore this limits visibility and detection opportunities. `nRecommendation: Set registry key '$PSModuleLogKey' value '$PSModuleLogValue' to '$PSModuleRecommended' and specify notable/abnormal modules to monitor. Monitor Windows EID 4103 for enhanced visibility." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
    else
{
    Write-Output "Finding: PowerShell Module Logging '$PSModuleLogValue' does not exist, therefore PowerShell Module Logging is disabled. `nBackground: PowerShell Module Logging auditing is not configured by default, therefore this limits visibility and detection opportunities. `nRecommendation: Set registry key '$PSModuleLogKey' value '$PSModuleLogValue' to '$PSModuleRecommended' and specify notable/abnormal modules to monitor. Monitor Windows EID 4103 for enhanced visibility." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# PowerShell Script Block Logging
Write-Output "`nCheck: PowerShell Script Block Logging" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$PSScriptBlockLogKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$PSScriptBlockLogValue = "EnableScriptBlockLogging"
$PSScriptBlockLogRecommended = "1"
if (Test-RegistryValue $PSScriptBlockLogKey $PSScriptBlockLogValue)
{
	$PSScriptBlockLogData = (Get-ItemPropertyValue -Path $PSScriptBlockLogKey -Name $PSScriptBlockLogValue -ea SilentlyContinue)
	if ($PSScriptBlockLogData -Eq "1") {
		Write-Output "Information: PowerShell Script Block Logging '$PSScriptBlockLogValue' is set to '1'. PowerShell Script Block Logging is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($PSScriptBlockLogData -Eq "0") { 
		Write-Output "Finding: PowerShell Script Block Logging '$PSScriptBlockLogValue' is set to '0'. PowerShell Script Block Logging is disabled. `nBackground: PowerShell Script Block Logging auditing is not configured by default, therefore this limits visibility and detection opportunities. `nRecommendation: Set registry key '$PSScriptBlockLogKey' value '$PSScriptBlockLogValue' to '$PSScriptBlockLogRecommended' and ensure not to enable Invocation. Monitor Windows EID 4104 for enhanced visibility." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
}
    else
{
    Write-Output "Finding: PowerShell Script Block Logging '$PSScriptBlockLogValue' does not exist, therefore PowerShell Script Block Logging is disabled. `nBackground: PowerShell Script Block Logging auditing is not configured by default, therefore this limits visibility and detection opportunities. `nRecommendation: Set registry key '$PSScriptBlockLogKey' value '$PSScriptBlockLogValue' to '$PSScriptBlockLogRecommended' and ensure not to enable Script Block Invocation. Monitor Windows EID 4104 for enhanced visibility." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# PowerShell Script Block Logging Invocation
Write-Output "`nCheck: PowerShell Script Block Logging Invocation" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$PSScriptBlockLogInvoKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$PSScriptBlockLogInvoValue = "EnableScriptBlockInvocationLogging"
$PSScriptBlockLogInvoRecommended = "0"
if (Test-RegistryValue $PSScriptBlockLogInvoKey $PSScriptBlockLogInvoValue)
{
	$PSScriptBlockLogInvoData = (Get-ItemPropertyValue -Path $PSScriptBlockLogInvoKey -Name $PSScriptBlockLogInvoValue -ea SilentlyContinue)
	if ($PSScriptBlockLogInvoData -Eq "1") {
		Write-Output "Finding: PowerShell Script Block Logging Invocation '$PSScriptBlockLogInvoValue' is set to '1'. PowerShell Script Block Logging Invocation is enabled. `nBackground: PowerShell Script Block Invocation can provide additional context, however is very noisy and is not required unless testing is carried out. `nRecommendation: Set registry key '$PSScriptBlockLogInvoKey' value '$PSScriptBlockLogInvoValue' to '$PSScriptBlockLogInvoRecommended', to ensure Script Block Invocation is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($PSScriptBlockLogInvoData -Eq "0") { 
		Write-Output "Information: PowerShell Script Block Logging Invocation '$PSScriptBlockLogInvoValue' is set to '0'. PowerShell Script Block Logging Invocation is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: PowerShell Script Block Logging Invocation '$PSScriptBlockLogInvoValue' does not exist, therefore PowerShell Script Block Logging Invocation is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# PowerShell Transcription Logging
Write-Output "`nCheck: PowerShell Transcription Logging" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$PSTranscriptLogKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
$PSTranscriptLogValue = "EnableTranscripting"
$PSTranscriptLogRecommended = "1"
$PSTranscriptLogDirValue = "OutputDirectory"
if (Test-RegistryValue $PSTranscriptLogKey $PSTranscriptLogValue)
{
	$PSTranscriptLogData = (Get-ItemPropertyValue -Path $PSTranscriptLogKey -Name $PSTranscriptLogValue -ea SilentlyContinue)
	if ($PSTranscriptLogData -Eq "1") {
		Write-Output "Information: PowerShell Transcription Logging '$PSTranscriptLogValue' is set to '1'. PowerShell Transcription Logging is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		# Fetch Output Directory
		Get-ItemProperty -Path $PSTranscriptLogKey -Name $PSTranscriptLogDirValue | Select-Object -ExpandProperty OutputDirectory -ea SilentlyContinue | Out-File $Destination\$Audit\RawData\PowerShell_Transcription_Logging_Path.txt}}
	elseif ($PSTranscriptLogData -Eq "0") { 
		Write-Output "Finding: PowerShell Transcription Logging '$PSTranscriptLogValue' is set to '0'. PowerShell Transcription Logging is disabled.`nBackground: PowerShell Transcription Logging auditing is not configured by default, therefore this limits visibility and investigation opportunities. `nRecommendation: Set registry key '$PSTranscriptLogKey' value '$PSTranscriptLogValue' to '$PSTranscriptLogRecommended' and ensure not to enable Invocation, finally store logs in a suitable directory path. Collect and investigate logs in the event of an incident involving PowerShell." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
    else
{
    Write-Output "Finding: PowerShell Transcription Logging '$PSTranscriptLogValue' does not exist, therefore PowerShell Transcription Logging is disabled.`nBackground: PowerShell Transcription Logging auditing is not configured by default, therefore this limits visibility and investigation opportunities. `nRecommendation: Set registry key '$PSTranscriptLogKey' value '$PSTranscriptLogValue' to '$PSTranscriptLogRecommended' and store logs in a suitable directory path. Collect and investigate logs in the event of an incident involving PowerShell." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# PowerShell Transcription Logging Invocation
Write-Output "`nCheck: PowerShell Transcription Logging Invocation" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$PSTranscriptLogInvoKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
$PSTranscriptLogInvoValue = "EnableInvocationHeader"
$PSTranscriptLogInvoRecommended = "0"
if (Test-RegistryValue $PSTranscriptLogInvoKey $PSTranscriptLogInvoValue)
{
	$PSTranscriptLogInvoData = (Get-ItemPropertyValue -Path $PSTranscriptLogInvoKey -Name $PSTranscriptLogInvoValue -ea SilentlyContinue)
	if ($PSTranscriptLogInvoData -Eq "1") {
		Write-Output "Finding: PowerShell Transcription Logging Invocation '$PSTranscriptLogInvoValue' is set to '1'. PowerShell Transcription Logging Invocation is enabled. PowerShell Transcription Logging Invocation is enabled. `nBackground: PowerShell Transcription Logging Invocation can provide additional context, however is very noisy and is not required unless testing is carried out. `nRecommendation: Set registry key '$PSTranscriptLogInvoKey' value '$PSTranscriptLogInvoValue' to '$PSTranscriptLogInvoRecommended', to ensure Transcription Logging Invocation is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($PSTranscriptLogInvoData -Eq "0") { 
		Write-Output "Information: PowerShell Transcription Logging Invocation '$PSTranscriptLogInvoValue is set to '0'. PowerShell Transcription Logging Invocation is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: PowerShell Transcription Logging Invocation '$PSTranscriptLogInvoValue' does not exist, therefore PowerShell Transcription Logging Invocation is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Remote Desktop Connections
Write-Output "`nCheck: Remote Desktop Connections" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$RDPConnectionsKey = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
$RDPConnectionsValue = "fDenyTSConnections"
$RDPConnectionsRecommended = "1"
if (Test-RegistryValue $RDPConnectionsKey $RDPConnectionsValue)
{
	$RDPConnectionsData = (Get-ItemPropertyValue -Path $RDPConnectionsKey -Name $RDPConnectionsValue -ea SilentlyContinue)
	if ($RDPConnectionsData -Eq "1") {
		Write-Output "Information: Remote Desktop Connections '$RDPConnectionsValue' is set to '1'. Remote Desktop Connections is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($RDPConnectionsData -Eq "0") { 
		Write-Output "Finding: Remote Desktop Connections '$RDPConnectionsValue' is set to '0'. Remote Desktop Connections is enabled. `nBackground: Threat actors may leverage Remote Desktop Services to carry out lateral movement. `nRecommendation: Set registry key '$RDPConnectionsKey' value '$RDPConnectionsValue' to '$RDPConnectionsRecommended', to prevent Remote Desktop Connections to the system. `nCaveat: If the host is a server and not a user endpoint, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: Remote Desktop Connections '$RDPConnectionsValue' does not exist, therefore Remote Desktop Connections is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Remote Desktop Authentication
Write-Output "`nCheck: Remote Desktop Authentication" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$RDPAuthKey = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$RDPAuthValue = "UserAuthentication"
$RDPAuthRecommended = "1"
if (Test-RegistryValue $RDPAuthKey $RDPAuthValue)
{
	$RDPAuthData = (Get-ItemPropertyValue -Path $RDPAuthKey -Name $RDPAuthValue -ea SilentlyContinue)
	if ($RDPAuthData -Eq "1") {
		Write-Output "Information: Remote Desktop Authentication '$RDPAuthValue' is set to '1'. Remote Desktop Network-Level Authentication is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($RDPAuthData -Eq "0") { 
		Write-Output "Finding: Remote Desktop Authentication '$RDPAuthValue' is set to '0'. Remote Desktop Network-Level Authentication is disabled. `nBackground: Threat actors may leverage Remote Desktop Services to carry out lateral movement. `nRecommendation: Set registry key '$RDPAuthKey' value '$RDPAuthValue' to '$RDPAuthRecommended', to ensure Network-Level Authentication is enabled, if RDP is allowed." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Remote Desktop Authentication '$RDPAuthValue' does not exist, therefore Remote Desktop Network-Level Authentication is disabled. `nBackground: Threat actors may leverage Remote Desktop Services to carry out lateral movement. `nRecommendation: Set registry key '$RDPAuthKey' value '$RDPAuthValue' to '$RDPAuthRecommended', to ensure Network-Level Authentication is enabled, if RDP is allowed." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Remote Desktop Unsolicited
Write-Output "`nCheck: Remote Desktop Unsolicited" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$RDPUnsolicitedKey = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$RDPUnsolicitedValue = "fAllowUnsolicited"
$RDPUnsolicitedRecommended = "0"
if (Test-RegistryValue $RDPUnsolicitedKey $RDPUnsolicitedValue)
{
	$RDPUnsolicitedData = (Get-ItemPropertyValue -Path $RDPUnsolicitedKey -Name $RDPUnsolicitedValue -ea SilentlyContinue)
	if ($RDPUnsolicitedData -Eq "1") {
		Write-Output "Finding: Remote Desktop Unsolicited '$RDPUnsolicitedValue' is set to '1'. Remote Desktop Unsolicited requests is enabled. `nBackground: Threat actors may leverage Remote Desktop Services to carry out lateral movement. `nRecommendation: Set registry key '$RDPUnsolicitedKey' value '$RDPUnsolicitedValue' to '$RDPUnsolicitedRecommended', to ensure unsolicited offers of help to the system is disabled, if RDP is allowed." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($RDPUnsolicitedData -Eq "0") { 
		Write-Output "Information: Remote Desktop Unsolicited '$RDPUnsolicitedValue' is set to '0'. Remote Desktop Unsolicited requests is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: Remote Desktop Unsolicited '$RDPUnsolicitedValue' does not exist, therefore Remote Desktop Unsolicited requests is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Remote Desktop Security Layer
Write-Output "`nCheck: Remote Desktop Security Layer" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$RDPSecurityLayerKey = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$RDPSecurityLayerValue = "SecurityLayer"
$RDPSecurityLayerRecommended = "2"
if (Test-RegistryValue $RDPSecurityLayerKey $RDPSecurityLayerValue)
{
	$RDPSecurityLayerData = (Get-ItemPropertyValue -Path $RDPSecurityLayerKey -Name $RDPSecurityLayerValue -ea SilentlyContinue)
	if ($RDPSecurityLayerData -Eq "0") {
		Write-Output "Finding: Remote Desktop Security Layer '$RDPSecurityLayerValue' is set to '0'. Remote Desktop Security Layer is not using SSL/TLS. `nBackground: Threat actors may leverage Remote Desktop Services to carry out lateral movement. `nRecommendation: Set registry key '$RDPSecurityLayerKey' value '$RDPSecurityLayerValue' to '$RDPSecurityLayerRecommended', to ensure SSL/TLS is utilised, if RDP is allowed." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($RDPSecurityLayerData -Eq "1") {
		Write-Output "Finding: Remote Desktop Security Layer '$RDPSecurityLayerValue' is set to '1'. Remote Desktop Security Layer is not required to use SSL/TLS, despite support. `nBackground: Threat actors may leverage Remote Desktop Services to carry out lateral movement. `nRecommendation: Set registry key '$RDPSecurityLayerKey' value '$RDPSecurityLayerValue' to '$RDPSecurityLayerRecommended', to ensure SSL/TLS is utilised, if RDP is allowed." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	elseif ($RDPSecurityLayerData -Eq "2") { 
		Write-Output "Information: Remote Desktop Security Layer '$RDPSecurityLayerValue' is set to '2'. Remote Desktop Security Layer is using SSL/TLS required." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}
}
}
    else
{
    Write-Output "Finding: Remote Desktop Security Layer '$RDPSecurityLayerValue' does not exist, therefore Remote Desktop Security Layer is disabled. `nBackground: Threat actors may leverage Remote Desktop Services to carry out lateral movement. `nRecommendation: Set registry key '$RDPSecurityLayerKey' value '$RDPSecurityLayerValue' to '$RDPSecurityLayerRecommended', to ensure SSL/TLS is utilised, if RDP is allowed." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Remote Desktop Max Idle Time
Write-Output "`nCheck: Remote Desktop Max Idle Time" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$RDPMaxIdleTimeKey = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$RDPMaxIdleTimeValue = "MaxIdleTime"
$RDPMaxIdleTimeRecommended = "900000"
$MaxIdleOptions = @{
"Never"="0";"1 Minute"="60000";"5 Minutes"="300000";"10 Minutes"="600000";"15 Minutes"="900000";"30 Minutes"="1800000";"1 Hour"="3600000";"2 Hours"="7200000";
"3 Hours"="10800000";"6 Hours"="21600000";"8 Hours"="28800000";"12 Hours"="43200000";"16 Hours"="57600000";"18 Hours"="64800000";"1 Day"="86400000";"2 Days"="172800000";
"3 Days"="259200000";"4 Days"="345600000";"5 Days"="432000000"
}
$MaxIdleOptions | Out-File $Destination\$Audit\Reference\RDP_Max_Idle_Time_Converters.txt
if (Test-RegistryValue $RDPMaxIdleTimeKey $RDPMaxIdleTimeValue)
{
	$RDPMaxIdleTimeData = (Get-ItemPropertyValue -Path $RDPMaxIdleTimeKey -Name $RDPMaxIdleTimeValue -ea SilentlyContinue)
	
	if ($RDPMaxIdleTimeData -Gt $RDPMaxIdleTimeRecommended) {
		Write-Output "Finding: Remote Desktop Max Idle Time '$RDPMaxIdleTimeValue' is greater than 15 minutes (RAW: $RDPMaxIdleTimeData). Remote Desktop Max Idle Time is not sufficient. `nBackground: Threat actors may leverage Remote Desktop Services to carry out lateral movement. `nRecommendation: Set registry key '$RDPMaxIdleTimeKey' value '$RDPMaxIdleTimeValue' to '$RDPMaxIdleTimeRecommended', to ensure Max Idle Time is maximum 15 minutes." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($RDPMaxIdleTimeData -Le $RDPMaxIdleTimeRecommended) { 
		Write-Output "Information: Remote Desktop Max Idle Time '$RDPMaxIdleTimeValue' is less than or equal to 15 minutes (RAW: $RDPMaxIdleTimeData). Remote Desktop Max Idle Time is sufficient." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Remote Desktop Max Idle Time '$RDPMaxIdleTimeValue' does not exist, therefore Remote Desktop Max Idle Time is not sufficient. `nBackground: Threat actors may leverage Remote Desktop Services to carry out lateral movement. `nRecommendation: Set registry key '$RDPMaxIdleTimeKey' value '$RDPMaxIdleTimeValue' to '$RDPMaxIdleTimeRecommended', to ensure Max Idle Time is maximum 15 minutes." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Remote Desktop Max Disconnection Time
Write-Output "`nCheck: Remote Desktop Max Disconnection Time" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$RDPMaxDisconnectTimeKey = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$RDPMaxDisconnectTimeValue = "MaxDisconnectionTime"
$RDPMaxDisconnectTimeRecommended = "60000"
$MaxDisconnectOptions = @{
"Never"="0";"1 Minute"="60000";"5 Minutes"="300000";"10 Minutes"="600000";"15 Minutes"="900000";"30 Minutes"="1800000";"1 Hour"="3600000";"2 Hours"="7200000";
"3 Hours"="10800000";"6 Hours"="21600000";"8 Hours"="28800000";"12 Hours"="43200000";"16 Hours"="57600000";"18 Hours"="64800000";"1 Day"="86400000";"2 Days"="172800000";
"3 Days"="259200000";"4 Days"="345600000";"5 Days"="432000000"
}
$MaxDisconnectOptions | Out-File $Destination\$Audit\Reference\RDP_Max_Disconnection_Time_Converters.txt
if (Test-RegistryValue $RDPMaxDisconnectTimeKey $RDPMaxDisconnectTimeValue)
{
	$RDPMaxDisconnectTimeData = (Get-ItemPropertyValue -Path $RDPMaxDisconnectTimeKey -Name $RDPMaxDisconnectTimeValue -ea SilentlyContinue)
	
	if ($RDPMaxDisconnectTimeData -Gt $RDPMaxDisconnectTimeRecommended) {
		Write-Output "Finding: Remote Desktop Max Disconnection Time '$RDPMaxDisconnectTimeValue' is greater than 1 minute (RAW: $RDPMaxDisconnectTimeData). Remote Desktop Max Disconnection Time is not sufficient. `nBackground: Threat actors may leverage Remote Desktop Services to carry out lateral movement. `nRecommendation: Set registry key '$RDPMaxDisconnectTimeKey' value '$RDPMaxDisconnectTimeValue' to '$RDPMaxDisconnectTimeRecommended', to ensure Max Disconnection Time is maximum 1 minute." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($RDPMaxDisconnectTimeData -Le $RDPMaxDisconnectTimeRecommended) { 
		Write-Output "Information: Remote Desktop Max Disconnection Time '$RDPMaxDisconnectTimeValue' is less than or equal to 1 minute (RAW: $RDPMaxDisconnectTimeData). Remote Desktop Max Disconnection Time is sufficient." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Remote Desktop Max Disconnection Time '$RDPMaxDisconnectTimeValue' does not exist, therefore Remote Desktop Max Disconnection Time is not sufficient. `nBackground: Threat actors may leverage Remote Desktop Services to carry out lateral movement. `nRecommendation: Set registry key '$RDPMaxDisconnectTimeKey' value '$RDPMaxDisconnectTimeValue' to '$RDPMaxDisconnectTimeRecommended', to ensure Max Disconnection Time is maximum 1 minute." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Automatic Updates
Write-Output "`nCheck: Windows Automatic Updates" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$AutoUpdatesKey = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
$AutoUpdatesValue = "NoAutoUpdate"
$AutoUpdatesRecommended = "0"
if (Test-RegistryValue $AutoUpdatesKey $AutoUpdatesValue)
{
	$AutoUpdatesData = (Get-ItemPropertyValue -Path $AutoUpdatesKey -Name $AutoUpdatesValue -ea SilentlyContinue)
	if ($AutoUpdatesData -Eq "1") {
		Write-Output "Finding: Windows Automatic Updates '$AutoUpdatesValue' is set to '1'. Windows Automatic Updates is disabled. `nBackground: If Windows Automatic Updates is disabled, bugs and patches may not be applied, rendering the system vulnerable. `nRecommendation: Set registry key '$AutoUpdatesKey' value '$AutoUpdatesValue' to '$AutoUpdatesRecommended', to ensure Windows Automatic Updates is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($AutoUpdatesData -Eq "0") { 
		Write-Output "Information: Windows Automatic Updates '$AutoUpdatesValue' is set to '0'. Windows Automatic Updates is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Windows Automatic Updates '$AutoUpdatesValue' does not exist, therefore Windows Automatic Updates is disabled. `nBackground: If Windows Automatic Updates is disabled, bugs and patches may not be applied, rendering the system vulnerable. `nRecommendation: Set registry key '$AutoUpdatesKey' value '$AutoUpdatesValue' to '$AutoUpdatesRecommended', to ensure Windows Automatic Updates is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# User Account Controls (UAC) aka Limited User Account (LUA)
Write-Output "`nCheck: User Account Controls (UAC) aka Limited User Account (LUA)" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$UACKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$UACValue = "EnableLUA"
$UACRecommended = "1"
if (Test-RegistryValue $UACKey $UACValue)
{
	$UACData = (Get-ItemPropertyValue -Path $UACKey -Name $UACValue -ea SilentlyContinue)
	if ($UACData -Eq "1") {
		Write-Output "Information: User Account Controls '$UACValue' is set to '1'. Program change notifications is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($UACData -Eq "0") { 
		Write-Output "Finding: User Account Controls '$UACValue' is set to '0'. Program change notifications is disabled. `nBackground: If User Account Control (UAC) is disabled, users will not be notified of any changes to the system, this could include malicious activity carried out by a threat actor. `nRecommendation: Set registry key '$UACKey' value '$UACValue' to '$UACRecommended', to ensure User Account Control is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: User Account Controls '$UACValue' does not exist, therefore program change notifications is disabled. `nBackground: If User Account Control (UAC) is disabled, users will not be notified of any changes to the system, this could include malicious activity carried out by a threat actor. `nRecommendation: Set registry key '$UACKey' value '$UACValue' to '$UACRecommended', to ensure User Account Control is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# PowerShell Operational Winevtx Max Size
Write-Output "`nCheck: PowerShell Operational Winevtx Max Size" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$PowEvtxMaxSizeKey = "HKLM:\System\CurrentControlSet\Services\EventLog\Windows PowerShell"
$PowEvtxMaxSizeValue = "MaxSize"
$PowEvtxMaxSizeRecommended = "104857600"
if (Test-RegistryValue $PowEvtxMaxSizeKey $PowEvtxMaxSizeValue)
{
	$PowEvtxMaxSizeData = (Get-ItemPropertyValue -Path $PowEvtxMaxSizeKey -Name $PowEvtxMaxSizeValue -ea SilentlyContinue)
	if ($PowEvtxMaxSizeData -Ge "$PowEvtxMaxSizeRecommended") {
		Write-Output "Information: PowerShell Operational Windows Event Log Max Size '$PowEvtxMaxSizeValue' is greater than or equal to 100MB (RAW: $PowEvtxMaxSizeData). PowerShell Operational winevtx log retention is sufficient." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($PowEvtxMaxSizeData -Le "$PowEvtxMaxSizeRecommended") { 
		Write-Output "Finding: PowerShell Operational Windows Event Log Max Size '$PowEvtxMaxSizeValue' is less than 1GB (RAW: $PowEvtxMaxSizeData). `nBackground: PowerShell Operational winevtx retains 15MB of logs by default, therefore this limits visibility and investigation opportunities. `nRecommendation: Set registry key '$PowEvtxMaxSizeKey' value '$PowEvtxMaxSizeValue' to '$PowEvtxMaxSizeRecommended' (100MB). `nCaveat: If PowerShell Operational winevtx is forwarded to a SIEM via a Windows Event Forwarding (WEF) collection server, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: PowerShell Operational Windows Event Log Max Size '$PowEvtxMaxSizeValue' does not exist, therefore is set to the locally configured value, which defaults to 1MB when not configured or if the key does not exist. `nBackground: PowerShell Operational winevtx retains 15MB of logs by default, therefore this limits visibility and investigation opportunities. `nRecommendation: Set registry key '$PowEvtxMaxSizeKey' value '$PowEvtxMaxSizeValue' to '$PowEvtxMaxSizeRecommended' (100MB). `nCaveat: If PowerShell Operational winevtx is forwarded to a SIEM via a Windows Event Forwarding (WEF) collection server, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Security Winevtx Max Size
Write-Output "`nCheck: Security Winevtx Max Size" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SecEvtxMaxSizeKey = "HKLM:\System\CurrentControlSet\Services\EventLog\Security"
$SecEvtxMaxSizeValue = "MaxSize"
$SecEvtxMaxSizeRecommended = "1073741824"
if (Test-RegistryValue $SecEvtxMaxSizeKey $SecEvtxMaxSizeValue)
{
	$SecEvtxMaxSizeData = (Get-ItemPropertyValue -Path $SecEvtxMaxSizeKey -Name $SecEvtxMaxSizeValue -ea SilentlyContinue)
	if ($SecEvtxMaxSizeData -Ge "$SecEvtxMaxSizeRecommended") {
		Write-Output "Information: Security Windows Event Log Max Size '$SecEvtxMaxSizeValue' is greater than or equal to 1GB (RAW: $SecEvtxMaxSizeData). Security winevtx log retention is sufficient." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SecEvtxMaxSizeData -Le "$SecEvtxMaxSizeRecommended") { 
		Write-Output "Finding: Security Windows Event Log Max Size '$SecEvtxMaxSizeValue' is less than 1GB (RAW: $SecEvtxMaxSizeData). `nBackground: Security winevtx retains 20MB of logs by default, therefore this limits visibility and investigation opportunities. `nRecommendation: Set registry key '$SecEvtxMaxSizeKey' value '$SecEvtxMaxSizeValue' to '$SecEvtxMaxSizeRecommended' (1GB). `nCaveat: If Security winevtx is forwarded to a SIEM via a Windows Event Forwarding (WEF) collection server, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Security Windows Event Log Max Size '$SecEvtxMaxSizeValue' does not exist, therefore is set to the locally configured value, which defaults to 1MB when not configured or if the key does not exist. `nBackground: Security winevtx retains 20MB of logs by default, therefore this limits visibility and investigation opportunities. `nRecommendation: Set registry key '$SecEvtxMaxSizeKey' value '$SecEvtxMaxSizeValue' to '$SecEvtxMaxSizeRecommended' (1GB). `nCaveat: If Security winevtx is forwarded to a SIEM via a Windows Event Forwarding (WEF) collection server, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# System Winevtx Max Size
Write-Output "`nCheck: System Winevtx Max Size" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SysEvtxMaxSizeKey = "HKLM:\System\CurrentControlSet\Services\EventLog\System"
$SysEvtxMaxSizeValue = "MaxSize"
$SysEvtxMaxSizeRecommended = "104857600"
if (Test-RegistryValue $SysEvtxMaxSizeKey $SysEvtxMaxSizeValue)
{
	$SysEvtxMaxSizeData = (Get-ItemPropertyValue -Path $SysEvtxMaxSizeKey -Name $SysEvtxMaxSizeValue -ea SilentlyContinue)
	if ($SysEvtxMaxSizeData -Ge "$SysEvtxMaxSizeRecommended") {
		Write-Output "Information: System Windows Event Log Max Size '$SysEvtxMaxSizeValue' is greater than or equal to 100MB (RAW: $SysEvtxMaxSizeData). System winevtx log retention is sufficient." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SysEvtxMaxSizeData -Le "$SysEvtxMaxSizeRecommended") { 
		Write-Output "Finding: System Windows Event Log Max Size '$SysEvtxMaxSizeValue' is less than 100MB (RAW: $SysEvtxMaxSizeData). `nBackground: System winevtx retains 20MB of logs by default, therefore this limits visibility and investigation opportunities. `nRecommendation: Set registry key '$SysEvtxMaxSizeKey' value '$SysEvtxMaxSizeValue' to '$SysEvtxMaxSizeRecommended' (100MB). `nCaveat: If System winevtx is forwarded to a SIEM via a Windows Event Forwarding (WEF) collection server, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: System Windows Event Log Max Size '$SysEvtxMaxSizeValue' does not exist, therefore is set to the locally configured value, which defaults to 1MB when not configured or if the key does not exist. `nBackground: System winevtx retains 20MB of logs by default, therefore this limits visibility and investigation opportunities. `nRecommendation: Set registry key '$SysEvtxMaxSizeKey' value '$SysEvtxMaxSizeValue' to '$SysEvtxMaxSizeRecommended' (100MB). `nCaveat: If System winevtx is forwarded to a SIEM via a Windows Event Forwarding (WEF) collection server, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Application Winevtx Max Size
Write-Output "`nCheck: Application Winevtx Max Size" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$AppEvtxMaxSizeKey = "HKLM:\System\CurrentControlSet\Services\EventLog\Application"
$AppEvtxMaxSizeValue = "MaxSize"
$AppEvtxMaxSizeRecommended = "104857600"
if (Test-RegistryValue $AppEvtxMaxSizeKey $AppEvtxMaxSizeValue)
{
	$AppEvtxMaxSizeData = (Get-ItemPropertyValue -Path $AppEvtxMaxSizeKey -Name $AppEvtxMaxSizeValue -ea SilentlyContinue)
	if ($AppEvtxMaxSizeData -Ge "$AppEvtxMaxSizeRecommended") {
		Write-Output "Information: Application Windows Event Log Max Size '$AppEvtxMaxSizeValue' is greater than or equal to 100MB (RAW: $AppEvtxMaxSizeData). Application winevtx log retention is sufficient." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($AppEvtxMaxSizeData -Le "$AppEvtxMaxSizeRecommended") { 
		Write-Output "Finding: Application Windows Event Log Max Size '$AppEvtxMaxSizeValue' is less than 100MB (RAW: $AppEvtxMaxSizeData). `nBackground: Application winevtx retains 20MB of logs by default, therefore this limits visibility and investigation opportunities. `nRecommendation: Set registry key '$AppEvtxMaxSizeKey' value '$AppEvtxMaxSizeValue' to '$AppEvtxMaxSizeRecommended' (100MB). `nCaveat: If Application winevtx is forwarded to a SIEM via a Windows Event Forwarding (WEF) collection server, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Application Windows Event Log Max Size '$AppEvtxMaxSizeValue' does not exist, therefore is set to the locally configured value, which defaults to 1MB when not configured or if the key does not exist. `nBackground: Application winevtx retains 20MB of logs by default, therefore this limits visibility and investigation opportunities. `nRecommendation: Set registry key '$AppEvtxMaxSizeKey' value '$AppEvtxMaxSizeValue' to '$AppEvtxMaxSizeRecommended' (100MB). `nCaveat: If Application winevtx is forwarded to a SIEM via a Windows Event Forwarding (WEF) collection server, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Security Winevtx Access
Write-Output "`nCheck: Security Winevtx Access" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SecEvtxAccessKey = "HKLM:\System\CurrentControlSet\Services\EventLog\Security"
$SecEvtxAccessValue = "RestrictGuestAccess"
$SecEvtxRecommended = "1"
if (Test-RegistryValue $SecEvtxAccessKey $SecEvtxAccessValue)
{
	$SecEvtxAccessData = (Get-ItemPropertyValue -Path $SecEvtxAccessKey -Name $SecEvtxAccessValue -ea SilentlyContinue)
	if ($SecEvtxAccessData -Eq "1") {
		Write-Output "Information: Security Windows Event Log Access '$SecEvtxAccessValue' is set to '1'. Guest access restriction to Security winevtx is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SecEvtxAccessData -Eq "0") { 
		Write-Output "Finding: Security Windows Event Log Access '$SecEvtxAccessValue' is set to '0'. Guest access restriction to Security winevtx is disabled. `nBackground: Threat actors may attempt to access or/and modify Windows event logs for defense evasion purposes. `nRecommendation: Set registry key '$SecEvtxAccessKey' value '$SecEvtxAccessValue' to '$SecEvtxRecommended', to ensure Guest access restriction to Security winevtx is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Security Windows Event Log Access '$SecEvtxAccessValue' does not exist, therefore Guest access restriction to Security winevtx is disabled. `nBackground: Threat actors may attempt to access or/and modify Windows event logs for defense evasion purposes. `nRecommendation: Set registry key '$SecEvtxAccessKey' value '$SecEvtxAccessValue' to '$SecEvtxRecommended', to ensure Guest access restriction to Security winevtx is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# System Winevtx Access
Write-Output "`nCheck: System Winevtx Access" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$SysEvtxAccessKey = "HKLM:\System\CurrentControlSet\Services\EventLog\System"
$SysEvtxAccessValue = "RestrictGuestAccess"
$SysEvtxAccessRecommended = "1"
if (Test-RegistryValue $SysEvtxAccessKey $SysEvtxAccessValue)
{
	$SysEvtxAccessData = (Get-ItemPropertyValue -Path $SysEvtxAccessKey -Name $SysEvtxAccessValue -ea SilentlyContinue)
	if ($SysEvtxAccessData -Eq "1") {
		Write-Output "Information: System Windows Event Log Access '$SysEvtxAccessValue' is set to '1'. Guest access restriction to System winevtx is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($SysEvtxAccessData -Eq "0") { 
		Write-Output "Finding: System Windows Event Log Access '$SysEvtxAccessValue' is set to '0'. Guest access restriction to System winevtx is disabled. `nBackground: Threat actors may attempt to access or/and modify Windows event logs for defense evasion purposes. `nRecommendation: Set registry key '$SysEvtxAccessKey' value '$SysEvtxAccessValue' to '$SysEvtxAccessRecommended', to ensure Guest access restriction to System winevtx is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: System Windows Event Log Access '$SysEvtxAccessValue' does not exist, therefore Guest access restriction to System winevtx is disabled. `nBackground: Threat actors may attempt to access or/and modify Windows event logs for defense evasion purposes. `nRecommendation: Set registry key '$SysEvtxAccessKey' value '$SysEvtxAccessValue' to '$SysEvtxAccessRecommended', to ensure Guest access restriction to System winevtx is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Application Winevtx Access
Write-Output "`nCheck: Application Winevtx Access" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$AppEvtxAccessKey = "HKLM:\System\CurrentControlSet\Services\EventLog\Application"
$AppEvtxAccessValue = "RestrictGuestAccess"
$AppEvtxAccessRecommended = "1"
if (Test-RegistryValue $AppEvtxAccessKey $AppEvtxAccessValue)
{
	$AppEvtxAccessData = (Get-ItemPropertyValue -Path $AppEvtxAccessKey -Name $AppEvtxAccessValue -ea SilentlyContinue)
	if ($AppEvtxAccessData -Eq "1") {
		Write-Output "Information: Application Windows Event Log Access '$AppEvtxAccessValue' is set to '1'. Guest access restriction to Application winevtx is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($AppEvtxAccessData -Eq "0") { 
		Write-Output "Finding: Application Windows Event Log Access '$AppEvtxAccessValue' is set to '0'. Guest access restriction to Application winevtx is disabled. `nBackground: Threat actors may attempt to access or/and modify Windows event logs for defense evasion purposes. `nRecommendation: Set registry key '$AppEvtxAccessKey' value '$AppEvtxAccessValue' to '$AppEvtxAccessRecommended', to ensure Guest access restriction to Application winevtx is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Application Windows Event Log Access '$AppEvtxAccessValue' does not exist, therefore Guest access restriction to Application winevtx is disabled. `nBackground: Threat actors may attempt to access or/and modify Windows event logs for defense evasion purposes. `nRecommendation: Set registry key '$AppEvtxAccessKey' value '$AppEvtxAccessValue' to '$AppEvtxAccessRecommended', to ensure Guest access restriction to Application winevtx is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender Disable AntiSpyware
Write-Output "`nCheck: Windows Defender Disable AntiSpyware" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefAntiSpywareKey = "HKLM:\Software\Policies\Microsoft\Windows Defender"
$DefAntiSpywareValue = "DisableAntiSpyware"
$DefAntiSpywareRecommended = "0"
if (Test-RegistryValue $DefAntiSpywareKey $DefAntiSpywareValue)
{
	$DefAntiSpywareData = (Get-ItemPropertyValue -Path $DefAntiSpywareKey -Name $DefAntiSpywareValue -ea SilentlyContinue)
	if ($DefAntiSpywareData -Eq "1") {
		Write-Output "Finding: Windows Defender AntiSpyware '$DefAntiSpywareValue' is set to '1'. AntiSpyware is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefAntiSpywareKey' value '$DefAntiSpywareValue' to '$DefAntiSpywareRecommended', to ensure Windows Defender Spyware is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefAntiSpywareData -Eq "0") { 
		Write-Output "Information: Windows Defender AntiSpyware '$DefAntiSpywareValue' is set to '0'. AntiSpyware is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: Windows Defender AntiSpyware '$DefAntiSpywareValue' does not exist, therefore AntiSpyware is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender Service Startup
Write-Output "`nCheck: Windows Defender Service Startup" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefServiceStartupKey = "HKLM:\Software\Policies\Microsoft\Windows Defender"
$DefServiceStartupValue = "AllowFastServiceStartup"
$DefServiceStartupRecommended = "1"
if (Test-RegistryValue $DefServiceStartupKey $DefServiceStartupValue)
{
	$DefServiceStartupData = (Get-ItemPropertyValue -Path $DefServiceStartupKey -Name $DefServiceStartupValue -ea SilentlyContinue)
	if ($DefServiceStartupData -Eq "1") {
		Write-Output "Information: Windows Defender Fast Service Startup '$DefServiceStartupValue' is set to '1'. Fast Service Startup is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefServiceStartupData -Eq "0") { 
		Write-Output "Finding: Windows Defender Fast Service Startup '$DefServiceStartupValue' is set to '0'. Fast Service Startup is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefServiceStartupKey' value '$DefServiceStartupValue' to '$DefServiceStartupRecommended', to ensure Windows Defender Service Startup is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Windows Defender Fast Service Startup '$DefServiceStartupValue' does not exist, therefore Fast Service Startup is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefServiceStartupKey' value '$DefServiceStartupValue' to '$DefServiceStartupRecommended', to ensure Windows Defender Service Startup is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender Service Alive
Write-Output "`nCheck: Windows Defender Service Alive" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefServiceAliveKey = "HKLM:\Software\Policies\Microsoft\Windows Defender"
$DefServiceAliveValue = "ServiceKeepAlive"
$DefServiceAliveRecommended = "1"
if (Test-RegistryValue $DefServiceAliveKey $DefServiceAliveValue)
{
	$DefServiceAliveData = (Get-ItemPropertyValue -Path $DefServiceAliveKey -Name $DefServiceAliveValue -ea SilentlyContinue)
	if ($DefServiceAliveData -Eq "1") {
		Write-Output "Information: Windows Defender Service Keep Alive '$DefServiceAliveValue' is set to '1'. Service Keep Alive is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefServiceAliveData -Eq "0") { 
		Write-Output "Finding: Windows Defender Service Keep Alive '$DefServiceAliveValue' is set to '0'. Service Keep Alive is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefServiceAliveKey' value '$DefServiceAliveValue' to '$DefServiceAliveRecommended', to ensure Windows Defender Service Keep Alive is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Windows Defender Service Keep Alive '$DefServiceAliveValue' does not exist, therefore Service Keep Alive is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefServiceAliveKey' value '$DefServiceAliveValue' to '$DefServiceAliveRecommended', to ensure Windows Defender Service Keep Alive is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender PUA
Write-Output "`nCheck: Windows Defender PUA" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefPUAKey = "HKLM:\Software\Policies\Microsoft\Windows Defender"
$DefPUAValue = "PUAProtection"
$DefPUARecommended = "1"
if (Test-RegistryValue $DefPUAKey $DefPUAValue)
{
	$DefPUAData = (Get-ItemPropertyValue -Path $DefPUAKey -Name $DefPUAValue -ea SilentlyContinue)
	if ($DefPUAData -Eq "1") {
		Write-Output "Information: Windows Defender Block Potentially Unwanted Applications '$DefPUAValue' is set to '1'. Blocking of PUA is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefPUAData -Eq "0") { 
		Write-Output "Finding: Windows Defender Block Potentially Unwanted Applications '$DefPUAValue' is set to '0'. Blocking of PUA is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefPUAKey' value '$DefPUAValue' to '$DefPUARecommended', to ensure Windows Defender PUA Protection is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	elseif ($DefPUAData -Eq "2") { 
		Write-Output "Finding: Windows Defender Block Potentially Unwanted Applications '$DefPUAValue' is set to '2'. Blocking of PUA is disabled, however audit mode is enabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefPUAKey' value '$DefPUAValue' to '$DefPUARecommended', to ensure Windows Defender PUA Protection is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}
}
}
    else
{
    Write-Output "Finding: Windows Defender Block Potentially Unwanted Applications '$DefPUAValue' does not exist, therefore Blocking of PUA is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefPUAKey' value '$DefPUAValue' to '$DefPUARecommended', to ensure Windows Defender PUA Protection is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender Routine Remediation
Write-Output "`nCheck: Windows Defender Routine Remediation" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefRoutineKey = "HKLM:\Software\Policies\Microsoft\Windows Defender"
$DefRoutineValue = "DisableRoutinelyTakingAction"
$DefRoutineRecommended = "0"
if (Test-RegistryValue $DefRoutineKey $DefRoutineValue)
{
	$DefRoutineData = (Get-ItemPropertyValue -Path $DefRoutineKey -Name $DefRoutineValue -ea SilentlyContinue)
	if ($DefRoutineData -Eq "1") {
		Write-Output "Finding: Windows Defender Routine Remediation '$DefRoutineValue' is set to '1'. Automatic Remediation is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefRoutineKey' value '$DefRoutineValue' to '$DefRoutineRecommended', to ensure Windows Defender Automatic Remediation is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefRoutineData -Eq "0") { 
		Write-Output "Information: Windows Defender Routine Remediation '$DefRoutineValue' is set to '0'. Automatic Remediation is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Information: Windows Defender Routine Remediation '$DefRoutineValue' does not exist, therefore Automatic Remediation is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender Realtime Monitoring
Write-Output "`nCheck: Windows Defender Realtime Monitoring" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefRealtimeKey = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
$DefRealtimeValue = "DisableRealtimeMonitoring"
$DefRealtimeRecommended = "0"
if (Test-RegistryValue $DefRealtimeKey $DefRealtimeValue)
{
	$DefRealtimeData = (Get-ItemPropertyValue -Path $DefRealtimeKey -Name $DefRealtimeValue -ea SilentlyContinue)
	if ($DefRealtimeData -Eq "1") {
		Write-Output "Finding: Windows Defender Realtime Monitoring '$DefRealtimeValue' is set to '1'. Realtime Monitoring is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefRealtimeKey' value '$DefRealtimeValue' to '$DefRealtimeRecommended', to ensure Windows Defender Realtime Monitoring is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefRealtimeData -Eq "0") { 
		Write-Output "Information: Windows Defender Realtime Monitoring '$DefRealtimeValue' is set to '0'. Realtime Monitoring is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Windows Defender Realtime Monitoring '$DefRealtimeValue' does not exist, therefore Realtime Monitoring is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender IOAV
Write-Output "`nCheck: Windows Defender IOAV" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefIOAVKey = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
$DefIOAVValue = "DisableIOAVProtection"
$DefIOAVRecommended = "0"
if (Test-RegistryValue $DefIOAVKey $DefIOAVValue)
{
	$DefIOAVData = (Get-ItemPropertyValue -Path $DefIOAVKey -Name $DefIOAVValue -ea SilentlyContinue)
	if ($DefIOAVData -Eq "1") {
		Write-Output "Finding: Windows Defender IOAV Protection '$DefIOAVValue' is set to '1'. IOAV Protection is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefIOAVKey' value '$DefIOAVValue' to '$DefIOAVRecommended', to ensure Windows Defender IOAV Protection is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefIOAVData -Eq "0") { 
		Write-Output "Information: Windows Defender IOAV Protection '$DefIOAVValue' is set to '0'. IOAV Protection is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Windows Defender IOAV Protection '$DefIOAVValue' does not exist, therefore IOAV Protection is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender Behaviour Monitoring
Write-Output "`nCheck: Windows Defender Behaviour Monitoring" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefBehaviourKey = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
$DefBehaviourValue = "DisableBehaviorMonitoring"
$DefBehaviourRecommended = "0"
if (Test-RegistryValue $DefBehaviourKey $DefBehaviourValue)
{
	$DefBehaviourData = (Get-ItemPropertyValue -Path $DefBehaviourKey -Name $DefBehaviourValue -ea SilentlyContinue)
	if ($DefBehaviourData -Eq "1") {
		Write-Output "Finding: Windows Defender Behaviour Monitoring '$DefBehaviourValue' is set to '1'. Behaviour Monitoring is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefBehaviourKey' value '$DefBehaviourValue' to '$DefBehaviourRecommended', to ensure Windows Defender Behaviour Monitoring is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefBehaviourData -Eq "0") { 
		Write-Output "Information: Windows Defender Behaviour Monitoring '$DefBehaviourValue' is set to '0'. Behaviour Monitoring is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Windows Defender Behaviour Monitoring '$DefBehaviourValue' does not exist, therefore Behaviour Monitoring is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender Removable Drive Scanning
Write-Output "`nCheck: Windows Defender Removable Drive Scanning" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefRemovableKey = "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan"
$DefRemovableValue = "DisableRemovableDriveScanning"
$DefRemovableRecommended = "0"
if (Test-RegistryValue $DefRemovableKey $DefRemovableValue)
{
	$DefRemovableData = (Get-ItemPropertyValue -Path $DefRemovableKey -Name $DefRemovableValue -ea SilentlyContinue)
	if ($DefRemovableData -Eq "1") {
		Write-Output "Finding: Windows Defender Removable Drive Scanning '$DefRemovableValue' is set to '1'. Removable Drive Scanning is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefRemovableKey' value '$DefRemovableValue' to '$DefRemovableRecommended', to ensure Windows Defender Removable Drive Scanning is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefRemovableData -Eq "0") { 
		Write-Output "Information: Windows Defender Removable Drive Scanning '$DefRemovableValue' is set to '0'. Removable Drive Scanning is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Windows Defender Removable Drive Scanning '$DefRemovableValue' does not exist, therefore Removable Drive Scanning is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefRemovableKey' value '$DefRemovableValue' to '$DefRemovableRecommended', to ensure Windows Defender Removable Drive Scanning is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender Email Scanning
Write-Output "`nCheck: Windows Defender Email Scanning" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefEmailKey = "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan"
$DefEmailValue = "DisableEmailScanning"
$DefEmailRecommended = "0"
if (Test-RegistryValue $DefEmailKey $DefEmailValue)
{
	$DefEmailData = (Get-ItemPropertyValue -Path $DefEmailKey -Name $DefEmailValue -ea SilentlyContinue)
	if ($DefEmailData -Eq "1") {
		Write-Output "Finding: Windows Defender Email Scanning '$DefEmailValue' is set to '1'. Email Scanning is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefEmailKey' value '$DefEmailValue' to '$DefEmailRecommended', to ensure Windows Defender Email Scanning is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefEmailData -Eq "0") { 
		Write-Output "Information: Windows Defender Email Scanning '$DefEmailValue' is set to '0'. Email Scanning is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Windows Defender Email Scanning '$DefEmailValue' does not exist, therefore Email Scanning is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefEmailKey' value '$DefEmailValue' to '$DefEmailRecommended', to ensure Windows Defender Email Scanning is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender Block At First Sight (MAPS)
Write-Output "`nCheck: Windows Defender Block At First Sight (MAPS)" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefBAFSKey = "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet"
$DefBAFSValue = "DisableBlockAtFirstSeen"
$DefBAFSRecommended = "0"
if (Test-RegistryValue $DefBAFSKey $DefBAFSValue)
{
	$DefBAFSData = (Get-ItemPropertyValue -Path $DefBAFSKey -Name $DefBAFSValue -ea SilentlyContinue)
	if ($DefBAFSData -Eq "1") {
		Write-Output "Finding: Windows Defender Block At First Sight '$DefBAFSValue' is set to '1'. Block At First Sight is disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefBAFSKey' value '$DefBAFSValue' to '$DefBAFSRecommended', to ensure Windows Defender Block At First Seen is enabled. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefBAFSData -Eq "0") { 
		Write-Output "Information: Windows Defender Block At First Sight '$DefBAFSValue' is set to '0'. Block At First Sight is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}
}
    else
{
    Write-Output "Finding: Windows Defender Block At First Sight '$DefBAFSValue' does not exist, therefore Block At First Sight is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Windows Defender Notification
Write-Output "`nCheck: Windows Defender Notification" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
$DefNotificationKey = "HKLM:\Software\Policies\Microsoft\Windows Defender\UX Configuration"
$DefNotificationValue = "NotificationSuppress"
$DefNotificationRecommended = "0"
if (Test-RegistryValue $DefNotificationKey $DefNotificationValue)
{
	$DefNotificationData = (Get-ItemPropertyValue -Path $DefNotificationKey -Name $DefNotificationValue -ea SilentlyContinue)
	if ($DefNotificationData -Eq "1") {
		Write-Output "Finding: Windows Defender Notification Suppress '$DefNotificationValue' is set to '1'. Notifications are disabled. `nBackground: Threat actors may attempt to modify or/and disable AntiVirus configurations for defense evasion purposes. `nRecommendation: Set registry key '$DefNotificationKey' value '$DefNotificationValue' to '$DefNotificationRecommended', to ensure Windows Defender does not suppress notifications. `nCaveat: If another AntiVirus or/and EDR is in use, this finding can be omitted." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
	elseif ($DefNotificationData -Eq "0") { 
		Write-Output "Information: Windows Defender Notification Suppress '$DefNotificationValue' is set to '0'. Notifications are enabled."
}
}
    else
{
    Write-Output "Information: Windows Defender Notification Suppress '$DefNotificationValue' does not exist, therefore Notifications are enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

# Do Not Run Microsoft Office Checks On Servers
Write-Output "`nCheck: Microsoft Office Checks" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
if($OS[0] -notlike "*Server*") {
	# Excel
	$ExcelVersionCom = New-Object -ComObject Excel.Application -ea SilentlyContinue
	$ExcelVersion = $ExcelVersionCom.Version
	Write-Output "`nMicrosoft Excel Version $ExcelVersion"  > $Destination\$Audit\RawData\Microsoft_Office_Versions.txt
	# Word
	$WordVersionCom = New-Object -ComObject Word.Application -ea SilentlyContinue
	$WordVersion = $WordVersionCom.Version
	Write-Output "`nMicrosoft Word Version $WordVersion"  >> $Destination\$Audit\RawData\Microsoft_Office_Versions.txt
	# Outlook
	$OutlookVersionCom = New-Object -ComObject Outlook.Application -ea SilentlyContinue
	$OutlookVersion = $OutlookVersionCom.Version
	$OutlookVersionSub = $OutlookVersion.SubString(0,4)
	Write-Output "`nMicrosoft Outlook Version $OutlookVersionSub" >> $Destination\$Audit\RawData\Microsoft_Office_Versions.txt
	# Excel Dynamic Data Exchange (DDE) Protocol Launch
	Write-Output "`nCheck: Excel Dynamic Data Exchange (DDE) Protocol Launch" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$ExcelDDELaunchKey = "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security\External Content"
	$ExcelDDELaunchValue = "DisableDDEServerLaunch"
	$ExcelDDELaunchRecommended = "0"
	if (Test-RegistryValue $ExcelDDELaunchKey $ExcelDDELaunchValue)
	{
		$ExcelDDELaunchData = (Get-ItemPropertyValue -Path $ExcelDDELaunchKey -Name $ExcelDDELaunchValue -ea SilentlyContinue)
		if ($ExcelDDELaunchData -Eq "0") {
			Write-Output "Information: Excel Dynamic Data Exchange (DDE) Protocol Launch '$ExcelDDELaunchValue' is set to '0'. Excel Dynamic Data Exchange (DDE) Protocol Launch is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($ExcelDDELaunchData -Eq "1") {
			Write-Output "Finding: Excel Dynamic Data Exchange (DDE) Protocol Launch '$ExcelDDELaunchValue' is set to '1'. Excel Dynamic Data Exchange (DDE) Protocol Launch is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to abuse the protocol for malicious execution. `nRecommendation: Set registry key '$ExcelDDELaunchKey' value '$ExcelDDELaunchValue' to '$ExcelDDELaunchRecommended', to ensure Excel Dynamic Data Exchange (DDE) features are not exploited for malicious execution. Microsoft defense-in-depth measure ADV170021." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Excel Dynamic Data Exchange (DDE) Protocol Launch '$ExcelDDELaunchValue' does not exist, therefore Excel Dynamic Data Exchange (DDE) Protocol Launch is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to abuse the protocol for malicious execution. `nRecommendation: Set registry key '$ExcelDDELaunchKey' value '$ExcelDDELaunchValue' to '$ExcelDDELaunchRecommended', to ensure Excel Dynamic Data Exchange (DDE) features are not exploited for malicious execution. Microsoft defense-in-depth measure ADV170021." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Excel Dynamic Data Exchange (DDE) Protocol Server Lookup
	Write-Output "`nCheck: Excel Dynamic Data Exchange (DDE) Protocol Server Lookup" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$ExcelDDESrvLookupKey = "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security\External Content"
	$ExcelDDESrvLookupValue = "DisableDDEServerLookup"
	$ExcelDDESrvLookupRecommended = "0"
	if (Test-RegistryValue $ExcelDDESrvLookupKey $ExcelDDESrvLookupValue)
	{
		$ExcelDDESrvLookupData = (Get-ItemPropertyValue -Path $ExcelDDESrvLookupKey -Name $ExcelDDESrvLookupValue -ea SilentlyContinue)
		if ($ExcelDDESrvLookupData -Eq "0") {
			Write-Output "Information: Excel Dynamic Data Exchange (DDE) Protocol Server Lookup '$ExcelDDESrvLookupValue' is set to '0'. Excel Dynamic Data Exchange (DDE) Protocol Server Lookup is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($ExcelDDESrvLookupData -Eq "1") {
			Write-Output "Finding: Excel Dynamic Data Exchange (DDE) Protocol Server Lookup '$ExcelDDESrvLookupValue' is set to '1'. Excel Dynamic Data Exchange (DDE) Protocol Server Lookup is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to abuse the protocol for malicious execution. `nRecommendation: Set registry key '$ExcelDDESrvLookupKey' value '$ExcelDDESrvLookupValue' to '$ExcelDDESrvLookupRecommended', to ensure Excel Dynamic Data Exchange (DDE) features are not exploited for malicious execution. Microsoft defense-in-depth measure ADV170021." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Excel Dynamic Data Exchange (DDE) Protocol Server Lookup '$ExcelDDESrvLookupValue' does not exist, therefore Excel Dynamic Data Exchange (DDE) Protocol Server Lookup is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to abuse the protocol for malicious execution. `nRecommendation: Set registry key '$ExcelDDESrvLookupKey' value '$ExcelDDESrvLookupValue' to '$ExcelDDESrvLookupRecommended', to ensure Excel Dynamic Data Exchange (DDE) features are not exploited for malicious execution. Microsoft defense-in-depth measure ADV170021." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Word Dynamic Data Exchange (DDE) Protocol
	Write-Output "`nCheck: Word Dynamic Data Exchange (DDE) Protocol" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$WordDDEKey = "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Security"
	$WordDDEValue = "AllowDDE"
	$WordDDERecommended = "0"
	if (Test-RegistryValue $WordDDEKey $WordDDEValue)
	{
		$WordDDEData = (Get-ItemPropertyValue -Path $WordDDEKey -Name $WordDDEValue -ea SilentlyContinue)
		if ($WordLinkWarnData -Eq "0") {
			Write-Output "Information: Word Dynamic Data Exchange (DDE) Protocol '$WordDDEValue' is set to '0'. Word Dynamic Data Exchange (DDE) Protocol is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($WordLinkWarnData -Eq "1") {
			Write-Output "Finding: Word Dynamic Data Exchange (DDE) Protocol '$WordDDEValue' is set to '1'. Word Dynamic Data Exchange (DDE) Protocol is partially enabled (allow DDE requests to an already running program, but prevent DDE requests that require another executable program to be launched). `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to abuse the protocol for malicious execution. `nRecommendation: Set registry key '$WordDDEKey' value '$WordDDEValue' to '$WordDDERecommended', to ensure Word Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		elseif ($WordLinkWarnData -Eq "2") {
			Write-Output "Finding: Word Dynamic Data Exchange (DDE) Protocol '$WordDDEValue' is set to '2'. Word Dynamic Data Exchange (DDE) Protocol is fully enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to abuse the protocol for malicious execution. `nRecommendation: Set registry key '$WordDDEKey' value '$WordDDEValue' to '$WordDDERecommended', to ensure Word Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
	}
		else
	{
		Write-Output "Finding: Word Dynamic Data Exchange (DDE) Protocol '$WordDDEValue' does not exist, therefore Word Dynamic Data Exchange (DDE) Protocol is fully enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to abuse the protocol for malicious execution. `nRecommendation: Set registry key '$WordDDEKey' value '$WordDDEValue' to '$WordDDERecommended', to ensure Word Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Excel (Office 2007>) Link Warnings - Dynamic Data Exchange (DDE)
	Write-Output "`nCheck: Excel (Office 2007>) Link Warnings - Dynamic Data Exchange (DDE)" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$ExcelLinkWarnKey = "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security"
	$ExcelLinkWarnValue = "WorkbookLinkWarnings"
	$ExcelLinkWarnRecommended = "2"
	if (Test-RegistryValue $ExcelLinkWarnKey $ExcelLinkWarnValue)
	{
		$ExcelLinkWarnData = (Get-ItemPropertyValue -Path $ExcelLinkWarnKey -Name $ExcelLinkWarnValue -ea SilentlyContinue)
		if ($ExcelLinkWarnData -Eq "2") {
			Write-Output "Information: Automatic Update of Workbook Links '$ExcelLinkWarnValue' is set to '2'. Automatic Update of Workbook Links is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($ExcelLinkWarnData -Ne "2") {
			Write-Output "Finding: Automatic Update of Workbook Links '$ExcelLinkWarnValue' is set to '$ExcelLinkWarnData'. Workbook link warnings is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to load external content. `nRecommendation: Set registry key '$ExcelLinkWarnKey' value '$ExcelLinkWarnValue' to '$ExcelLinkWarnRecommended', to ensure Excel Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Automatic Update of Workbook Links '$ExcelLinkWarnValue' does not exist, therefore Automatic Update of Workbook Links is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to load external content. `nRecommendation: Set registry key '$ExcelLinkWarnKey' value '$ExcelLinkWarnValue' to '$ExcelLinkWarnRecommended', to ensure Excel Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Word (Office 2010>) Link Warnings - Dynamic Data Exchange (DDE)
	Write-Output "`nCheck: Word (Office 2010>) Link Warnings - Dynamic Data Exchange (DDE)" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$WordLinkWarnKey = "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Options"
	$WordLinkWarnValue = "DontUpdateLinks"
	$WordLinkWarnRecommended = "1"
	if (Test-RegistryValue $WordLinkWarnKey $WordLinkWarnValue)
	{
		$WordLinkWarnData = (Get-ItemPropertyValue -Path $WordLinkWarnKey -Name $WordLinkWarnValue -ea SilentlyContinue)
		if ($WordLinkWarnData -Eq "1") {
			Write-Output "Information: Automatic Update of Word Links '$WordLinkWarnValue' is set to '1'. Automatic Update of Word Links is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($WordLinkWarnData -Ne "1") {
			Write-Output "Finding: Automatic Update of Word Links '$WordLinkWarnValue' is set to '$WordLinkWarnData'. Automatic Update of Word Links is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to load external content. `nRecommendation: Set registry key '$WordLinkWarnKey' value '$WordLinkWarnValue' to '$WordLinkWarnRecommended', to ensure Word Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Automatic Update of Word Links '$WordLinkWarnValue' does not exist, therefore Automatic Update of Word Links is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to load external content. `nRecommendation: Set registry key '$WordLinkWarnKey' value '$WordLinkWarnValue' to '$WordLinkWarnRecommended', to ensure Word Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Legacy Word (Office 2007) Link Warnings - Dynamic Data Exchange (DDE)
	Write-Output "`nCheck: Legacy Word (Office 2007) Link Warnings - Dynamic Data Exchange (DDE)" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$LegacyWordLinkWarnKey = "HKCU:\Software\Microsoft\Office\12.0\Word\Options"
	$LegacyWordLinkWarnValue = "fNoCalclinksOnopen_90_1"
	$LegacyWordLinkWarnRecommended = "1"
	if (Test-RegistryValue $LegacyWordLinkWarnKey $LegacyWordLinkWarnValue)
	{
		$LegacyWordLinkWarnData = (Get-ItemPropertyValue -Path $LegacyWordLinkWarnKey -Name $LegacyWordLinkWarnValue -ea SilentlyContinue)
		if ($LegacyWordLinkWarnData -Eq "1") {
			Write-Output "Information: Automatic Update of Word Links '$LegacyWordLinkWarnValue' is set to '1'. Automatic Update of Word Links is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($LegacyWordLinkWarnData -Ne "1") {
			Write-Output "Finding: Automatic Update of Word Links '$LegacyWordLinkWarnValue' is set to '$LegacyWordLinkWarnData'. Automatic Update of Word Links is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to load external content. `nRecommendation: Set registry key '$LegacyWordLinkWarnKey' value '$LegacyWordLinkWarnValue' to '$LegacyWordLinkWarnRecommended', to ensure Word Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Automatic Update of Word Links '$LegacyWordLinkWarnValue' does not exist, therefore Automatic Update of Word Links is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to load external content. `nRecommendation: Set registry key '$LegacyWordLinkWarnKey' value '$LegacyWordLinkWarnValue' to '$LegacyWordLinkWarnRecommended', to ensure Word Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Outlook (Office 2010>) Link Warnings - Dynamic Data Exchange (DDE)
	Write-Output "`nCheck: Outlook (Office 2010>) Link Warnings - Dynamic Data Exchange (DDE)" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$OutlookLinkWarnKey = "HKCU:\Software\Microsoft\Office\$OutlookVersionSub\Word\Options\WordMail"
	$OutlookLinkWarnValue = "DontUpdateLinks"
	$OutlookLinkWarnRecommended = "1"
	if (Test-RegistryValue $OutlookLinkWarnKey $OutlookLinkWarnValue)
	{
		$OutlookLinkWarnData = (Get-ItemPropertyValue -Path $OutlookLinkWarnKey -Name $OutlookLinkWarnValue -ea SilentlyContinue)
		if ($OutlookLinkWarnData -Eq "1") {
			Write-Output "Information: Automatic Update of Outlook Links '$OutlookLinkWarnValue' is set to '1'. Automatic Update of Outlook Links is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($OutlookLinkWarnData -Ne "1") {
			Write-Output "Finding: Automatic Update of Outlook Links '$OutlookLinkWarnValue' is set to '$OutlookLinkWarnData'. Automatic Update of Outlook Links is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to load external content. `nRecommendation: Set registry key '$OutlookLinkWarnKey' value '$OutlookLinkWarnValue' to '$OutlookLinkWarnRecommended', to ensure Outlook Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Automatic Update of Outlook Links '$OutlookLinkWarnValue' does not exist, therefore Automatic Update of Outlook Links is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to load external content. `nRecommendation: Set registry key '$OutlookLinkWarnKey' value '$OutlookLinkWarnValue' to '$OutlookLinkWarnRecommended', to ensure Outlook Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Legacy Outlook (Office 2007) Link Warnings - Dynamic Data Exchange (DDE)
	Write-Output "`nCheck: Legacy Outlook (Office 2010>) Link Warnings - Dynamic Data Exchange (DDE)" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$LegacyOutlookLinkWarnKey = "HKCU:\Software\Microsoft\Office\12.0\Word\Options\vpref"
	$LegacyOutlookLinkWarnValue = "fNoCalclinksOnopen_90_1"
	$LegacyOutlookLinkWarnRecommended = "1"
	if (Test-RegistryValue $LegacyOutlookLinkWarnKey $LegacyOutlookLinkWarnValue)
	{
		$LegacyOutlookLinkWarnData = (Get-ItemPropertyValue -Path $LegacyOutlookLinkWarnKey -Name $LegacyOutlookLinkWarnValue -ea SilentlyContinue)
		if ($LegacyOutlookLinkWarnData -Eq "1") {
			Write-Output "Information: Automatic Update of Outlook Links '$LegacyOutlookLinkWarnValue' is set to '1'. Automatic Update of Outlook Links is disabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($LegacyOutlookLinkWarnData -Ne "1") {
			Write-Output "Finding: Automatic Update of Outlook Links '$LegacyOutlookLinkWarnValue' is set to '$LegacyOutlookLinkWarnData'. Automatic Update of Outlook Links is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to load external content. `nRecommendation: Set registry key '$LegacyOutlookLinkWarnKey' value '$LegacyOutlookLinkWarnValue' to '$LegacyOutlookLinkWarnRecommended', to ensure Outlook Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Automatic Update of Outlook Links '$LegacyOutlookLinkWarnValue' does not exist, therefore Automatic Update of Outlook Links is enabled. `nBackground: Threat actors may exploit Dynamic Data Exchange (DDE) features, to load external content. `nRecommendation: Set registry key '$LegacyOutlookLinkWarnKey' value '$LegacyOutlookLinkWarnValue' to '$LegacyOutlookLinkWarnRecommended', to ensure Outlook Dynamic Data Exchange (DDE) features are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Excel VBA Warnings
	Write-Output "`nCheck: Excel VBA Warnings" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$ExcelVBAWarnKey = "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security"
	$ExcelVBAWarnValue = "VBAWarnings"
	$ExcelVBAWarnRecommended = "2"
	if (Test-RegistryValue $ExcelVBAWarnKey $ExcelVBAWarnValue)
	{
		$ExcelVBAWarnData = (Get-ItemPropertyValue -Path $ExcelVBAWarnKey -Name $ExcelVBAWarnValue -ea SilentlyContinue)
		if ($ExcelVBAWarnData -Eq "2") {
			Write-Output "Information: Excel VBA Warnings '$ExcelVBAWarnValue' is set to '2'. VBA macros are fully disabled (with notification)." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($ExcelVBAWarnData -Eq "1") {
			Write-Output "Finding: Excel VBA Warnings '$ExcelVBAWarnValue' is set to '1'. VBA macros are fully enabled. `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$ExcelVBAWarnKey' value '$ExcelVBAWarnValue' to '$ExcelVBAWarnRecommended', to ensure Excel VBA macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		elseif ($ExcelVBAWarnData -Eq "3") {
			Write-Output "Finding: Excel VBA Warnings '$ExcelVBAWarnValue' is set to '3'. VBA macros are partially enabled (only digitally signed macros are permitted). `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$ExcelVBAWarnKey' value '$ExcelVBAWarnValue' to '$ExcelVBAWarnRecommended', to ensure Excel VBA macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		elseif ($ExcelVBAWarnData -Eq "4") {
			Write-Output "Finding: Excel VBA Warnings '$ExcelVBAWarnValue' is set to '4'. VBA macros are disabled (without notification). `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$ExcelVBAWarnKey' value '$ExcelVBAWarnValue' to '$ExcelVBAWarnRecommended', to ensure Excel VBA macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
	}
	}
		else
	{
		Write-Output "Finding: Excel VBA Warnings '$ExcelVBAWarnValue' does not exist, therefore VBA macros are enabled. `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$ExcelVBAWarnKey' value '$ExcelVBAWarnValue' to '$ExcelVBAWarnRecommended', to ensure Excel VBA macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Word VBA Macro Warnings
	Write-Output "`nCheck: Word VBA Macro Warnings" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$WordVBAWarnKey = "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Security"
	$WordVBAWarnValue = "VBAWarnings"
	$WordVBAWarnRecommended = "2"
	if (Test-RegistryValue $WordVBAWarnKey $WordVBAWarnValue)
	{
		$WordVBAWarnData = (Get-ItemPropertyValue -Path $WordVBAWarnKey -Name $WordVBAWarnValue -ea SilentlyContinue)
		if ($WordVBAWarnData -Eq "2") {
			Write-Output "Information: Word VBA Warnings '$WordVBAWarnValue' is set to '2'. VBA macros are fully disabled (with notification)." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($WordVBAWarnData -Eq "1") {
			Write-Output "Finding: Word VBA Warnings '$WordVBAWarnValue' is set to '1'. VBA macros are fully enabled. `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$WordVBAWarnKey' value '$WordVBAWarnValue' to '$WordVBAWarnRecommended', to ensure Word VBA macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		elseif ($WordVBAWarnData -Eq "3") {
			Write-Output "Finding: Word VBA Warnings '$WordVBAWarnValue' is set to '3'. VBA macros are partially enabled (only digitally signed macros are permitted). `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$WordVBAWarnKey' value '$WordVBAWarnValue' to '$WordVBAWarnRecommended', to ensure Word VBA macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		elseif ($WordVBAWarnData -Eq "4") {
			Write-Output "Finding: Word VBA Warnings '$WordVBAWarnValue' is set to '4'. VBA macros are disabled (without notification). `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$WordVBAWarnKey' value '$WordVBAWarnValue' to '$WordVBAWarnRecommended', to ensure Word VBA macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
	}
	}
		else
	{
		Write-Output "Finding: Word VBA Warnings '$WordVBAWarnValue' does not exist, therefore VBA macros are enabled. `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$WordVBAWarnKey' value '$WordVBAWarnValue' to '$WordVBAWarnRecommended', to ensure Word VBA macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Excel Mark-Of-The-Web Macro Block
	Write-Output "`nCheck: Excel Mark-Of-The-Web Macro Block" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$ExcelMOTWKey = "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security"
	$ExcelMOTWValue = "blockcontentexecutionfrominternet"
	$ExcelMOTWRecommended = "1"
	if (Test-RegistryValue $ExcelMOTWKey $ExcelMOTWValue)
	{
		$ExcelMOTWData = (Get-ItemPropertyValue -Path $ExcelMOTWKey -Name $ExcelMOTWValue -ea SilentlyContinue)
		if ($ExcelMOTWData -Eq "1") {
			Write-Output "Information: Excel Mark-Of-The-Web Macro Block '$ExcelMOTWValue' is set to '1'. Mark-Of-The-Web macro block is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($ExcelMOTWData -Eq "0") {
			Write-Output "Finding: Excel Mark-Of-The-Web Macro Block '$ExcelMOTWValue' is set to '0'. Mark-Of-The-Web macro block is disabled. `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$ExcelMOTWKey' value '$ExcelMOTWValue' to '$ExcelMOTWRecommended', to ensure Excel Mark-Of-The-Web macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Excel Mark-Of-The-Web Macro Block '$ExcelMOTWValue' does not exist, therefore Mark-Of-The-Web macro block is disabled. `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$ExcelMOTWKey' value '$ExcelMOTWValue' to '$ExcelMOTWRecommended', to ensure Excel Mark-Of-The-Web macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Word Mark-Of-The-Web Macro Block
	Write-Output "`nCheck: Word Mark-Of-The-Web Macro Block" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$WordMOTWKey = "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Security"
	$WordMOTWValue = "blockcontentexecutionfrominternet"
	$WordMOTWRecommended = "1"
	if (Test-RegistryValue $WordMOTWKey $WordMOTWValue)
	{
		$WordMOTWData = (Get-ItemPropertyValue -Path $WordMOTWKey -Name $WordMOTWValue -ea SilentlyContinue)
		if ($WordMOTWData -Eq "1") {
			Write-Output "Information: Word Mark-Of-The-Web Macro Block '$WordMOTWValue' is set to '1'. Mark-Of-The-Web macro block is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($WordMOTWData -Eq "0") {
			Write-Output "Finding: Word Mark-Of-The-Web Macro Block '$WordMOTWValue' is set to '0'. Mark-Of-The-Web macro block is disabled. `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$WordMOTWKey' value '$WordMOTWValue' to '$WordMOTWRecommended', to ensure Word Mark-Of-The-Web macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Word Mark-Of-The-Web Macro Block '$WordMOTWValue' does not exist, therefore Mark-Of-The-Web macro block is disabled. `nBackground: Threat actors may exploit macrosfor malicious execution. `nRecommendation: Set registry key '$WordMOTWKey' value '$WordMOTWValue' to '$WordMOTWRecommended', to ensure Word Mark-Of-The-Web macros are not exploited for malicious execution." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Excel Internet Files Protected View
	Write-Output "`nCheck: Excel Internet Files Protected View" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$ExcelInternetPVKey = "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security\ProtectedView"
	$ExcelInternetPVValue = "DisableInternetFilesInPV"
	$ExcelInternetPVRecommended = "0"
	if (Test-RegistryValue $ExcelInternetPVKey $ExcelInternetPVValue)
	{
		$ExcelInternetPVData = (Get-ItemPropertyValue -Path $ExcelInternetPVKey -Name $ExcelInternetPVValue -ea SilentlyContinue)
		if ($ExcelInternetPVData -Eq "0") {
			Write-Output "Information: Excel Internet Files Protected View '$ExcelInternetPVValue' is set to '0'. Excel Internet Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($ExcelInternetPVData -Eq "1") {
			Write-Output "Finding: Excel Internet Files Protected View '$ExcelInternetPVValue' is set to '1'. Excel Internet Files Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$ExcelInternetPVKey' value '$ExcelInternetPVValue' to '$ExcelInternetPVRecommended', to ensure Excel Internet Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Excel Internet Files Protected View '$ExcelInternetPVValue' does not exist, therefore Excel Internet Files Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$ExcelInternetPVKey' value '$ExcelInternetPVValue' to '$ExcelInternetPVRecommended', to ensure Excel Internet Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Word Internet Files Protected View
	Write-Output "`nCheck: Word Internet Files Protected View" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$WordInternetPVKey = "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Security\ProtectedView"
	$WordInternetPVValue = "DisableInternetFilesInPV"
	$WordInternetPVRecommended = "0"
	if (Test-RegistryValue $WordInternetPVKey $WordInternetPVValue)
	{
		$WordInternetPVData = (Get-ItemPropertyValue -Path $WordInternetPVKey -Name $WordInternetPVValue -ea SilentlyContinue)
		if ($WordInternetPVData -Eq "0") {
			Write-Output "Information: Word Internet Files Protected View '$WordInternetPVValue' is set to '0'. Word Internet Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($WordInternetPVData -Eq "1") {
			Write-Output "Finding: Word Internet Files Protected View '$WordInternetPVValue' is set to '1'. Word Internet Files Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$WordInternetPVKey' value '$WordInternetPVValue' to '$WordInternetPVRecommended', to ensure Word Internet Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Word Internet Files Protected View '$WordInternetPVValue' does not exist, therefore Word Internet Files Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$WordInternetPVKey' value '$WordInternetPVValue' to '$WordInternetPVRecommended', to ensure Word Internet Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Excel Attachment Files Protected View
	Write-Output "`nCheck: Excel Attachment Files Protected View" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$ExcelAttachmentPVKey = "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security\ProtectedView"
	$ExcelAttachmentPVValue = "DisableAttachementsInPV"
	$ExcelAttachmentPVRecommended = "0"
	if (Test-RegistryValue $ExcelAttachmentPVKey $ExcelAttachmentPVValue)
	{
		$ExcelAttachmentPVData = (Get-ItemPropertyValue -Path $ExcelAttachmentPVKey -Name $ExcelAttachmentPVValue -ea SilentlyContinue)
		if ($ExcelAttachmentPVData -Eq "0") {
			Write-Output "Information: Excel Attachment Files Protected View '$ExcelAttachmentPVValue' is set to '0'. Excel Attachment Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($ExcelAttachmentPVData -Eq "1") {
			Write-Output "Finding: Excel Attachment Files Protected View '$ExcelAttachmentPVValue' is set to '1'. Excel Attachment Files Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$ExcelAttachmentPVKey' value '$ExcelAttachmentPVValue' to '$ExcelAttachmentPVRecommended', to ensure Excel Attachment Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Excel Attachment Files Protected View '$ExcelAttachmentPVValue' does not exist, therefore Excel Attachment Files Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$ExcelAttachmentPVKey' value '$ExcelAttachmentPVValue' to '$ExcelAttachmentPVRecommended', to ensure Excel Attachment Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Word Attachment Files Protected View
	Write-Output "`nCheck: Word Attachment Files Protected View" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$WordAttachmentPVKey = "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Security\ProtectedView"
	$WordAttachmentPVValue = "DisableAttachementsInPV"
	$WordAttachmentPVRecommended = "0"
	if (Test-RegistryValue $WordAttachmentPVKey $WordAttachmentPVValue)
	{
		$WordAttachmentPVData = (Get-ItemPropertyValue -Path $WordAttachmentPVKey -Name $WordAttachmentPVValue -ea SilentlyContinue)
		if ($WordAttachmentPVData -Eq "0") {
			Write-Output "Information: Word Attachment Files Protected View '$WordAttachmentPVValue' is set to '0'. Word Attachment Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($WordAttachmentPVData -Eq "1") {
			Write-Output "Finding: Word Attachment Files Protected View '$WordAttachmentPVValue' is set to '1'. Word Attachment Files Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$WordAttachmentPVKey' value '$WordAttachmentPVValue' to '$WordAttachmentPVRecommended', to ensure Word Attachment Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Word Attachment Files Protected View '$WordAttachmentPVValue' does not exist, therefore Word Attachment Files Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$WordAttachmentPVKey' value '$WordAttachmentPVValue' to '$WordAttachmentPVRecommended', to ensure Word Attachment Files Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Excel Unsafe Location Protected View
	Write-Output "`nCheck: Excel Unsafe Location Protected View" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$ExcelUnsafeLocPVKey = "HKCU:\Software\Microsoft\Office\$ExcelVersion\Excel\Security\ProtectedView"
	$ExcelUnsafeLocPVValue = "DisableUnsafeLocationsInPV"
	$ExcelUnsafeLocPVRecommended = "0"
	if (Test-RegistryValue $ExcelUnsafeLocPVKey $ExcelUnsafeLocPVValue)
	{
		$ExcelUnsafeLocPVData = (Get-ItemPropertyValue -Path $ExcelUnsafeLocPVKey -Name $ExcelUnsafeLocPVValue -ea SilentlyContinue)
		if ($ExcelUnsafeLocPVData -Eq "0") {
			Write-Output "Information: Excel Unsafe Location Protected View '$ExcelUnsafeLocPVValue' is set to '0'. Excel Unsafe Location Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($ExcelUnsafeLocPVData -Eq "1") {
			Write-Output "Finding: Excel Unsafe Location Protected View '$ExcelUnsafeLocPVValue' is set to '1'. Excel Unsafe Location Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$ExcelUnsafeLocPVKey' value '$ExcelUnsafeLocPVValue' to '$ExcelUnsafeLocPVRecommended', to ensure Excel Unsafe Location Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Excel Unsafe Location Protected View '$ExcelUnsafeLocPVValue' does not exist, therefore Excel Unsafe Location Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$ExcelUnsafeLocPVKey' value '$ExcelUnsafeLocPVValue' to '$ExcelUnsafeLocPVRecommended', to ensure Excel Unsafe Location Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}

	# Word Unsafe Location Protected View
	Write-Output "`nCheck: Word Unsafe Location Protected View" >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	$WordUnsafeLocPVKey = "HKCU:\Software\Microsoft\Office\$WordVersion\Word\Security\ProtectedView"
	$WordUnsafeLocPVValue = "DisableUnsafeLocationsInPV"
	$WordUnsafeLocPVRecommended = "0"
	if (Test-RegistryValue $WordUnsafeLocPVKey $WordUnsafeLocPVValue)
	{
		$WordUnsafeLocPVData = (Get-ItemPropertyValue -Path $WordUnsafeLocPVKey -Name $WordUnsafeLocPVValue -ea SilentlyContinue)
		if ($WordUnsafeLocPVData -Eq "0") {
			Write-Output "Information: Word Unsafe Location Protected View '$WordUnsafeLocPVValue' is set to '0'. Word Unsafe Location Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt}
		elseif ($WordUnsafeLocPVData -Eq "1") {
			Write-Output "Finding: Word Unsafe Location Protected View '$WordUnsafeLocPVValue' is set to '1'. Word Unsafe Location Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$WordUnsafeLocPVKey' value '$WordUnsafeLocPVValue' to '$WordUnsafeLocPVRecommended', to ensure Word Unsafe Location Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
		}
	}
		else
	{
		Write-Output "Finding: Word Unsafe Location Protected View '$WordUnsafeLocPVValue' does not exist, therefore Word Unsafe Location Protected View is disabled. `nBackground: Threat actors may disable file protected view, to allow malicious execution. `nRecommendation: Set registry key '$WordUnsafeLocPVKey' value '$WordUnsafeLocPVValue' to '$WordUnsafeLocPVRecommended', to ensure Word Unsafe Location Protected View is enabled." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
	}
	}
else
{
	Write-Output "Information: Microsoft Office Checks not carried out, as system is a Windows server." >> $Destination\$Audit\WINAudit_Security_Configuration_Report.txt
}

########## Organise Collection ##########

Stop-Transcript | Out-Null

# Compress Archive
Get-ChildItem -Path $Destination\$Audit | Compress-Archive -DestinationPath $Destination\$Audit.zip -CompressionLevel Fastest

# Delete Folder
Get-ChildItem -Path "$Destination\$Audit\\*" -Recurse | Remove-Item -Force -Recurse
Remove-Item "$Destination\$Audit"

Write-Host "`nScript completed!" -ForegroundColor green -BackgroundColor black
