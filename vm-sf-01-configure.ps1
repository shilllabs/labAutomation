
[CmdletBinding()]

param 
( 
    [Parameter(ValuefromPipeline=$true,Mandatory=$true)] [string]$Domain_DNSName,
    [Parameter(ValuefromPipeline=$true,Mandatory=$true)] [string]$win_username,
    [Parameter(ValuefromPipeline=$true,Mandatory=$true)] [String]$win_userpass
)
start-transcript -Path "c:\logging2.txt"
#$SMAP = ConvertTo-SecureString -AsPlainText $win_userpass -Force
[SecureString]$secureString = $win_userpass | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$credentialObject = New-Object System.Management.Automation.PSCredential -ArgumentList "$win_username@$Domain_DNSName", $secureString
out-file c:\temp\creds2.txt -InputObject $credentialObject
out-file c:\temp\inputvariables2.txt -InputObject $win_username, $win_userpass

#download storefront
Invoke-WebRequest -Uri 'https://shilllabs-my.sharepoint.com/:u:/p/shane/EeGae6pjRm1FimrdcjN-BuYBtHuN2ikCDva9z3QAwqBalw?e=jRdXyZ&download=1' -OutFile c:\temp\CitrixStoreFront-x64.exe

#install storefront
c:\temp\CitrixStoreFront-x64.exe -silent


#probably reboot after this
#Import-Module Citrix.StoreFront
c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -File 'C:\Program Files\Citrix\Receiver StoreFront\PowerShellSDK\Examples\SimpleDeployment.ps1' -HostbaseUrl "https://sf-01.shilllabs.cloud" -SiteId 1 -Farmtype XenDesktop -FarmServers "cc-01.shilllabs.cloud" -StoreVirtualPath "/Citrix/Store"

#clean up autologon
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'DefaultUserName'
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'DefaultPassword'
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'AutoAdminLogon'

Stop-Transcript