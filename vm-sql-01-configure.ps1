
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

#download sql server iso
Invoke-WebRequest -Uri 'https://shilllabs-my.sharepoint.com/:u:/p/shane/EQGQnfF0m05AnmfUNxWbKnoBWJxCx23jSpJZNNogOQnklA?e=MRuRL4&download=1' -OutFile c:\temp\SW_DVD9_SQL_Svr_Enterprise_Edtn_2019Dec2019_64Bit_English_MLF_X22-22247.ISO

#mount the sql iso
Mount-DiskImage -ImagePath "c:\temp\SW_DVD9_SQL_Svr_Enterprise_Edtn_2019Dec2019_64Bit_English_MLF_X22-22247.ISO"

#install sql server
#c:\temp\CitrixStoreFront-x64.exe -silent


#probably reboot after this
#Import-Module Citrix.StoreFront
#powershell -ExecutionPolicy Unrestricted -File 'C:\Program Files\Citrix\Receiver StoreFront\PowerShellSDK\Examples\SimpleDeployment.ps1' -HostbaseUrl "http://sf-01.shilllabs.cloud" -SiteId 1 -Farmtype XenDesktop -FarmServers "cc-01.shilllabs.cloud" -StoreVirtualPath "/Citrix/Store"

#clean up autologon
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'DefaultUserName'
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'DefaultPassword'
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'AutoAdminLogon'

Stop-Transcript