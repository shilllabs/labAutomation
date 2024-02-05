
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


#clean up autologon
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'DefaultUserName'
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'DefaultPassword'
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'AutoAdminLogon'

Stop-Transcript