
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
#Invoke-WebRequest -Uri 'https://shilllabs-my.sharepoint.com/:u:/p/shane/EQGQnfF0m05AnmfUNxWbKnoBWJxCx23jSpJZNNogOQnklA?e=MRuRL4&download=1' -OutFile c:\temp\SW_DVD9_SQL_Svr_Enterprise_Edtn_2019Dec2019_64Bit_English_MLF_X22-22247.ISO
Invoke-WebRequest -Uri 'https://ctxuspsusazstorage01.blob.core.usgovcloudapi.net/filecontrainer/SW_DVD9_SQL_Svr_Enterprise_Edtn_2019Dec2019_64Bit_English_MLF_X22-22247.ISO' -OutFile c:\temp\SW_DVD9_SQL_Svr_Enterprise_Edtn_2019Dec2019_64Bit_English_MLF_X22-22247.ISO

#download sql config
Invoke-WebRequest -Uri 'https://shilllabs-my.sharepoint.com/:u:/p/shane/ESUnoDr_8gZJhIRnJElI8QgB0y968-ErGFlotLNvT1ze4w?e=gZbrnj&download=1' -OutFile c:\temp\ConfigurationFile.ini

#download sql server management setup
#Invoke-WebRequest -Uri 'https://shilllabs-my.sharepoint.com/:u:/p/shane/EVlxiMjLkYlIsvCHAV2BzMsBB7Ke0sHdaT9bT1i50Ek5GA?e=iAUc3f&download=1' -OutFile c:\temp\SSMS-Setup-ENU.exe
Invoke-WebRequest -Uri 'https://ctxuspsusazstorage01.blob.core.usgovcloudapi.net/filecontrainer/SSMS-Setup-ENU.exe' -OutFile c:\temp\SSMS-Setup-ENU.exe

#mount the sql iso and get the drive letter
$mountResult = Mount-DiskImage -ImagePath "c:\temp\SW_DVD9_SQL_Svr_Enterprise_Edtn_2019Dec2019_64Bit_English_MLF_X22-22247.ISO"
$driveLetter = ($mountResult | Get-Volume).DriveLetter
$application = $driveLetter + ":\Setup.exe"
$parameteres = "/IAcceptSQLServerLicenseTerms /ConfigurationFile=c:\temp\ConfigurationFile.ini"

#install sql server
Start-Process -FilePath $application -ArgumentList $parameteres

#install sql server management setup
Start-Process -FilePath "c:\temp\SSMS-Setup-ENU.exe" -ArgumentList "/Install /Quiet"

#clean up autologon
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'DefaultUserName'
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'DefaultPassword'
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'AutoAdminLogon'

out-file "c:\sql_done.txt" "SQL Install script has completed"

Stop-Transcript