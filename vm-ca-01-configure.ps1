
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

#set parameters
$params = @{
    CAType              = "EnterpriseRootCa"
    CryptoProviderName  = "RSA#Microsoft Software Key Storage Provider"
    KeyLength           = 4096
    HashAlgorithmName   = "SHA512"
    ValidityPeriod      = "Years"
    ValidityPeriodUnits = 30
}

#install ca features
Install-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools

#install ca role
Install-AdcsCertificationAuthority @params -Credential $credentialObject -Force
Stop-Transcript