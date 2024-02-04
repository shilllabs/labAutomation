
[CmdletBinding()]

param 
( 
    [Parameter(ValuefromPipeline=$true,Mandatory=$true)] [string]$win_username,
    [Parameter(ValuefromPipeline=$true,Mandatory=$true)] [String]$win_userpass
)

#$SMAP = ConvertTo-SecureString -AsPlainText $win_userpass -Force
[SecureString]$secureString = $win_userpass | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$credentialObejct = New-Object System.Management.Automation.PSCredential -ArgumentList $win_username, $secureString


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
Install-AdcsCertificationAuthority @params -Credential $credentialObejct -Force