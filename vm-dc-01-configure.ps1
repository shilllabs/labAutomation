[CmdletBinding()]

param 
( 
    [Parameter(ValuefromPipeline=$true,Mandatory=$true)] [string]$adminuser_pw
)
start-transcript -Path "c:\logging2.txt"
[SecureString]$secureAdminUserPw = $adminuser_pw | ConvertTo-SecureString -AsPlainText -Force

out-file c:\temp\creds2.txt -InputObject $secureAdminUserPw
out-file c:\temp\inputvariables2.txt -InputObject $adminuser_pw

#Create Organizational Units
New-ADOrganizationalUnit -Name "Resources" -Path "DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Resources,DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "Admins" -Path "OU=Accounts,OU=Resources,DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "SvcAccts" -Path "OU=Accounts,OU=Resources,DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "Users" -Path "OU=Accounts,OU=Resources,DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=Resources,DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Resources,DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "Workstations" -Path "OU=Resources,DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "Citrix" -Path "OU=Resources,DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Citrix,OU=Resources,DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "Maintenance" -Path "OU=Servers,OU=Citrix,OU=Resources,DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "Workstations" -Path "OU=Citrix,OU=Resources,DC=shilllabs,DC=cloud"
New-ADOrganizationalUnit -Name "Maintenance" -Path "OU=Workstations,OU=Citrix,OU=Resources,DC=shilllabs,DC=cloud"

#Create User Accounts
New-ADUser -Name "Shane Smith (ADM)" -displayName "Shane Smith (ADM)" -description "Adminstrative User" -givenName "Shane" -surname "Smith" -samAccountName "shane_adm" -UserPrincipalName "shane_adm@shilllabs.cloud" -enabled $true -passwordNeverExpires $true -path "OU=Admins,OU=Accounts,OU=Resources,DC=shilllabs,DC=cloud" -accountPassword $secureAdminUserPw

#Create AD Groups
New-ADGroup -Name "CitrixUsers" -Path "OU=Groups,OU=Resources,DC=shilllabs,DC=cloud" -GroupCategory "Security" -GroupScope "Global"

#Add Users To Groups
Add-ADGroupMember -Identity "Domain Admins" -Members "Shane_ADM"

#set the default computer OU
redircmp "OU=Resources,DC=shilllabs,DC=cloud"
Stop-Transcript