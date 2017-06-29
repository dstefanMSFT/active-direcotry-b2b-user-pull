<# 
 
.SYNOPSIS
    Sample script to create a differencing list between Guest accounts in an Azure AD tenant and an on-prem Active Directory OU
    Includes options to 
    - create users in the OU who exist in AAD and are members of a specified group but are not present in the AD
    - optionally disable and move shadow accounts in the OU who no longer exist in Azure AD to a different OU
    - optionally delete shadow accounts in the OU who no longer exist in Azure AD

    This would be used to create shadow accounts in AD for use by Application Proxy for KCD delegation for B2B Guest accounts.

    The shadow account will be created with the following properties:
            -AccountPassword = random strong password
            -ChangePasswordAtLogon = $false
            –PasswordNeverExpires = $true
            -SmartcardLogonRequired = $true

    NOTE - this does not have support for nesting in the AAD Group

	Ian Parramore ianparr@microsoft.com

.DESCRIPTION

    Version: 1.0.1

    This is currently a beta level script and intended to be used as a demonstration script

.DISCLAIMER
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

    Copyright (c) Microsoft Corporation. All rights reserved.
#>


<#
BUGBUG

- add cert based auth
- decide on where and whether to filter on active/disabled AAD status
- should we use V1 or V2 AAD PSH cmdlets
- how should we populate the samAccountName? At the moment I take first 20 characters of the UPN
- if the B2B user is re-invited after having been deleted and the shadow account is archived, recreation of a new shadow accounn will fail. 
  Should we handle this? We could check the archive OU and move the account back. THoughts?
- need error handling if Add-AdUser call fails
- add reporting - should be off by default but available for troubleshooting
- clean up telemetry

/BUGBUG
#>



# Set up variables

# This needs updating to target the relevent group
# $B2BGroupSid = "97623264-4f72-46cf-b4e5-1205bb57f4a3"
$B2BGroupSid = "7940bfb4-9b68-4c19-8180-aeb6fab569fd"

$ShadowAccountOU = "OU=ShadowAccounts,DC=corp,DC=pfe,DC=ninja"
$ShadowAccountOUArchive = "OU=Archive,OU=ShadowAccounts,DC=corp,DC=pfe,DC=ninja"
$createmissingshadowaccounts = $true

# only one of the following should be true. If both are True then disable action takes precedence
$disableorphanedshadowaccounts = $false
$deleteorphanedshadowaccounts = $false


$TenantGuestUsersHash = @{} 
$UsersInB2BGroupHash = @{}
$B2bShadowAccountsHash = @{}

# to do - add Cert based authentication
# at the moment we will manually auth using ADAL duing the Connect-MsolService call
# Connect-MsolService

$appID = "a37744ce-8849-4567-bee5-93ca719848ec" # Insert your application's Client ID, a Globally Unique ID (registered by Global Admin)
$appSecret = "bnxyQLlqJ7E0lI38Z+TtNk65VA4aqbmF/2se8RJuJsk="  # Insert your application's Client Key/Secret string
$loginURL       = "https://login.microsoftonline.com/" # AAD Instance; for example https://login.microsoftonline.com
$tenantdomain   = "pfeninja.onmicrosoft.com"    # AAD Tenant; for example, contoso.onmicrosoft.com
$resource       = "https://graph.windows.net"
$body=$creds
$body = @{grant_type="client_credentials";resource=$resource;client_id=$appID;client_secret=$appSecret}
$oauth      = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.5 -Body $body 
Connect-AzureAD -AadAccessToken $oauth.access_token -TenantId 944d9418-0d20-4e86-9e1d-dce70945d8f1 -AccountId $appID


# Populate hash table with all Guest users from tenant using object ID as key
# This is to make just one MSOL-User call fore efficiency purposes
Get-AzureADUser -All $true -Filter "userType eq 'Guest'" |  `
    ForEach-Object {$TenantGuestUsersHash[$_.ObjectId] = $_}

# Populate hash table with membership of target group from Azure AD using object ID as key
# we will then reference across into the Guest use hash table as needed.
 Get-AzureADGroupMember -ObjectId $B2BGroupSid -all $true | `
        ForEach-Object {$UsersInB2BGroupHash[$_.ObjectId] = $_}

# Populate hash table with all accounts in shadow account OU using UPN as key
# consider setting value to Null instead of the object as we don't use this
Get-AdUser -filter * -SearchBase $ShadowAccountOU | `
Select-Object UserPrincipalName, Name, Description | ` 
ForEach-Object {$B2bShadowAccountsHash[$_.UserPrincipalName] = $_}


# For each tenant Guest account UPN in the group check if it exists in SHadow OU hash table
# If exists then remove from both lists
# End state of B2B Group list will be all tenant guest accounts in the group not in the shadow OU
# End state of shadow account list will be all shadow accounts without a matching tenant guest account


ForEach($key in $($UsersInB2BGroupHash.Keys))
    {

    
    # remove non-guest users from the AAD Group list
    if($TenantGuestUsersHash.ContainsKey($key) -eq $false)
        {
        # if we want to output anything about non-Guest users it needs to pull from the Group Membership hash 
        # as these users will not be in the guest users hash table e.g. 
        # $UsersInB2BGroupHash[$key].emailaddress

        $UsersInB2BGroupHash.Remove($key)
        }

    # B2B guest user already has a shadow account remove from both lists
    # we'll then end up with 2 differencing lists
    elseif ($B2bShadowAccountsHash.ContainsKey($TenantGuestUsersHash[$key].userprincipalname))
        {
        # $TenantGuestUsersHash[$key].userprincipalname
        # Write-Host $key "account exists in both AAD group and AD OU - removing from both lists"
        $UsersInB2BGroupHash.Remove($key)
        $B2bShadowAccountsHash.Remove($key)
        }
    }
    
<#
Write-Host ""
Write-Host "*****Tenant Object ID's that need shadow accounts creating*****"
$UsersInB2BGroupHash.Keys
Write-Host ""
Write-Host "*****Shadow account UPNs with no matching tenant account - review for removal*****"
$B2bShadowAccountsHash.Keys
Write-Host ""
#>

If ($createmissingshadowaccounts -eq $true)
{
    ForEach($key in $($UsersInB2BGroupHash.keys))
        {
        $key
        $TenantGuestUsersHash[$key].UserPrincipalName

        $samaccountname = $TenantGuestUsersHash[$key].userprincipalname.Substring(0, 20)
        $samaccountname 

        # generate random password
        $bytes = New-Object Byte[] 32
        $rand = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rand.GetBytes($bytes)
        $rand.Dispose()
        $RandPassword = [System.Convert]::ToBase64String($bytes)
            
        New-ADUser -Name $samaccountname `
            -SamAccountName $samaccountname `
            -Path $ShadowAccountOU `
            -UserPrincipalName $TenantGuestUsersHash[$key].userprincipalname `
            -Description $TenantGuestUsersHash[$key].userprincipalname `
            -DisplayName $TenantGuestUsersHash[$key].Value.DisplayName `
            -AccountPassword (ConvertTo-SecureString $RandPassword -AsPlainText -Force) `
            -ChangePasswordAtLogon $false `
            –PasswordNeverExpires $true `
            -SmartcardLogonRequired $true `
        }
        Enable-ADAccount -Identity $samaccountname
}


# clean up time for any Shadow Accounts where the AAD guest account no longer exists
 If ($disableorphanedshadowaccounts -eq $true -or $deleteorphanedshadowaccounts -eq $true)
 {

      ForEach ($shadow in $($B2bShadowAccountsHash.keys))
        {
            # $upn = the key from B2bShadowAccountsHash = $shadow
            # disable operation takes precedence over deletion
            If ($disableorphanedshadowaccounts -eq $true)
            {
                Get-AdUser -Filter {UserPrincipalName -eq $shadow} -SearchBase $ShadowAccountOU| Set-ADUser -Enabled $false -Description 'Disabled pending removal' 
                Get-AdUser -Filter {UserPrincipalName -eq $shadow} -SearchBase $ShadowAccountOU | Move-ADObject -TargetPath $ShadowAccountOUArchive
                
            }
            ElseIf ($deleteorphanedshadowaccounts = $true)
            {
                Get-AdUser -Filter {UserPrincipalName -eq $shadow} -SearchBase $ShadowAccountOU | Remove-AdUser
            }
        }

  }





