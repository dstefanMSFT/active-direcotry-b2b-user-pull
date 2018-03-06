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
	Daniel Stefaniak dstefan@microsoft.com

.DESCRIPTION

    Version: 1.0.2

    This is currently a beta level script and intended to be used as a demonstration script

.DISCLAIMER
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

    Copyright (c) Microsoft Corporation. All rights reserved.
#>

<#
Recommended ToDo/caveats for production deployments
- add certificate based authentication for Service Principal Name
- decide on where and whether to filter on active/disabled AAD status
- At the moment script takes first 20 characters of the UPN
- if the B2B user is re-invited after having been deleted and the shadow account is archived, recreation of a new shadow accounn will fail. 
- there is no error handling if Add-AdUser call fails
- add reporting - should be off by default but available for troubleshooting
/ToDo/caveats
#>

# Set up variables
# Replace all TODO items
$B2BGroupSid = "TODO" #Cloud group's ObjectID
$ShadowAccountOU = "TODO" #Organizational Unit for placing shadow accounts
$ShadowAccountOUArchive = "TODO" #Organizational Unit for moving disabled shadows
$createmissingshadowaccounts = $true
# Only one of the following should be true. If both are True then disable action takes precedence
$disableorphanedshadowaccounts = $false
$deleteorphanedshadowaccounts = $false
# Requires Azure AD configuration - refer to documentation
$appID = "TODO" # Insert your application's Client ID, a Globally Unique ID (registered by Global Admin)
$appSecret = "TODO"  # Insert your application's Client Key/Secret string
$tenantdomain   = "TODO"    # AAD Tenant; for example, contoso.onmicrosoft.com
$tenantID = "TODO" # Identifier of the tenant domain

# No need to modify more variables
# Variable initialization
$TenantGuestUsersHash = @{} 
$UsersInB2BGroupHash = @{}
$B2bShadowAccountsHash = @{}
$loginURL = "https://login.microsoftonline.com/" # AAD Instance; for example https://login.microsoftonline.com for public or https://login.microsoftonline.us for government cloud
$resource = "https://graph.windows.net"
$body = @{grant_type="client_credentials";resource=$resource;client_id=$appID;client_secret=$appSecret}
$oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.5 -Body $body 
Connect-AzureAD -AadAccessToken $oauth.access_token -TenantId $tenantID -AccountId $appID

# Populate hash table with all Guest users from tenant using object ID as key
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
# Below Write-host lines can be used for debug purposes
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





