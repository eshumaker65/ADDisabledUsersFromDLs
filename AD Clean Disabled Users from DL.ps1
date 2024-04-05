#####################################################################################################################################
#                                                       Impport Common Functions                                                    #
#####################################################################################################################################
Clear-Host
$ErrorActionPreference = "Stop"

# Import custom module
Import-Module MezShell 

# Set app name global var
$Global:ApplicationName = "Check Disabled Accounts"

# Set params for logging
MezSetLog -ApplicationName $Global:ApplicationName -TechCode 'IT' -LocalLogging 1 -ConsoleLogging 1

# Start
$MessageContent = '************ Starting ' + $Global:ApplicationName + '.'; MezWriteLog $MessageContent -Color Green

#####################################################################################################################################
#                                                       Do App Stuff                                                                #
#####################################################################################################################################

if (1 -eq 1) {  # Looking for users that are disabled, but not in the disabled ou
    MezWriteLog 'Scanning for disabled users in the wrong OUs.' -color green

    # Scan for disabled users not in the correct OUs, spit out the users for the list
    $DisabledUsers = Get-ADUser -server hqs-dc03  -Filter { Enabled -eq "False" } | Where-Object { ($_.DistinguishedName -notlike "*OU=Disabled*") }
    ForEach ($Disabled in $DisabledUsers) {
        $MessageContent = 'User: ' + $Disabled + ' is disabled, but not in a disabled OU. Remediating.' ; MezWriteLog $MessageContent -color Yellow
        Move-ADObject -Identity $Disabled -TargetPath "OU=Disabled Users,DC=hq,DC=mezzetta,DC=com"
        Write-Host '.' -NoNewline      
    }
    MezWriteLog 'Scan complete for disabled users in the wrong OU.' -color green
}

if (1 -eq 1) {  # Check that disabled users don't have managers
    # Fetch users with the Manager property
    $users = Get-ADUser -Server HQS-DC03 -Filter * -SearchBase "OU=Disabled Users,DC=hq,DC=mezzetta,DC=com" -SearchScope "OneLevel" -Properties Manager

    # Loop through each user and check if they have a manager assigned
    foreach ($user in $users) {
        if ($user.Manager) {
            $MessageContent = 'User '+$user.name+' has a manager assigned. Removing.'; MezWriteLog $MessageContent -color yellow
            Set-ADUser -Identity $user -Manager $null
        } else {
            $MessageContent = 'User '+$user.name+' has no manager.'; MezWriteLog $MessageContent -color green
        }
    }


    $users = Get-ADUser -Server HQS-DC03 -Filter * -SearchBase "OU=Disabled Cleared Users,OU=Disabled Users,DC=hq,DC=mezzetta,DC=com" -SearchScope "OneLevel" -Properties Manager

    # Loop through each user and check if they have a manager assigned
    foreach ($user in $users) {
        if ($user.Manager) {
            $MessageContent = 'User '+$user.name+' has a manager assigned. Removing.'; MezWriteLog $MessageContent -color yellow
            Set-ADUser -Identity $user -Manager $null
        } else {
            $MessageContent = 'User '+$user.name+' has no manager.'; MezWriteLog $MessageContent -color green
        }
    }
}

if (1 -eq 1) {  # This checks that disabled users don't have random groups attached, move to cleared
    MezWriteLog 'Scanning disabled users for incorrect groups.' -color green
    # Query AD.
    $DisabledUsers = Get-ADUser -server HQS-DC03 -Filter * -SearchBase “OU=Disabled Users,DC=hq,DC=mezzetta,DC=com” -searchscope "OneLevel" 
    MezWriteLog 'Now verifying that there are no memberships for disabled users other than accepted groups.' -color Green

    ForEach ($User in $DisabledUsers) {
        # Check that user is not Domain User
        $groupMembership = Get-ADPrincipalGroupMembership -Identity $User -server HQS-DC03 
    
        # Set filter, pull user membership
        $groupsToFilterOut = @("Disabled Users", "Email-Reject-Incoming","Domain Users")
        $filteredGroups = $groupMembership | Where-Object { $_.Name -notmatch ($groupsToFilterOut -join '|') }

        # Use the count to kick out fails
        IF ($filteredGroups.count -gt 1) {
            # remove every group in filteredgroups
            ForEach ($FilterGroup in $filteredGroups) {
                Remove-ADGroupMember -Identity $FilterGroup -Members $user -server hqs-dc03 -Confirm:$False
            }
            $MessageContent = 'User ' + $User.SamAccountName + ' had extra groups, remediated.'; MezWriteLog $MessageContent -color Yellow 
        }
        $MessageContent = 'User ' + $User.SamAccountName + ' moved to archive.'; MezWriteLog $MessageContent -color Yellow 
        Move-ADObject -Identity $user -TargetPath 'OU=Disabled Cleared Users,OU=Disabled Users,DC=hq,DC=mezzetta,DC=com'
    }
    MezWriteLog 'Scan complete for incorrect groups.' -color green
}

#####################################################################################################################################
#                                                       Wrap it up                                                                  #
#####################################################################################################################################
$MessageContent = '************ Ended ' + $Global:ApplicationName + '.'; MezWriteLog $MessageContent -Color Green

