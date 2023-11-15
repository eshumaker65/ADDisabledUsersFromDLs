#####################################################################################################################################
#                                                       Impport Common Functions                                                    #
#####################################################################################################################################
Clear-Host
Import-Module MezShell

# Config the MezShell logger, start the app.
MezSetLog -ApplicationName 'Scraping DLs for disabled users' -TechCode 'IT' -LocalLogging 1 -ConsoleLogging 1
MezWriteLog '************ Starting!' -Color Green

# Build an array.
$BadGroupUser = New-Object System.Collections.ArrayList
$BadDisabledWrongOU = New-Object System.Collections.ArrayList
$DeleteMyMailbox = New-Object System.Collections.ArrayList

if (1 -eq 2) {
    MezWriteLog 'Scanning disabled users for incorrect groups.' -color green
    # Query AD.
    $DisabledUsers = Get-ADUser -server HQS-DC03 -Filter * -SearchBase “OU=Disabled Users,DC=hq,DC=mezzetta,DC=com” -ResultSetSize 8
    MezWriteLog 'Now verifying that there are no memberships for disabled users other than accepted groups.' -color Green

    ForEach ($User in $DisabledUsers) {
        # Enum through the users looking for groups that are not allowed on disabled users.
        $MessageContent = 'Running user: ' + $User.SamAccountName ; MezWriteLog $MessageContent -Color Blue
        
        # Groups to filter out
        $groupsToFilterOut = @("Disabled Users", "Email-Reject-Incoming")

        # Get the group membership, filter the exclusions
        $groupMembership = Get-ADPrincipalGroupMembership -Identity $User -server HQS-DC03 ; $filteredGroups = $groupMembership | Where-Object { $_.Name -notmatch ($groupsToFilterOut -join '|') }

        # Display the filtered groups
        IF ($filteredGroups.count -gt 1) {
            # Write log entries, add bad user to the list
            $MessageContent = 'Found user with extra groups: ' + $User.SamAccountName ; MezWriteLog $MessageContent -color Yellow 
            [void]$BadGroupUser.add($user.SamAccountName)
        }
    }

    ForEach ($Badguy in $BadGroupUser) {
        # Combine all the bad users, burp on the end of the log file.
        $MessageContent = 'User: ' + $BadGuy + ' has too many groups.' ; MezWriteLog $MessageContent -color Yellow
    }
    MezWriteLog 'Scan complete for incorrect groups.' -color green
}

if (1 -eq 2) {
    MezWriteLog 'Scanning for disabled users in the wrong OUs.' -color green

    # Scan for disabled users not in the correct OUs, spit out the users for the list
    $DisabledUsers = Get-ADUser -server hqs-dc03  -Filter { Enabled -eq "False" } | Where-Object { ($_.DistinguishedName -notlike "*OU=Disabled*") }
    ForEach ($Disabled in $DisabledUsers) {
        $MessageContent = 'User: ' + $Disabled + ' is disabled, but not in a disabled OU.' ; MezWriteLog $MessageContent -color Yellow
        [void]$BadDisabledWrongOU.add($MessageContent)
    }
    MezWriteLog 'Scan complete for disabled users in the wrong OU.' -color green
}

if (1 -eq 1) {
    MezWriteLog 'Checking mailbox size for users.' -color green
    # $DisabledUsers = Get-ADUser -server hqs-dc03  -Filter {Enabled -eq "False"} -ResultSetSize 50
    # $DisabledUsers = Get-ADUser dwong -server hqs-dc03   # An example of a user who's name is not unique
    # $DisabledUsers = Get-ADUser guest -server hqs-dc03   # An example of a user who's account is not propogated in exchange
    
    $DisabledUsers | Format-Table
    # $Var = MezExchangeCon
    ForEach ($User in $DisabledUsers) {
        # $User | Format-Table Name, samaccountname, userprincipalname
        IF ($null -ne $User.UserPrincipalName) {
            $MessageContent = 'User:' + $User.Userprincipalname ; mezwritelog $MessageContent -color blue
            Try {
                $TotalItems = Get-Mailbox $User.UserPrincipalName -ErrorAction stop | Get-MailboxStatistics -ErrorAction stop | Select-Object ItemCount,
                @{
                    name       = "TotalItemSize"
                    expression = { ($_.TotalItemSize.value.ToString() -replace '[A-Z0-9.\s]+\(' -replace '\sbytes\)' -replace ',') }
                }

                $TotalItemSize = $TotalItems.TotalItemSize.tostring()
                $TotalItemSize = [Decimal]$TotalItemSize

                if ($TotalItemSize -gt 1000) {
                    $MessageContent = 'User:' + $User.SamAccountName + ' mailbox size over 1000: ' + $TotalItemSize + ' Mailbox must be backed up before deletion.'; MezWriteLog $MessageContent -Color Green
                }
                else {
                    $MessageContent = 'User:' + $User.SamAccountName + ' mailbox size under 1000: ' + $TotalItemSize + ' Mailbox is empty, so you should delete it.'; MezWriteLog $MessageContent -color blue
                    $DeleteMyMailbox.add($MessageContent)
                }
            }
            Catch {
                If ($_.Exception -like "*couldn't be found on*") {
                    $MessageContent = 'User: ' + $User.samaccountname + ' skipped, does not exist on Exchange. Check for delete.' ; MezWriteLog $Messagecontent -Color Yellow
                    [void]$DeleteMyMailbox.add($MessageContent)
                }
                elseif ($_.Exception -like "*The specified mailbox Identity*") {
                    $MessageContent = 'User: ' + $User.samaccountname + ' skipped, name is not unique.' ; MezWriteLog $Messagecontent -Color Yellow
                    [void]$DeleteMyMailbox.add($MessageContent) 
                } 
                Else {
                    $_.Exception
                    MezWriteLog 'An unhandled problem occurred.... Run it in debug.' -color Yellow
                }
            }                
        }
        else {
            $MessageContent = 'User:' + $User.SamAccountName + ' has no UPN. Skipped.' ; MezWriteLog $MessageContent -Color Yellow
        }
    }
    
}

if (1 -eq 2) {
    MezWriteLog 'Shoot out a ticket' -color green
}

$DeleteMyMailbox

MezWriteLog 'Completed! ************' -color Green