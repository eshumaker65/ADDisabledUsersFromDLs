#####################################################################################################################################
#                                                       Impport Common Functions                                                    #
#####################################################################################################################################
Clear-Host
Import-Module MezShell
$myArray = @()

MezSetLog -ApplicationName 'Scraping DLs for disabled users' -TechCode 'IT' -LocalLogging 1 -ConsoleLogging 1
MezWriteLog '************ Starting!' -Color Green

MezWriteLog 'Application started. Scanning AD user OUs for disabled users.' -color Green
$DisabledUsers = Get-ADUser -server HQS-DC03 -Filter * -SearchBase “OU=Disabled Users,DC=hq,DC=mezzetta,DC=com” 

MezWriteLog 'Now verifying that there are no memberships for disabled users.' -color Green
ForEach ($User in $DisabledUsers) {
    $myArray += Get-ADUser $User.samaccountname -server HQS-DC03 |  Get-ADPrincipalGroupMembership -server HQS-DC03 | FT Name
    $objectToRemove = 'Disabled Users'
    $myArray = $myArray | Where-Object { $_ -ne $objectToRemove }
    $objectToRemove = 'Email-Reject-Incoming'
    $myArray = $myArray | Where-Object { $_ -ne $objectToRemove }
    if ($myArray.count -gt 0) {
        $Content = 'Processing user: ' + $User
        MezWriteLog $Content -color blue
        $myArray
        $myArray.Clear() 
    }
}   

MezWriteLog 'Completed! ************' -color Green
