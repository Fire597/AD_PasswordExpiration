<#
Purpose of this script is to send email alerts to IT Department when the password of an account 
present in a monitored OU or group is about to expire.
#>

#True = monitored by Group ; False = Monitored by OU.
$MonitoredByGroup = $false

#OU to monitor
$Monitored_OUS = @(
    "OU=Users,DC=test,DC=internal"
)

#Groups to monitor
$Monitored_Groups = @(
    "CN=Users,DC=test,DC=internal"
)

#Different categories to trigger alerts
$PasswordExpirationThresholds = @(1, 5, 7) | Sort-Object # days before password expiration


$Users = @()

$DbgLog = $False

# Debug mode function
Function DebugLog # Function used througout the script in order to log errors
{
    param (
        $Message,
        $ErrorMessage
    )
    if ($DbgLog)
    {
        return @(' ',$Message,"Error: $ErrorMessage")
    }
}


function SendAnEmail
{
    param(
        $User,
        $Subject,
        $Threshold,
        $Time
    )

    try
    {
        $SmtpServer = "mail.test.internal"
        $Port = 25
        $FromAddress = "noreply@test.internal"

        # Send an email to the user
        $ToAddress = "IT.dept@test.internal"
        $Body = "The password of $User is going to expire on $Time. Please change the password to ensure continuous access to this account."

        Send-MailMessage -SmtpServer $SmtpServer -From $FromAddress -To $ToAddress -Subject $Subject -Body $Body -Port $Port
        Write-Host $(DebugLog "Successfully sent an email." "None")
    }
    catch
    {
        Write-Host $(DebugLog "Couldn't sent an email." $($_.ToString()))
    }
}


# Get all users in Active Directory depending on groups and OUs
if ($MonitoredByGroup){
    foreach ($Group in $Monitored_Groups )
    {
        $Users += Get-ADGroupMember -Identity $Group -Properties "msDS-UserPasswordExpiryTimeComputed"
        Write-Host $(DebugLog "Successfully added Users from Group." "None")
    }
}
else {
    foreach ($OU in $Monitored_OUS)
    {
        $Users += Get-ADUser -Filter * -SearchBase $OU -Properties "msDS-UserPasswordExpiryTimeComputed"
        Write-Host $(DebugLog "Successfully added Users from OUs." "None")
    }
}

# Parse each user
foreach ($User in $Users) {
    # Get the password expiry time
    Write-Host $(DebugLog "Strating parsing of $User.name." "None")
    $PasswordExpiration = $User."msDS-UserPasswordExpiryTimeComputed"
    try {
        $PasswordExpirationTime = [datetime]::FromFileTime($PasswordExpiration)
    }
    catch {
        Write-Host $(DebugLog "This account's password doesn't expire. It is either set as it in its account or member of a misconfigured policy." $($_.ToString()))
    }
    

    # Check if the password is going to expire soon
    foreach ($Threshold in $PasswordExpirationThresholds) {
        if (($PasswordExpirationTime -lt (Get-Date).AddDays($Threshold)) -and ($PasswordExpirationTime -gt (Get-Date))) {
            # Send an email to the user
            $Message = "The password of $($User.Name) is going to expire in less than $Threshold days."
            SendAnEmail $User.Name $Message $Threshold $PasswordExpirationTime
            break
        }
    }

    # Check that the password hasn't already expire
    if ($PasswordExpirationTime -lt (Get-Date)) {
        # Send an email to the user
        $Message = "The password of $($User.Name) is already expired."
        SendAnEmail $User.Name $Message $Threshold $PasswordExpirationTime
    }
}