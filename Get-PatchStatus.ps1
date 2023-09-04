<#
.DESCRIPTION
This script is designed to get the pending patches for systems based on Active Directory group.
The Configuration Manager client must be installed.

.PARAMETER PatchGroup
Enter an Active Directory Group that Contains Computers or Computers.

.PARAMETER To
Enter the email address to send the result to.

.PARAMETER SMTPSrv
Please enter the SMTP Computer address that can accept unauthenticated messages.

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$PatchGroup,
    [Parameter(Mandatory = $true)]
    [string]$To,
    [Parameter(Mandatory = $true)]
    [string]$SMTPSrv
)

#variables
[System.Collections.ArrayList]$CurrentLog=@()
Function Write-Log {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
    [String]$Level = "INFO",
    [Parameter(Mandatory=$True)]
    [string]$Message
    )
    #create empty log variable if one does not exist.
    if($null -eq $CurrentLog){
        [System.Collections.ArrayList]$CurrentLog=@()
    }
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    If($null -ne $CurrentLog) {
        $CurrentLog.Add($Line) | Out-Null
        Write-Host $Line
    }
    Else {
        Write-Output $Line
    }
}

if((Get-ADObject -Filter {name -like $PatchGroup}).ObjectClass -eq "group"){
    try {
        $Computers = Get-ADGroupMember -Identity $PatchGroup | Where-Object {$_.objectClass -eq "computer"}
        Write-Log -Level INFO -Message "$PatchGroup found. Getting Computer list."
    }
    catch {
        Write-Log -Level ERROR -Message "Could not locate group $PatchGroup"
        Exit
    }
}
else{
    try {
        $Computers = Get-ADObject -Filter {name -like $PatchGroup}
        Write-Log -Level INFO -Message "$PatchGroup located."
    }
    catch {
        Write-Log -Level ERROR -Message "$PatchGroup could not be located."
        Exit
    }
}

Write-Log -Message "Checking status for the following Computers: $($Computers.name)"
foreach($Computer in $Computers){
    Write-Log -Message "Checking $($Computer.name)"
    if(Test-Connection -ComputerName $Computer.name -Count 1){
        Write-Log -Message "$($Computer.name) is online."
    }
    else{
        Write-Log -Message "$($Computer.name) is offline. Please investigate."
        $Computers.Remove($Computer)
        continue 
    }
    $Result = Invoke-Command -ComputerName $Computer.name -ScriptBlock {
        [datetime]$UpTime = (Get-CimInstance -ClassName win32_operatingsystem).lastbootuptime
        $Updates = Get-WmiObject -Namespace root\CCM\ClientSDK -Class CCM_SoftwareUpdate -Filter ComplianceState=0
        $FailedUpdates = Get-WmiObject -Namespace root\CCM\ClientSDK -Class CCM_SoftwareUpdate -Filter ComplianceState=13
        $Name = $env:COMPUTERNAME
        $Properties = @(
            [pscustomobject]@{
                Name=$Name;
                LastBootTime=$UpTime;
                PendingUpdates=$updates.count;
                FailedUpdates=$FailedUpdates.count}
        )
        return $Properties
    }
    Write-Log -Level INFO -Message "Computer Name: $($Result.name) - Pending Updates: $($Result.pendingupdates) - Last Reboot: $($Result.LastBootTime) - Failed updates: $($Result.FailedUpdates)"
}

$Body = $CurrentLog | Out-String
Send-MailMessage -SmtpComputer $SMTPSrv -To $To -From "PatchStatus@NoReply.com" -Subject "Patch results for $PatchGroup" -Body $Body