<#
.DESCRIPTION
This script will initiate a patching cycle for the servers in the requested group.
It will check the evaluation state for all updates listed as pending using a WMI call to the CCM_SoftwareUpdate Class
EvaluationState - meaning  https://docs.microsoft.com/en-us/sccm/develop/reference/core/clients/sdk/ccm_softwareupdate-client-wmi-class

.PARAMETER PatchGroup
Enter the Active Directory Group containing the designated servers.

.PARAMETER WriteToConsole
Writes all log details to the console for interactive use

.PARAMETER RunTimeHours
Limits the total run time to the specified value. Default is 1 hour.

.PARAMETER RebootToStart
Restart any servers that have not been rebooted in the last 60 days.

$PatchGroup = "s-patchingscript-test"
$PatchGroup = "s-SCCM-ServerUpdate-Assisted"
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$PatchGroup,

    [Parameter()]
    [switch]$WriteToConsole,

    [Parameter()]
    [int]$RunTimeHours = "1",

    [Parameter()]
    [switch]$RebootToStart
)

[System.Collections.ArrayList]$currentlog=@()
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
    if($null -eq $currentlog){
        [System.Collections.ArrayList]$currentlog=@()
    }
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    If($WriteToConsole -eq $true) {
        $currentlog.Add($Line) | Out-Null
        Write-Host $Line
    }
    Else {
        $currentlog.Add($Line) | Out-Null
    }
}

$StartTime = (Get-Date)
$To = "12ca0c26.arsrr.com@amer.teams.ms"
$Servers = Get-ADGroupMember -Identity $PatchGroup
$EndJob = $false
#Create an array of all servers
[pscustomobject]$ServerArray = @()

Write-Log -Level INFO -Message "Starting Patch Cycle for $PatchGroup"
foreach($item in $Servers){
    if(Test-Connection -ComputerName $item.name -Count 1 -ErrorAction SilentlyContinue){
        $Server = [pscustomobject]@{
            ServerName = $item.name
            Status = "Incomplete"
            Attempts = 0
        }
        Write-Log INFO -Message "Found $($item.name), adding to patching list."
        $ServerArray += $Server
    }
    else{
        Write-Log WARN -Message "Could not communicate with $($item.name). This server will be skipped."
    }
}

if($RebootToStart){
    Write-Log -Level INFO -Message "Checking if servers have not been rebooted in the last 60 days."
    foreach($Server in $Servers){
        $UpTime = Get-WmiObject
        if($UpTime -lt $StartTime.AddDays(60)){
            Write-Log -Level INFO -Message "Restarting $($Server.name)"
            Restart-Computer -ComputerName $Server.name
        }
    }
}

#create arraylist so objects can be removed as they complete
[System.Collections.ArrayList]$PendingServers = $serverarray
Do{
    Write-Log -Level INFO -Message "Checking servers for pending updates."
    if(!$PendingServers){
        $EndJob = $true
    }
    foreach($ServerObj in $ServerArray){
        if($ServerObj.status -eq "Complete"){
            Write-Host "$($ServerObj.ServerName) is showing complete. Skipping..."
            $PendingServers.Remove($ServerObj)
        }
        #check if server if fully booted
        if(!(Get-Service -Name "Server" -ComputerName $ServerObj.ServerName)){
            $ServerObj.status = "Rebooting"
            break
        }
        if($ServerObj.Attempts -gt "3"){
            Write-Log -Level WARN -Message "3 attempts have been made to install updates for $($ServerObj.ServerName). Marking server complete. Please investigate!"
            $ServerObj.Status = "Complete"
            $PendingServers.Remove($ServerObj)
        }
        Write-Log -Level INFO -Message "Checking $($ServerObj.ServerName)"
        if($ServerObj.Status -eq "Incomplete"){
            $approvedUpdates = 0
            $pendingpatches = 0
            $rebootpending = 0 
            $failedUpdates = 0
            try{
                #Get list of all instances of CCM_SoftwareUpdate from root\CCM\ClientSDK for missing updates https://msdn.microsoft.com/en-us/library/jj155450.aspx?f=255&MSPPError=-2147217396
                $TargetedUpdates = Get-WmiObject -ComputerName $ServerObj.ServerName -Namespace root\CCM\ClientSDK -Class CCM_SoftwareUpdate -Filter ComplianceState=0
                $approvedUpdates = ($TargetedUpdates | Measure-Object).count
                $InProgressUpdates = ($TargetedUpdates | Where-Object {$_.EvaluationState -eq 7} | Measure-Object).count
                $nonestateupdates = ($TargetedUpdates | Where-Object {$_.EvaluationState -eq 0} | Measure-Object).count
                $pendingpatches = ($TargetedUpdates | Where-Object {$_.EvaluationState -ne 8} | Measure-Object).count
                $rebootpending = ($TargetedUpdates | Where-Object {$_.EvaluationState -eq 8} | Measure-Object).count
                #Need deal with the state 13 - ciJobStateError - usually the update installation failed.
                $failedUpdates = ($TargetedUpdates | Where-Object {$_.EvaluationState -eq 13} | Measure-Object).count 
            }
            catch{
                #log entry below is not being written during the catch. Investigate
                Write-Log -Level ERROR -Message "Can't Get-WmiObject from $($ServerObj.name)"
                $ServerObj.Status = "Failed"
                $PendingServers.Remove($ServerObj)
            }
            #reboot server if there is a pending reboot
            if(($rebootpending -gt 0) -and ($InProgressUpdates -eq 0)){
                #If all Updates have been installed and need reboot then reboot it
                try{
                    Restart-Computer $ServerObj.ServerName -Force
                    $ServerObj.Status = "Complete"
                    Write-Log -Message "ApprovedUpdates:$approvedUpdates  PendingPatches:$pendingpatches   RebootPending:$rebootpending  Rebooting $($ServerObj.name) ......"
                    $PendingServers.Remove($ServerObj)
                }
                catch{
                    Write-Log -Level ERROR -Message "$($ServerObj.ServerName): all deployed updates have been installed but failed to reboot it, please investigate"
                    $ServerObj.Status = "Failed"
                    $PendingServers.remove($ServerObj)
                }
            }
            #If there is no update waiting for install and no pending reboot, set Status to Yes
            if(($pendingpatches -eq 0) -and ($rebootpending -eq 0)){
                #Server already patched and reboot
                $ServerObj.Status = "Complete"
                Write-Log -Level INFO -Message "$($ServerObj.ServerName) completed."
                Write-Host "$($ServerObj.ServerName) completed." -ForegroundColor Green
                $PendingServers.Remove($ServerObj)
            }
            # EvaluationState - meaning  https://docs.microsoft.com/en-us/sccm/develop/reference/core/clients/sdk/ccm_softwareupdate-client-wmi-class
            #If there is any failed update, install the update again
            if($failedUpdates -gt 1){       
                    try{
                        Write-Log -Level INFO -Message "Retrying failed updates for $($ServerObj.ServerName) - Attempt number: $($ServerObj.Attempts)"
                        $ServerObj.Attempts ++
    	                $MissingUpdatesReformatted = @($TargetedUpdates | ForEach-Object {if($_.EvaluationState -eq 13){[WMI]$_.__PATH}}) 
    	                # The following is the invoke of the CCM_SoftwareUpdatesManager.InstallUpdates with the approved updates 
    	                $InstallReturn = Invoke-WmiMethod -ComputerName $ServerObj.ServerName -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$MissingUpdatesReformatted) -Namespace root\ccm\clientsdk 
                        Write-Log -Level INFO -Message "$InstallReturn"
    	            }
    	            catch{
                        Write-Log -Level ERROR -Message "$($ServerObj.ServerName) failed updates - $fail
                        Downloaded Updates but unable to install them, please check the server"
                        $ServerObj.Status = "Failed"
                        $PendingServers.Remove($ServerObj)
                    }
                    Finally{
                        $failedUpdates = ($MissingUpdatesReformatted).name
                        Write-Log -Level INFO -Message "$($ServerObj.ServerName), Failed Updates:$failedUpdates,  initiated $failedUpdates patches for install."                        
                    }
                }
            #If any update is waiting for install, intall the update.
            if(($approvedUpdates -gt 0) -or ($nonestateupdates -gt 0)){
                #Install Updates
                try{
                    #getting wmi path of updates to install remotely
                    $MissingUpdatesReformatted = @($TargetedUpdates | ForEach-Object {if($_.ComplianceState -eq 0){[WMI]$_.__PATH}}) 
                    #The following is the invoke of the CCM_SoftwareUpdatesManager.InstallUpdates with $MissingUpdatesReformatted updates
                    $InstallReturn = Invoke-WmiMethod -ComputerName $ServerObj.ServerName -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$MissingUpdatesReformatted) -Namespace root\ccm\clientsdk 
                    Write-Log -Level INFO -Message "$($ServerObj.ServerName), Targeted Patches: $approvedUpdates, Pending patches: $pendingpatches, Reboot Pending: $rebootpending, Initiated $pendingpatches patches for install"
                }
                catch{
                    Write-Log -Level INFO -Message "$($ServerObj.ServerName), pending patches - $pendingpatches but unable to install them, please check the server."
                    $ServerObj.Status = "Failed"
                    $PendingServers.Remove($ServerObj)
                }
            }
        }
    }
    if((Get-Date) -gt $StartTime.AddHours("$RunTimeHours")){
        $EndJob = $true
        Write-Log -Level INFO -Message "Run time of $RunTimeHours hour has elasped. Ending session gracefully."
    }
    if(-not $EndJob){
        #Sleep some time between each loop. 
        Write-Log -Level INFO -Message "Waiting 2 minutes to allow installs and reboots before checking again."
        Start-Sleep -Seconds 120
        Write-Host "Sleeping for 2 minutes. Remaining servers: 
        $($PendingServers.ServerName)"
    }
}
until(
    $EndJob -eq $true
)
Write-Log -Level INFO -Message "Patch cycle for $PatchGroup is complete."
$body = $currentlog | Out-String
Send-MailMessage -SmtpServer "smtp.ars.com" -To $To -From "InitiatedPatching@ars.com" -Subject "Log results from patch cycle for $PatchGroup" -Body $body