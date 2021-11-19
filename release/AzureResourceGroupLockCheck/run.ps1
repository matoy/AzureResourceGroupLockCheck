using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

#####
#
# TT 20211020 AzureResourceGroupLockCheck
# This script is executed by an Azure Function App
# It checks if some resource groups in a specific subscription don't have a
# delete lock
# It can be triggered by any monitoring system to get the results and status
#
# "subscriptionid" GET parameter allows to specify the subscription to check
#
# "exclusion" GET parameter can be passed with comma separated resource groups
# names that should be excluded from the check
#
# "readonly" GET parameter can be passed with comma separated resource groups
# names that should have a read only lock instead of the delete lock (default)
#
# used AAD credentials read access to the specified subscription
#
# API ref:
# https://docs.microsoft.com/fr-fr/rest/api/resources/resource-groups/list
# https://docs.microsoft.com/fr-fr/rest/api/resources/management-locks/list-at-resource-group-level
#
#####

$exclusion = [string] $Request.Query.exclusion
if (-not $exclusion) {
    $exclusion = ""
}

$readonly = [string] $Request.Query.readonly
if (-not $readonly) {
    $readonly = ""
}

$subscriptionid = [string] $Request.Query.Subscriptionid
if (-not $subscriptionid) {
    $subscriptionid = "00000000-0000-0000-0000-000000000000"
}

# init variables
$alert = 0
$body = ""
$signature = $env:Signature
$maxConcurrentJobs = [int] $env:MaxConcurrentJobs
[System.Collections.ArrayList] $exclusionsTab = $exclusion.split(",")
$readonlysTab = $readonly.split(",")
foreach ($current in ($env:AzureResourceGroupLockGlobalExceptions).split(",")) {
	$exclusionsTab.Add($current)
}
# connect with SPN account creds
$tenantId = $env:TenantId
$applicationId = $env:AzureResourceGroupLockCheckApplicationID
$password = $env:AzureResourceGroupLockCheckSecret
$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $applicationId, $securePassword
Connect-AzAccount -Credential $credential -Tenant $tenantId -ServicePrincipal

# get token
$azContext = Get-AzContext
$azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
$token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)

# create http headers
$headers = @{}
$headers.Add("Authorization", "bearer " + "$($Token.Accesstoken)")
$headers.Add("contenttype", "application/json")

$uri = "https://management.azure.com/subscriptions/$subscriptionid/resourcegroups?api-version=2021-04-01"
$rgs = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers).value

# if many resource groups, too long execution would cause an http timeout from 
# the monitoring system calling the function
# multithreading is required to avoid long execution time if many resource groups
if ($rgs.count -lt $maxConcurrentJobs) {
	$MaxRunspaces = $rgs.count
}
else {
	$MaxRunspaces = $maxConcurrentJobs
}
$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxRunspaces)
$RunspacePool.Open()
$Jobs = New-Object System.Collections.ArrayList
foreach ($rg in $rgs) {
	$PowerShell = [powershell]::Create()
	$PowerShell.RunspacePool = $RunspacePool
	[void]$PowerShell.AddScript({
	    Param ($headers, $subscriptionid, $rg, $exclusionsTab, $readonlysTab)

		$out = ""
		$deleteLock = $false
		$readonlyLock = $false
		$uri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$($rg.name)/providers/Microsoft.Authorization/locks?api-version=2016-09-01"
		$locks = (Invoke-RestMethod -Method Get -Uri $uri -Headers $headers).value

		foreach ($lock in $locks) {
			#checks the scope level ; continue if not at rg level
			$scope = $locks.id.split("/")
			if ($scope[6] -ne "Microsoft.Authorization") {
				continue 
			}
			
			if ($lock.properties.level -eq "CanNotDelete") {
				$deleteLock = $true
			}
			if ($lock.properties.level -eq "ReadOnly") {
				$readonlyLock = $true
			}
		}
		if ($exclusionsTab -contains $rg.name) {
			$state = ""
			if ($deleteLock -eq $true) { $state = " (delete lock is present)" }
			if ($readonlyLock -eq $true) { $state = " (readonly lock is present)" }
			$out += "OK - $($rg.Name): resource group excluded from lock check$state"
		}
		elseif ($readonlysTab -contains $rg.name -and $readonlyLock -ne $true) {
			$state = ""
			if ($deleteLock -eq $true) { $state = " (only delete lock is present)" }
			$out += "CRITICAL - $($rg.Name): resource group should have a readonly lock check$state"
		}
		elseif ($deleteLock -eq $false -and $readonlyLock -eq $false) {
			$out += "CRITICAL - $($rg.Name): resource group has no lock check"
		}
		else {
			$state = ""
			if ($readonlyLock -eq $true) { $state = " (readonly lock is present)" }
			$out += "OK - $($rg.Name): resource group is locked$state"
		}
		echo $out
	}).AddArgument($headers).AddArgument($subscriptionid).AddArgument($rg).AddArgument($exclusionsTab).AddArgument($readonlysTab)
	
	$JobObj = New-Object -TypeName PSObject -Property @{
		Runspace = $PowerShell.BeginInvoke()
		PowerShell = $PowerShell  
    }
    $Jobs.Add($JobObj) | Out-Null
}
while ($Jobs.Runspace.IsCompleted -contains $false) {
	$running = ($Jobs.Runspace | where {$_.IsCompleted -eq $false}).count
    Write-Host (Get-date).Tostring() "Still $running jobs running..."
	Start-Sleep 1
}
foreach ($job in $Jobs) {
	$current = $job.PowerShell.EndInvoke($job.Runspace)
	$job.PowerShell.Dispose()
	if ($current -match "CRITICAL") {
		$alert++
		$body = $current + "`n" + $body
	}
	else {
		$body += $current + "`n"
	}
}
if ($rgs.count -eq 0) {
	$alert++
	$body += "No resource group or missing permission on subscription id: $subscriptionid`n"
}
# add ending status and signature to results
$body += "`n$signature`n"
if ($alert) {
    $body = "Status CRITICAL - Missing/incorrect lock on $alert/$($rgs.count) resource group(s)!`n" + $body
}
else {
    $body = "Status OK - No alert on any $($rgs.count) resource group(s)`n" + $body
}
Write-Host $body

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $body
})
