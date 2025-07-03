<#PSScriptInfo

.VERSION 0.2
.GUID 1866ffe4-3800-4166-aaee-9b485b2cc051
.AUTHOR Nick Benton
.COMPANYNAME
.COPYRIGHT GPL
.TAGS Graph Intune Windows Autopilot GroupTags
.LICENSEURI https://github.com/ennnbeee/IntuneDeviceCleaner/blob/main/LICENSE
.PROJECTURI https://github.com/ennnbeee/IntuneDeviceCleaner
.ICONURI https://raw.githubusercontent.com/ennnbeee/IntuneDeviceCleaner/refs/heads/main/img/idc-icon.png
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
v0.1 - Initial release
v0.2 - Option to clean Entra objects, capture of BitLocker and FileVault recovery keys

.PRIVATEDATA
#>

<#
.SYNOPSIS
IntuneDeviceCleaner

.DESCRIPTION
IntuneDeviceCleaner

.PARAMETER deviceCheckInDays
Number of days since last device check-in to consider a device stale.

.PARAMETER entraObject
Option to disable, delete or ignore the Entra ID object of the device. Valid values are 'disable', 'delete', 'ignore'. Default is 'ignore'.

.PARAMETER operatingSystem
The operating system of the devices to filter by. Valid values are 'windows', 'ios', 'android', 'macos', 'linux'.

.PARAMETER ownershipType
The ownership type of the devices to filter by. Valid values are 'company', 'personal'.

.PARAMETER enrolmentType
The enrolment type of the devices to filter by. Valid values are 'windowsCoManagement', 'mdm'.

.PARAMETER joinType
The Entra Join Type of the devices to filter by. Valid values are 'azureADJoined', 'hybridAzureADJoined', 'azureADRegistered'.

.PARAMETER whatIf
Boolean; to enable WhatIf mode to simulate changes.

.PARAMETER tenantId
Provide the Id of the Entra ID tenant to connect to.

.PARAMETER appId
Provide the Id of the Entra App registration to be used for authentication.

.PARAMETER appSecret
Provide the App secret to allow for authentication to graph

.EXAMPLE
Interactive Authentication
.\IntuneDeviceCleaner.ps1

.NOTES
Version:        0.2
Author:         Nick Benton
WWW:            oddsandendpoints.co.uk
Creation Date:  03/07/2025
#>

[CmdletBinding(DefaultParameterSetName = 'Default')]

param(

    [Parameter(Mandatory = $true, HelpMessage = 'Number of days since last device check-in to consider a device stale')]
    [ValidateRange(1, 730)]
    [int]$deviceCheckInDays,

    [Parameter(Mandatory = $false, HelpMessage = 'Option to disable, delete or ignore the Entra ID object of the device')]
    [ValidateSet('disable', 'delete', 'ignore')]
    [string]$entraObject = 'ignore',

    [Parameter(Mandatory = $false, HelpMessage = 'The operating system of the devices to filter by')]
    [ValidateSet('windows', 'ios', 'android', 'macos', 'linux')]
    [string]$operatingSystem,

    [Parameter(Mandatory = $false, HelpMessage = 'The ownership type of the devices to filter by')]
    [ValidateSet('company', 'personal')]
    [string]$ownershipType,

    [Parameter(Mandatory = $false, HelpMessage = 'The enrolment type of the devices to filter by')]
    [ValidateSet('windowsCoManagement', 'mdm')]
    [string]$enrolmentType,

    [Parameter(Mandatory = $false, HelpMessage = 'The Entra Join Type of the devices to filter by')]
    [ValidateSet('azureADJoined', 'hybridAzureADJoined', 'azureADRegistered')]
    [string]$joinType,

    [Parameter(Mandatory = $false, HelpMessage = 'Provide the Id of the Entra ID tenant to connect to')]
    [ValidateLength(36, 36)]
    [String]$tenantId,

    [Parameter(Mandatory = $false, ParameterSetName = 'appAuth', HelpMessage = 'Provide the Id of the Entra App registration to be used for authentication')]
    [ValidateLength(36, 36)]
    [String]$appId,

    [Parameter(Mandatory = $true, ParameterSetName = 'appAuth', HelpMessage = 'Provide the App secret to allow for authentication to graph')]
    [ValidateNotNullOrEmpty()]
    [String]$appSecret,

    [Parameter(Mandatory = $false, HelpMessage = 'WhatIf mode to simulate changes')]
    [boolean]$whatIf

)

#region Functions
function Test-JSONData() {

    param (
        $JSON
    )

    try {
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $TestJSON | Out-Null
        $validJson = $true
    }
    catch {
        $validJson = $false
        $_.Exception
    }
    if (!$validJson) {
        Write-Host "Provided JSON isn't in valid JSON format" -f Red
        break
    }

}
function Connect-ToGraph {
    <#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Authentication module.

.DESCRIPTION
The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.

.PARAMETER TenantId
Specifies the tenantId from Entra ID to which to authenticate.

.PARAMETER AppId
Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.

.PARAMETER AppSecret
Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.

.PARAMETER Scopes
Specifies the user scopes for interactive authentication.

.EXAMPLE
Connect-ToGraph -tenantId $tenantId -appId $app -appSecret $secret

-#>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)] [string]$tenantId,
        [Parameter(Mandatory = $false)] [string]$appId,
        [Parameter(Mandatory = $false)] [string]$appSecret,
        [Parameter(Mandatory = $false)] [string[]]$scopes
    )

    process {
        Import-Module Microsoft.Graph.Authentication
        $version = (Get-Module microsoft.graph.authentication | Select-Object -ExpandProperty Version).major

        if ($AppId -ne '') {
            $body = @{
                grant_type    = 'client_credentials';
                client_id     = $appId;
                client_secret = $appSecret;
                scope         = 'https://graph.microsoft.com/.default';
            }

            $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body
            $accessToken = $response.access_token

            if ($version -eq 2) {
                Write-Host 'Version 2 module detected'
                $accessTokenFinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
            }
            else {
                Write-Host 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
                $accessTokenFinal = $accessToken
            }
            $graph = Connect-MgGraph -AccessToken $accessTokenFinal
            Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
        }
        else {
            if ($version -eq 2) {
                Write-Host 'Version 2 module detected'
            }
            else {
                Write-Host 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
            }
            $graph = Connect-MgGraph -Scopes $scopes -TenantId $tenantId
            Write-Host "Connected to Intune tenant $($graph.TenantId)"
        }
    }
}
function Get-StaleManagedDevice() {

    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateRange(1, 730)]
        [int]$days
    )

    $dateTime = (Get-Date).AddDays(-$days).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $graphApiVersion = 'beta'
    $Resource = "deviceManagement/managedDevices?`$filter=(((managementAgent%20eq%20%27mdm%27)%20or%20(managementAgent%20eq%20%27configurationManagerClientMdm%27)%20or%20(managementAgent%20eq%20%27easMdm%27)%20or%20(managementAgent%20eq%20%27configurationManagerClientMdmEas%27)%20or%20(managementAgent%20eq%20%27googleCloudDevicePolicyController%27)%20or%20(managementAgent%20eq%20%27intuneAosp%27))%20and%20(lastSyncDateTime%20lt%20$dateTime))&`$top=500"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $graphResults = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject

        $results = @()
        $results += $graphResults.value

        $pages = $graphResults.'@odata.nextLink'
        while ($null -ne $pages) {

            $additional = Invoke-MgGraphRequest -Uri $pages -Method Get

            if ($pages) {
                $pages = $additional.'@odata.nextLink'
            }
            $results += $additional.value
        }
        $results
    }
    catch {
        Write-Error $Error[0].ErrorDetails.Message
        break
    }
}
function Set-StaleManagedDevice() {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$id
    )


    $graphApiVersion = 'beta'
    $Resource = "deviceManagement/managedDevices('$id')/retire"

    if ($PSCmdlet.ShouldProcess('Retiring Intune managed device')) {
        try {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
            Invoke-MgGraphRequest -Uri $uri -Method Post

        }
        catch {
            Write-Error $Error[0].ErrorDetails.Message
            break
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output 'Intune managed device would be retired'
    }
    else {
        Write-Output 'Intune managed device was not retired'
    }

}
function Get-EntraIDObject() {

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param
    (

        [parameter(Mandatory = $true)]
        [ValidateSet('user', 'device')]
        [string]$object

    )

    $graphApiVersion = 'beta'
    if ($object -eq 'user') {
        $Resource = "users?`$filter=userType eq 'member' and accountEnabled eq true"
    }
    else {
        $Resource = 'devices'
    }

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $graphResults = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject

        $results = @()
        $results += $graphResults.value

        $pages = $graphResults.'@odata.nextLink'
        while ($null -ne $pages) {

            $additional = Invoke-MgGraphRequest -Uri $pages -Method Get -OutputType PSObject

            if ($pages) {
                $pages = $additional.'@odata.nextLink'
            }
            $results += $additional.value
        }

        $results
    }
    catch {
        Write-Error $Error[0].ErrorDetails.Message
        break
    }
}
function Set-EntraIDObject() {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]
    param
    (
        [parameter(Mandatory = $true)]
        $Id,

        [parameter(Mandatory = $true)]
        [ValidateSet('disable', 'delete')]
        $action
    )

    $graphApiVersion = 'Beta'
    $Resource = "devices/$Id"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

    if ($PSCmdlet.ShouldProcess('Disabling or deleting Entra ID object')) {
        try {
            if ($action -eq 'disable') {
                $JSON = @'
        {
            "accountEnabled": false
        }
'@
                Test-JSONData -Json $JSON
                Invoke-MgGraphRequest -Uri $uri -Method Patch -Body $JSON -ContentType 'application/json'
            }
            else {
                Invoke-MgGraphRequest -Uri $uri -Method DELETE
            }
        }
        catch {
            Write-Error $_.Exception.Message
            break
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output 'Entra ID object would be disabled or deleted'
    }
    else {
        Write-Output 'Entra ID object was not disabled or deleted'
    }

}
function Get-RecoveryKey() {

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param
    (

        [parameter(Mandatory = $true)]
        $Id,

        [parameter(Mandatory = $true)]
        [ValidateSet('windows', 'macos')]
        $os
    )

    try {
        $recoveryKeys = @()
        $graphApiVersion = 'beta'
        if ($os -eq 'windows') {
            $Resource = "informationProtection/bitlocker/recoveryKeys?`$filter=deviceId%20eq%20%27$Id%27"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
            $keyObjects = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value

            foreach ($keyObject in $keyObjects) {
                $keyResource = "informationProtection/bitlocker/recoveryKeys/$($keyObject.id)?`$select=key"
                $keyUri = "https://graph.microsoft.com/$graphApiVersion/$keyResource "
                $recoveryKeys += (Invoke-MgGraphRequest -Uri $keyUri -Method Get -OutputType PSObject).key
            }
        }
        else {
            $Resource = "deviceManagement/managedDevices('$id')/getFileVaultKey"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
            $recoveryKeys += (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value

        }
        return $recoveryKeys
    }
    catch {
        Write-Host "No recovery keys for device ID $Id." -ForegroundColor Yellow
    }

}
#endregion Functions

#region intro
Write-Host '
 _______         __
|_     _|.-----.|  |_.--.--.-----.-----.
 _|   |_ |     ||   _|  |  |     |  -__|
|_______||__|__||____|_____|__|__|_____|
' -ForegroundColor Cyan
Write-Host '
 _____               __              ______ __
|     \.-----.--.--.|__|.----.-----.|      |  |.-----.---.-.-----.-----.----.
|  --  |  -__|  |  ||  ||  __|  -__||   ---|  ||  -__|  _  |     |  -__|   _|
|_____/|_____|\___/ |__||____|_____||______|__||_____|___._|__|__|_____|__|
' -ForegroundColor Green

Write-Host 'IntuneDeviceCleaner - Removal of stale devices based on additional criteria' -ForegroundColor Green
Write-Host 'Nick Benton - oddsandendpoints.co.uk' -NoNewline;
Write-Host ' | Version' -NoNewline; Write-Host ' 0.2 Public Preview' -ForegroundColor Yellow -NoNewline
Write-Host ' | Last updated: ' -NoNewline; Write-Host '2025-07-03' -ForegroundColor Magenta
Write-Host ''
Write-Host 'If you have any feedback, please open an issue at https://github.com/ennnbeee/AutopilotGroupTagger/issues' -ForegroundColor Cyan
Write-Host ''
if ($whatIf -eq $true) {
    Write-Host "Starting the 'IntuneDeviceCleaner' Script in whatIf mode" -ForegroundColor Cyan
}
else {
    Write-Host "Starting the 'IntuneDeviceCleaner' Script in production mode" -ForegroundColor Red
}
Write-Host ''
#endregion intro

#region testing
<# For testing purposes, uncomment the following lines and set the parameters as needed.
$deviceCheckInDays = 1
$operatingSystem = 'android'
$ownershipType = 'company'
$joinType = ''
$enrolmentType = 'mdm'
$whatIf = $true
#>
#endregion testing

#region variables
$rndWait = Get-Random -Minimum 1 -Maximum 3
$requiredScopes = @('DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All', 'Device.ReadWrite.All', 'BitlockerKey.Read.All')
[String[]]$scopes = $requiredScopes -join ', '
#endregion variables

#region module check
if (!$IsMacOS -and !$IsLinux) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $elevatedStatus = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

$modules = @('Microsoft.Graph.Authentication')
foreach ($module in $modules) {
    Write-Host "Checking for $module PowerShell module..." -ForegroundColor Cyan
    Write-Host ''
    if (!(Get-Module -Name $module -ListAvailable)) {
        if ($elevatedStatus -eq $true) {
            Write-Host "PowerShell Module $module not found, installing for all users." -ForegroundColor Yellow
            Write-Host ''
            Install-Module -Name $module -AllowClobber
        }

        else {
            Write-Host "PowerShell Module $module not found, installing for current user." -ForegroundColor Yellow
            Write-Host ''
            Install-Module -Name $module -Scope CurrentUser -AllowClobber
        }

    }
    Write-Host "PowerShell Module $module found." -ForegroundColor Green
    Write-Host ''
    Import-Module -Name $module -Force
}
#endregion module check

#region app auth
try {
    if (!$tenantId) {
        Write-Host 'Connecting using interactive authentication' -ForegroundColor Yellow
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
    }
    else {
        if ((!$appId -and !$appSecret) -or ($appId -and !$appSecret) -or (!$appId -and $appSecret)) {
            Write-Host 'Missing App Details, connecting using user authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -Scopes $scopes -ErrorAction Stop
        }
        else {
            Write-Host 'Connecting using App authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -appId $appId -appSecret $appSecret -ErrorAction Stop
        }
    }
    $context = Get-MgContext
    Write-Host ''
    Write-Host "Successfully connected to Microsoft Graph tenant with ID $($context.TenantId)." -ForegroundColor Green
}
catch {
    Write-Error $_.Exception.Message
    exit
}
#endregion app auth

#region scopes
$currentScopes = $context.Scopes
# Validate required permissions
$missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
if ($missingScopes.Count -gt 0) {
    Write-Host 'WARNING: The following scope permissions are missing:' -ForegroundColor Red
    $missingScopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ''
    Write-Host 'Please ensure these permissions are granted to the app registration for full functionality.' -ForegroundColor Yellow
    exit
}
Write-Host ''
Write-Host 'All required scope permissions are present.' -ForegroundColor Green
#endregion scopes

#region Entra devices
Write-Host 'Getting Entra device objects...' -ForegroundColor Cyan
$entraDevices = Get-EntraIDObject -object device
Write-Host "Found $($entraDevices.Count) devices from Entra ID." -ForegroundColor Green
if ($entraDevices.Count -eq 0) {
    Write-Host 'Found no Windows devices in Entra.' -ForegroundColor Red
    break
}
Write-Host ''
#optimising the entra device data
$optEntraDevices = @{}
foreach ($itemEntraDevice in $entraDevices) {
    $optEntraDevices[$itemEntraDevice.deviceid] = $itemEntraDevice
}
#endregion Entra devices

#region stale devices
Write-Host "Checking for stale devices that haven't checked in for $deviceCheckInDays days..." -ForegroundColor Cyan
$allStaleDevices = Get-StaleManagedDevice -days $deviceCheckInDays
Write-Host "Found $($allStaleDevices.Count) stale devices that haven't checked in for $deviceCheckInDays days." -ForegroundColor Green
Write-Host
#endregion stale devices

#region device filtering
#OS
$filteredStaleDevicesOS = @()
if ($operatingSystem) {
    Write-Host "Filtering stale devices by operating system: $operatingSystem" -ForegroundColor Cyan
    $filteredStaleDevicesOS += $allStaleDevices | Where-Object { $_.operatingSystem -like "*$operatingSystem*" }
    Write-Host "Found $($filteredStaleDevicesOS.Count) stale devices with operating system: $operatingSystem" -ForegroundColor Green
    Write-Host ''
}
else {
    $filteredStaleDevicesOS += $allStaleDevices | Where-Object { $_.operatingSystem -like "*$operatingSystem*" }
}

#ownership
$filteredStaleDevicesOwnership = @()
if ($ownershipType) {
    Write-Host "Filtering stale devices by ownership: $ownershipType" -ForegroundColor Cyan
    $filteredStaleDevicesOwnership += $filteredStaleDevicesOS | Where-Object { $_.ownerType -like "*$ownershipType*" }
    Write-Host "Found $($filteredStaleDevicesOwnership.Count) stale devices with ownership: $ownershipType" -ForegroundColor Green
    Write-Host ''
}
else {
    $filteredStaleDevicesOwnership += $filteredStaleDevicesOS | Where-Object { $_.ownerType -like "*$ownershipType*" }
}

#enrolment
$filteredStaleDevicesEnrolment = @()
if ($enrolmentType) {
    Write-Host "Filtering stale devices by enrolment: $enrolmentType" -ForegroundColor Cyan
    $filteredStaleDevicesEnrolment += $filteredStaleDevicesOwnership | Where-Object { $_.managementAgent -like "*$enrolmentType*" }
    Write-Host "Found $($filteredStaleDevicesEnrolment.Count) stale devices with enrolment: $enrolmentType" -ForegroundColor Green
    Write-Host ''
}
else {
    $filteredStaleDevicesEnrolment += $filteredStaleDevicesOwnership | Where-Object { $_.managementAgent -like "*$enrolmentType*" }
}

#joinType
$filteredStaleDevicesJoin = @()
if ($joinType) {
    Write-Host "Filtering stale devices by Entra Join Type: $joinType" -ForegroundColor Cyan
    $filteredStaleDevicesJoin += $filteredStaleDevicesEnrolment | Where-Object { $_.deviceEnrollmentType -like "*$joinType*" }
    Write-Host "Found $($filteredStaleDevicesJoin.Count) stale devices with Entra Join Type: $joinType" -ForegroundColor Green
    Write-Host ''
}
else {
    $filteredStaleDevicesJoin += $filteredStaleDevicesEnrolment | Where-Object { $_.deviceEnrollmentType -like "*$joinType*" }
}

#final filter
$filteredStaleDevices = @()
$filteredStaleDevices += $filteredStaleDevicesJoin
if ($filteredStaleDevices.Count -eq 0) {
    Write-Host 'No stale devices found matching the specified criteria.' -ForegroundColor Yellow
    Write-Host 'Please review the filters you have selected and try again.' -ForegroundColor Yellow
    exit
}
else {
    Write-Host "Total stale devices after filtering: $($filteredStaleDevices.Count)" -ForegroundColor Green
    Write-Host ''
    if ($whatIf -eq $true) {
        Write-Host 'WhatIf mode is enabled the following devices would be retired.' -ForegroundColor Magenta
    }
    else {
        Write-Host 'The following devices will be retired:' -ForegroundColor Cyan
    }
    $filteredStaleDevices | ForEach-Object {
        Write-Host "$($_.deviceName), ID: $($_.id), Last Check-in: $($_.lastSyncDateTime)" -ForegroundColor white
    }
    Write-Host ''
    Write-Warning 'Please review the devices above before proceeding with retirement.' -WarningAction Inquire
}
#endregion device filtering

#region device retirement
$staleDeviceDetails = @()
foreach ($filteredStaleDevice in $filteredStaleDevices) {
    Start-Sleep -Seconds $rndWait
    Write-Host "Processing stale device: $($filteredStaleDevice.deviceName) (ID: $($filteredStaleDevice.id))" -ForegroundColor Cyan

    $deviceObject = $optEntraDevices[$filteredStaleDevice.azureADDeviceId]
    Write-Host "Getting device details from Entra ID for device $($filteredStaleDevice.deviceName) (ID: $($filteredStaleDevice.id))..." -ForegroundColor White
    if ($filteredStaleDevice.operatingSystem -like '*windows*' -or $filteredStaleDevice.operatingSystem -like '*mac*') {
        Write-Host "Retrieving recovery keys for device $($filteredStaleDevice.deviceName) (ID: $($filteredStaleDevice.id))..." -ForegroundColor Cyan
        if ($filteredStaleDevice.operatingSystem -like '*windows*') {
            $keys = Get-RecoveryKey -Id $($deviceObject.deviceId) -os windows
        }
        else {
            $keys = Get-RecoveryKey -Id $($deviceObject.deviceId) -os macos
        }
        $staleDeviceDetails += [PSCustomObject]@{
            name            = $($filteredStaleDevice.deviceName)
            intuneId        = $($filteredStaleDevice.id)
            entraId         = $($deviceObject.Id)
            ownership       = $($filteredStaleDevice.ownerType)
            lastCheckIn     = $($filteredStaleDevice.lastSyncDateTime)
            osVersion       = $($filteredStaleDevice.osVersion)
            userPrincipal   = $($filteredStaleDevice.userPrincipalName)
            userDisplayName = $($filteredStaleDevice.userDisplayName)
            Keys            = [string]$keys
        }
    }
    else {
        $staleDeviceDetails += [PSCustomObject]@{
            name            = $($filteredStaleDevice.deviceName)
            intuneId        = $($filteredStaleDevice.id)
            entraId         = $($deviceObject.Id)
            ownership       = $($filteredStaleDevice.ownerType)
            lastCheckIn     = $($filteredStaleDevice.lastSyncDateTime)
            osVersion       = $($filteredStaleDevice.osVersion)
            userPrincipal   = $($filteredStaleDevice.userPrincipalName)
            userDisplayName = $($filteredStaleDevice.userDisplayName)
            Keys            = $null
        }
    }

    if ($whatIf -eq $true) {
        Write-Host "WhatIf mode enabled: Device $($filteredStaleDevice.deviceName) (ID: $($filteredStaleDevice.id)) would be retired." -ForegroundColor Magenta
    }
    else {
        Set-StaleManagedDevice -id $filteredStaleDevice.id
        Write-Host "Device $($filteredStaleDevice.deviceName) (ID: $($filteredStaleDevice.id)) has been retired." -ForegroundColor Green
    }

    #region Entra ID Object
    if ($entraObject -eq 'disable') {
        if ($whatIf -eq $true) {
            Write-Host "WhatIf mode enabled: Entra ID object for device $($filteredStaleDevice.deviceName) (ID: $($deviceObject.Id) would be disabled." -ForegroundColor Magenta
        }
        else {
            Set-EntraIDObject -Id $deviceObject.Id -Action disable
            Write-Host "Entra ID object for device $($filteredStaleDevice.deviceName) (ID: $($deviceObject.Id) has been disabled." -ForegroundColor Green
        }

    }
    elseif ($entraObject -eq 'delete') {
        if ($whatIf -eq $true) {
            Write-Host "WhatIf mode enabled: Entra ID object for device $($filteredStaleDevice.deviceName) (ID: $($deviceObject.Id) would be deleted." -ForegroundColor Magenta
        }
        else {
            #autopilot devices
            if (([string]::IsNullOrEmpty($deviceObject.physicalIds))) {
                Write-Host "Entra ID object for device $($filteredStaleDevice.deviceName) (ID: $($deviceObject.Id) is an Autopilot device and cannot be deleted." -ForegroundColor Yellow
            }
            else {
                Set-EntraIDObject -Id $deviceObject.Id -Action delete
                Write-Host "Entra ID object for device $($filteredStaleDevice.deviceName) (ID: $($deviceObject.Id) has been deleted." -ForegroundColor Green
            }
        }
    }
    else {
        Write-Host "Entra ID object for device $($filteredStaleDevice.deviceName) (ID: $($deviceObject.Id) will be ignored." -ForegroundColor Green
    }
    #endregion Entra ID Object
    Write-Host ''
}
$csv = "IntuneDeviceCleaner-$(Get-Date -Format yyyy-MM-dd).csv"
$staleDeviceDetails | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
Write-Host "Stale device details have been saved to $csv." -ForegroundColor Green
#endregion device retirement