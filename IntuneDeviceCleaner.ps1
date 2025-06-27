<#PSScriptInfo

.VERSION 0.1
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

.PRIVATEDATA
#>

<#
.SYNOPSIS
IntuneDeviceCleaner

.DESCRIPTION
IntuneDeviceCleaner

.PARAMETER whatIf
Switch to enable WhatIf mode to simulate changes.

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
Version:        0.1
Author:         Nick Benton
WWW:            oddsandendpoints.co.uk
Creation Date:  27/09/2025
#>

[CmdletBinding(DefaultParameterSetName = 'Default')]

param(

    [Parameter(Mandatory = $false, HelpMessage = '')]
    [ValidateRange(30, 270)]
    [int]$deviceCheckInDays,

    [Parameter(Mandatory = $false, HelpMessage = '')]
    [ValidateSet('windows', 'ios', 'android', 'macos', 'linux')]
    [string]$operatingSystem,

    [Parameter(Mandatory = $false, HelpMessage = '')]
    [ValidateSet('company', 'personal')]
    [string]$ownershipType,

    [Parameter(Mandatory = $false, HelpMessage = '')]
    [ValidateSet('windowsCoManagement', 'mdm')]
    [string]$enrolmentType,

    [Parameter(Mandatory = $false, HelpMessage = '')]
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
    [switch]$whatIf

)

#region Functions
Function Test-JSON {

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
        Write-Host "Provided JSON isn't in valid JSON format" -ForegroundColor Red
        break
    }

}
Function Connect-ToGraph {
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

    Process {
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
Function Get-StaleManagedDevice() {

    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateRange(30, 270)]
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



Function Set-StaleManagedDevice() {

    [cmdletbinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [string]$id
    )


    $graphApiVersion = 'beta'
    $Resource = "deviceManagement/managedDevices('$id')/retire"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        Invoke-MgGraphRequest -Uri $uri -Method Post

    }
    catch {
        Write-Error $Error[0].ErrorDetails.Message
        break
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
Write-Host ' | Version' -NoNewline; Write-Host ' 0.1 Public Preview' -ForegroundColor Yellow -NoNewline
Write-Host ' | Last updated: ' -NoNewline; Write-Host '2025-06-27' -ForegroundColor Magenta
Write-Host ''
Write-Host 'If you have any feedback, please open an issue at https://github.com/ennnbeee/AutopilotGroupTagger/issues' -ForegroundColor Cyan
Write-Host ''
#endregion intro

#region testing
$deviceCheckInDays = 90
$operatingSystem = 'windows'
$ownershipType = 'company'
#endregion testing

#region variables
$requiredScopes = @('Device.ReadWrite.All', 'DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All','DeviceManagementManagedDevices.PrivilegedOperations.All')
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
    If (!(Get-Module -Name $module -ListAvailable)) {
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
    Exit
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



$filteredStaleDevices = @()
$allStaleDevices = Get-StaleManagedDevice -days $deviceCheckInDays

$filteredStaleDevicesOS = @()
if ($operatingSystem) {
    Write-Host "Filtering stale devices by operating system: $operatingSystem" -ForegroundColor Cyan
    $filteredStaleDevicesOS += $allStaleDevices | Where-Object { $_.operatingSystem -like "*$operatingSystem*" }
    if ($filteredStaleDevicesOS.Count -eq 0) {
        Write-Host "No stale devices found with operating system: $operatingSystem" -ForegroundColor Yellow
    }
    else {
        Write-Host "Found $($filteredStaleDevicesOS.Count) stale devices with operating system: $operatingSystem" -ForegroundColor Green
    }
}
$filteredStaleDevices += $filteredStaleDevicesOS


foreach ($filteredStaleDevice in $filteredStaleDevices) {
    Set-StaleManagedDevice -id $filteredStaleDevice.id
}

