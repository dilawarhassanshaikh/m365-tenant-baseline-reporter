#Requires -Version 7.0
#Requires -Modules @{ModuleName='Microsoft.Graph.Authentication';ModuleVersion='2.0.0'},
#                  @{ModuleName='ExchangeOnlineManagement';ModuleVersion='3.0.0'},
#                  @{ModuleName='MicrosoftTeams';ModuleVersion='5.0.0'}

<#
.SYNOPSIS
    M365 Tenant Baseline Reporter — main entry point.

.DESCRIPTION
    Orchestrates all baseline assessment modules across:
      - Microsoft Entra ID (formerly Azure AD)
      - Exchange Online & Defender for Office 365
      - Microsoft Teams & SharePoint Online
      - Microsoft 365 Defender (MDO, MDE posture)

    All data collection uses the Microsoft Graph PowerShell SDK v2+
    and ExchangeOnlineManagement v3+ (REST-based). Legacy MSOnline,
    AzureAD, and MSOL cmdlets are NOT used.

.PARAMETER TenantId
    Azure AD Tenant ID (GUID). Required.

.PARAMETER ClientId
    App Registration Client ID for unattended/app-only auth.
    If omitted, interactive delegated auth is used.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only auth (paired with ClientId).

.PARAMETER OutputPath
    Folder path where HTML/JSON reports will be written.
    Defaults to .\Reports\<timestamp>

.PARAMETER Scopes
    Which baseline areas to assess. Defaults to all.
    Valid values: EntraID, ExchangeOnline, TeamsSharePoint, DefenderOffice365

.PARAMETER ComplianceFramework
    Framework to tag findings against. Valid: CIS, NIST80053, ZeroTrust, NESA
    Defaults to CIS.

.EXAMPLE
    # Interactive auth, all scopes
    .\Invoke-M365BaselineReport.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    # App-only auth, Entra ID + EXO only
    .\Invoke-M365BaselineReport.ps1 -TenantId "..." -ClientId "..." `
        -CertificateThumbprint "..." -Scopes EntraID,ExchangeOnline

.NOTES
    Author : Dilawar Hassan Shaikh
    GitHub : github.com/dilawarhassanshaikh/m365-tenant-baseline-reporter
    Version: 2.0.0
    Updated: 2026-06
    License: MIT
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid]$TenantId,

    [Parameter()]
    [string]$ClientId,

    [Parameter()]
    [string]$CertificateThumbprint,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateSet('EntraID','ExchangeOnline','TeamsSharePoint','DefenderOffice365')]
    [string[]]$Scopes = @('EntraID','ExchangeOnline','TeamsSharePoint','DefenderOffice365'),

    [Parameter()]
    [ValidateSet('CIS','NIST80053','ZeroTrust','NESA')]
    [string]$ComplianceFramework = 'CIS'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Paths ──────────────────────────────────────────────────────────────
$ScriptRoot  = $PSScriptRoot
$Timestamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $OutputPath) {
    $OutputPath = Join-Path $ScriptRoot "Reports\$Timestamp"
}
$null = New-Item -ItemType Directory -Path $OutputPath -Force

$LogFile = Join-Path $OutputPath "baseline-run-$Timestamp.log"
#endregion

#region ── Logging ────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')]$Level = 'INFO')
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    $entry | Tee-Object -FilePath $LogFile -Append | Write-Host -ForegroundColor (
        switch ($Level) { 'WARN' { 'Yellow' }; 'ERROR' { 'Red' }; default { 'Cyan' } }
    )
}
#endregion

#region ── Module check ───────────────────────────────────────────────────────
Write-Log "Checking required modules..."
$RequiredModules = @(
    @{ Name = 'Microsoft.Graph.Authentication';   MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Identity.SignIns';  MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Identity.DirectoryManagement'; MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Groups';            MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Users';             MinVersion = '2.0.0' }
    @{ Name = 'Microsoft.Graph.Security';          MinVersion = '2.0.0' }
    @{ Name = 'ExchangeOnlineManagement';          MinVersion = '3.0.0' }
    @{ Name = 'MicrosoftTeams';                    MinVersion = '5.0.0' }
)

$MissingModules = @()
foreach ($mod in $RequiredModules) {
    $installed = Get-Module -ListAvailable -Name $mod.Name |
        Where-Object { $_.Version -ge [version]$mod.MinVersion } |
        Select-Object -First 1
    if (-not $installed) {
        $MissingModules += "$($mod.Name) >= $($mod.MinVersion)"
    }
}

if ($MissingModules.Count -gt 0) {
    Write-Log "Missing modules:`n  $($MissingModules -join "`n  ")" -Level ERROR
    Write-Log "Run: Install-Module <ModuleName> -Scope CurrentUser -Force" -Level ERROR
    throw "Install missing modules before continuing."
}
Write-Log "All modules verified."
#endregion

#region ── Authentication ─────────────────────────────────────────────────────
Write-Log "Connecting to Microsoft Graph..."

$GraphScopes = @(
    'Policy.Read.All'
    'Directory.Read.All'
    'IdentityRiskyUser.Read.All'
    'PrivilegedAccess.Read.AzureAD'
    'Reports.Read.All'
    'AuditLog.Read.All'
    'SecurityEvents.Read.All'
    'Organization.Read.All'
    'Domain.Read.All'
    'RoleManagement.Read.Directory'
    'UserAuthenticationMethod.Read.All'
    'IdentityProvider.Read.All'
)

try {
    if ($ClientId -and $CertificateThumbprint) {
        Connect-MgGraph -TenantId $TenantId.ToString() `
                        -ClientId $ClientId `
                        -CertificateThumbprint $CertificateThumbprint `
                        -NoWelcome
        Write-Log "Connected via app-only (certificate)."
    } else {
        Connect-MgGraph -TenantId $TenantId.ToString() `
                        -Scopes $GraphScopes `
                        -NoWelcome
        Write-Log "Connected via delegated (interactive)."
    }
} catch {
    Write-Log "Graph connection failed: $_" -Level ERROR
    throw
}

# EXO connection (needed for EXO + Defender scopes)
if ($Scopes -contains 'ExchangeOnline' -or $Scopes -contains 'DefenderOffice365') {
    Write-Log "Connecting to Exchange Online..."
    try {
        if ($ClientId -and $CertificateThumbprint) {
            Connect-ExchangeOnline -AppId $ClientId `
                                   -CertificateThumbprint $CertificateThumbprint `
                                   -Organization ((Get-MgOrganization).VerifiedDomains |
                                       Where-Object IsDefault | Select-Object -ExpandProperty Name) `
                                   -ShowBanner:$false
        } else {
            Connect-ExchangeOnline -ShowBanner:$false
        }
        Write-Log "Connected to Exchange Online."
    } catch {
        Write-Log "EXO connection failed: $_" -Level WARN
    }
}

# Teams connection
if ($Scopes -contains 'TeamsSharePoint') {
    Write-Log "Connecting to Microsoft Teams..."
    try {
        Connect-MicrosoftTeams -TenantId $TenantId.ToString() | Out-Null
        Write-Log "Connected to Microsoft Teams."
    } catch {
        Write-Log "Teams connection failed: $_" -Level WARN
    }
}
#endregion

#region ── Run modules ────────────────────────────────────────────────────────
$AllResults = [System.Collections.Generic.List[PSCustomObject]]::new()

$ModuleMap = @{
    'EntraID'           = 'Get-EntraIDBaseline.ps1'
    'ExchangeOnline'    = 'Get-ExchangeOnlineBaseline.ps1'
    'TeamsSharePoint'   = 'Get-TeamsSharePointBaseline.ps1'
    'DefenderOffice365' = 'Get-DefenderO365Baseline.ps1'
}

foreach ($scope in $Scopes) {
    $modulePath = Join-Path $ScriptRoot $ModuleMap[$scope]
    if (Test-Path $modulePath) {
        Write-Log "Running $scope baseline assessment..."
        try {
            $results = & $modulePath -OutputPath $OutputPath -ComplianceFramework $ComplianceFramework
            $AllResults.AddRange([PSCustomObject[]]$results)
            Write-Log "$scope: $($results.Count) checks completed."
        } catch {
            Write-Log "$scope assessment error: $_" -Level ERROR
        }
    } else {
        Write-Log "Module not found: $modulePath" -Level WARN
    }
}
#endregion

#region ── Generate consolidated report ──────────────────────────────────────
Write-Log "Generating consolidated HTML report..."
$reportScript = Join-Path $ScriptRoot 'New-BaselineHtmlReport.ps1'
if (Test-Path $reportScript) {
    & $reportScript -Results $AllResults `
                    -OutputPath $OutputPath `
                    -TenantId $TenantId `
                    -Framework $ComplianceFramework
}

# Export raw JSON
$jsonPath = Join-Path $OutputPath "baseline-results-$Timestamp.json"
$AllResults | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
Write-Log "JSON results: $jsonPath"
#endregion

#region ── Disconnect ─────────────────────────────────────────────────────────
Write-Log "Disconnecting sessions..."
try { Disconnect-MgGraph | Out-Null } catch {}
try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch {}
try { Disconnect-MicrosoftTeams | Out-Null } catch {}

Write-Log "Baseline report complete. Output: $OutputPath"
Write-Output $AllResults
#endregion
