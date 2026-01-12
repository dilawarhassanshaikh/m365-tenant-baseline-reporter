param(
 [string]$OutputPath = "./out",
 [string]$ReportName = "TenantBaseline"
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module (Join-Path $PSScriptRoot "..\src\TenantBaseline.psm1") -Force
Write-Host "Starting M365 Tenant Baseline (Graph-only)"
Connect-TBGraph
$findings = [ordered]@{
 organization        = Collect-TBOrganization
 authorizationPolicy = Collect-TBAuthorizationPolicy
 conditionalAccess   = Collect-TBConditionalAccess
 adminRoles          = Collect-TBAdminRoles
}
$controls = Get-TBControls
$result = Score-TBBaseline -Controls $controls -Findings $findings
if (!(Test-Path $OutputPath)) {
 New-Item -ItemType Directory -Path $OutputPath | Out-Null
}
$result | ConvertTo-Json -Depth 6 | Set-Content "$OutputPath\$ReportName.json"
New-TBHtmlReport -Path "$OutputPath\$ReportName.html" -Result $result
Write-Host "Baseline completed"
