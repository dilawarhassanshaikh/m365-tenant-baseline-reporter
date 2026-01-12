. $PSScriptRoot/utils/Auth.ps1
. $PSScriptRoot/collectors/Collect-Organization.ps1
. $PSScriptRoot/collectors/Collect-AuthorizationPolicy.ps1
. $PSScriptRoot/collectors/Collect-ConditionalAccess.ps1
. $PSScriptRoot/collectors/Collect-AdminRoles.ps1
. $PSScriptRoot/scoring/Score-Baseline.ps1
. $PSScriptRoot/reporting/New-HtmlReport.ps1
function Get-TBControls {
 Get-Content "$PSScriptRoot\..\controls\controls.json" -Raw | ConvertFrom-Json
}
Export-ModuleMember -Function *-TB*
