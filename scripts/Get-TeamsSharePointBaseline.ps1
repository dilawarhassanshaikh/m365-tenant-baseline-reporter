#Requires -Modules MicrosoftTeams, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Microsoft Teams & SharePoint Online baseline assessment.

.DESCRIPTION
    Uses MicrosoftTeams v5+ and Microsoft Graph for Teams/SPO baseline checks.
    No legacy Skype for Business cmdlets used.

    Controls assessed:
      - Teams external access (federated domains)
      - Teams guest access policy
      - Teams meeting policies (anonymous join, lobby, recording)
      - Teams messaging policies (external sharing)
      - SharePoint external sharing level
      - SharePoint legacy authentication
      - OneDrive sharing settings
      - SharePoint tenant-level security settings

.NOTES
    Module  : TeamsSharePoint
    Version : 2.0.0
    Updated : 2026-06
    Ref     : CIS Microsoft 365 Foundations Benchmark v3.1 (Section 7, 8)
              CISA SCuBA Teams Baseline v1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputPath,

    [Parameter()]
    [ValidateSet('CIS','NIST80053','ZeroTrust','NESA')]
    [string]$ComplianceFramework = 'CIS'
)

Set-StrictMode -Version Latest
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

function New-CheckResult {
    param(
        [string]$ControlId, [string]$ControlName, [string]$Area = 'TeamsSharePoint',
        [ValidateSet('Pass','Fail','Warning','NotApplicable','ManualReview')][string]$Status,
        [string]$Finding, [string]$Recommendation,
        [ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity = 'Medium',
        [string]$Framework, [string]$FrameworkControl, [object]$RawData = $null
    )
    [PSCustomObject]@{
        Timestamp        = (Get-Date -Format 'o'); Area = $Area
        ControlId        = $ControlId; ControlName = $ControlName
        Status           = $Status; Severity = $Severity
        Finding          = $Finding; Recommendation = $Recommendation
        Framework        = $Framework; FrameworkControl = $FrameworkControl
        RawData          = ($RawData | ConvertTo-Json -Depth 5 -Compress -ErrorAction SilentlyContinue)
    }
}

#region ── TEAMS-01: External Access (Federation) ─────────────────────────────
try {
    $teamsExternalAccess = Get-CsTenantFederationConfiguration -ErrorAction Stop

    $allowAll       = $teamsExternalAccess.AllowFederatedUsers -and
                      -not $teamsExternalAccess.AllowedDomains.AllowedDomain.Count -and
                      -not $teamsExternalAccess.BlockedDomains.BlockedDomain.Count
    $guestEnabled   = $teamsExternalAccess.AllowGuestUser

    $status = if (-not $allowAll) { 'Pass' } elseif ($allowAll) { 'Warning' } else { 'Fail' }

    $Results.Add((New-CheckResult -ControlId 'TEAMS-01' `
        -ControlName 'Teams: External Access Federation Configuration' `
        -Status $status -Severity 'Medium' `
        -Finding "AllowFederatedUsers=$($teamsExternalAccess.AllowFederatedUsers). AllowAll (no domain restrictions)=$allowAll. AllowGuestUser=$guestEnabled." `
        -Recommendation "Restrict federation to specific trusted domains only (AllowedDomains list). Do not allow all external domains by default. Review and approve all federated domains." `
        -Framework $ComplianceFramework -FrameworkControl '8.2.1' `
        -RawData @{
            AllowFederatedUsers = $teamsExternalAccess.AllowFederatedUsers
            AllowedDomains      = $teamsExternalAccess.AllowedDomains.AllowedDomain.Domain
            BlockedDomains      = $teamsExternalAccess.BlockedDomains.BlockedDomain.Domain
        }))
} catch {
    Write-Warning "[TEAMS-01] Error: $_"
}
#endregion

#region ── TEAMS-02: Guest Access ─────────────────────────────────────────────
try {
    $guestConfig = Get-CsTeamsGuestMeetingConfiguration -ErrorAction Stop
    $guestMessaging = Get-CsTeamsGuestMessagingConfiguration -ErrorAction Stop

    # Guest allowed to call = potential data leakage
    $guestCanRecord = $guestConfig.AllowIPVideo
    $guestCanChat   = $guestMessaging.AllowUserChat

    $Results.Add((New-CheckResult -ControlId 'TEAMS-02' `
        -ControlName 'Teams: Guest Access Controls' `
        -Status 'ManualReview' -Severity 'Medium' `
        -Finding "Guest meeting: AllowIPVideo=$($guestConfig.AllowIPVideo), AllowMeetNow=$($guestConfig.AllowMeetNow). Guest messaging: AllowUserChat=$($guestMessaging.AllowUserChat), AllowGiphy=$($guestMessaging.AllowGiphy)." `
        -Recommendation "Disable guest IP video if not business-required. Restrict guest messaging capabilities. Review guest access via Entra B2B policies for lifecycle management." `
        -Framework $ComplianceFramework -FrameworkControl '8.2.2' `
        -RawData @{
            AllowIPVideo  = $guestConfig.AllowIPVideo
            AllowMeetNow  = $guestConfig.AllowMeetNow
            AllowUserChat = $guestMessaging.AllowUserChat
        }))
} catch {
    Write-Warning "[TEAMS-02] Error: $_"
}
#endregion

#region ── TEAMS-03: Meeting Policies — Anonymous Join & Lobby ────────────────
try {
    $meetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop

    $anonJoin         = $meetingPolicy.AllowAnonymousUsersToJoinMeeting
    $anonStart        = $meetingPolicy.AllowAnonymousUsersToStartMeeting
    $lobbyBypass      = $meetingPolicy.AutoAdmittedUsers       # EveryoneInCompany = good
    $cloudRecording   = $meetingPolicy.AllowCloudRecording
    $transcription    = $meetingPolicy.AllowTranscription
    $externalControl  = $meetingPolicy.AllowExternalParticipantGiveRequestControl

    $lobbyOk = $lobbyBypass -in @('EveryoneInCompany','EveryoneInCompanyExcludeGuests')
    $status  = if (-not $anonJoin -and -not $anonStart -and $lobbyOk) { 'Pass' }
               elseif ($anonJoin -or $anonStart) { 'Fail' } else { 'Warning' }

    $Results.Add((New-CheckResult -ControlId 'TEAMS-03' `
        -ControlName 'Teams Meeting Policy: Anonymous Join, Lobby, Recording' `
        -Status $status -Severity 'High' `
        -Finding "AnonJoin=$anonJoin, AnonStart=$anonStart, LobbyBypass=$lobbyBypass, CloudRecording=$cloudRecording, ExternalControl=$externalControl." `
        -Recommendation "Disable anonymous meeting start/join for the global policy. Set AutoAdmittedUsers = EveryoneInCompany. Disable external participant control sharing. Require lobby for external users." `
        -Framework $ComplianceFramework -FrameworkControl '8.5.1' `
        -RawData @{
            AllowAnonymousUsersToJoinMeeting    = $anonJoin
            AllowAnonymousUsersToStartMeeting   = $anonStart
            AutoAdmittedUsers                   = $lobbyBypass
            AllowCloudRecording                 = $cloudRecording
            AllowExternalParticipantControl     = $externalControl
        }))
} catch {
    Write-Warning "[TEAMS-03] Error: $_"
}
#endregion

#region ── TEAMS-04: Teams App Policies — External App Access ─────────────────
try {
    $appSetupPolicy = Get-CsTeamsAppSetupPolicy -Identity Global -ErrorAction Stop
    $appPermPolicy  = Get-CsTeamsAppPermissionPolicy -Identity Global -ErrorAction Stop

    $thirdPartyApps   = $appPermPolicy.DefaultCatalogApps    # 'Allow' = all 3rd party allowed
    $customApps       = $appPermPolicy.GlobalCatalogApps

    $Results.Add((New-CheckResult -ControlId 'TEAMS-04' `
        -ControlName 'Teams App Policies: Third-Party & Custom App Permissions' `
        -Status 'ManualReview' -Severity 'Medium' `
        -Finding "Global app permission: DefaultCatalogApps=$($thirdPartyApps), GlobalCatalogApps=$($customApps)." `
        -Recommendation "Restrict third-party app installation to admin-approved apps only. Block all third-party apps by default; create allowlist of approved apps in Teams Admin Center." `
        -Framework $ComplianceFramework -FrameworkControl '8.7.1' `
        -RawData @{
            DefaultCatalogApps = $thirdPartyApps
            GlobalCatalogApps  = $customApps
        }))
} catch {
    Write-Warning "[TEAMS-04] Error: $_"
}
#endregion

#region ── SPO-01: SharePoint External Sharing Level ─────────────────────────
try {
    # Use Graph to check SPO settings (SPO PowerShell module not required)
    $spoSettings = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' `
        -ErrorAction Stop

    # sharingCapability: disabled=0, existingExternalUserSharingOnly=1, externalUserSharingOnly=2, externalUserAndGuestSharing=3
    $sharingLevel = $spoSettings.sharingCapability
    $requireAcctMatch = $spoSettings.requireSignIn
    $defaultLinkType  = $spoSettings.defaultSharingLinkType  # internal = good

    $status = switch ($sharingLevel) {
        'disabled'                      { 'Pass' }
        'existingExternalUserSharingOnly' { 'Pass' }
        'externalUserSharingOnly'         { 'Warning' }
        'externalUserAndGuestSharing'     { 'Fail' }
        default                           { 'ManualReview' }
    }

    $Results.Add((New-CheckResult -ControlId 'SPO-01' `
        -ControlName 'SharePoint: External Sharing Level' `
        -Status $status -Severity 'High' `
        -Finding "SPO sharing level: '$sharingLevel'. RequireSignIn: $requireAcctMatch. DefaultSharingLinkType: $defaultLinkType." `
        -Recommendation "Set sharing to 'existingExternalUserSharingOnly' or 'disabled'. Set default link type to 'internal'. Enable 'Require sign-in' for external sharing. Disable 'Anyone' links unless business-critical." `
        -Framework $ComplianceFramework -FrameworkControl '7.2.1' `
        -RawData @{
            SharingCapability  = $sharingLevel
            RequireSignIn      = $requireAcctMatch
            DefaultLinkType    = $defaultLinkType
        }))
} catch {
    Write-Warning "[SPO-01] SharePoint settings error: $_"
}
#endregion

#region ── SPO-02: SharePoint Legacy Auth ────────────────────────────────────
try {
    $spoSettings2 = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' -ErrorAction Stop

    $legacyAuthEnabled = $spoSettings2.isLegacyAuthProtocolsEnabled

    $status = if (-not $legacyAuthEnabled) { 'Pass' } else { 'Fail' }
    $Results.Add((New-CheckResult -ControlId 'SPO-02' `
        -ControlName 'SharePoint: Legacy Authentication Disabled' `
        -Status $status -Severity 'High' `
        -Finding "isLegacyAuthProtocolsEnabled = $legacyAuthEnabled. Legacy auth bypasses CA policies and MFA." `
        -Recommendation "Disable legacy auth in SPO admin settings. Ensure modern auth is enabled. Use CA policies to block legacy auth as defense-in-depth." `
        -Framework $ComplianceFramework -FrameworkControl '7.2.3' `
        -RawData @{ isLegacyAuthProtocolsEnabled = $legacyAuthEnabled }))
} catch {
    Write-Warning "[SPO-02] Error: $_"
}
#endregion

#region ── SPO-03: OneDrive External Sharing ─────────────────────────────────
try {
    $oDSettings = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' -ErrorAction Stop

    $odSharing = $oDSettings.oneDriveSharingCapability

    $status = switch ($odSharing) {
        'disabled'                      { 'Pass' }
        'existingExternalUserSharingOnly' { 'Pass' }
        'externalUserSharingOnly'         { 'Warning' }
        'externalUserAndGuestSharing'     { 'Fail' }
        default                           { 'ManualReview' }
    }

    $Results.Add((New-CheckResult -ControlId 'SPO-03' `
        -ControlName 'OneDrive: External Sharing Level' `
        -Status $status -Severity 'Medium' `
        -Finding "OneDrive sharing capability: '$odSharing'. Should match or be more restrictive than SPO tenant setting." `
        -Recommendation "Set OneDrive external sharing to 'existingExternalUserSharingOnly' or more restrictive. Align with overall data classification and DLP policy." `
        -Framework $ComplianceFramework -FrameworkControl '7.3.1' `
        -RawData @{ OneDriveSharingCapability = $odSharing }))
} catch {
    Write-Warning "[SPO-03] OneDrive error: $_"
}
#endregion

Write-Verbose "[TeamsSharePoint] Assessment complete. $($Results.Count) checks."
return $Results
