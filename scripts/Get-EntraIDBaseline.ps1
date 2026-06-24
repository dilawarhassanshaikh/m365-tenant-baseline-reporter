#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns,
#                  Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups,
#                  Microsoft.Graph.Users

<#
.SYNOPSIS
    Entra ID (Azure AD) tenant baseline assessment — Graph SDK v2+.

.DESCRIPTION
    Checks the following Entra ID baseline controls using Microsoft Graph only.
    No MSOnline or AzureAD legacy module cmdlets are used.

    Controls assessed:
      - Conditional Access policies (MFA, legacy auth, risk-based)
      - Security defaults status
      - Password policies (SSPR, banned passwords, smart lockout)
      - Privileged Identity Management (PIM) role assignments
      - Guest & external collaboration settings
      - Authentication methods policy
      - Tenant-level identity security settings
      - Admin role holders (permanent vs eligible)
      - Named locations & trusted IPs
      - Entra ID Protection risk policy status

.NOTES
    Module  : EntraID
    Version : 2.0.0
    Updated : 2026-06
    Ref     : CIS Microsoft 365 Foundations Benchmark v3.1
              CISA SCuBA AAD Baseline v1.0
              NIST SP 800-53 Rev.5 (IA, AC controls)
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

#region ── Helper ─────────────────────────────────────────────────────────────
function New-CheckResult {
    param(
        [string]$ControlId,
        [string]$ControlName,
        [string]$Area = 'EntraID',
        [ValidateSet('Pass','Fail','Warning','NotApplicable','ManualReview')]
        [string]$Status,
        [string]$Finding,
        [string]$Recommendation,
        [ValidateSet('Critical','High','Medium','Low','Informational')]
        [string]$Severity = 'Medium',
        [string]$Framework,
        [string]$FrameworkControl,
        [object]$RawData = $null
    )
    [PSCustomObject]@{
        Timestamp        = (Get-Date -Format 'o')
        Area             = $Area
        ControlId        = $ControlId
        ControlName      = $ControlName
        Status           = $Status
        Severity         = $Severity
        Finding          = $Finding
        Recommendation   = $Recommendation
        Framework        = $Framework
        FrameworkControl = $FrameworkControl
        RawData          = ($RawData | ConvertTo-Json -Depth 5 -Compress -ErrorAction SilentlyContinue)
    }
}

function Get-FrameworkControl {
    param([string]$ControlId, [string]$Framework)
    $map = @{
        'CIS' = @{
            'EID-01' = '1.1.1'   # Security Defaults
            'EID-02' = '1.2.1'   # CA MFA All Users
            'EID-03' = '1.2.2'   # CA Block Legacy Auth
            'EID-04' = '1.2.3'   # CA Sign-in Risk
            'EID-05' = '1.2.4'   # CA User Risk
            'EID-06' = '1.3.1'   # PIM privileged roles
            'EID-07' = '1.1.3'   # Guest access restriction
            'EID-08' = '2.1.1'   # SSPR
            'EID-09' = '1.1.4'   # Password protection
            'EID-10' = '1.3.3'   # Permanent GA check
            'EID-11' = '1.1.7'   # Auth methods: FIDO2/WHfB
            'EID-12' = '1.2.6'   # CA device compliance
        }
        'NIST80053' = @{
            'EID-01' = 'IA-2'
            'EID-02' = 'IA-2(1)'
            'EID-03' = 'IA-2(12)'
            'EID-04' = 'IA-2(12)'
            'EID-05' = 'AC-7'
            'EID-06' = 'AC-6(5)'
            'EID-07' = 'AC-3'
            'EID-08' = 'IA-5'
            'EID-09' = 'IA-5(1)'
            'EID-10' = 'AC-6(5)'
            'EID-11' = 'IA-2(2)'
            'EID-12' = 'SC-7'
        }
        'ZeroTrust' = @{
            'EID-01' = 'Identity.1'
            'EID-02' = 'Identity.2'
            'EID-03' = 'Identity.3'
            'EID-04' = 'Identity.4'
            'EID-05' = 'Identity.4'
            'EID-06' = 'Identity.5'
            'EID-07' = 'Identity.6'
            'EID-08' = 'Identity.7'
            'EID-09' = 'Identity.7'
            'EID-10' = 'Identity.5'
            'EID-11' = 'Identity.2'
            'EID-12' = 'Endpoint.1'
        }
    }
    return ($map[$Framework]?[$ControlId] ?? 'N/A')
}
#endregion

Write-Verbose "[EntraID] Starting baseline assessment..."

#region ── EID-01: Security Defaults ─────────────────────────────────────────
try {
    $secDefaults = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    $enabled = $secDefaults.isEnabled

    # NOTE: If CA policies are in use, Security Defaults should be OFF
    $caPolicies = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$filter=state eq ''enabled'''
    $hasEnabledCA = $caPolicies.value.Count -gt 0

    if ($hasEnabledCA -and -not $enabled) {
        $status = 'Pass'
        $finding = "Security Defaults disabled; $($caPolicies.value.Count) CA policies active. Correct pattern for managed CA."
        $rec = "Maintain CA policies with at least: MFA for all users, block legacy auth, risk-based sign-in."
    } elseif (-not $hasEnabledCA -and $enabled) {
        $status = 'Warning'
        $finding = "Security Defaults enabled with no CA policies. Provides baseline protection but limited granularity."
        $rec = "Upgrade to Conditional Access policies for granular, risk-adaptive control."
    } elseif ($hasEnabledCA -and $enabled) {
        $status = 'Fail'
        $finding = "Security Defaults AND CA policies both enabled. This is a conflict — Security Defaults will block some CA scenarios."
        $rec = "Disable Security Defaults. CA policies supersede and should be the single control plane."
        $sev = 'High'
    } else {
        $status = 'Fail'
        $finding = "Security Defaults disabled and no CA policies found. Tenant has no baseline identity enforcement."
        $rec = "Deploy CA policies immediately: MFA for all users, block legacy auth, admin MFA, risk-based sign-in."
        $sev = 'Critical'
    }

    $Results.Add((New-CheckResult -ControlId 'EID-01' `
        -ControlName 'Security Defaults / CA Policy Coverage' `
        -Status $status `
        -Severity ($sev ?? 'Low') `
        -Finding $finding `
        -Recommendation $rec `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-01' $ComplianceFramework) `
        -RawData @{ SecurityDefaultsEnabled = $enabled; ActiveCAPolicies = $caPolicies.value.Count }))
} catch {
    Write-Warning "[EID-01] Error: $_"
}
#endregion

#region ── EID-02: CA Policy — MFA for All Users ─────────────────────────────
try {
    $allPolicies = (Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies').value

    # Look for policies requiring MFA (grantControls includes mfa) targeting All Users, enabled
    $mfaPolicies = $allPolicies | Where-Object {
        $_.state -eq 'enabled' -and
        $_.grantControls.builtInControls -contains 'mfa' -and
        ($_.conditions.users.includeUsers -contains 'All' -or
         $_.conditions.users.includeGroups.Count -gt 0)
    }

    $status = if ($mfaPolicies.Count -gt 0) { 'Pass' } else { 'Fail' }
    $Results.Add((New-CheckResult -ControlId 'EID-02' `
        -ControlName 'CA: Require MFA for All Users' `
        -Status $status `
        -Severity 'Critical' `
        -Finding "Found $($mfaPolicies.Count) enabled CA policy/policies requiring MFA targeting All Users or groups." `
        -Recommendation "Ensure at least one enabled CA policy requires MFA for all users. Exclude break-glass accounts, not service accounts." `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-02' $ComplianceFramework) `
        -RawData ($mfaPolicies | Select-Object id, displayName, state)))
} catch {
    Write-Warning "[EID-02] Error: $_"
}
#endregion

#region ── EID-03: CA Policy — Block Legacy Authentication ────────────────────
try {
    $legacyBlockPolicies = $allPolicies | Where-Object {
        $_.state -eq 'enabled' -and
        $_.grantControls.builtInControls -contains 'block' -and
        $_.conditions.clientAppTypes -and
        ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
         $_.conditions.clientAppTypes -contains 'other')
    }

    $status = if ($legacyBlockPolicies.Count -gt 0) { 'Pass' } else { 'Fail' }
    $Results.Add((New-CheckResult -ControlId 'EID-03' `
        -ControlName 'CA: Block Legacy Authentication Protocols' `
        -Status $status `
        -Severity 'Critical' `
        -Finding "Found $($legacyBlockPolicies.Count) enabled CA policy/policies blocking legacy auth (exchangeActiveSync + other)." `
        -Recommendation "Create a CA policy: All Users, All Cloud Apps, Client app = Exchange ActiveSync + Other clients → Block. Legacy auth bypasses MFA." `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-03' $ComplianceFramework) `
        -RawData ($legacyBlockPolicies | Select-Object id, displayName, state)))
} catch {
    Write-Warning "[EID-03] Error: $_"
}
#endregion

#region ── EID-04: CA Policy — Sign-in Risk ───────────────────────────────────
try {
    $riskSignInPolicies = $allPolicies | Where-Object {
        $_.state -eq 'enabled' -and
        $_.conditions.signInRiskLevels -and
        $_.conditions.signInRiskLevels.Count -gt 0
    }

    $hasHighMedium = $riskSignInPolicies | Where-Object {
        $_.conditions.signInRiskLevels -contains 'high' -or
        $_.conditions.signInRiskLevels -contains 'medium'
    }

    $status = if ($hasHighMedium.Count -gt 0) { 'Pass' } else { 'Fail' }
    $Results.Add((New-CheckResult -ControlId 'EID-04' `
        -ControlName 'CA: Sign-in Risk Policy (Medium/High → MFA or Block)' `
        -Status $status `
        -Severity 'High' `
        -Finding "Found $($riskSignInPolicies.Count) risk-based sign-in CA policies; $($hasHighMedium.Count) cover High/Medium risk." `
        -Recommendation "Create CA policy: All Users, All Apps, Sign-in risk = High/Medium → Require MFA (or block High). Requires Entra ID P2." `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-04' $ComplianceFramework) `
        -RawData ($riskSignInPolicies | Select-Object id, displayName, state, @{n='RiskLevels';e={$_.conditions.signInRiskLevels}})))
} catch {
    Write-Warning "[EID-04] Error: $_"
}
#endregion

#region ── EID-05: CA Policy — User Risk ─────────────────────────────────────
try {
    $riskUserPolicies = $allPolicies | Where-Object {
        $_.state -eq 'enabled' -and
        $_.conditions.userRiskLevels -and
        $_.conditions.userRiskLevels.Count -gt 0
    }

    $hasHighUser = $riskUserPolicies | Where-Object {
        $_.conditions.userRiskLevels -contains 'high'
    }

    $status = if ($hasHighUser.Count -gt 0) { 'Pass' } else { 'Fail' }
    $Results.Add((New-CheckResult -ControlId 'EID-05' `
        -ControlName 'CA: User Risk Policy (High → Password Change + MFA)' `
        -Status $status `
        -Severity 'High' `
        -Finding "Found $($riskUserPolicies.Count) user risk CA policies; $($hasHighUser.Count) cover High user risk." `
        -Recommendation "CA policy: All Users, User risk = High → Require MFA + password change. Requires Entra ID P2." `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-05' $ComplianceFramework)))
} catch {
    Write-Warning "[EID-05] Error: $_"
}
#endregion

#region ── EID-06: PIM — Privileged Role Assignments ─────────────────────────
try {
    # Get all active (not eligible) role assignments for privileged roles
    $privilegedRoles = @(
        '62e90394-69f5-4237-9190-012177145e10'  # Global Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814'  # Privileged Role Administrator
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'  # Privileged Authentication Administrator
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'  # Application Administrator
        '158c047a-c907-4556-b7ef-446551a6b5f7'  # Cloud Application Administrator
        'b0f54661-2d74-4c50-afa3-1ec803f12efe'  # Billing Administrator
        '29232cdf-9323-42fd-ade2-1d097af3e4de'  # Exchange Administrator
        '194ae4cb-b126-40b2-bd5b-6091b380977d'  # Security Administrator
    )

    $activeAssignments = @()
    foreach ($roleId in $privilegedRoles) {
        try {
            $assignments = (Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$roleId'&`$expand=principal").value
            foreach ($a in $assignments) {
                $roleDetails = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$roleId"
                $activeAssignments += [PSCustomObject]@{
                    RoleName    = $roleDetails.displayName
                    Principal   = $a.principal.displayName
                    PrincipalId = $a.principalId
                    AssignType  = 'Permanent'
                }
            }
        } catch {}
    }

    $globalAdmins = $activeAssignments | Where-Object { $_.RoleName -eq 'Global Administrator' }
    $tooManyGA    = $globalAdmins.Count -gt 4

    $status = if (-not $tooManyGA -and $activeAssignments.Count -lt 20) { 'Pass' } else { 'Fail' }
    $Results.Add((New-CheckResult -ControlId 'EID-06' `
        -ControlName 'PIM: Privileged Role Permanent Assignments' `
        -Status $status `
        -Severity 'High' `
        -Finding "Found $($globalAdmins.Count) permanent Global Administrators, $($activeAssignments.Count) total privileged role assignments (permanent)." `
        -Recommendation "Global Administrators: 2–4 maximum. Use PIM eligible assignments. Avoid permanent standing access for privileged roles." `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-06' $ComplianceFramework) `
        -RawData $activeAssignments))
} catch {
    Write-Warning "[EID-06] Error: $_"
}
#endregion

#region ── EID-07: Guest Access Settings ─────────────────────────────────────
try {
    $authPolicy = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'

    # allowInvitesFrom: adminsAndGuestInviters or adminsOnly = good; everyone = fail
    $inviteFrom     = $authPolicy.allowInvitesFrom
    $guestPerms     = $authPolicy.guestUserRoleId  # 10dae51f = Member-level guest (bad), 2af84b1e = Limited guest (good)

    $inviteOk   = $inviteFrom -in @('adminsAndGuestInviters','none','adminsOnly')
    $permOk     = $guestPerms -eq '2af84b1e-9983-48f3-a3c1-862b9cf5ab90'  # Restricted guest

    $status = if ($inviteOk -and $permOk) { 'Pass' } elseif ($inviteOk -or $permOk) { 'Warning' } else { 'Fail' }
    $Results.Add((New-CheckResult -ControlId 'EID-07' `
        -ControlName 'Guest Collaboration: Invite Permissions & Role Assignment' `
        -Status $status `
        -Severity 'Medium' `
        -Finding "Guest invite permission: '$inviteFrom'. Guest user role: $(if ($permOk) {'Restricted (Good)'} else {'Member-level (Risky)'})." `
        -Recommendation "Set allowInvitesFrom = 'adminsAndGuestInviters'. Set guest role to 'Restricted Guest User' (least privilege). Block guests from enumerating directory." `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-07' $ComplianceFramework) `
        -RawData @{ AllowInvitesFrom = $inviteFrom; GuestUserRoleId = $guestPerms }))
} catch {
    Write-Warning "[EID-07] Error: $_"
}
#endregion

#region ── EID-08: SSPR ───────────────────────────────────────────────────────
try {
    $sspr = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy' `
        -ErrorAction SilentlyContinue

    # SSPR lives in the passwordResetPolicies — check via Graph beta
    $ssprPolicy = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/beta/policies/selfServiceSignUp' `
        -ErrorAction SilentlyContinue

    # Check auth methods for phone/email (SSPR indicators)
    $authMethods = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'

    $emailEnabled = ($authMethods.authenticationMethodConfigurations |
        Where-Object { $_.id -eq 'Email' -and $_.state -eq 'enabled' }).Count -gt 0
    $phoneEnabled = ($authMethods.authenticationMethodConfigurations |
        Where-Object { $_.id -in @('MicrosoftAuthenticator','Sms') -and $_.state -eq 'enabled' }).Count -gt 0

    $status = if ($emailEnabled -or $phoneEnabled) { 'Pass' } else { 'Warning' }
    $Results.Add((New-CheckResult -ControlId 'EID-08' `
        -ControlName 'SSPR & Authentication Methods Policy' `
        -Status $status `
        -Severity 'Medium' `
        -Finding "Authentication Methods: Email=$emailEnabled, Phone/Authenticator=$phoneEnabled. Review SSPR enablement in Entra portal." `
        -Recommendation "Enable SSPR for all users. Require 2 authentication methods. Prefer Authenticator app over SMS. Disable SMS-only SSPR for privileged accounts." `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-08' $ComplianceFramework)))
} catch {
    Write-Warning "[EID-08] Error: $_"
}
#endregion

#region ── EID-09: Password Protection (Smart Lockout) ───────────────────────
try {
    $passwordPolicy = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/domains' |
        Select-Object -ExpandProperty value | Where-Object { $_.isDefault }

    # Smart lockout is in beta
    $lockoutPolicy = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/beta/settings' -ErrorAction SilentlyContinue
    $lockoutSetting = $lockoutPolicy.value | Where-Object { $_.displayName -eq 'Password Rule Settings' }

    $Results.Add((New-CheckResult -ControlId 'EID-09' `
        -ControlName 'Password Protection: Smart Lockout & Banned Passwords' `
        -Status 'ManualReview' `
        -Severity 'Medium' `
        -Finding "Smart lockout threshold and banned password list require manual validation in Entra portal (Authentication methods > Password protection)." `
        -Recommendation "Set lockout threshold ≤ 10, lockout duration ≥ 60s. Enable custom banned password list. Enable password protection for on-premises AD if hybrid." `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-09' $ComplianceFramework)))
} catch {
    Write-Warning "[EID-09] Error: $_"
}
#endregion

#region ── EID-10: No Permanent Global Administrators ────────────────────────
try {
    # Already have this data from EID-06
    $permanentGACount = if ($activeAssignments) {
        ($activeAssignments | Where-Object { $_.RoleName -eq 'Global Administrator' }).Count
    } else { -1 }

    # Also check for break-glass (cloud-only, no MFA enforced) — heuristic check
    $cloudOnlyGAs = @()
    try {
        $gaRoleId = '62e90394-69f5-4237-9190-012177145e10'
        $gaMembers = (Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$gaRoleId'&`$expand=principal").value
        foreach ($m in $gaMembers) {
            if ($m.principal.'@odata.type' -eq '#microsoft.graph.user') {
                $user = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/users/$($m.principalId)?`$select=id,displayName,userPrincipalName,onPremisesSyncEnabled"
                if ($user.onPremisesSyncEnabled -ne $true) {
                    $cloudOnlyGAs += $user.userPrincipalName
                }
            }
        }
    } catch {}

    $status = if ($permanentGACount -le 4 -and $permanentGACount -ge 2) { 'Pass' }
              elseif ($permanentGACount -gt 4) { 'Fail' }
              elseif ($permanentGACount -lt 2) { 'Warning' }
              else { 'ManualReview' }

    $Results.Add((New-CheckResult -ControlId 'EID-10' `
        -ControlName 'Global Administrator Count & Cloud-Only Break-Glass' `
        -Status $status `
        -Severity 'High' `
        -Finding "Permanent Global Administrators: $permanentGACount. Cloud-only GA accounts (potential break-glass): $($cloudOnlyGAs.Count). Accounts: $($cloudOnlyGAs -join ', ')." `
        -Recommendation "Maintain 2–4 GA accounts. All should be cloud-only, MFA-registered, and monitored. Use PIM for all other privileged access." `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-10' $ComplianceFramework) `
        -RawData @{ PermanentGACount = $permanentGACount; CloudOnlyGAs = $cloudOnlyGAs }))
} catch {
    Write-Warning "[EID-10] Error: $_"
}
#endregion

#region ── EID-11: Authentication Methods — Phishing-Resistant MFA ───────────
try {
    $authMethods = Invoke-MgGraphRequest -Method GET `
        -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'

    $fido2Config = $authMethods.authenticationMethodConfigurations |
        Where-Object { $_.id -eq 'Fido2' }
    $whfbConfig  = $authMethods.authenticationMethodConfigurations |
        Where-Object { $_.id -eq 'WindowsHelloForBusiness' }
    $certConfig  = $authMethods.authenticationMethodConfigurations |
        Where-Object { $_.id -eq 'X509Certificate' }
    $smsConfig   = $authMethods.authenticationMethodConfigurations |
        Where-Object { $_.id -eq 'Sms' }

    $fido2Enabled = $fido2Config?.state -eq 'enabled'
    $whfbEnabled  = $whfbConfig?.state  -eq 'enabled'
    $certEnabled  = $certConfig?.state  -eq 'enabled'
    $smsEnabled   = $smsConfig?.state   -eq 'enabled'

    $phishingResistant = $fido2Enabled -or $certEnabled
    $status = if ($phishingResistant) { 'Pass' } elseif ($whfbEnabled) { 'Warning' } else { 'Fail' }

    $Results.Add((New-CheckResult -ControlId 'EID-11' `
        -ControlName 'Authentication Methods: Phishing-Resistant MFA Enabled' `
        -Status $status `
        -Severity 'High' `
        -Finding "FIDO2=$fido2Enabled, Windows Hello for Business=$whfbEnabled, Certificate-based=$certEnabled, SMS (legacy, avoid)=$smsEnabled." `
        -Recommendation "Enable FIDO2 security keys and/or CBA for privileged accounts. Disable SMS authentication where possible. Target Zero Trust: require phishing-resistant MFA via CA for admins." `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-11' $ComplianceFramework) `
        -RawData @{ FIDO2 = $fido2Enabled; WHfB = $whfbEnabled; CBA = $certEnabled; SMS = $smsEnabled }))
} catch {
    Write-Warning "[EID-11] Error: $_"
}
#endregion

#region ── EID-12: CA — Require Compliant / Hybrid-Joined Device ─────────────
try {
    $deviceCompliancePolicies = $allPolicies | Where-Object {
        $_.state -eq 'enabled' -and
        ($_.grantControls.builtInControls -contains 'compliantDevice' -or
         $_.grantControls.builtInControls -contains 'domainJoinedDevice')
    }

    $status = if ($deviceCompliancePolicies.Count -gt 0) { 'Pass' } else { 'Warning' }
    $Results.Add((New-CheckResult -ControlId 'EID-12' `
        -ControlName 'CA: Require Compliant or Hybrid-Joined Device' `
        -Status $status `
        -Severity 'Medium' `
        -Finding "Found $($deviceCompliancePolicies.Count) CA policies requiring compliant or hybrid-joined device." `
        -Recommendation "Create CA policies requiring device compliance for access to sensitive/all cloud apps. Integrate with Intune for compliance signals." `
        -Framework $ComplianceFramework `
        -FrameworkControl (Get-FrameworkControl 'EID-12' $ComplianceFramework) `
        -RawData ($deviceCompliancePolicies | Select-Object id, displayName, state)))
} catch {
    Write-Warning "[EID-12] Error: $_"
}
#endregion

Write-Verbose "[EntraID] Assessment complete. $($Results.Count) checks."
return $Results
