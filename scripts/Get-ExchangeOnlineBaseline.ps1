#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Exchange Online baseline assessment — ExchangeOnlineManagement v3+ (REST).

.DESCRIPTION
    Uses ExchangeOnlineManagement v3+ REST-based cmdlets only.
    No legacy EXO v1 cmdlets (New-PSSession, Import-PSSession, Basic Auth, etc.).

    Controls assessed:
      - DKIM signing configuration
      - DMARC record validation via DNS
      - SPF record validation via DNS
      - Anti-spam policy (outbound, inbound)
      - Anti-malware policy (zero-hour auto purge, admin notify)
      - Anti-phishing policy (impersonation, spoof intelligence)
      - Modern Authentication (SMTP AUTH, basic auth blocks)
      - Mailbox auditing
      - Transport rules (sensitive data forwarding, external forwarding)

.NOTES
    Module  : ExchangeOnline
    Version : 2.0.0
    Updated : 2026-06
    Ref     : CIS Microsoft 365 Foundations Benchmark v3.1 (Section 2)
              CISA SCuBA Exchange Online Baseline v1.0
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
        [string]$ControlId, [string]$ControlName, [string]$Area = 'ExchangeOnline',
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

#region ── EXO-01: DKIM Signing ───────────────────────────────────────────────
try {
    $dkimConfigs = Get-DkimSigningConfig -ErrorAction Stop
    $disabledDomains = $dkimConfigs | Where-Object { -not $_.Enabled }
    $status = if ($disabledDomains.Count -eq 0) { 'Pass' } else { 'Fail' }

    $Results.Add((New-CheckResult -ControlId 'EXO-01' `
        -ControlName 'DKIM: Signing Enabled for All Accepted Domains' `
        -Status $status -Severity 'High' `
        -Finding "Total domains: $($dkimConfigs.Count). Domains with DKIM disabled: $($disabledDomains.Count). Disabled: $($disabledDomains.Domain -join ', ')." `
        -Recommendation "Enable DKIM for all accepted domains: Set-DkimSigningConfig -Identity <domain> -Enabled `$true. Publish CNAME records in DNS as instructed." `
        -Framework $ComplianceFramework -FrameworkControl '2.1.4' `
        -RawData ($dkimConfigs | Select-Object Domain, Enabled, Status, Selector1CNAME, Selector2CNAME)))
} catch {
    Write-Warning "[EXO-01] DKIM error: $_"
}
#endregion

#region ── EXO-02: DMARC — DNS Check ─────────────────────────────────────────
try {
    $acceptedDomains = Get-AcceptedDomain | Where-Object { $_.DomainType -eq 'Authoritative' }
    $dmarcResults = foreach ($domain in $acceptedDomains) {
        try {
            $dmarcRecord = Resolve-DnsName -Name "_dmarc.$($domain.DomainName)" -Type TXT -ErrorAction SilentlyContinue
            $dmarcTxt    = $dmarcRecord | Where-Object { $_.Strings -match 'v=DMARC1' } |
                           Select-Object -ExpandProperty Strings -First 1

            $policy    = if ($dmarcTxt -match 'p=(none|quarantine|reject)') { $Matches[1] } else { 'missing' }
            $pctMatch  = if ($dmarcTxt -match 'pct=(\d+)') { [int]$Matches[1] } else { 100 }
            $rufuMatch = if ($dmarcTxt -match 'ruf=([^ ;]+)') { $Matches[1] } else { 'none' }

            [PSCustomObject]@{
                Domain      = $domain.DomainName
                DmarcRecord = $dmarcTxt ?? 'NOT FOUND'
                Policy      = $policy
                Pct         = $pctMatch
                RufAddress  = $rufuMatch
                IsCompliant = ($policy -in @('quarantine','reject') -and $pctMatch -eq 100)
            }
        } catch {
            [PSCustomObject]@{ Domain = $domain.DomainName; DmarcRecord = 'ERROR'; Policy = 'error'; IsCompliant = $false }
        }
    }

    $nonCompliant = $dmarcResults | Where-Object { -not $_.IsCompliant }
    $status = if ($nonCompliant.Count -eq 0) { 'Pass' }
              elseif (($dmarcResults | Where-Object { $_.Policy -eq 'none' }).Count -gt 0) { 'Fail' }
              else { 'Warning' }

    $Results.Add((New-CheckResult -ControlId 'EXO-02' `
        -ControlName 'DMARC: Policy = quarantine or reject on All Domains' `
        -Status $status -Severity 'High' `
        -Finding "Domains checked: $($dmarcResults.Count). Non-compliant (missing/none/pct<100): $($nonCompliant.Count). Domains: $($nonCompliant.Domain -join ', ')." `
        -Recommendation "Set DMARC policy to 'quarantine' then progress to 'reject' at pct=100. Configure ruf/rua report addresses. _dmarc.<domain> TXT record." `
        -Framework $ComplianceFramework -FrameworkControl '2.1.5' `
        -RawData $dmarcResults))
} catch {
    Write-Warning "[EXO-02] DMARC error: $_"
}
#endregion

#region ── EXO-03: SPF Records ────────────────────────────────────────────────
try {
    $spfResults = foreach ($domain in $acceptedDomains) {
        try {
            $spfRecord = Resolve-DnsName -Name $domain.DomainName -Type TXT -ErrorAction SilentlyContinue |
                Where-Object { $_.Strings -match 'v=spf1' } | Select-Object -First 1
            $spfTxt = $spfRecord.Strings -join ''
            [PSCustomObject]@{
                Domain     = $domain.DomainName
                SpfRecord  = $spfTxt ?? 'NOT FOUND'
                HasHardFail = $spfTxt -match '\-all$'
                HasSoftFail = $spfTxt -match '~all$'
                IsCompliant = ($spfTxt -match 'v=spf1' -and ($spfTxt -match '\-all$' -or $spfTxt -match '~all$'))
            }
        } catch {
            [PSCustomObject]@{ Domain = $domain.DomainName; SpfRecord = 'ERROR'; IsCompliant = $false }
        }
    }

    $noSpf      = $spfResults | Where-Object { -not $_.IsCompliant }
    $noHardFail = $spfResults | Where-Object { $_.IsCompliant -and -not $_.HasHardFail }
    $status = if ($noSpf.Count -eq 0 -and $noHardFail.Count -eq 0) { 'Pass' }
              elseif ($noSpf.Count -eq 0) { 'Warning' } else { 'Fail' }

    $Results.Add((New-CheckResult -ControlId 'EXO-03' `
        -ControlName 'SPF: Records Present and Hard Fail Configured' `
        -Status $status -Severity 'High' `
        -Finding "Domains without SPF: $($noSpf.Count). Domains with SPF but soft-fail (~all) only: $($noHardFail.Count)." `
        -Recommendation "Publish SPF TXT record for all domains. Prefer '-all' (hard fail) over '~all'. Include all authorized sending IPs and services." `
        -Framework $ComplianceFramework -FrameworkControl '2.1.3' `
        -RawData $spfResults))
} catch {
    Write-Warning "[EXO-03] SPF error: $_"
}
#endregion

#region ── EXO-04: SMTP AUTH — Disabled at Organization Level ────────────────
try {
    $transportConfig = Get-TransportConfig -ErrorAction Stop
    $smtpAuthDisabled = -not $transportConfig.SmtpClientAuthenticationDisabled

    # Note: v3 EXO: SmtpClientAuthenticationDisabled = $true means SMTP AUTH is OFF (good)
    $status = if ($transportConfig.SmtpClientAuthenticationDisabled -eq $true) { 'Pass' } else { 'Fail' }
    $Results.Add((New-CheckResult -ControlId 'EXO-04' `
        -ControlName 'SMTP AUTH: Disabled at Organization Level' `
        -Status $status -Severity 'High' `
        -Finding "SmtpClientAuthenticationDisabled = $($transportConfig.SmtpClientAuthenticationDisabled). SMTP AUTH enabled org-wide = risky (bypasses modern auth/MFA)." `
        -Recommendation "Set-TransportConfig -SmtpClientAuthenticationDisabled `$true. Re-enable per-mailbox only for legacy devices/apps that require it: Set-CASMailbox -SmtpClientAuthenticationDisabled `$false." `
        -Framework $ComplianceFramework -FrameworkControl '2.1.10' `
        -RawData @{ SmtpClientAuthenticationDisabled = $transportConfig.SmtpClientAuthenticationDisabled }))
} catch {
    Write-Warning "[EXO-04] SMTP Auth error: $_"
}
#endregion

#region ── EXO-05: Anti-Malware — ZAP & Admin Notify ─────────────────────────
try {
    $malwarePolicies = Get-MalwareFilterPolicy -ErrorAction Stop
    $defaultPolicy   = $malwarePolicies | Where-Object { $_.Name -eq 'Default' }

    $zapEnabled     = $defaultPolicy.ZapEnabled
    $adminNotify    = $defaultPolicy.EnableInternalSenderAdminNotifications
    $fileTypes      = $defaultPolicy.FileTypeAction

    $status = if ($zapEnabled -and $adminNotify) { 'Pass' }
              elseif ($zapEnabled -or $adminNotify) { 'Warning' } else { 'Fail' }

    $Results.Add((New-CheckResult -ControlId 'EXO-05' `
        -ControlName 'Anti-Malware: ZAP Enabled & Admin Notifications' `
        -Status $status -Severity 'High' `
        -Finding "Default policy: ZAP=$zapEnabled, AdminNotify=$adminNotify, FileTypeAction=$fileTypes." `
        -Recommendation "Enable ZAP, admin notifications for malware detections. Block common attack file types (.exe, .ps1, .vbs, .hta, .bat, .cmd). Review custom policies for overrides." `
        -Framework $ComplianceFramework -FrameworkControl '2.1.8' `
        -RawData ($defaultPolicy | Select-Object Name, ZapEnabled, EnableInternalSenderAdminNotifications, FileTypeAction)))
} catch {
    Write-Warning "[EXO-05] Malware policy error: $_"
}
#endregion

#region ── EXO-06: Anti-Spam — Outbound Policy ───────────────────────────────
try {
    $outboundSpam = Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop
    $defaultOut   = $outboundSpam | Where-Object { $_.Name -eq 'Default' }

    $autoForwardMode = $defaultOut.AutoForwardingMode  # Should be 'Off' or 'Automatic'
    $notifyAdmin     = $defaultOut.NotifyOutboundSpam

    $status = if ($autoForwardMode -eq 'Off' -and $notifyAdmin) { 'Pass' }
              elseif ($autoForwardMode -eq 'Off' -or $notifyAdmin) { 'Warning' } else { 'Fail' }

    $Results.Add((New-CheckResult -ControlId 'EXO-06' `
        -ControlName 'Anti-Spam Outbound: Auto-Forwarding & Admin Notification' `
        -Status $status -Severity 'High' `
        -Finding "Outbound spam default policy: AutoForwardingMode=$autoForwardMode, NotifyAdmin=$notifyAdmin." `
        -Recommendation "Set AutoForwardingMode = Off to block external auto-forwarding (common data exfiltration path). Enable admin notification for high-volume senders." `
        -Framework $ComplianceFramework -FrameworkControl '2.1.6' `
        -RawData ($defaultOut | Select-Object Name, AutoForwardingMode, NotifyOutboundSpam, BccSuspiciousOutboundMail)))
} catch {
    Write-Warning "[EXO-06] Outbound spam error: $_"
}
#endregion

#region ── EXO-07: Anti-Phishing — Impersonation & Spoof Intelligence ─────────
try {
    $antiPhishPolicies = Get-AntiPhishPolicy -ErrorAction Stop
    $defaultPhish      = $antiPhishPolicies | Where-Object { $_.Name -eq 'Office365 AntiPhish Default' }

    $spoofEnabled      = $defaultPhish.EnableSpoofIntelligence
    $unverifiedSender  = $defaultPhish.EnableUnauthenticatedSender  # Shows ? for unverified
    $honorDmarcPolicy  = $defaultPhish.HonorDmarcPolicy
    $phishThreshold    = $defaultPhish.PhishThresholdLevel          # 1=Standard, 2=Aggressive, 3=More aggressive, 4=Most aggressive

    $status = if ($spoofEnabled -and $honorDmarcPolicy -and $phishThreshold -ge 2) { 'Pass' }
              elseif ($spoofEnabled) { 'Warning' } else { 'Fail' }

    $Results.Add((New-CheckResult -ControlId 'EXO-07' `
        -ControlName 'Anti-Phishing: Spoof Intelligence & DMARC Honour Policy' `
        -Status $status -Severity 'High' `
        -Finding "Default policy: SpoofIntelligence=$spoofEnabled, HonorDMARC=$honorDmarcPolicy, PhishThreshold=$phishThreshold, UnauthenticatedSenderIndicator=$unverifiedSender." `
        -Recommendation "Enable spoof intelligence, honour DMARC policy. Set phishing threshold to Aggressive (2+). For MDO P2: configure user/domain impersonation protection for key executives." `
        -Framework $ComplianceFramework -FrameworkControl '2.1.7' `
        -RawData ($defaultPhish | Select-Object Name, EnableSpoofIntelligence, HonorDmarcPolicy, PhishThresholdLevel, EnableUnauthenticatedSender)))
} catch {
    Write-Warning "[EXO-07] Anti-phishing error: $_"
}
#endregion

#region ── EXO-08: Mailbox Auditing ──────────────────────────────────────────
try {
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
    $auditEnabled = $orgConfig.AuditDisabled -eq $false

    # Check a sample of mailboxes for auditing status
    $mailboxSample = Get-Mailbox -ResultSize 20 -Filter { RecipientTypeDetails -eq 'UserMailbox' } |
        Select-Object DisplayName, UserPrincipalName, AuditEnabled, AuditOwner, AuditDelegate, AuditAdmin

    $auditOff = $mailboxSample | Where-Object { -not $_.AuditEnabled }
    $status   = if (-not $orgConfig.AuditDisabled -and $auditOff.Count -eq 0) { 'Pass' }
                elseif ($orgConfig.AuditDisabled) { 'Fail' } else { 'Warning' }

    $Results.Add((New-CheckResult -ControlId 'EXO-08' `
        -ControlName 'Mailbox Auditing: Enabled Org-Wide' `
        -Status $status -Severity 'Medium' `
        -Finding "Org-level audit: AuditDisabled=$($orgConfig.AuditDisabled). Sample of 20 mailboxes: $($auditOff.Count) have auditing off." `
        -Recommendation "Ensure AuditDisabled=`$false org-wide (default since 2019 for E3+). Verify per-mailbox AuditEnabled. Review AuditOwner/Delegate/Admin actions to include key events like MailItemsAccessed, FolderBind." `
        -Framework $ComplianceFramework -FrameworkControl '3.2.1' `
        -RawData @{ OrgAuditDisabled = $orgConfig.AuditDisabled; SampleDisabledCount = $auditOff.Count }))
} catch {
    Write-Warning "[EXO-08] Mailbox audit error: $_"
}
#endregion

#region ── EXO-09: External Forwarding Transport Rules ───────────────────────
try {
    $fwdRules = Get-TransportRule -ErrorAction Stop |
        Where-Object {
            ($_.RedirectMessageTo -match '\.' -or $_.CopyTo -match '\.') -or
            ($_.Actions | Where-Object { $_.Name -match 'Forward|Redirect' -and $_.Addresses -match '@' })
        }

    $status = if ($fwdRules.Count -eq 0) { 'Pass' } else { 'Warning' }
    $Results.Add((New-CheckResult -ControlId 'EXO-09' `
        -ControlName 'Transport Rules: External Forwarding / Redirect Rules' `
        -Status $status -Severity 'Medium' `
        -Finding "Found $($fwdRules.Count) transport rule(s) that may forward or redirect mail externally. Rules: $($fwdRules.Name -join ', ')." `
        -Recommendation "Review each forwarding transport rule. Legitimate rules should be documented. Block user-created auto-forwarding via the outbound spam policy (AutoForwardingMode=Off)." `
        -Framework $ComplianceFramework -FrameworkControl '2.4.1' `
        -RawData ($fwdRules | Select-Object Name, State, Priority, Description)))
} catch {
    Write-Warning "[EXO-09] Transport rules error: $_"
}
#endregion

#region ── EXO-10: Modern Auth — Block Basic Auth (Auth Policies) ─────────────
try {
    $authPolicies = Get-AuthenticationPolicy -ErrorAction Stop
    $basicAuthBlocked = $authPolicies | Where-Object {
        -not $_.AllowBasicAuthActiveSync -and
        -not $_.AllowBasicAuthPop -and
        -not $_.AllowBasicAuthImap -and
        -not $_.AllowBasicAuthSmtp -and
        -not $_.AllowBasicAuthWebServices
    }

    $status = if ($basicAuthBlocked.Count -gt 0) { 'Pass' }
              elseif ($authPolicies.Count -eq 0) { 'Warning' } else { 'Fail' }

    $Results.Add((New-CheckResult -ControlId 'EXO-10' `
        -ControlName 'Modern Auth: Basic Auth Blocked via Authentication Policies' `
        -Status $status -Severity 'Critical' `
        -Finding "Auth policies found: $($authPolicies.Count). Policies with all Basic Auth blocked: $($basicAuthBlocked.Count)." `
        -Recommendation "Create/update Authentication Policy to block all basic auth protocols. Assign to all users. Use CA legacy auth block as defense-in-depth. New-AuthenticationPolicy 'Block Basic Auth' then Set-User -AuthenticationPolicy." `
        -Framework $ComplianceFramework -FrameworkControl '2.1.12' `
        -RawData ($authPolicies | Select-Object Name, AllowBasicAuthActiveSync, AllowBasicAuthPop, AllowBasicAuthImap, AllowBasicAuthSmtp)))
} catch {
    Write-Warning "[EXO-10] Auth policy error: $_"
}
#endregion

Write-Verbose "[ExchangeOnline] Assessment complete. $($Results.Count) checks."
return $Results
