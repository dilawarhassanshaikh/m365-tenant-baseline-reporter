# M365 Tenant Baseline Reporter v2.0

> **Modernized** — all legacy `MSOnline`, `AzureAD`, and EXO v1 cmdlets replaced.
> Uses **Microsoft Graph PowerShell SDK v2+** and **ExchangeOnlineManagement v3+** (REST-based) exclusively.

[![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-blue?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![Graph SDK](https://img.shields.io/badge/Graph%20SDK-v2%2B-0078d4?logo=microsoft)](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
[![EXO v3](https://img.shields.io/badge/EXO-v3%2B-0072c6?logo=microsoftexchange)](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

A read-only M365 tenant security baseline assessment tool. Evaluates your tenant configuration against CIS Microsoft 365 Foundations Benchmark v3.1, CISA SCuBA baselines, NIST SP 800-53, Zero Trust, and NESA (UAE) frameworks. Outputs an interactive HTML report and raw JSON.

---

## What's New in v2.0

| Area | Old (Retired) | New (v2.0) |
|---|---|---|
| Identity queries | `MSOnline`, `AzureAD` module cmdlets | `Microsoft.Graph.*` SDK v2+ |
| CA policy reading | `Get-AzureADMSConditionalAccessPolicy` | `Invoke-MgGraphRequest` / `Get-MgIdentityConditionalAccessPolicy` |
| EXO connection | `New-PSSession` + `Import-PSSession` (Basic Auth) | `Connect-ExchangeOnline` v3 (REST, Modern Auth) |
| MFA status | `Get-MsolUser -StrongAuthenticationRequirements` | Graph `userRegistrationDetails` (Authentication Methods) |
| Role members | `Get-MsolRoleMember` | `Invoke-MgGraphRequest` roleAssignments |
| SPO settings | `Set-SPOTenant` (SPO module) | Graph `/admin/sharepoint/settings` |
| Teams federation | `Get-CsOnlinePstnGateway` (legacy) | `Get-CsTenantFederationConfiguration` (Teams PS v5) |

---

## Prerequisites

### PowerShell Modules

```powershell
# Install all required modules (PowerShell 7+ required)
Install-Module Microsoft.Graph.Authentication            -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.SignIns          -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Groups                    -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Users                     -Scope CurrentUser -Force
Install-Module Microsoft.Graph.Security                  -Scope CurrentUser -Force
Install-Module ExchangeOnlineManagement                  -Scope CurrentUser -Force  # v3+
Install-Module MicrosoftTeams                            -Scope CurrentUser -Force  # v5+
```

### Permissions Required

**Delegated (interactive):**

| Permission | Purpose |
|---|---|
| `Policy.Read.All` | CA policies, auth methods policy |
| `Directory.Read.All` | Users, groups, roles, domains |
| `IdentityRiskyUser.Read.All` | Risk-based identity data |
| `PrivilegedAccess.Read.AzureAD` | PIM role assignments |
| `Reports.Read.All` | Usage and audit reports |
| `AuditLog.Read.All` | Sign-in and audit logs |
| `SecurityEvents.Read.All` | Security alerts |
| `RoleManagement.Read.Directory` | Directory role assignments |
| `UserAuthenticationMethod.Read.All` | Auth method registrations |

**App-only (unattended/pipeline):**
Same permissions as above, granted as **Application** permissions on an App Registration with a certificate.

---

## Usage

### Interactive (Delegated Auth)

```powershell
.\Invoke-M365BaselineReport.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### App-Only (Unattended / CI/CD)

```powershell
.\Invoke-M365BaselineReport.ps1 `
    -TenantId              "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ClientId              "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
    -CertificateThumbprint "AABBCCDDEE..." `
    -Scopes                EntraID, ExchangeOnline `
    -ComplianceFramework   CIS
```

### Specific Scope Only

```powershell
# Entra ID + EXO only
.\Invoke-M365BaselineReport.ps1 -TenantId "..." -Scopes EntraID, ExchangeOnline

# UAE/NESA compliance framing
.\Invoke-M365BaselineReport.ps1 -TenantId "..." -ComplianceFramework NESA
```

---

## Repo Structure

```
m365-tenant-baseline-reporter/
├── scripts/
│   ├── Invoke-M365BaselineReport.ps1      # Main orchestrator
│   ├── Get-EntraIDBaseline.ps1            # 12 Entra ID controls
│   ├── Get-ExchangeOnlineBaseline.ps1     # 10 EXO controls
│   ├── Get-TeamsSharePointBaseline.ps1    # 7 Teams/SPO controls
│   └── New-BaselineHtmlReport.ps1         # Interactive HTML report
└── README.md
```

---

## Controls Coverage

### Entra ID (12 controls)
| ID | Control | Framework |
|---|---|---|
| EID-01 | Security Defaults / CA Policy Coverage | CIS 1.1.1 |
| EID-02 | CA: Require MFA for All Users | CIS 1.2.1 |
| EID-03 | CA: Block Legacy Authentication | CIS 1.2.2 |
| EID-04 | CA: Sign-in Risk Policy | CIS 1.2.3 |
| EID-05 | CA: User Risk Policy | CIS 1.2.4 |
| EID-06 | PIM: Privileged Role Permanent Assignments | CIS 1.3.1 |
| EID-07 | Guest Collaboration Settings | CIS 1.1.3 |
| EID-08 | SSPR & Authentication Methods Policy | CIS 2.1.1 |
| EID-09 | Password Protection / Smart Lockout | CIS 1.1.4 |
| EID-10 | Global Administrator Count | CIS 1.3.3 |
| EID-11 | Phishing-Resistant MFA (FIDO2/CBA) | CIS 1.1.7 |
| EID-12 | CA: Device Compliance Requirement | CIS 1.2.6 |

### Exchange Online (10 controls)
| ID | Control | Framework |
|---|---|---|
| EXO-01 | DKIM Signing — All Domains | CIS 2.1.4 |
| EXO-02 | DMARC — quarantine/reject Policy | CIS 2.1.5 |
| EXO-03 | SPF Records — Hard Fail | CIS 2.1.3 |
| EXO-04 | SMTP AUTH Disabled Org-Wide | CIS 2.1.10 |
| EXO-05 | Anti-Malware: ZAP + Admin Notify | CIS 2.1.8 |
| EXO-06 | Anti-Spam Outbound: Auto-Forward Block | CIS 2.1.6 |
| EXO-07 | Anti-Phishing: Spoof Intelligence | CIS 2.1.7 |
| EXO-08 | Mailbox Auditing Enabled | CIS 3.2.1 |
| EXO-09 | External Forwarding Transport Rules | CIS 2.4.1 |
| EXO-10 | Basic Auth Blocked (Auth Policies) | CIS 2.1.12 |

### Teams & SharePoint (7 controls)
| ID | Control | Framework |
|---|---|---|
| TEAMS-01 | Teams External Federation Restriction | CIS 8.2.1 |
| TEAMS-02 | Teams Guest Access Controls | CIS 8.2.2 |
| TEAMS-03 | Meeting Policy: Anonymous Join/Lobby | CIS 8.5.1 |
| TEAMS-04 | Teams App Permissions | CIS 8.7.1 |
| SPO-01 | SharePoint External Sharing Level | CIS 7.2.1 |
| SPO-02 | SharePoint Legacy Auth Disabled | CIS 7.2.3 |
| SPO-03 | OneDrive External Sharing | CIS 7.3.1 |

---

## Output

```
Reports/
└── 20260601-143022/
    ├── M365-Baseline-Report-20260601-143022.html   # Interactive report
    ├── baseline-results-20260601-143022.json        # Raw JSON
    └── baseline-run-20260601-143022.log             # Run log
```

The HTML report includes:
- Summary scorecard with compliance percentage
- Per-control status (Pass / Fail / Warning / Manual Review)
- Severity rating per finding
- Framework control mapping
- Filterable/searchable results table

---

## Security Notes

- **Read-only**: No configuration changes are made to the tenant.
- **No credential storage**: Tokens are held in memory only for the session duration.
- **App-only auth**: For pipelines, use certificate-based auth — not client secrets.
- **Least privilege**: Request only the Graph scopes listed above.

---

## Author

**Dilawar Hassan Shaikh** — Microsoft Cloud Security Architect
🔗 [github.com/dilawarhassanshaikh](https://github.com/dilawarhassanshaikh)
🔗 [linkedin.com/in/dilawarshaikh](https://linkedin.com/in/dilawarshaikh)
📄 [Zenodo Research](https://zenodo.org/search?q=dilawarhassanshaikh)

---

## License

MIT — see [LICENSE](LICENSE).
