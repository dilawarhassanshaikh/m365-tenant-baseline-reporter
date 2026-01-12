# M365 Tenant Baseline Reporter (Graph-only)
PowerShell-only Microsoft 365 tenant baseline reporting tool using Microsoft Graph.
This repository provides a **simple, read-only baseline assessment** to help administrators understand high-level tenant and identity posture **without installing Exchange or SharePoint PowerShell modules**.
---
## What this tool does
- Connects to Microsoft 365 using Microsoft Graph
- Collects basic tenant and identity configuration data
- Evaluates settings against a baseline framework
- Generates:
 - **JSON output** (raw findings, automation-friendly)
 - **HTML report** (simple, human-readable)
This tool is designed for **visibility and assessment**, not enforcement.
---
## Requirements
- PowerShell **7+**
- Microsoft Graph PowerShell SDK
Install Microsoft Graph (one time):
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser

---
## Microsoft Graph permissions

The tool requests the following read-only Microsoft Graph scopes:

Organization.Read.All

Policy.Read.All

Directory.Read.All

Admin consent is recommended for consistent results.

How to run

Download the repository
Click Code → Download ZIP

Extract the ZIP to a local folder
cd path\to\m365-tenant-baseline-reporter
Run the script:

pwsh .\scripts\Invoke-TenantBaseline.ps1


Sign in when prompted to Microsoft Graph

Output

Results are written to the out folder in the repository root.

Generated files:

TenantBaseline.json
Raw findings and baseline evaluation (automation-friendly)

TenantBaseline.html
Simple, human-readable baseline report

Open the HTML report:

Start-Process .\out\TenantBaseline.html

Sample output

Below is a sanitized example of the generated HTML report:

What this tool does NOT do

Does not modify tenant configuration

Does not enable or disable policies

Does not require Exchange or SharePoint PowerShell modules

Does not send data outside your environment

Does not replace Microsoft Secure Score or Microsoft Defender

All operations are read-only and run locally.

Current status

Early preview (v0.1)

Focused on structure, data collection, and reporting foundation

Some checks may return Unknown depending on tenant configuration or permissions

Designed to be extended over time
Open PowerShell 7

Navigate to the extracted folder:
