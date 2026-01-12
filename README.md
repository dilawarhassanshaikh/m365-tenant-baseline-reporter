# M365 Tenant Baseline Reporter (Graph-only)
PowerShell-only Microsoft 365 tenant baseline reporting tool using Microsoft Graph.
This repository provides a **simple, read-only baseline assessment** to help administrators understand high-level tenant and identity posture without installing Exchange or SharePoint PowerShell modules.
---
## What this tool does
- Connects to Microsoft 365 using Microsoft Graph
- Collects basic tenant and identity configuration data
- Evaluates settings against a baseline framework
- Generates:
 - JSON output (raw findings)
 - HTML report (human-readable)
This tool is designed for **visibility and assessment**, not enforcement.
---
## Requirements
- PowerShell **7+**
- Microsoft Graph PowerShell SDK
Install Microsoft Graph (one time):
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
