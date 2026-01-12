# M365 Tenant Baseline Reporter (Graph-only)
PowerShell-only Microsoft 365 tenant baseline reporting tool using Microsoft Graph.
This tool provides a simple, read-only way for administrators to understand
high-level tenant and identity posture without installing Exchange or SharePoint
PowerShell modules.
## What this tool does
- Connects to Microsoft 365 using Microsoft Graph
- Collects basic tenant and identity configuration data
- Evaluates settings against a baseline framework
- Generates:
 - JSON output (raw findings, automation-friendly)
 - HTML report (simple, human-readable)
This tool is designed for visibility and assessment, not enforcement.
## Quick usage
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
pwsh .\scripts\Invoke-TenantBaseline.ps1
```
This tool is read-only and runs locally using Microsoft Graph.

## Requirements
- PowerShell 7 or later
- Microsoft Graph PowerShell SDK

## Microsoft Graph permissions
The tool uses the following read-only Microsoft Graph permissions:
- Organization.Read.All
- Policy.Read.All
- Directory.Read.All
Admin consent is recommended for consistent and complete results.

## Output
Results are written to the out folder in the repository.
Generated files:
• TenantBaseline.json
Raw findings and baseline evaluation
• TenantBaseline.html
Human-readable baseline report
```powershell
Start-Process .\out\TenantBaseline.html
```

## What this tool does NOT do
- Does not modify tenant configuration
- Does not enable or disable policies
- Does not require Exchange or SharePoint PowerShell modules
- Does not send data outside your environment
- Does not replace Microsoft Secure Score or Microsoft Defender
All operations are read-only.

## Current status
Early preview (v0.1)
- Focused on basic collection and reporting
- Some checks may return Unknown depending on tenant permissions
- To be extended over time

## License
MIT License
