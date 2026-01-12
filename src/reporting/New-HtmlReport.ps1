function New-TBHtmlReport {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)]$Result
  )

  $controls = @($Result.controls)
  $score = $Result.scorePercent

  $passCount    = ($controls | Where-Object { $_.status -eq "Pass" }).Count
  $failCount    = ($controls | Where-Object { $_.status -eq "Fail" }).Count
  $unknownCount = ($controls | Where-Object { $_.status -eq "Unknown" }).Count
  $totalCount   = $controls.Count

  # Safe access for common findings (won't break if null)
  $tenantName = $Result.findings.organization.displayName
  $tenantId   = $Result.findings.organization.tenantId
  $secDef     = $Result.findings.authorizationPolicy.securityDefaultsEnabled
  $caCount    = $Result.findings.conditionalAccess.count
  $gaCount    = $Result.findings.adminRoles.globalAdmins

  if ($null -eq $tenantName) { $tenantName = "N/A" }
  if ($null -eq $tenantId)   { $tenantId = "N/A" }
  if ($null -eq $secDef)     { $secDef = "N/A" }
  if ($null -eq $caCount)    { $caCount = "N/A" }
  if ($null -eq $gaCount)    { $gaCount = "N/A" }

  $generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

  $rows = foreach ($c in $controls) {
    $status = $c.status
    if ($null -eq $status -or $status -eq "") { $status = "Unknown" }

    $badgeClass = switch ($status) {
      "Pass" { "badge pass" }
      "Fail" { "badge fail" }
      default { "badge unknown" }
    }

    @"
<tr>
  <td class="mono">$($c.id)</td>
  <td>$($c.title)</td>
  <td>$($c.category)</td>
  <td>$($c.severity)</td>
  <td><span class="$badgeClass">$status</span></td>
  <td>$($c.recommendation)</td>
</tr>
"@
  }

  $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>M365 Tenant Baseline Report</title>
<style>
  :root {
    --bg: #0b1220;
    --card: #111a2e;
    --muted: #9aa7bd;
    --text: #e8eefc;
    --line: rgba(255,255,255,.08);
    --pass: #22c55e;
    --fail: #ef4444;
    --unknown: #94a3b8;
  }
  body { margin:0; font-family: Segoe UI, Arial, sans-serif; background: var(--bg); color: var(--text); }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 28px 18px 50px; }
  h1 { margin: 0 0 6px; font-size: 26px; }
  .sub { color: var(--muted); margin-bottom: 18px; }
  .grid { display: grid; gap: 12px; grid-template-columns: repeat(12, 1fr); margin: 14px 0 20px; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 14px; }
  .card h3 { margin: 0 0 6px; font-size: 13px; color: var(--muted); font-weight: 600; letter-spacing: .2px; }
  .card .big { font-size: 22px; font-weight: 700; }
  .span-6 { grid-column: span 6; }
  .span-4 { grid-column: span 4; }
  .span-3 { grid-column: span 3; }
  .span-12 { grid-column: span 12; }
  .badge { padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; display: inline-block; }
  .pass { background: rgba(34,197,94,.18); color: var(--pass); border: 1px solid rgba(34,197,94,.35); }
  .fail { background: rgba(239,68,68,.18); color: var(--fail); border: 1px solid rgba(239,68,68,.35); }
  .unknown { background: rgba(148,163,184,.16); color: var(--unknown); border: 1px solid rgba(148,163,184,.35); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 14px; }
  th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { font-size: 12px; color: var(--muted); font-weight: 700; background: rgba(255,255,255,.03); }
  tr:hover td { background: rgba(255,255,255,.03); }
  .foot { color: var(--muted); margin-top: 14px; font-size: 12px; }
  .pill { display:inline-block; padding: 4px 10px; border-radius: 999px; border: 1px solid var(--line); color: var(--muted); }
  @media (max-width: 900px) {
    .span-6,.span-4,.span-3 { grid-column: span 12; }
    th:nth-child(6), td:nth-child(6) { display:none; } /* hide long recommendation on small screens */
  }
</style>
</head>
<body>
  <div class="wrap">
    <h1>M365 Tenant Baseline Report</h1>
    <div class="sub">
      <span class="pill">Generated: $generatedAt</span>
      &nbsp; <span class="pill">Tenant: $tenantName</span>
      &nbsp; <span class="pill">Tenant ID: <span class="mono">$tenantId</span></span>
    </div>

    <div class="grid">
      <div class="card span-3">
        <h3>Score</h3>
        <div class="big">$score%</div>
      </div>
      <div class="card span-3">
        <h3>Controls</h3>
        <div class="big">$totalCount</div>
      </div>
      <div class="card span-2">
        <h3>Pass</h3>
        <div class="big" style="color:var(--pass)">$passCount</div>
      </div>
      <div class="card span-2">
        <h3>Fail</h3>
        <div class="big" style="color:var(--fail)">$failCount</div>
      </div>
      <div class="card span-2">
        <h3>Unknown</h3>
        <div class="big" style="color:var(--unknown)">$unknownCount</div>
      </div>

      <div class="card span-4">
        <h3>Security Defaults</h3>
        <div class="big">$secDef</div>
      </div>
      <div class="card span-4">
        <h3>Conditional Access Policies</h3>
        <div class="big">$caCount</div>
      </div>
      <div class="card span-4">
        <h3>Global Administrators</h3>
        <div class="big">$gaCount</div>
      </div>

      <div class="card span-12">
        <h3>Control Results</h3>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody>
            $($rows -join "`n")
          </tbody>
        </table>
        <div class="foot">Note: v0.1 marks only SECDEF_001 as Pass/Fail. Other controls are currently shown as Unknown until implemented.</div>
      </div>
    </div>
  </div>
</body>
</html>
"@

  Set-Content -Path $Path -Value $html -Encoding UTF8
}
