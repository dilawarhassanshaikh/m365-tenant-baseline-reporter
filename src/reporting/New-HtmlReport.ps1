function New-HtmlReport {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)]$Result
  )

  $controls = @($Result.controls)
  $score = $Result.scorePercent

  $passCount    = ($controls | Where-Object { $_.status -eq "Pass" }).Count
  $failCount    = ($controls | Where-Object { $_.status -eq "Fail" }).Count
  $unknownCount = ($controls | Where-Object { $_.status -eq "Unknown" }).Count

  $tenantName = $Result.findings.organization.displayName
  if ([string]::IsNullOrWhiteSpace($tenantName)) { $tenantName = "N/A" }

  $generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

  $rows = foreach ($c in $controls) {
    $status = if ($c.status) { $c.status } else { "Unknown" }
    $badge  = switch ($status) {
      "Pass" { "pass" }
      "Fail" { "fail" }
      default { "unknown" }
    }

@"
<tr>
  <td class="mono">$($c.id)</td>
  <td>$($c.title)</td>
  <td>$($c.category)</td>
  <td>$($c.severity)</td>
  <td><span class="badge $badge">$status</span></td>
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
<title>M365 Tenant Baseline</title>
<style>
  body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#0b1220;color:#e8eefc}
  h1{margin:0 0 6px;font-size:24px}
  .muted{color:#9aa7bd;margin:0 0 18px}
  .cards{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 18px}
  .card{background:#111a2e;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:12px;min-width:160px}
  .card .label{color:#9aa7bd;font-size:12px;font-weight:600}
  .card .value{font-size:20px;font-weight:700;margin-top:4px}
  table{width:100%;border-collapse:collapse;background:#111a2e;border:1px solid rgba(255,255,255,.08);border-radius:12px;overflow:hidden}
  th,td{padding:10px;border-bottom:1px solid rgba(255,255,255,.08);vertical-align:top}
  th{color:#9aa7bd;font-size:12px;text-transform:uppercase;letter-spacing:.3px;background:rgba(255,255,255,.03)}
  tr:hover td{background:rgba(255,255,255,.03)}
  .badge{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700}
  .badge.pass{color:#22c55e;border:1px solid rgba(34,197,94,.35);background:rgba(34,197,94,.14)}
  .badge.fail{color:#ef4444;border:1px solid rgba(239,68,68,.35);background:rgba(239,68,68,.14)}
  .badge.unknown{color:#94a3b8;border:1px solid rgba(148,163,184,.35);background:rgba(148,163,184,.12)}
  .mono{font-family:ui-monospace,Consolas,Menlo,monospace;font-size:12px}
</style>
</head>
<body>
  <h1>M365 Tenant Baseline</h1>
  <p class="muted">Tenant: <b>$tenantName</b> &nbsp; | &nbsp; Generated: $generatedAt</p>

  <div class="cards">
    <div class="card"><div class="label">Score</div><div class="value">$score%</div></div>
    <div class="card"><div class="label">Pass</div><div class="value">$passCount</div></div>
    <div class="card"><div class="label">Fail</div><div class="value">$failCount</div></div>
    <div class="card"><div class="label">Unknown</div><div class="value">$unknownCount</div></div>
    <div class="card"><div class="label">Controls</div><div class="value">$($controls.Count)</div></div>
  </div>

  <h2 style="font-size:16px;margin:14px 0 10px">Control Results</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Title</th><th>Category</th><th>Severity</th><th>Status</th><th>Recommendation</th>
      </tr>
    </thead>
    <tbody>
      $($rows -join "`n")
    </tbody>
  </table>
</body>
</html>
"@

  Set-Content -Path $Path -Value $html -Encoding UTF8
}
