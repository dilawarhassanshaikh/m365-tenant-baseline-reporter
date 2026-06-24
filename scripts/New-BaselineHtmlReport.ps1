<#
.SYNOPSIS
    Generates a consolidated HTML baseline report from assessment results.

.NOTES
    Version : 2.0.0
    Updated : 2026-06
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [PSCustomObject[]]$Results,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [Parameter(Mandatory)]
    [guid]$TenantId,

    [Parameter()]
    [string]$Framework = 'CIS'
)

$Timestamp    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'
$ReportFile   = Join-Path $OutputPath "M365-Baseline-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"

# Summary stats
$total    = $Results.Count
$pass     = ($Results | Where-Object Status -eq 'Pass').Count
$fail     = ($Results | Where-Object Status -eq 'Fail').Count
$warn     = ($Results | Where-Object Status -eq 'Warning').Count
$manual   = ($Results | Where-Object Status -eq 'ManualReview').Count
$score    = if ($total -gt 0) { [math]::Round(($pass / ($total - $manual)) * 100, 1) } else { 0 }

$critical = ($Results | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'Critical' }).Count
$high     = ($Results | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'High' }).Count

function Get-StatusBadge ([string]$status) {
    $map = @{
        'Pass'          = '<span class="badge pass">✔ Pass</span>'
        'Fail'          = '<span class="badge fail">✖ Fail</span>'
        'Warning'       = '<span class="badge warn">⚠ Warning</span>'
        'ManualReview'  = '<span class="badge manual">👁 Manual Review</span>'
        'NotApplicable' = '<span class="badge na">— N/A</span>'
    }
    return $map[$status] ?? $status
}

function Get-SevBadge ([string]$sev) {
    $map = @{
        'Critical'     = '<span class="sev critical">Critical</span>'
        'High'         = '<span class="sev high">High</span>'
        'Medium'       = '<span class="sev medium">Medium</span>'
        'Low'          = '<span class="sev low">Low</span>'
        'Informational'= '<span class="sev info">Info</span>'
    }
    return $map[$sev] ?? $sev
}

# Build table rows
$rows = foreach ($r in ($Results | Sort-Object Area, ControlId)) {
    $rowClass = switch ($r.Status) {
        'Fail'    { 'row-fail' }
        'Warning' { 'row-warn' }
        'Pass'    { 'row-pass' }
        default   { '' }
    }
    @"
<tr class="$rowClass">
    <td><code>$($r.ControlId)</code></td>
    <td>$($r.Area)</td>
    <td>$($r.ControlName)</td>
    <td>$(Get-StatusBadge $r.Status)</td>
    <td>$(Get-SevBadge $r.Severity)</td>
    <td class="finding">$($r.Finding)</td>
    <td class="rec">$($r.Recommendation)</td>
    <td>$($r.FrameworkControl)</td>
</tr>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>M365 Tenant Baseline Report</title>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --border: #2d3148;
    --text: #e2e8f0; --muted: #8892a4;
    --pass: #22c55e; --fail: #ef4444; --warn: #f59e0b; --manual: #818cf8; --na: #64748b;
    --crit: #dc2626; --high: #ea580c; --med: #ca8a04; --low: #16a34a; --info: #0284c7;
    --accent: #6366f1;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.5; padding: 24px; }
  h1 { font-size: 1.6rem; font-weight: 700; color: #fff; margin-bottom: 4px; }
  .meta { color: var(--muted); font-size: 12px; margin-bottom: 24px; }
  .meta span { margin-right: 20px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 28px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; }
  .card .val { font-size: 2rem; font-weight: 800; }
  .card .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }
  .card.pass .val { color: var(--pass); }
  .card.fail .val { color: var(--fail); }
  .card.warn .val { color: var(--warn); }
  .card.manual .val { color: var(--manual); }
  .card.score .val { color: var(--accent); }
  .filters { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; }
  .filters select, .filters input { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 6px 12px; border-radius: 6px; font-size: 13px; outline: none; }
  .filters input { min-width: 240px; }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 10px; overflow: hidden; }
  thead tr { background: #1e2130; }
  th { padding: 11px 12px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); white-space: nowrap; }
  td { padding: 10px 12px; border-top: 1px solid var(--border); vertical-align: top; }
  td.finding { max-width: 300px; font-size: 12px; color: #c4cad6; }
  td.rec { max-width: 280px; font-size: 12px; color: #a0aec0; }
  tr.row-fail { background: rgba(239,68,68,.04); }
  tr.row-warn { background: rgba(245,158,11,.03); }
  tr.row-pass { }
  tr:hover { background: rgba(99,102,241,.06); }
  code { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 12px; background: rgba(255,255,255,.06); padding: 2px 5px; border-radius: 3px; }
  .badge { display: inline-block; padding: 2px 9px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge.pass   { background: rgba(34,197,94,.15); color: var(--pass); }
  .badge.fail   { background: rgba(239,68,68,.15); color: var(--fail); }
  .badge.warn   { background: rgba(245,158,11,.15); color: var(--warn); }
  .badge.manual { background: rgba(129,140,248,.15); color: var(--manual); }
  .badge.na     { background: rgba(100,116,139,.12); color: var(--na); }
  .sev { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
  .sev.critical { background: rgba(220,38,38,.18); color: #fca5a5; }
  .sev.high     { background: rgba(234,88,12,.18); color: #fdba74; }
  .sev.medium   { background: rgba(202,138,4,.18); color: #fde047; }
  .sev.low      { background: rgba(22,163,74,.18); color: #86efac; }
  .sev.info     { background: rgba(2,132,199,.18); color: #7dd3fc; }
  .hidden { display: none !important; }
  .footer { margin-top: 24px; text-align: center; color: var(--muted); font-size: 11px; }
  .progress-bar { height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; margin-top: 6px; }
  .progress-fill { height: 100%; background: linear-gradient(90deg, var(--accent), var(--pass)); border-radius: 4px; transition: width .5s; }
</style>
</head>
<body>

<h1>🛡️ M365 Tenant Baseline Report</h1>
<div class="meta">
  <span>🏢 Tenant: <strong>$TenantId</strong></span>
  <span>📅 Generated: <strong>$Timestamp</strong></span>
  <span>📋 Framework: <strong>$Framework</strong></span>
  <span>⚙️ Reporter: <strong>m365-tenant-baseline-reporter v2.0.0</strong></span>
</div>

<div class="cards">
  <div class="card score">
    <div class="val">$score%</div>
    <div class="lbl">Compliance Score</div>
    <div class="progress-bar"><div class="progress-fill" style="width:${score}%"></div></div>
  </div>
  <div class="card pass"><div class="val">$pass</div><div class="lbl">Passing</div></div>
  <div class="card fail"><div class="val">$fail</div><div class="lbl">Failing</div></div>
  <div class="card warn"><div class="val">$warn</div><div class="lbl">Warnings</div></div>
  <div class="card manual"><div class="val">$manual</div><div class="lbl">Manual Review</div></div>
  <div class="card fail"><div class="val" style="color:#dc2626">$critical</div><div class="lbl">Critical Fails</div></div>
  <div class="card fail"><div class="val" style="color:#ea580c">$high</div><div class="lbl">High Fails</div></div>
</div>

<div class="filters">
  <input type="text" id="searchBox" placeholder="🔍 Search controls, findings..." oninput="filterTable()">
  <select id="statusFilter" onchange="filterTable()">
    <option value="">All Statuses</option>
    <option value="Fail">Fail</option>
    <option value="Warning">Warning</option>
    <option value="Pass">Pass</option>
    <option value="ManualReview">Manual Review</option>
  </select>
  <select id="areaFilter" onchange="filterTable()">
    <option value="">All Areas</option>
    <option value="EntraID">Entra ID</option>
    <option value="ExchangeOnline">Exchange Online</option>
    <option value="TeamsSharePoint">Teams / SharePoint</option>
    <option value="DefenderOffice365">Defender for Office 365</option>
  </select>
  <select id="sevFilter" onchange="filterTable()">
    <option value="">All Severities</option>
    <option value="Critical">Critical</option>
    <option value="High">High</option>
    <option value="Medium">Medium</option>
    <option value="Low">Low</option>
  </select>
</div>

<table id="resultsTable">
  <thead>
    <tr>
      <th>Control ID</th>
      <th>Area</th>
      <th>Control Name</th>
      <th>Status</th>
      <th>Severity</th>
      <th>Finding</th>
      <th>Recommendation</th>
      <th>$Framework Ref</th>
    </tr>
  </thead>
  <tbody id="tableBody">
    $($rows -join "`n")
  </tbody>
</table>

<div class="footer">
  Generated by <strong>m365-tenant-baseline-reporter</strong> |
  <a href="https://github.com/dilawarhassanshaikh/m365-tenant-baseline-reporter" style="color:var(--accent)">github.com/dilawarhassanshaikh/m365-tenant-baseline-reporter</a>
</div>

<script>
function filterTable() {
  const search = document.getElementById('searchBox').value.toLowerCase();
  const status = document.getElementById('statusFilter').value;
  const area   = document.getElementById('areaFilter').value;
  const sev    = document.getElementById('sevFilter').value;
  const rows   = document.querySelectorAll('#tableBody tr');
  rows.forEach(row => {
    const text   = row.innerText.toLowerCase();
    const cells  = row.querySelectorAll('td');
    const rowStatus = cells[3]?.innerText ?? '';
    const rowArea   = cells[1]?.innerText ?? '';
    const rowSev    = cells[4]?.innerText ?? '';
    const show = (!search || text.includes(search)) &&
                 (!status || rowStatus.includes(status)) &&
                 (!area   || rowArea.includes(area)) &&
                 (!sev    || rowSev.includes(sev));
    row.classList.toggle('hidden', !show);
  });
}
</script>
</body>
</html>
"@

$html | Set-Content -Path $ReportFile -Encoding UTF8
Write-Host "[Report] HTML report saved: $ReportFile" -ForegroundColor Green
Write-Output $ReportFile
