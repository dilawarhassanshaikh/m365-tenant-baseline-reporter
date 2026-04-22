import { BaselineResult } from "./types";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

export function exportToJson(result: BaselineResult) {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(result, null, 2));
  const downloadAnchorNode = document.createElement('a');
  downloadAnchorNode.setAttribute("href", dataStr);
  downloadAnchorNode.setAttribute("download", `TenantBaseline_${result.findings.organization.displayName.replace(/\s+/g, '_')}.json`);
  document.body.appendChild(downloadAnchorNode);
  downloadAnchorNode.click();
  downloadAnchorNode.remove();
}

export function exportToHtml(result: BaselineResult) {
  const passCount = result.controls.filter(c => c.status === 'Pass').length;
  const failCount = result.controls.filter(c => c.status === 'Fail').length;
  const unknownCount = result.controls.filter(c => c.status === 'Unknown').length;

  const rows = result.controls.map(c => `
    <tr>
      <td class="mono">${c.id}</td>
      <td>${c.title}</td>
      <td>${c.category}</td>
      <td>${c.severity}</td>
      <td><span class="badge ${c.status?.toLowerCase() || 'unknown'}">${c.status || 'Unknown'}</span></td>
      <td>${c.recommendation}</td>
    </tr>
  `).join('');

  const html = `
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
  <p class="muted">Tenant: <b>${result.findings.organization.displayName}</b> &nbsp; | &nbsp; Generated: ${new Date(result.generatedAt).toLocaleString()}</p>

  <div class="cards">
    <div class="card"><div class="label">Score</div><div class="value">${result.scorePercent}%</div></div>
    <div class="card"><div class="label">Pass</div><div class="value">${passCount}</div></div>
    <div class="card"><div class="label">Fail</div><div class="value">${failCount}</div></div>
    <div class="card"><div class="label">Unknown</div><div class="value">${unknownCount}</div></div>
    <div class="card"><div class="label">Controls</div><div class="value">${result.controls.length}</div></div>
  </div>

  <h2 style="font-size:16px;margin:14px 0 10px">Control Results</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Title</th><th>Category</th><th>Severity</th><th>Status</th><th>Recommendation</th>
      </tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
</body>
</html>
  `;

  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const downloadAnchorNode = document.createElement('a');
  downloadAnchorNode.setAttribute("href", url);
  downloadAnchorNode.setAttribute("download", `TenantBaseline_${result.findings.organization.displayName.replace(/\s+/g, '_')}.html`);
  document.body.appendChild(downloadAnchorNode);
  downloadAnchorNode.click();
  downloadAnchorNode.remove();
  URL.revokeObjectURL(url);
}

export function exportToPdf(result: BaselineResult) {
  const doc = new jsPDF();

  // Header
  doc.setFontSize(20);
  doc.text("M365 Tenant Baseline Report", 14, 22);

  doc.setFontSize(11);
  doc.setTextColor(100);
  doc.text(`Tenant: ${result.findings.organization.displayName}`, 14, 30);
  doc.text(`Generated: ${new Date(result.generatedAt).toLocaleString()}`, 14, 36);
  doc.text(`Tenant ID: ${result.findings.organization.tenantId}`, 14, 42);

  // Summary
  doc.setFontSize(14);
  doc.setTextColor(0);
  doc.text("Executive Summary", 14, 55);

  const passCount = result.controls.filter(c => c.status === 'Pass').length;
  const failCount = result.controls.filter(c => c.status === 'Fail').length;

  autoTable(doc, {
    startY: 60,
    head: [['Metric', 'Value']],
    body: [
      ['Baseline Score', `${result.scorePercent}%`],
      ['Total Controls', result.controls.length.toString()],
      ['Passed Controls', passCount.toString()],
      ['Failed Controls', failCount.toString()],
      ['Unknown/Manual Review', (result.controls.length - passCount - failCount).toString()],
    ],
    theme: 'striped',
  });

  // Controls Table
  doc.setFontSize(14);
  doc.text("Control Details", 14, (doc as any).lastAutoTable.finalY + 15);

  autoTable(doc, {
    startY: (doc as any).lastAutoTable.finalY + 20,
    head: [['ID', 'Title', 'Category', 'Severity', 'Status']],
    body: result.controls.map(c => [
      c.id,
      c.title,
      c.category,
      c.severity,
      c.status || 'Unknown'
    ]),
    columnStyles: {
      0: { cellWidth: 25 },
      1: { cellWidth: 60 },
      4: { fontStyle: 'bold' }
    }
  });

  // Recommendations (Formal Layout)
  doc.addPage();
  doc.setFontSize(14);
  doc.text("Recommendations", 14, 22);

  let y = 30;
  result.controls.filter(c => c.status === 'Fail').forEach(c => {
    if (y > 270) {
      doc.addPage();
      y = 22;
    }
    doc.setFontSize(11);
    doc.setFont("helvetica", "bold");
    doc.text(`${c.id}: ${c.title}`, 14, y);
    y += 6;
    doc.setFont("helvetica", "normal");
    const splitText = doc.splitTextToSize(`Recommendation: ${c.recommendation}`, 180);
    doc.text(splitText, 14, y);
    y += (splitText.length * 6) + 4;
  });

  doc.save(`TenantBaseline_${result.findings.organization.displayName.replace(/\s+/g, '_')}.pdf`);
}
