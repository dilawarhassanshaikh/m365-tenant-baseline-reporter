function New-TBHtmlReport {
 param($Path, $Result)
 $html = @"
<!doctype html>
<html>
<head><meta charset="utf-8"><title>M365 Baseline</title></head>
<body style="font-family:Segoe UI,Arial; margin:24px;">
<h1>M365 Tenant Baseline</h1>
<p><b>Score:</b> $($Result.scorePercent)%</p>
<h2>Controls</h2>
<pre>$($Result.controls | ConvertTo-Json -Depth 4)</pre>
</body>
</html>
"@
 Set-Content -Path $Path -Value $html -Encoding UTF8
}
