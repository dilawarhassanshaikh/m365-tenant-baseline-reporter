function Score-TBaseline {
  param($Controls, $Findings)

  $score = 0
  $max = ($Controls | Measure-Object weight -Sum).Sum

  foreach ($c in $Controls) {

    # Default everything to Unknown first (safe)
    $c | Add-Member -NotePropertyName status -NotePropertyValue "Unknown" -Force

    # SECDEF_001: Security Defaults enabled => Pass, else Fail
    if ($c.id -eq "SECDEF_001") {
      if ($Findings.authorizationPolicy.securityDefaultsEnabled -eq $true) {
        $c | Add-Member -NotePropertyName status -NotePropertyValue "Pass" -Force
        $score += [int]$c.weight
      }
      else {
        $c | Add-Member -NotePropertyName status -NotePropertyValue "Fail" -Force
      }
      continue
    }

    # For now (v0.1): keep other controls Unknown until implemented
    # (This avoids misleading "Pass" results for everything)
    $c | Add-Member -NotePropertyName status -NotePropertyValue "Unknown" -Force
  }

  return @{
    scorePercent = if ($max -gt 0) { [math]::Round(($score / $max) * 100, 2) } else { 0 }
    controls     = $Controls
    findings     = $Findings
  }
}
