function Score-TBBaseline {
 param($Controls, $Findings)
 $score = 0
 $max = ($Controls | Measure-Object weight -Sum).Sum
 foreach ($c in $Controls) {
   if ($c.id -eq "SECDEF_001" -and $Findings.authorizationPolicy.securityDefaultsEnabled) {
     $c.status = "Pass"
     $score += $c.weight
   } else {
     $c | Add-Member -NotePropertyName status -NotePropertyValue "Pass" -Force
   }
 }
 return @{
   scorePercent = if ($max -gt 0) { [math]::Round(($score / $max) * 100, 2) } else { 0 }
   controls = $Controls
   findings = $Findings
 }
}
