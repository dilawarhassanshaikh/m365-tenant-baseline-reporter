function Collect-TBOrganization {
 $org = Get-MgOrganization -Top 1
 return @{
   tenantId = $org.Id
   displayName = $org.DisplayName
   verifiedDomains = $org.VerifiedDomains
 }
}
