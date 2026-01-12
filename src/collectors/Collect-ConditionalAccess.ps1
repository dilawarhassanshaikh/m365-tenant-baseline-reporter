function Collect-TBConditionalAccess {
 try {
   $policies = Get-MgIdentityConditionalAccessPolicy -All
   return @{
     count = $policies.Count
     policies = $policies | Select DisplayName, State
   }
 } catch {
   return @{ error = "Conditional Access not readable" }
 }
}
