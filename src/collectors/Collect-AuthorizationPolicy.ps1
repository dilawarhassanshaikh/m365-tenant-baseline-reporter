function Collect-TBAuthorizationPolicy {
 $authz = Get-MgPolicyAuthorizationPolicy
 $secDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
 return @{
   securityDefaultsEnabled = $secDefaults.IsEnabled
   allowInvitesFrom = $authz.AllowInvitesFrom
 }
}
