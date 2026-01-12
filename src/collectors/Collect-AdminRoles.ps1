function Collect-TBAdminRoles {
 $roles = Get-MgDirectoryRole -All
 $ga = $roles | Where-Object DisplayName -eq "Global Administrator"
 $members = if ($ga) {
   Get-MgDirectoryRoleMember -DirectoryRoleId $ga.Id -All
 }
 return @{
   globalAdmins = $members.Count
 }
}
