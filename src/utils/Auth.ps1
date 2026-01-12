function Connect-TBGraph {
 Import-Module Microsoft.Graph -ErrorAction Stop
 Connect-MgGraph -Scopes `
   "Organization.Read.All",
   "Policy.Read.All",
   "Directory.Read.All" | Out-Null
}
