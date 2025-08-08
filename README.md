# get-d2l-brightspace-oauth-token-powershell
Gets an OAuth Token from D2L Brightspace API using powershell

# To Use
```
Import-Module ".\D2L.Brightspace.Api.psm1"

$params = @{
  Domain = "https://myschooldomain.brightspace.com"
  Scope = "content:*:* core:*:* datahub:*:* datasets:*:* discussions:*:* enrollment:*:* globalusermapping:*:* grades:*:* quizzing:*:* reporting:*:* role:*:* users:*:*"
  RedirectUri = "https://localhost:40433/d2loauth2/fake_endpoint/redirecturi"
}
$myToken = Get-BrightspaceApiToken
```
# Example API Call
```
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Bearer {0}" -f $myToken.AccessToken)
$lpVersion = "1.51"
$response = Invoke-RestMethod ("{0}/d2l/api/lp/{1}/users/whoami" -f $myToken.Domain, $lpVersion) -Method 'GET' -Headers $headers
$response | ConvertTo-Json
```
