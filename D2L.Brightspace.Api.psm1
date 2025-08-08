<# SPDX-License-Identifier: GPL-3.0-or-later #>
<#
	N: Joseph A. Ramirez II 
	E: jaramirezii@outlook.com
	P: 4096/9D8BE5E5 A1B3 1B96 46C4 8243 BE8B  99D9 2EEF 58A5 9D8B E5E5
	S: USA
#>

function Get-BrightspaceApiToken {
	<#
	.SYNOPSIS
	Gets A new OAuth Token from Brightspace using API.
	
	.DESCRIPTION
	This function loads saved encrypted credentials from file and signs into Brightspace.
	It retrieves a new OAuth 2.0 Token using the Brightspace API domain.
	
	Before using: 
	(1) Create a Brightspace Login Account for use by the script. (Service Account)
	(2) And, Register An OAuth App in Brightspace ( ClientId, ClientSecret, RedirectUri, and Scope )
		Admin Settings > Manage Extensibility >  OAuth 2.0 >  Register An App

	.PARAMETER WorkingDirectory
	Specifies the location where to load or store Brightspace credentials.
	The file is encrypted using Windows Data Protection API (DPAPI).
	
	.PARAMETER Domain
	Specifies the Brightspace Domain. 
	Example: $Domain = "https://mydomain.brightspace.com"
	
	.PARAMETER Scope
	Specifies the API Permissions. Must match what is configure for the App.
	Example: $Scope = "content:*:* core:*:* datahub:*:* datasets:*:* discussions:*:* enrollment:*:* globalusermapping:*:* grades:*:* quizzing:*:* reporting:*:* role:*:* users:*:*"
	
	.PARAMETER RedirectUri
	Specifies the App RedirectUri. This URL does not need to be real.
	Example: $RediretUri = "https://localhost:40433/d2loauth2/fake_endpoint/redirecturi"

	.EXAMPLE
	$params = @{
		Domain = "https://mydomain.brightspace.com"
		Scope = "content:*:* core:*:* datahub:*:* datasets:*:* discussions:*:* enrollment:*:* globalusermapping:*:* grades:*:* quizzing:*:* reporting:*:* role:*:* users:*:*"
		RedirectUri = "https://localhost:40433/d2loauth2/fake_endpoint/redirecturi"
	}	
	$myToken = Get-BrightspaceApiToken @params
	#>
    param (
        [string]$WorkingDirectory = ".",
		[Parameter(Mandatory=$true)]
		[string]$Domain,
		[Parameter(Mandatory=$true)]
		[string]$Scope,
		[Parameter(Mandatory=$true)]
		[string]$RedirectUri
	)
	
	# ===================================================
	# API URLs
	# ===================================================
	$authorizationEndpoint	= "https://auth.brightspace.com/oauth2/auth"
	$tokenEndpoint			= "https://auth.brightspace.com/core/connect/token"
		

	# ===================================================
	# Load saved Username & Passwords
	# ===================================================
	try
	{
		$credentials = Import-CliXml -Path "$($WorkingDirectory)\PSCredentials.$env:USERNAME@$env:USERDOMAIN.xml"
	}
	catch
	{
		Write-Host "Stored PSCredentials file not found. Recreating..."
		$credentials = @{
			brightspaceServiceAccount	= New-Object PSCredential( (read-host -Prompt "Username for Brightspace Service Account"), (read-host -Prompt "Password for Brightspace Service Account" -asSecureString))
			brightspaceAppAccount		= New-Object PSCredential( (read-host -Prompt "Client ID for Brightspace App Account")   , (read-host -Prompt "Client Secret for Brightspace App Account" -asSecureString))
			}
		mkdir $WorkingDirectory	
		$credentials | Export-CliXml -Path "$($WorkingDirectory)\PSCredentials.$env:USERNAME@$env:USERDOMAIN.xml"
	}
	$brightspaceServiceAccountUsername	= $credentials.brightspaceServiceAccount.UserName	
	$brightspaceServiceAccountPassword	= $credentials.brightspaceServiceAccount.GetNetworkCredential().Password
	$clientID							= $credentials.brightspaceAppAccount.UserName
	$clientSecret						= $credentials.brightspaceAppAccount.GetNetworkCredential().Password

	# ===================================================
	# PKCE security - Extra OAuth Security Layer 
	# ===================================================
	$charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	$codeVerifier=""; $i = (Get-Random -Minimum 43 -Maximum 128)
	do { $i -= 1; $codeVerifier += ($charset.ToCharArray() | Get-Random) } while ($i -gt 0)
	$state=""; $i = (Get-Random -Minimum 8 -Maximum 16)
	do { $i -= 1; $state += ($charset.ToCharArray() | Get-Random) } while ($i -gt 0)
	$hasher = New-Object System.Security.Cryptography.SHA256Managed
	$hashedStringBytes = $hasher.ComputeHash( [System.Text.Encoding]::UTF8.GetBytes($codeVerifier) )
	$codeVerifierBase64encoded = [Convert]::ToBase64String($hashedStringBytes)
	$codeVerifierBase64Urlencoded = ($codeVerifierBase64encoded.Split('=')[0]).Replace('+','-').Replace('/','_')
	$codeChallenge = $codeVerifierBase64Urlencoded

	# ===================================================
	# Log in to Brightspace site with local account
	# ===================================================
	$uri 		= "{0}/d2l/lp/auth/login/login.d2l" -f $Domain
	$webSession = New-Object "Microsoft.PowerShell.Commands.WebRequestSession"
	$headers 	= New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Content-Type", "application/x-www-form-urlencoded")
	$body = @{
		"noredirect"	= "1"
		"userName"		= $brightspaceServiceAccountUsername
		"password"		= $brightspaceServiceAccountPassword
	}
	$response = Invoke-WebRequest $uri -Method "POST" -Headers $headers -Body $body -SessionVariable webSession -ErrorVariable webSessionError -ErrorAction Ignore

	# ===================================================
	# Initiate Contact With Authorization EndPoint
	# ===================================================
	$uri		= "{0}?response_type=code&client_id={1}&scope={2}&redirect_uri={3}&state={4}&code_challenge={5}&code_challenge_method=S256" -f $authorizationEndpoint, [system.uri]::EscapeDataString($clientID), [system.uri]::EscapeDataString($Scope), [system.uri]::EscapeDataString($RedirectUri), $state, $codeChallenge
	$response 	= Invoke-WebRequest $uri -Method "GET" -WebSession $webSession -MaximumRedirection 0 -ErrorVariable webSessionError -ErrorAction Ignore

	# ===================================================
	# Step through Redirects until the $RedirectUri is found
	# ===================================================
	while ( $response.Headers.ContainsKey("Location") -and (-not($response.Headers.Location.StartsWith($RedirectUri))) )
	{
		$response = Invoke-WebRequest $response.Headers.Location -Method "GET" -WebSession $webSession -MaximumRedirection 0 -ErrorVariable webSessionError -ErrorAction Ignore
	}

	$webSession.MaximumRedirection = 5  #reset the max redirection

	# ===================================================
	# Extract OAuth Authorization Code
	# ===================================================
	Add-Type -AssemblyName System.Web
	$authorization_code = [system.uri]::UnescapeDataString((([System.Web.HttpUtility]::ParseQueryString($response.Headers.Location.Split('?')[1]))["code"]))
	$stateResponse=(([System.Web.HttpUtility]::ParseQueryString($response.Headers.Location.Split('?')[1]))["state"])

	if (!$state.Equals($stateResponse)) {
		Write-Host "*** ERROR ***: The sent value of the url state parameter did not match the received value."
		exit 1
	}
	
	# ===================================================
	# Initiate Contact With Token Endpoint
	# ===================================================
	$uri = $tokenEndpoint
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$base64encodedCredentials = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(("{0}:{1}" -f $clientID, $clientSecret)))
	$headers = @{
		"Content-Type"	= "application/x-www-form-urlencoded"
		"Authorization"	= "Basic {0}" -f $base64encodedCredentials
		"User-Agent" 	= "Powershell Script"
		"Accept"		= "*/*"
		"Cache-Control"	= "no-cache"
		"Host"			= "auth.brightspace.com"
	}
	$body = @{
		"grant_type"	= "authorization_code"
		"code"			= $authorization_code
		"redirect_uri"	= $RedirectUri
		"client_id"		= $clientID
		"code_verifier" = $codeVerifier
	}
	$response = Invoke-WebRequest $uri -Method "POST" -Headers $headers -Body $body -WebSession $webSession -ErrorVariable webSessionError -ErrorAction Ignore
	
	$r = ($response.Content | ConvertFrom-Json)

	$apiToken = @{
			AccessToken  = $r.access_token
			RefreshToken = $r.refresh_token
			ExpiresIn 	 = $r.expires_in
			Scope 		 = $r.scope
			TokenType 	 = $r.token_type
			Domain 		 = $domain
	}
	return $apiToken
}
		
Export-ModuleMember -Function '*'

