param ([switch] $SaveCredentials)
<#
    Description: Authentication Script for Sophos Central
    Parameters: -SaveCredentials -> will store then entered credentials locally on the PC, this is needed when
                                    running the script unattended
#>

Clear-Host
Write-Output "==============================================================================="
Write-Output "Sophos API - Admin Authentication Example"
Write-Output "==============================================================================="

# Define the filename and path for the credential file
$CredentialFile = $PSScriptRoot + '\Sophos_Central_Admin_Credentials.json'

# Check if Central API Credentials have been stored, if not then prompt the user to enter the credentials
if (((Test-Path $CredentialFile) -eq $false) -or $SaveCredentials){
	# Prompt for Credentials
	$ClientId = Read-Host "Please Enter your Client ID"
    if ($ClientID -eq "") {Break}
	$ClientSecret = Read-Host "Please Enter your Client Secret" -AsSecureString
} else { 
    # Read Credentials from JSON File
    $Credentials = Get-Content $CredentialFile | ConvertFrom-Json
    $ClientId = $Credentials[0]
    $ClientSecret = $Credentials[1] | ConvertTo-SecureString
}

# We are making use of the PSCredentials object to store the API credentials
# The Client Secret will be encrypted for the user excuting the script
# When scheduling execution of the script remember to use the same user context
$SecureCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $ClientId , $ClientSecret

# SOPHOS OAuth URL
$AuthURI = "https://id.sophos.com/api/v2/oauth2/token"

# Body and Header for oAuth2 Authentication
$AuthBody = @{}
$AuthBody.Add("grant_type", "client_credentials")
$AuthBody.Add("client_id", $SecureCredentials.GetNetworkCredential().Username)
$AuthBody.Add("client_secret", $SecureCredentials.GetNetworkCredential().Password)
$AuthBody.Add("scope", "token")
$AuthHead = @{}
$AuthHead.Add("content-type", "application/x-www-form-urlencoded")

# Set TLS Version
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Post Request to SOPHOS for OAuth2 token
try {
    $Result = (Invoke-RestMethod -Method Post -Uri $AuthURI -Body $AuthBody -Headers $AuthHead -ErrorAction SilentlyContinue -ErrorVariable ScriptError)
    if ($SaveCredentials) {
	    $ClientSecret = $ClientSecret | ConvertFrom-SecureString
	    ConvertTo-Json $ClientID, $ClientSecret | Out-File $CredentialFile -Force
    }
} catch {
    # If there's an error requesting the token, say so, display the error, and break:
    Write-Output "" 
	Write-Output "AUTHENTICATION FAILED - Unable to retreive SOPHOS API Authentication Token"
    Write-Output "Please verify the credentials used!" 
    Write-Output "" 
    Write-Output "If you are working with saved credentials then you can reset them by calling"
    Write-Output "this script with the -SaveCredentials parameter"
    Write-Output "" 
    Read-Host -Prompt "Press ENTER to continue..."
    Break
}

# Set the Token for use later on:
$Token = $Result.access_token

# SOPHOS Whoami URI:
$WhoamiURI = "https://api.central.sophos.com/whoami/v1"

# SOPHOS Whoami Headers:
$WhoamiHead = @{}
$WhoamiHead.Add("Content-Type", "application/json")
$WhoamiHead.Add("Authorization", "Bearer $Token")

# Post Request to SOPHOS for Whoami Details:
$Result = (Invoke-RestMethod -Method Get -Uri $WhoamiURI -Headers $WhoamiHead -ErrorAction SilentlyContinue -ErrorVariable ScriptError)

# Check if we are using tenant (Central Admin) credentials
if ($Result.idType -ne "tenant") {
    Write-Output "Aborting script - idType does not match tenant!"
    Break
}

# Save Response details
$TenantID = $Result.id
$DataRegion = $Result.ApiHosts.dataRegion

################# INSERT CODE HERE ###############
# add this code snippet to one of the auth code samples for Central Admin, Central Enterprise Dashboard or Central Partner (snippets 1 2 or 3)
# you will find a line that says INSERT CODE HERE

# Tenant Headers:
$TenantHead = @{}
$TenantHead.Add("Authorization" ,"Bearer $Token")
$TenantHead.Add("X-Tenant-ID" ,"$TenantID")
$TenantHead.Add("Content-Type", "application/json")

if ($null -ne $DataRegion){
	# Post Request to Firewall API:
	$Result = (Invoke-RestMethod -Method Get -Uri $DataRegion"/account-health-check/v1/health-check" -Headers $TenantHead -ErrorAction SilentlyContinue -ErrorVariable ScriptError)
}

Write-Host "Account Health Check"

### Output Protected Endpoints
Write-Host ("`nProtection Status")
Write-Host ("-------------------------------")
Write-Host ("Unprotected Computers: " + $Result.endpoint.protection.computer.notFullyProtected + " out of " + $Result.endpoint.protection.computer.total)
Write-Host ("Unprotected Servers: " + $Result.endpoint.protection.server.notFullyProtected + " out of " + $Result.endpoint.protection.server.total)

### Output Policy Status
Write-Host ("`nPolicy Status")
Write-Host ("-------------------------------")
Write-Host ("Computer policies not on recommended settings: " + $Result.endpoint.policy.computer.'threat-protection'.notOnRecommended + " out of " + $Result.endpoint.policy.computer.'threat-protection'.total)
Write-Host ("Server policies not on recommended settings : " + $Result.endpoint.policy.server.'server-threat-protection'.notOnRecommended + " out of " + $Result.endpoint.policy.server.'server-threat-protection'.total)

### Output Exclusions
Write-Host ("`nExclusion Status")
Write-Host ("-------------------------------")
Write-Host ("Risky exclusions for computers: " + $Result.endpoint.exclusions.policy.computer.numberOfSecurityRisks)
Write-Host ("Risky exclusions for servers: " + $Result.endpoint.exclusions.policy.server.numberOfSecurityRisks)
Write-Host ("Risky global exclusions: " + $Result.endpoint.exclusions.global.numberOfSecurityRisks)

### Output Tamper Protection
Write-Host ("`nTamper Protection")
Write-Host ("-------------------------------")
Write-Host ("Tamper Protection enabled for account: " + $Result.endpoint.tamperProtection.global)
Write-Host ("Computers with disabled Tamper Protection: " + $Result.endpoint.tamperProtection.computer.disabled + " out of " + $Result.endpoint.tamperProtection.computer.total )
Write-Host ("Servers  with disabled Tamper Protection: " + $Result.endpoint.tamperProtection.server.disabled + " out of " + $Result.endpoint.tamperProtection.server.total)  @{label='Central Connection';e={$_.status.connected}}