param (
    [Parameter(Mandatory=$true)]
    [string]$ParamClientId = "",

    [Parameter(Mandatory=$true)]
    [string]$ParamClientSecret = ""
)

function Split-StringAfterEqualSign {
    param (
        [string]$inputString
    )

    try {
        if (-not $inputString.Contains("=")) {
            throw "Input string does not contain an '=' sign."
        }

        $splitString = $inputString -split "="
        return @{
            Key = $splitString[0]
            Value = $splitString[1]
        }
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}
Clear-Host
try {
    if (($null -eq $ParamClientId) -or ($ParamClientId -eq "")) {
        Write-Output "No Client Id provided"
        {break}
    }
        if (($null -eq $ParamClientSecret) -or ($ParamClientSecret -eq "")){
        Write-Output "No Client Secret provided"
        {break}
    }
    else {
        $resultClient = Split-StringAfterEqualSign -inputString $ParamClientId
        #Write-Host "Id Client     : "$resultClient.Key
        #Write-Host "Client ID     : "$resultClient.Value
        $ClientId=$resultClient.Value
        $resultSecret = Split-StringAfterEqualSign -inputString $ParamClientSecret
        #Write-Host "Id Secret     : "$resultSecret.Key
        #Write-Host "Client Secret : "$resultSecret.Value
        $ClientSecret=$resultSecret.Value
    }
} catch {
    Write-Error "A basic error occurred: $_"
    exit 1
}
Write-Output "==============================================================================="
Write-Output "Sophos CENTRAL API - Account HealtCheck"
Write-Output "==============================================================================="
# SOPHOS OAuth URL
$AuthURI = "https://id.sophos.com/api/v2/oauth2/token"

# Body and Header for oAuth2 Authentication
$AuthBody = @{}
$AuthBody.Add("grant_type", "client_credentials")
$AuthBody.Add("client_id", $ClientId)
$AuthBody.Add("client_secret", $ClientSecret)
#$AuthBody.Add("client_id", $SecureCredentials.GetNetworkCredential().Username)
#$AuthBody.Add("client_secret", $SecureCredentials.GetNetworkCredential().Password)
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
    Read-Host -Prompt "Press ENTER to continue..."
    exit 2
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
Write-Host ("Servers  with disabled Tamper Protection: " + $Result.endpoint.tamperProtection.server.disabled + " out of " + $Result.endpoint.tamperProtection.server.total)