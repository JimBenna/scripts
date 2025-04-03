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
Write-Output "            Sophos CENTRAL API - Endpoints details and Status"
Write-Output "==============================================================================="
#Date Management for variable

#CSV filename and full directory
$ScriptLaunchDate= Get-Date -Format "yyyyMMddHHmmssfff"
$OutputFile = "Endpoints_list_$ScriptLaunchDate.json"


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

$EndpointList = @()
$NextKey = $null

# SOPHOS Endpoint API Headers:
$TenantHead = @{}
$TenantHead.Add("Authorization" ,"Bearer $Token")
$TenantHead.Add("X-Tenant-ID" ,"$TenantID")
$TenantHead.Add("Content-Type", "application/json")

do {
    $GetEndpoints = (Invoke-RestMethod -Method Get -Uri $DataRegion"/endpoint/v1/endpoints?pageTotal=true&pageFromKey=$NextKey&view=summary&sort=healthStatus" -Headers $TenantHead -ErrorAction SilentlyContinue -ErrorVariable ScriptError)
    $NextKey = $GetEndpoints.pages.nextKey
    $EndpointList += $GetEndpoints.items
} while ($null -ne $NextKey)      
#$EndpointList
$EndpointsListArray = @()
foreach ($Node in $EndpointList) {
    $EndpointsListArray += [pscustomobject]@{
        id                      = $Node.id
        type                    = $Node.type
        hostname                = $Node.hostname
        HealthStatus            = $Node.health.overall
        HealthThreats           = $Node.health.threats
        HealthServices          = $Node.health.services
        IsServer                = $Node.os.IsServer
        platform                = $Node.os.platform
        name                    = $Node.os.name
        OsMajorVersion          = $Node.os.majorVersion
        OsMinorVersion          = $Node.os.minorVersion
        OsBuild                 = $Node.os.build
        IpV4AddList             = $Node.ipv4Addresses
        IpV6AddList             = $Node.ipv6Addresses
        MacAddList              = $Node.macAddresses           
        LoggedUser              = $Node.associatedPerson.viaLogin
        TamperProtectionStatus  = $Node.tamperProtectionEnabled
        IsolationStatus         = $Node.isolation.status
        IsolatedByAdmin         = $Node.isolation.adminIsolated
        IsolatedAuto            = $Node.isolation.selfIsolated
    }
}

#$EndpointsListArray | Format-Table -Wrap
$Table_In_JSON = $EndpointsListArray | Sort-Object -Property id | ConvertTo-Json -Depth 5
#$Table_In_JSON
$Table_In_JSON | Out-File -FilePath $OutputFile utf8    
Write-Output ""
Write-Output "Script executed successfully ..."
                                                   
