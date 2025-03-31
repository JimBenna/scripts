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
Write-Output "Sophos CENTRAL API - Endpoints Status"
Write-Output "==============================================================================="
#Date Management for variable

#CSV filename and full directory
$ScriptLaunchDate= Get-Date -Format "yyyyMMddHHmmssfff"
$CSV_Endpoints_list = "Endpoints_list_$ScriptLaunchDate.csv"


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

$EndpointList = @()
$NextKey = $null

# SOPHOS Endpoint API Headers:
$TenantHead = @{}
$TenantHead.Add("Authorization" ,"Bearer $Token")
$TenantHead.Add("X-Tenant-ID" ,"$TenantID")
$TenantHead.Add("Content-Type", "application/json")

do {
    $GetEndpoints = (Invoke-RestMethod -Method Get -Uri $DataRegion"/endpoint/v1/endpoints?pageTotal=true&pageFromKey=$NextKey&fields=hostname,tamperProtectionEnabled,health,os&view=summary&sort=healthStatus" -Headers $TenantHead -ErrorAction SilentlyContinue -ErrorVariable ScriptError)
    $NextKey = $GetEndpoints.pages.nextKey

    $EndpointList += $GetEndpoints.items
} while ($null -ne $NextKey)      

Write-Output $EndpointList | Format-Table -Property @{label='Name';e={$_.Hostname}}, 
                                                    @{label='TP Status';align='right';e={$_.tamperProtectionEnabled}},
                                                    @{label='Health Overall';align='right';e={$_.health.overall}}, 
                                                    @{label='Health Threats';align='right';e={$_.health.threats.status}}, 
                                                    @{label='Health Services';align='right';e={$_.health.services.status}}, 
                                                    @{label='OS';e={$_.os.name}}


$FilterData=New-Object System.Data.Datatable
[void]$FilterData.Columns.Add("HostID")
[void]$FilterData.Columns.Add("Hostname")
[void]$FilterData.Columns.Add("HealtStatus")
[void]$FilterData.Columns.Add("ThreatsList")
[void]$FilterData.Columns.Add("Services")
[void]$FilterData.Columns.Add("IsServer")
[void]$FilterData.Columns.Add("Platform")
[void]$FilterData.Columns.Add("Name")
[void]$FilterData.Columns.Add("MajorVersion")
[void]$FilterData.Columns.Add("MinorVersion")
[void]$FilterData.Columns.Add("BuildVersion")
[void]$FilterData.Columns.Add("TamperProtectionEnabled")


foreach ($row in $EndpointList) 
{
    [void]$FilterData.Rows.Add($row.id,$row.hostname,$row.health.overall,$row.health.threats.status,$row.services,$row.os.IsServer,$row.os.platform, $row.os.name, $row.os.majorVersion, $row.os.minorVersion, $row.os.build, $row.tamperProtectionEnabled)       
}
#Create files
#$FilterData
$FilterData | Export-Csv -Path $CSV_Endpoints_list -NoTypeInformation                                                    
