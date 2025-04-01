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
Write-Output "Sophos CENTRAL API - Display Detections list"
Write-Output "==============================================================================="
#CSV filename and full directory
$ScriptLaunchDate= Get-Date -Format "yyyyMMddHHmmssfff"
$CSV_Endpoints_list = "Cases_list_$ScriptLaunchDate.csv"

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

################# INSERT CODE HERE ###############
# add this code snippet to the auth code samples for Central (snippets 1)
# you will find a line that says INSERT CODE HERE

$Detections_Total = 0
$Detections_Critical = 0
$Detections_High = 0
$Detections_Medium = 0
$Detections_Low = 0
$Detections_Info = 0

# SOPHOS Endpoint API Headers:
$TenantHead = @{}
$TenantHead.Add("Authorization", "Bearer $Token")
$TenantHead.Add("X-Tenant-ID", "$TenantID")
$TenantHead.Add("Content-Type", "application/json")

#Calc last 30 days for the query in UTC format
$currtime = Get-Date
$fromtime = $currtime.AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.FFFZ")
$tilltime = $currtime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.FFFZ")

$TenantBody = '{ "from": "' + $fromtime + '", "to": "' + $tilltime + '"}'

try {
    Write-Output("[Detections] Send Request to retreive the detections from the last 7 days...")
    $Request = (Invoke-RestMethod -Method Post -Uri $DataRegion"/detections/v1/queries/detections" -Headers $TenantHead -Body $TenantBody -ErrorAction SilentlyContinue -ErrorVariable ScriptError)   
    Write-Output "[Detections] Request sent, wait for results..."

    do {
        Start-Sleep -Milliseconds 500
        $Request = (Invoke-RestMethod -Method Get -Uri $DataRegion"/detections/v1/queries/detections/$($Request.id)" -Headers $TenantHead -ErrorAction SilentlyContinue -ErrorVariable ScriptError)   
    } while ($Request.Result -eq "notAvailable")
    Write-Output("[Detections] Request ready, retreiving results")

    $uri = "$($DataRegion)/detections/v1/queries/detections/$($Request.id)/results?pageSize=2000"
    $Detections =  (Invoke-RestMethod -Method Get -Uri $uri -Headers $TenantHead -ErrorAction SilentlyContinue -ErrorVariable ScriptError)
    foreach ($Detection in $Detections.items) {
        $Detections_Total += 1
        
        switch ($Detection.severity) {
            0 {$Detections_info += 0}
            1 {$Detections_Low += 1}
            2 {$Detections_Low += 1}
            3 {$Detections_Low += 1}
            4 {$Detections_Medium += 1}
            5 {$Detections_Medium += 1}
            6 {$Detections_Medium += 1}
            7 {$Detections_High += 1}
            8 {$Detections_High += 1}
            9 {$Detections_Critical += 1}
            10 {$Detections_Critical += 1}
        }
    }

    Write-Output("")
    Write-Output("[Detections] Details:")
    $Detections.items | Format-Table -Property `
        @{label='Severity';e={ if ($_.severity -eq 0) { "Info" } elseif ($_.severity -le 3) { "Low" } elseif ($_.severity -le 6) { "Medium" } elseif ($_.severity -le 8) { "High" } elseif ($_.severity -le 10) { "Critical" }}},
        @{label='Detection';e={$_.detectionRule}}, 
        @{label='time';e={$_.sensorGeneratedAt}}, 
        @{label='Host';e={$_.device.entity}}, 
        @{label='Sensor Type';e={$_.sensor.type}}, 
        @{label='MITRE Attack';e={$_.mitreAttacks.tactic.name}}

    Write-Output("[Detections] Summary:")
    Write-Output("$($Detections_Critical) (Critical) + $($Detections_High) (High) + $($Detections_Medium) (Medium) + $($Detections_Low) (Low) + $($Detections_Info) (Info)")
    Write-Output("$($Detections_Total) detections total")

} catch {
    # Something went wrong, get error details...
    Write-Host "   --> $($_)"
}