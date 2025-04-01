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
Write-Output "Sophos CENTRAL API - Retrieve Cases list"
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

$Cases_Total = 0
$Cases_Critical = 0
$Cases_High = 0
$Cases_Medium = 0
$Cases_Low = 0
$Cases_Info = 0
$Cases_Unknown = 0

# SOPHOS Endpoint API Headers:
$TenantHead = @{}
$TenantHead.Add("Authorization", "Bearer $Token")
$TenantHead.Add("X-Tenant-ID", "$TenantID")
$TenantHead.Add("Content-Type", "application/json")

try {
    Write-Output("[Cases] Retreive cases created in the last 30 days...")
    $Cases = (Invoke-RestMethod -Method get -Uri $DataRegion"/cases/v1/cases?createdAfter=-P30D&pageSize=5000" -Headers $TenantHead  -ErrorAction SilentlyContinue -ErrorVariable ScriptError)   

    foreach ($Case in $Cases.items) {
        $Cases_Total += 1

        switch ($Case.severity) {
            "Informational" {$Cases_Info += 1}
            "low"           {$Cases_Low += 1}
            "medium"        {$Cases_Medium += 1}
            "high"          {$Cases_Higg += 1}
            "critical"      {$Cases_Critical += 1}
            Default         {$Cases_Unknown += 1}
        }
    }

    Write-Output("")
    Write-Output("[Cases] Details:")
    $Cases.items | Format-Table -Property `
        @{label='Severity';e={$_.severity}},
        @{label='Case ID';e={$_.id}}, 
        @{label='Status';e={$_.status}}, 
        @{label='Assignee';e={$_.assignee.name}}, 
        @{label='Name';e={$_.name}}, 
        @{label='Managed By';e={$_.managedBy}},
        @{label='Case type';e={$_.type}}

    Write-Output("[Cases] Summary:")
    Write-Output("$($Cases_Critical) (Critical) + $($Cases_High) (High) + $($Cases_Medium) (Medium) + $($Cases_Low) (Low) + $($Cases_Info) (Info) + $($Cases_Unknown) (Not classified yet)")
    Write-Output("$($Cases_Total) Cases total")

} catch {
    # Something went wrong, get error details...
    Write-Host "   --> $($_)"
}