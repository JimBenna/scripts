param (
    [Parameter(Mandatory=$true)]
    [string]$ParamClientId = "",

    [Parameter(Mandatory=$true)]
    [string]$ParamClientSecret = "",

    [Parameter(Mandatory=$true)]
    [string]$JsonInputFile = ""
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
    if (($null -eq $JsonInputFile) -or ($JsonInputFile -eq "")){
        Write-Output "No JSON input file provided"
        {break}
    }
    else 
    {
        $resultClient = Split-StringAfterEqualSign -inputString $ParamClientId
        #Write-Host "Id Client     : "$resultClient.Key
        #Write-Host "Client ID     : "$resultClient.Value
        $ClientId=$resultClient.Value
        $resultSecret = Split-StringAfterEqualSign -inputString $ParamClientSecret
        #Write-Host "Id Secret     : "$resultSecret.Key
        #Write-Host "Client Secret : "$resultSecret.Value
        $ClientSecret=$resultSecret.Value
        $JsonFileVariable = Split-StringAfterEqualSign -inputString $JsonInputFile
        $JsonFile = $JsonFileVariable.Value
        if (-Not (Test-Path -Path $JsonFile)) 
        {
            # Input file does not exist, we should stop
            Write-Host "File "$JsonFile" does not exist"
            exit 11
        }
        else 
        {
            try {
                $file01 = Get-Item $JsonFile
                $file01.OpenRead().Close()    
            }
            catch {
                Write-Host "File "$JsonFile" exists but can not be accessed in Read mode"
                exit 12    
            }
        }
    }
} catch {
    Write-Error "A basic error occurred: $_"
    exit 1
}
Write-Output "==============================================================================="
Write-Output "              Sophos CENTRAL API - Update Protection Policies"
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

# SOPHOS Endpoint API Headers:
$TenantHead = @{}
$TenantHead.Add("Authorization" ,"Bearer $Token")
$TenantHead.Add("X-Tenant-ID" ,"$TenantID")
$TenantHead.Add("Content-Type", "application/json")

# Define URI for updating the local site list
$Uri = $DataRegion+"/endpoint/v1/policies"


# Import data from CSV
Write-Output "Importing data from json input file..."
Write-Output ""
Get-Content
$local:importFile = Get-content -Path $JsonFile -Raw | ConvertFrom-Json 
$local:ArrayPolicySettings = @($local:importFile)

$local:ArrayPolicySettings | Format-Table -Wrap

# Iterate through all sites from CSV
Write-Output "Updating Protection Policies in Sophos Central..."
Write-Output ""

foreach ($Item in $local:ArrayPolicySettings)
{
    $Body = $Item | ConvertTo-Json -Depth 5
Write-Host "Body ID               :"$Item.id
#Write-host "Body Settings         :"$Item.Settings
write-host "Body Settings in Json :"$($Item.settings) | ConvertTo-Json -Depth 5

    # Invoke Request
#    $Result = (Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Headers $TenantHead -Body $Body -ErrorAction SilentlyContinue -ErrorVariable ScriptError)
#    Write-Output "Created $($Result.type) Protection policy named : $($Result.name) with ID $($Result.id)"
    
}
Write-Output ""
Write-Output "Successfully updated the protection policies in Sophos Central..."
Write-Output "-----------------------------------------------------------------"