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
Write-Output "Sophos API - Firewall updates status check"
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

#Date Management for variable

#CSV filename and full directory
$ScriptLaunchDate= Get-Date -Format "yyyyMMddHHmmssfff"
$CSVFW_list = "Firewalls_list_$ScriptLaunchDate.csv"
$CSVFW_Upgrade_list = "Firewalls_Upgradable_$ScriptLaunchDate.csv"
$CSVFW_Clusters_list = "Firewalls_clusters_$ScriptLaunchDate.csv"


#Write-Host $ScriptLaunchDate

# Create table for storing results
$FirewallTable = New-Object System.Data.Datatable
[void]$FirewallTable.Columns.Add("CustomerTenant")
[void]$FirewallTable.Columns.Add("Serial")
[void]$FirewallTable.Columns.Add("Hostname")
[void]$FirewallTable.Columns.Add("FwID")
[void]$FirewallTable.Columns.Add("Label")
[void]$FirewallTable.Columns.Add("Firmware_Name")
[void]$FirewallTable.Columns.Add("Firmware_version")
[void]$FirewallTable.Columns.Add("Upgrade_to")
[void]$FirewallTable.Columns.Add("Connected")
[void]$FirewallTable.Columns.Add("Management")


# SOPHOS API Headers:
$TenantHead = @{}
$TenantHead.Add("Authorization", "Bearer $Token")
$TenantHead.Add("X-Tenant-ID", "$TenantID")
$TenantHead.Add("Content-Type", "application/json")

# Post Request to Firewall API:
$FWList = (Invoke-RestMethod -Method Get -Uri $DataRegion"/firewall/v1/firewalls" -Headers $TenantHead -ErrorAction SilentlyContinue -ErrorVariable ScriptError)

$FWClusterTable=New-Object System.Data.Datatable
[void]$FWClusterTable.Columns.Add("CustomerTenantID")
[void]$FWClusterTable.Columns.Add("ClusterID")
[void]$FWClusterTable.Columns.Add("ClusterMode")
[void]$FWClusterTable.Columns.Add("UnitID")
[void]$FWClusterTable.Columns.Add("UnitSerialNumber")
[void]$FWClusterTable.Columns.Add("UnitStatus")
[void]$FWClusterTable.Columns.Add("PeerID")
[void]$FWClusterTable.Columns.Add("PeerSerialNumber")



foreach ($FWC in $FWList.items) {

    if ($null -ne $FWC.cluster) {
[void]$FWClusterTable.Rows.Add($FWC.tenant.id,$FWC.cluster.id,$FWC.cluster.mode,$FWC.id,$FWC.serialNumber,$FWC.cluster.Status,$FWC.cluster.peers.id, $FWC.cluster.peers.serialNumber)       
}
}
# $FWClusterTable


foreach ($FW in $FWList.items) {
    # Only check firewall with Firewall Management active
    if ($null -ne $FW.status.managingStatus) {
        $Body = '{ "firewalls": ["'+$FW.id+'"]}'
        try {
            $FWCheck = (Invoke-RestMethod -Method POST -Uri $DataRegion"/firewall/v1/firewalls/actions/firmware-upgrade-check" -Headers $TenantHead -Body $Body)
                If  ( $FWCheck.firmwareVersions.Count -gt 0 )
                        {

# Soft UPGRADE list the last entry of upgradable version to enable step by step updates.
# Let's imagine the following scenario : Firewall is in version X.123
# And it can be updated to X.345 or X.678, or X.789, then we will update step by step. the script will take in consideration upgrade from X.123 to X.345

                        $MajIndex=$FWCheck.firmwareVersions.count-1
                        $UpgradeToVersion=$FWCheck.firmwareVersions[$MajIndex].version
                        }
                else    {
                        #$UpgradeToVersion = $null
                        $UpgradeToVersion = ""
                        }
            [void]$FirewallTable.Rows.Add($FW.tenant.id, $FW.serialNumber,$FW.hostname, $FW.id, $FW.name, $FW.firmwareVersion, $FWCheck.firewalls.firmwareVersion, $UpgradeToVersion, $FW.status.connected,$FW.status.managingStatus)
        } catch {
            # No result found --> Central Firewall Management not active!
        }
    }
}

# Display the results 
# $FirewallTable                                               

#$FirewallTable | Format-Table -wrap -Property   @{label='Hostname           ';e={$_.Hostname}},
#                                                @{label='Serial Number      ';e={$_.Serial}},
#                                                @{label='Firewall ID        ';e={$_.FwID}},                                                
#                                                @{label='Firmware Name      ';e={$_.Firmware_Name}}, 
#                                                @{label='Firmware Version   ';e={$_.Firmware_version}}, 
#                                                @{label='Upgrade to version ';e={$_.Upgrade_to}},                                               
#                                                @{label='Connected          ';e={$_.Connected}},
#                                                @{label='Managing Status    ';e={$_.Management}}

$FilterData=@()
#$FilterData=$FirewallTable | Where-Object {$_.Upgrade_to.Value -notcontains $null -and $_.Upgrade_to.Value -notcontains ""}
#$FilterData=$FirewallTable
foreach ($row in $FirewallTable) {
    # Check if cell number 06 in the row is not empty
     if ($row[7
     
     ] -ne "") {
         $FilterData += ,$row
    }
}
#$FirewallTable| Sort-Object -Property CustomerTenant,Serial
#Write-host "-----"
#$FilterData| Sort-Object -Property CustomerTenant,Serial
#Write-host "-----"
#$FWClusterTable| Sort-Object -Property CustomerTenantID,ClusterID



#Create files
#$FilterData | Export-Csv -Path $CSVOutputFile -NoHeader -NoTypeInformation
$FirewallTable | Export-Csv -Path $CSVFW_list
$FilterData | Export-Csv -Path $CSVFW_Upgrade_list 
$FWClusterTable | Export-Csv -Path $CSVFW_Clusters_list