[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$ClientId="",

    [Parameter(Mandatory=$true)]
    [string]$ClientSecret = ""
)

try {
    if (($null -eq $ClientId) -or ($ClientId -eq "")) {
        Write-Output "No Client Id provided"
        {break}
    }
        if (($null -eq $ClientSecret) -or ($ClientSecret -eq "")){
        Write-Output "No Client Secret provided"
        {break}
    }
    else {
        Write-Host "Client Id     : "$ClientId
        Write-Host "Client Secret : "$ClientSecret
    }
} catch {
    Write-Error "An error occurred: $_"
    exit 1
}

Clear-Host
Write-Output "==============================================================================="
Write-Output "Sophos API - List all Licenses Details"
Write-Output "==============================================================================="


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

# Write-Host $WhoamiHead

# Check if we are using tenant (Central Admin) credentials
if ($Result.idType -ne "tenant") {
    Write-Output "Aborting script - idType does not match tenant!"
    Break
}

# Save Response details
$TenantID = $Result.id
# $DataRegion = $Result.ApiHosts.dataRegion
$DataRegion = $Result.ApiHosts

# $EndpointList = @()
#$NextKey = $null

################# INSERT CODE HERE ###############
# add this code snippet to one of the auth code samples for Central Admin, Central Enterprise Dashboard or Central Partner (snippets 1 2 or 3)
# you will find a line that says INSERT CODE HERE
#Date for filename
$ScriptLaunchDate= Get-Date -Format "yyyyMMddHHmmssfff"
#CSV filename and full directory
$CSV_License_list = "Products_Licenses_List_$ScriptLaunchDate.csv"
$CSV_FW_License_list = "Firewall_Licenses_List_$ScriptLaunchDate.csv"



# SOPHOS Licenses API Headers:
$TenantHead = @{}
$TenantHead.Add("Authorization" ,"Bearer $Token")
$TenantHead.Add("X-Tenant-ID" ,"$TenantID")
$TenantHead.Add("Content-Type", "application/json")
$DataRegion ="https://api.central.sophos.com/licenses/v1/licenses"

#Write-Host $Token
#Write-Host $TenantID

    $GetLicenses = (Invoke-RestMethod -Method Get -Uri $DataRegion -Headers $TenantHead -ErrorAction SilentlyContinue -ErrorVariable ScriptError)
    $License_list=$GetLicenses.licenses

$DataFirewall="https://api.central.sophos.com/licenses/v1/licenses/firewalls"
$GetLicensesFirewall = (Invoke-RestMethod -Method Get -Uri $DataFirewall -Headers $TenantHead -ErrorAction SilentlyContinue -ErrorVariable ScriptError)
$FirewallItemsList=$GetLicensesFirewall.items



Write-Output ""
Write-Output ""    
Write-Output "==============================================================================="
Write-Output "List Products Licenses details"
Write-Output "==============================================================================="
$ProductLicensesTable=New-Object System.Data.Datatable
[void]$ProductLicensesTable.Columns.Add("Unique ID")
[void]$ProductLicensesTable.Columns.Add("License ID")
[void]$ProductLicensesTable.Columns.Add("Product Code")
[void]$ProductLicensesTable.Columns.Add("Product Name")
[void]$ProductLicensesTable.Columns.Add("Product Generic Code")
[void]$ProductLicensesTable.Columns.Add("Start Date")
[void]$ProductLicensesTable.Columns.Add("End Date")
[void]$ProductLicensesTable.Columns.Add("Perpetual License")
[void]$ProductLicensesTable.Columns.Add("License Type")
[void]$ProductLicensesTable.Columns.Add("Quantity")
[void]$ProductLicensesTable.Columns.Add("Unlimited")
[void]$ProductLicensesTable.Columns.Add("Current Usage")
[void]$ProductLicensesTable.Columns.Add("Current Usage Date")
[void]$ProductLicensesTable.Columns.Add("Current Usage Colleced At")



foreach ($FWC in $License_list) {

    $StartingDateFormat=[datetime]::ParseExact($FWC.startDate, "yyyy-MM-dd",$null).ToString("dd/MM/yyyy")
    $EndingDateFormat=[datetime]::ParseExact($FWC.endDate, "yyyy-MM-dd",$null).ToString("dd/MM/yyyy")
    $UsagegDateFormat=[datetime]::ParseExact($FWC.usage.current.date, "yyyy-MM-dd",$null).ToString("dd/MM/yyyy")
 #   $UsageCollectedDateFormat=[datetime]::ParseExact($FWC.usage.current.collectedAt, "yyyy-MM-dd",$null).ToString("dd/MM/yyyy")
[void]$ProductLicensesTable.Rows.Add($FWC.id,$FWC.licenseIdentifier,$FWC.Product.code,$FWC.Product.name,$FWC.Product.GenericCode,$StartingDateFormat,$EndingDateFormat,$FWC.perpetual,$FWC.type,$FWC.quantity,$FWC.unlimited,$FWC.usage.current.count,$UsagegDateFormat,$FWC.usage.current.collectedAt)
}

#$ProductLicensesTable
#$License_list | Format-Table -Property @{label='id';e={$_.id}}, 
#                                                    @{label='licenseIdentifier';e={$_.licenseIdentifier}}, 
#                                                    @{label='Product Code';e={$_.Product.code}},
#                                                    @{label='Product Generic Code';e={$_.Product.GenericCode}},                                                    
#                                                    @{label='Product Name';e={$_.Product.name}},                                                    
#                                                    @{label='Start Date';e={[datetime]::ParseExact($_.startDate, "yyyy-MM-dd",$null).ToString("dd/MM/yyyy")}},
#                                                    @{label='End Date';e={[datetime]::ParseExact($_.endDate, "yyyy-MM-dd",$null).ToString("dd/MM/yyyy")}},
#                                                    @{label='Perpetual';e={$_.perpetual}},
#                                                    @{label='Unlimited';e={$_.unlimited}},                                                    
#                                                    @{label='Type';e={$_.type}},
#                                                    @{label='Quantity';e={$_.quantity}},
#                                                    @{label='Usage Count';e={$_.usage.current.count}},                                                                                                                                                            
#                                                    @{label='Usage Date';e={$_.usage.current.date}},
#                                                    @{label='CollectedAt';e={$_.usage.current.collectedAt}}  

Write-Output ""
Write-Output ""    
Write-Output "==============================================================================="
Write-Output "List Firewall Licenses details"
Write-Output "==============================================================================="

$FirewallsLicensesTable=New-Object System.Data.Datatable
[void]$FirewallsLicensesTable.Columns.Add("Serial Number")
[void]$FirewallsLicensesTable.Columns.Add("Owner ID")
[void]$FirewallsLicensesTable.Columns.Add("Owner Type")
[void]$FirewallsLicensesTable.Columns.Add("Org ID")
[void]$FirewallsLicensesTable.Columns.Add("Partner")
[void]$FirewallsLicensesTable.Columns.Add("Tenant ID")
[void]$FirewallsLicensesTable.Columns.Add("Billing Tenant")
[void]$FirewallsLicensesTable.Columns.Add("Model")
[void]$FirewallsLicensesTable.Columns.Add("Model Type")
[void]$FirewallsLicensesTable.Columns.Add("Last Seen")
[void]$FirewallsLicensesTable.Columns.Add("License 01 UID")
[void]$FirewallsLicensesTable.Columns.Add("License 01 ID")
[void]$FirewallsLicensesTable.Columns.Add("License 01 Product Code")
[void]$FirewallsLicensesTable.Columns.Add("License 01 Product Name")
[void]$FirewallsLicensesTable.Columns.Add("License 01 Product Generic Code")
[void]$FirewallsLicensesTable.Columns.Add("License 01 Start Date")
[void]$FirewallsLicensesTable.Columns.Add("License 01 End Date")
[void]$FirewallsLicensesTable.Columns.Add("License 01 Perpetual")
[void]$FirewallsLicensesTable.Columns.Add("License 01 Type")
[void]$FirewallsLicensesTable.Columns.Add("License 01 Quantity")
[void]$FirewallsLicensesTable.Columns.Add("License 02 UID")
[void]$FirewallsLicensesTable.Columns.Add("License 02 ID")
[void]$FirewallsLicensesTable.Columns.Add("License 02 Product Code")
[void]$FirewallsLicensesTable.Columns.Add("License 02 Product Name")
[void]$FirewallsLicensesTable.Columns.Add("License 02 Product Generic Code")
[void]$FirewallsLicensesTable.Columns.Add("License 02 Start Date")
[void]$FirewallsLicensesTable.Columns.Add("License 02 End Date")
[void]$FirewallsLicensesTable.Columns.Add("License 02 Perpetual")
[void]$FirewallsLicensesTable.Columns.Add("License 02 Type")
[void]$FirewallsLicensesTable.Columns.Add("License 02 Quantity")
[void]$FirewallsLicensesTable.Columns.Add("License 03 UID")
[void]$FirewallsLicensesTable.Columns.Add("License 03 ID")
[void]$FirewallsLicensesTable.Columns.Add("License 03 Product Code")
[void]$FirewallsLicensesTable.Columns.Add("License 03 Product Name")
[void]$FirewallsLicensesTable.Columns.Add("License 03 Product Generic Code")
[void]$FirewallsLicensesTable.Columns.Add("License 03 Start Date")
[void]$FirewallsLicensesTable.Columns.Add("License 03 End Date")
[void]$FirewallsLicensesTable.Columns.Add("License 03 Perpetual")
[void]$FirewallsLicensesTable.Columns.Add("License 03 Type")
[void]$FirewallsLicensesTable.Columns.Add("License 03 Quantity")
[void]$FirewallsLicensesTable.Columns.Add("License 04 UID")
[void]$FirewallsLicensesTable.Columns.Add("License 04 ID")
[void]$FirewallsLicensesTable.Columns.Add("License 04 Product Code")
[void]$FirewallsLicensesTable.Columns.Add("License 04 Product Name")
[void]$FirewallsLicensesTable.Columns.Add("License 04 Product Generic Code")
[void]$FirewallsLicensesTable.Columns.Add("License 04 Start Date")
[void]$FirewallsLicensesTable.Columns.Add("License 04 End Date")
[void]$FirewallsLicensesTable.Columns.Add("License 04 Perpetual")
[void]$FirewallsLicensesTable.Columns.Add("License 04 Type")
[void]$FirewallsLicensesTable.Columns.Add("License 04 Quantity")
[void]$FirewallsLicensesTable.Columns.Add("License 05 UID")
[void]$FirewallsLicensesTable.Columns.Add("License 05 ID")
[void]$FirewallsLicensesTable.Columns.Add("License 05 Product Code")
[void]$FirewallsLicensesTable.Columns.Add("License 05 Product Name")
[void]$FirewallsLicensesTable.Columns.Add("License 05 Product Generic Code")
[void]$FirewallsLicensesTable.Columns.Add("License 05 Start Date")
[void]$FirewallsLicensesTable.Columns.Add("License 05 End Date")
[void]$FirewallsLicensesTable.Columns.Add("License 05 Perpetual")
[void]$FirewallsLicensesTable.Columns.Add("License 05 Type")
[void]$FirewallsLicensesTable.Columns.Add("License 05 Quantity")
[void]$FirewallsLicensesTable.Columns.Add("License 06 UID")
[void]$FirewallsLicensesTable.Columns.Add("License 06 ID")
[void]$FirewallsLicensesTable.Columns.Add("License 06 Product Code")
[void]$FirewallsLicensesTable.Columns.Add("License 06 Product Name")
[void]$FirewallsLicensesTable.Columns.Add("License 06 Product Generic Code")
[void]$FirewallsLicensesTable.Columns.Add("License 06 Start Date")
[void]$FirewallsLicensesTable.Columns.Add("License 06 End Date")
[void]$FirewallsLicensesTable.Columns.Add("License 06 Perpetual")
[void]$FirewallsLicensesTable.Columns.Add("License 06 Type")
[void]$FirewallsLicensesTable.Columns.Add("License 06 Quantity")
[void]$FirewallsLicensesTable.Columns.Add("License 07 UID")
[void]$FirewallsLicensesTable.Columns.Add("License 07 ID")
[void]$FirewallsLicensesTable.Columns.Add("License 07 Product Code")
[void]$FirewallsLicensesTable.Columns.Add("License 07 Product Name")
[void]$FirewallsLicensesTable.Columns.Add("License 07 Product Generic Code")
[void]$FirewallsLicensesTable.Columns.Add("License 07 Start Date")
[void]$FirewallsLicensesTable.Columns.Add("License 07 End Date")
[void]$FirewallsLicensesTable.Columns.Add("License 07 Perpetual")
[void]$FirewallsLicensesTable.Columns.Add("License 07 Type")
[void]$FirewallsLicensesTable.Columns.Add("License 07 Quantity")
[void]$FirewallsLicensesTable.Columns.Add("License 08 UID")
[void]$FirewallsLicensesTable.Columns.Add("License 08 ID")
[void]$FirewallsLicensesTable.Columns.Add("License 08 Product Code")
[void]$FirewallsLicensesTable.Columns.Add("License 08 Product Name")
[void]$FirewallsLicensesTable.Columns.Add("License 08 Product Generic Code")
[void]$FirewallsLicensesTable.Columns.Add("License 08 Start Date")
[void]$FirewallsLicensesTable.Columns.Add("License 08 End Date")
[void]$FirewallsLicensesTable.Columns.Add("License 08 Perpetual")
[void]$FirewallsLicensesTable.Columns.Add("License 08 Type")
[void]$FirewallsLicensesTable.Columns.Add("License 08 Quantity")


foreach ($Obj in $FirewallItemsList) {

#    $StartingDateFormat=[datetime]::ParseExact($FWC.startDate, "yyyy-MM-dd",$null).ToString("dd/MM/yyyy")
#    $EndingDateFormat=[datetime]::ParseExact($FWC.endDate, "yyyy-MM-dd",$null).ToString("dd/MM/yyyy")
#    $UsagegDateFormat=[datetime]::ParseExact($FWC.usage.current.date, "yyyy-MM-dd",$null).ToString("dd/MM/yyyy")
 
[void]$FirewallsLicensesTable.Rows.Add($Obj.serialNumber,
$Obj.owner.id,
$Obj.owner.type,
$Obj.organization.id,
$Obj.Partner,
$Obj.tenant.id,
$Obj.billingTenant,
$Obj.model,
$Obj.modelType,
$Obj.lastSeenAt,
$Obj.licenses[0].id,
$Obj.licenses[0].licenseIdentifier,
$Obj.licenses[0].Product.code,
$Obj.licenses[0].Product.name,
$Obj.licenses[0].Product.genericCode,
$Obj.licenses[0].startDate,
$Obj.licenses[0].endDate,
$Obj.licenses[0].perpetual,
$Obj.licenses[0].type,
$Obj.licenses[0].quantity,
$Obj.licenses[1].id,
$Obj.licenses[1].licenseIdentifier,
$Obj.licenses[1].Product.code,
$Obj.licenses[1].Product.name,
$Obj.licenses[1].Product.genericCode,
$Obj.licenses[1].startDate,
$Obj.licenses[1].endDate,
$Obj.licenses[1].perpetual,
$Obj.licenses[1].type,
$Obj.licenses[1].quantity,
$Obj.licenses[2].id,
$Obj.licenses[2].licenseIdentifier,
$Obj.licenses[2].Product.code,
$Obj.licenses[2].Product.name,
$Obj.licenses[2].Product.genericCode,
$Obj.licenses[2].startDate,
$Obj.licenses[2].endDate,
$Obj.licenses[2].perpetual,
$Obj.licenses[2].type,
$Obj.licenses[2].quantity,
$Obj.licenses[3].id,
$Obj.licenses[3].licenseIdentifier,
$Obj.licenses[3].Product.code,
$Obj.licenses[3].Product.name,
$Obj.licenses[3].Product.genericCode,
$Obj.licenses[3].startDate,
$Obj.licenses[3].endDate,
$Obj.licenses[3].perpetual,
$Obj.licenses[3].type,
$Obj.licenses[3].quantity,
$Obj.licenses[4].id,
$Obj.licenses[4].licenseIdentifier,
$Obj.licenses[4].Product.code,
$Obj.licenses[4].Product.name,
$Obj.licenses[4].Product.genericCode,
$Obj.licenses[4].startDate,
$Obj.licenses[4].endDate,
$Obj.licenses[4].perpetual,
$Obj.licenses[4].type,
$Obj.licenses[4].quantity,
$Obj.licenses[5].id,
$Obj.licenses[5].licenseIdentifier,
$Obj.licenses[5].Product.code,
$Obj.licenses[5].Product.name,
$Obj.licenses[5].Product.genericCode,
$Obj.licenses[5].startDate,
$Obj.licenses[5].endDate,
$Obj.licenses[5].perpetual,
$Obj.licenses[5].type,
$Obj.licenses[5].quantity,
$Obj.licenses[6].id,
$Obj.licenses[6].licenseIdentifier,
$Obj.licenses[6].Product.code,
$Obj.licenses[6].Product.name,
$Obj.licenses[6].Product.genericCode,
$Obj.licenses[6].startDate,
$Obj.licenses[6].endDate,
$Obj.licenses[6].perpetual,
$Obj.licenses[6].type,
$Obj.licenses[6].quantity,
$Obj.licenses[7].id,
$Obj.licenses[7].licenseIdentifier,
$Obj.licenses[7].Product.code,
$Obj.licenses[7].Product.name,
$Obj.licenses[7].Product.genericCode,
$Obj.licenses[7].startDate,
$Obj.licenses[7].endDate,
$Obj.licenses[7].perpetual,
$Obj.licenses[7].type,
$Obj.licenses[7].quantity)
}


# 8 Licences possibles.











    

#$FirewallItemsList | Format-Table -Property @{label='Serial #';e={$_.serialNumber}}, 
#                                                    @{label='Owner ID';e={$_.owner.id}},  
#                                                    @{label='Owner Type';e={$_.owner.type}},
#                                                    @{label='Organization';e={$_.organization.id}},
#                                                    @{label='Partner';e={$_.partner.id}},
#                                                    @{label='Tenant';e={$_.tenant.id}},
#                                                    @{label='Billing Tenant';e={$_.billingTenant}},
#                                                    @{label='Model Type';e={$_.modelType}},
#                                                    @{label='Model';e={$_.model}},
#                                                    @{label='Last Seen';e={$_.lastSeenAt}}                                                    
                                                                                                       
                                                                                                                                                           
#Create files
# (Get-Culture).DateTimeFormat.ShortDatePattern
$ProductLicensesTable
$FirewallsLicensesTable
#$ProductLicensesTable | Export-Csv -Path $CSV_License_list -UseCulture
#$FirewallsLicensesTable | Export-Csv -Path $CSV_FW_License_list -UseCulture
