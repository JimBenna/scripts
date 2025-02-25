param ([switch] $SaveCredentials)
<#
    Description: Authentication Script for Sophos Central
    Parameters: -SaveCredentials -> will store then entered credentials locally on the PC, this is needed when
                                    running the script unattended
#>
Clear-Host
Write-Output "==============================================================================="
Write-Output "Sophos API - List all Licenses Details"
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
$FirewallItemsList | Format-Table -Property @{label='Serial #';e={$_.serialNumber}}, 
                                                    @{label='Owner ID';e={$_.owner.id}},  
                                                    @{label='Owner Type';e={$_.owner.type}},
                                                    @{label='Organization';e={$_.organization.id}},
                                                    @{label='Partner';e={$_.partner.id}},
                                                    @{label='Tenant';e={$_.tenant.id}},
                                                    @{label='Billing Tenant';e={$_.billingTenant}},
                                                    @{label='Model Type';e={$_.modelType}},
                                                    @{label='Model';e={$_.model}},
                                                    @{label='Last Seen';e={$_.lastSeenAt}}                                                    
                                                                                                       
                                                                                                                                                           
#Create files
(Get-Culture).DateTimeFormat.ShortDatePattern
$ProductLicensesTable | Export-Csv -Path $CSV_License_list -UseCulture
#$FirewallItemsList | Export-Csv -Path $CSV_FW_License_list 
