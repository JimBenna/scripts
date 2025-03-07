# This script reads 2 json files 
# 1. contains firewall list
# 2. Output of data retrieved from each firewalls in the list
#
# ---- CLI Parameters ----
param (
    [Parameter(Mandatory = $true, HelpMessage = "Please provide Firewalls list file in JSON format :")]
    [string]$Param01 = "",
    # Param01 is firewalls list.    
    [Parameter(Mandatory = $true, HelpMessage = "Please provide Output file name with full path    :")]
    [string]$Param02 = ""
    # Param02 is the Input JSON file that contains the URL that aree retrieved from each firewall in the list
    
)
Clear-Host
Write-Output "==============================================================================="
Write-Output "Sophos Firewall API - Retrieve Web Filtering URL lists"
Write-Output "==============================================================================="
Write-Output ""
Write-Output "It requires 2 parameters : "
Write-Output ""
Write-Host $MyInvocation.MyCommand.Name" param01=<firewall_list.json> param02=<url_list.json>" -ForegroundColor Green
Write-Output ""


# ---- Functions ----
function Split-StringAfterEqualSign {
    param (
        [string]$inputString
    )
    try {
        if (-not $inputString.Contains("=")) {
            throw "Input string does not contain an '=' sign."
        }

        $splitString = $inputString -split "="
        #        write-host $splitString[1]
        if (($null -eq $splitString[1]) -or ($splitString[1] -eq "")) {
            throw "No value after '=' for $splitString"
        } 
        return @{
            Key   = $splitString[0]
            Value = $splitString[1]
        }
    }
    catch {
        Write-Error "An error occurred : $_"
        exit 4
    }
}

function BuildURLFunction {
    param (
        [string]$FuncFwIP,
        [string]$FuncFwPort,
        [string]$FuncFwLogin,
        [string]$FuncFwPwd,
        [string]$FuncFwTimeOut
    )
    $FuncUrlLogin = "https://" + $FuncFwIP + ":" + $FuncFwPort + "/webconsole/APIController?reqxml=<Request><Login><Username>" + $FuncFwLogin + "</Username><Password>" + $FuncFwPwd + "</Password></Login><GET>"
    $FuncUrlCommand = "<WebFilterURLGroup/>"
    $FuncUrlEnding = "</GET></Request>"
    $FuncUrlContentType = @{}
    $FuncUrlContentType.Add("content-type", "application/xml")
    [string]$WholeCompletedURL = $FuncUrlLogin + $FuncUrlCommand + $FuncUrlEnding
    return $WholeCompletedURL
}

function TranformInterfacesXmlListToArray {
    param (
        [xml]$XmlDocument
    )
    $XmlTag = $XmlDocument.SelectNodes("//WebFilterURLGroup")
    $OutTagArray = @()
    foreach ($Node in $XmlTag) {
        $OutTagArray += [pscustomobject]@{            
            Name        = $Node.Name
            XmlUrlList  = $Node.URLlist.URL
            Description = $Node.Description
            IsDefault   = $Node.IsDefault
        }
    }
    return $OutTagArray
}
# MAIN PROGRAM
try {
    if (($null -eq $Param01) -or ($Param01 -eq "")) {
        Write-Host "   No input firewalls list has been provided   " -ForegroundColor Red -BackgroundColor Yellow -NoNewline
        write-host""
        write-host""        
        exit 2
    }
    if (($null -eq $Param02) -or ($Param02 -eq "")) {
        Write-Host "   No Input URL file list has been provided   " -ForegroundColor Red -BackgroundColor Yellow -NoNewline
        write-host""
        write-host""        
        exit 3
    }
#    if (($null -eq $Param03) -or ($Param03 -eq "")) {
#        Write-Host "   No Output log file list has been provided   " -ForegroundColor Red -BackgroundColor Yellow -NoNewline
#        write-host""
#        write-host""        
#        exit 4
#    }
    else {
        #
        # ALL Is OK now we can compute. 
        #
        $result01 = Split-StringAfterEqualSign -inputString $Param01
        #        Write-Host "Param01 Name          : "$result01.Key
        #        Write-Host "Param01 content       : "$result01.Value
        $Input01Name = $result01.key
        $Input01Value = $result01.Value
        #        Write-Host "First Parameter name  : "$Input01Name
        #        Write-Host "Input Filename        : "$Input01Value
        $InputFile = $Input01Value

        $result02 = Split-StringAfterEqualSign -inputString $Param02
        #        Write-Host "Param02 Name          : "$result02.Key
        #        Write-Host "Param02 content       : "$result02.Value
        $Input02Name = $result02.key
        $Input02Value = $result02.Value
        #        Write-Host "Second Parameter name : "$Input02Name
        #        Write-Host "Output Filename       : "$Input02Value
        #        $result03 = Split-StringAfterEqualSign -inputString $Param03
#        Write-Host "Param03 Name        : "$result03.Key
#        Write-Host "Param03 content     : "$result03.Value
#        $Input03Name = $result03.key
#        $Input03Value = $result03.Value          
        $OutputFile = $Input02Value
        if (Test-Path -Path $InputFile) {
            # Input file exists, we can continue
            try {
                $file = Get-Item $InputFile
                $file.OpenRead().Close()
                $ImportJsonFile = Get-content -Path $InputFile | ConvertFrom-Json
                $Counter = 0
                $MainTable = [System.Collections.ArrayList]::new()
                foreach ($Item in $ImportJsonFile) {
                    try {
#                        Write-Host "---------------------------------------------------------"
#                        Write-Host "Iteration Number           :"$Counter
                        $FwAdminIpAddress = $Item.IPAddress
#                        Write-Host "IP Address                 :"$FwAdminIpAddress
                        $FwAdminListeningPort = $Item.AccesPortNb
#                        Write-Host "Port Number                :"$FwAdminListeningPort
                        $EncryptedPassword = $Item.Password
                        $Password = ConvertTo-SecureString -String $EncryptedPassword
                        $Credentials = New-Object System.Management.Automation.PSCredential ($Item.LoginName, $Password)
#                        Write-Host "Credentials Login name     : $($Credentials.UserName)"
#                        Write-Host "Credentials Login Password : $($Credentials.GetNetworkCredential().Password)"
                        $AccessTimeOut = $Item.TimeOut
#                        Write-Host "Access TimeOut             :"$AccessTimeOut
                        $FuncURL = BuildURLFunction -FuncFwIP $FwAdminIpAddress -FuncFwPort $FwAdminListeningPort -FuncFwLogin $($Credentials.UserName) -FuncFwPwd $($Credentials.GetNetworkCredential().Password)
#                        Write-Host $FuncURL
                        try {
                            $HttpResult = (Invoke-RestMethod -Uri $FuncURL -Method Post -ContentType "application/xml" -SkipCertificateCheck -TimeoutSec $AccessTimeOut)
                            $EntriesListArray = TranformInterfacesXmlListToArray -XmlDocument $HttpResult
                            $Firewalls_Object = [PSCustomObject]@{
                                Firewall     = $Item.IPAddress
                                FirewallURLS = $EntriesListArray
                            }
                            #                        $Firewalls_Object
                            $MainTable.add($Firewalls_Object) | Out-Null
                        }
                        catch {
                            Write-host "Error calling URL"
                            Write-Host "Error : $($_.Exception.Message)"
                        }
                    }
                    catch {
                        Write-Host "Error encountered while parsing "$InputFile
                        Write-Host "Error $($_.Exception.Message)"
                        exit 1
                    }
                }            
                #            Write-Host ""
                $Counter++
#                Write-Host "Compteur :" $Counter
            }
            catch {
                Write-Host "File "$FullFileName" exists but can not be accessed in Read mode"
                exit 2               
            }
        }
        else {
            # Input file does not exist exit program
            Write-Host "File "$InputFile" does not exist"
            exit 3
        }
    }
    
}
catch {
    write-host ""
    Write-Error "An error occurred: $_"
    write-host ""
    exit 1
}

#End of loops
# $MainTable | Format-Table -AutoSize
$Table_In_JSON = $MainTable | ConvertTo-Json -Depth 6
#$Table_In_JSON
$Table_In_JSON | Out-File -FilePath $OutputFile utf8

