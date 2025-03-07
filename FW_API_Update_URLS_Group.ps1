# This script use 2 json files 
# 1. contains firewall list
# 2. Output of data retrieved from each firewalls in the list
param (
    [Parameter(Mandatory = $true), HelpMessage = "Please provide Firewalls list file in JSON format :"]
    [string]$Param01 = "",
    # Param01 is firewalls list.    
    [Parameter(Mandatory = $true), HelpMessage = "Please provide Output file name with full path    :"]
    [string]$Param02 = ""
    # Param02 is the Output JSON file    
)
Clear-Host
Write-Output "==============================================================================="
Write-Output "Sophos Firewall API - Update Web Filtering URL lists"
Write-Output "==============================================================================="
Write-Output ""
Write-Output "It requires 2 parameters : "
Write-Output ""
Write-Host $MyInvocation.MyCommand.Name" param01=<firewall_list.json> param02<=url_list.json>" -ForegroundColor Green
Write-Output ""
#
# ---- CLI Parameters ----

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
        write-host $splitString[1]
        if (($null -eq $splitString[1]) -or ($splitString[1] -eq "")) 
            {
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
    $FuncUrlCommand = "<IPHost/>"
    $FuncUrlEnding = "</GET></Request>"
    $FuncUrlContentType = @{}
    $FuncUrlContentType.Add("content-type", "application/xml")
    [string]$WholeCompletedURL = $FuncUrlLogin + $FuncUrlCommand + $FuncUrlEnding
    return $WholeCompletedURL
}

try {
    if (($null -eq $Param01) -or ($Param01 -eq "")) {
        Write-Host "   No input firewalls list has been provided   " -ForegroundColor Red -BackgroundColor Yellow -NoNewline
        write-host""
        write-host""        
        exit 2
    }
    if (($null -eq $Param02) -or ($Param02 -eq "")) {
        Write-Host "   No Input WebURL file list has been provided   " -ForegroundColor Red -BackgroundColor Yellow -NoNewline
        write-host""
        write-host""        
        exit 3
    }
    else {
 
        $result01 = Split-StringAfterEqualSign -inputString $Param01
#        Write-Host "Param01 Name        : "$result01.Key
#        Write-Host "Param01 content     : "$result01.Value
        $Input01Name = $result01.key
        $Input01Value = $result01.Value

        $result02 = Split-StringAfterEqualSign -inputString $Param02
#        Write-Host "Param02 Name        : "$result02.Key
#        Write-Host "Param02 content     : "$result02.Value
        $Input02Name = $result02.key
        $Input02Value = $result02.Value
    }
}
catch {
    write-host ""
    Write-Error "An error occurred: $_"
    write-host ""
    exit 1
}