# This script use 2 json files 
# 1. contains firewall list
# 2. contains a list of url that have to be pushed to firewall WebFilter URL Group
#
# ---- CLI Parameters ----
param (
    # Param01 is firewalls list.    
    [Parameter(Mandatory = $true, HelpMessage = "Please provide Firewalls list file in JSON format :")]
    [string]$Param01 = "",
    # Param02 is the input JSON file taht contains all URL that have to be pushed to firewalls    
    [Parameter(Mandatory = $true, HelpMessage = "Please provide Output file name with full path    :")]
    [string]$Param02 = ""
    # Param03 is the Log filename
    #    [Parameter(Mandatory = $true, HelpMessage = "Please provide Output Log file                    :")]
    #    [string]$Param03 = ""
)
Clear-Host
Write-Output "==============================================================================="
Write-Output "Sophos Firewall API - Update Web Filtering URL lists"
Write-Output "==============================================================================="
Write-Output ""
Write-Output "It requires 3 parameters : "
Write-Output ""
Write-Host $MyInvocation.MyCommand.Name" param01=<firewall_list.json> param02<=url_list.json> param03<=Ouput Log file.txt>" -ForegroundColor Green
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
        write-host $splitString[1]
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
        exit 5
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
        write-host""     
        Write-Host "   No input firewalls list has been provided   " -ForegroundColor Red -BackgroundColor Yellow -NoNewline
        write-host""
        exit 10
    }
    if (($null -eq $Param02) -or ($Param02 -eq "")) {
        write-host""
        Write-Host "   No Input WebURL file list has been provided   " -ForegroundColor Red -BackgroundColor Yellow -NoNewline
        write-host""        
        exit 20
    }
    #    if (($null -eq $Param03) -or ($Param03 -eq "")) {
    #        write-host""
    #        Write-Host "   No Output log file name has been provided   " -ForegroundColor Red -BackgroundColor Yellow -NoNewline
    #        write-host""        
    #        exit 4
    #    }
    else {
        # Check values are not empties 
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

        #        $result03 = Split-StringAfterEqualSign -inputString $Param03
        #        Write-Host "Param03 Name        : "$result03.Key
        #        Write-Host "Param03 content     : "$result03.Value
        #        $Input03Name = $result03.key
        #        $Input03Value = $result03.Value
    }    
    # Ready to go
    if (-Not (Test-Path -Path $Input01Value)) {
        # Input file does not exist, we should stop
        Write-Host "File "$Input01Value" does not exist"
        exit 11
    }
    else {
        try {
            $file01 = Get-Item $Input01Value
            $file01.OpenRead().Close()    
        }
        catch {
            Write-Host "File "$Input01Value" exists but can not be accessed in Read mode"
            exit 12    
        }
    }
    if (-Not (Test-Path -Path $Input02Value)) {
        # Input file does not exist, we should stop
        Write-Host "File "$Input02Value" does not exist"
        exit 21
    }
    else {
        # All input files exist We can continue
        try {
            $file02 = Get-Item $Input02Value
            $file02.OpenRead().Close()    
        }
        catch {
            Write-Host "File "$Input02Value" exists but can not be accessed in Read mode"
            exit 22    
        }
        try {
            $ImportJsonFwFile = Get-content -Path $Input01Value -Raw | ConvertFrom-Json
            $ImportJsonURLFile = Get-content -Path $Input02Value -Raw | ConvertFrom-Json
            $ArrayFwList = @($ImportJsonFwFile)
            $ArrayUrlListForFw = @($ImportJsonURLFile)
            $ArrayUrlListForFw
            # Convert table to xml Document


            $IndexNames = @{}
            $IndexNames = $ArrayUrlListForFw.FirewallURLS
            $NombreDeNoms = $ArrayUrlListForFw.FirewallURLS.Name.Count

            Write-Host "Nombre de noms :"$NombreDeNoms

            for ($FirewallCount = 0; $FirewallCount -lt $ArrayUrlListForFw.Firewall.Length; $FirewallCount++) {
                Write-Host "Firewall Name   :"$ArrayUrlListForFw.Firewall[$FirewallCount]
                $Xml = New-Object System.Xml.XmlDocument
                # Create root
                $Root = $Xml.CreateElement("WebFilterURLGroup")
                $Xml.AppendChild($Root) | Out-Null

                for ($i = 0; $i -lt 1; $i++) {
                    #           Add Name
                    $WebListName = $Xml.CreateElement("Name")
                    $WebListName.InnerText = $ArrayUrlListForFw.FirewallURLS.Name[$i]
                    $Root.AppendChild($WebListName) | Out-Null
                    #           Add URL List
                    $ElementUrlList = $Xml.CreateElement("URLlist")
                    foreach ($UrlInTheList in $ArrayUrlListForFw.FirewallURLS[$i].XmlUrlList) {
                        $URL01 = $Xml.CreateElement("URL")
                        $URL01.InnerText = $UrlInTheList
                        $ElementUrlList.AppendChild($URL01) | Out-Null
                    }
                    $Root.AppendChild($ElementUrlList) | Out-Null 
                    #           Add Description
                    $Description = $Xml.CreateElement("Description")
                    $Description.InnerText = $ArrayUrlListForFw.FirewallURLS.Description[$i]
                    $Root.AppendChild($Description) | Out-Null
                }
                $xmlfilepath = "/home/user/test.xml"
                $xml.Save($xmlfilepath)
            }
            $Counter = 0
            $MainTable = [System.Collections.ArrayList]::new()
            foreach ($Item in $ImportJsonFwFile) {
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
                    #                try {
                    #                    $HttpResult = (Invoke-RestMethod -Uri $FuncURL -Method Post -ContentType "application/xml" -SkipCertificateCheck -TimeoutSec $AccessTimeOut)
                    #                    $EntriesListArray = TranformInterfacesXmlListToArray -XmlDocument $HttpResult
                    #                    $Firewalls_Object = [PSCustomObject]@{
                    #                        Firewall     = $Item.IPAddress
                    #                        FirewallURLS = $EntriesListArray
                    #                    }
                    #                        $Firewalls_Object
                    #                    $MainTable.add($Firewalls_Object) | Out-Null
                    #                }
                    #                catch {
                    #                    Write-host "Error calling URL"
                    #                    Write-Host "Error : $($_.Exception.Message)"
                    #                }
                }
                catch {
                    Write-Host "Error encountered while parsing "$InputFile
                    Write-Host "Error $($_.Exception.Message)"
                    exit 1
                }
            }            
            Write-Host ""
            $FwCounter++
            Write-Host "Firewall Number in "$Input01Value ":" $FwCounter
    
        }
        catch {
            write-host ""
            Write-Error "An error occurred: $_"
            write-host ""
            exit 1
        }
    }
}
catch {
    write-host ""
    Write-Error "An error occurred: $_"
    write-host ""
    exit 1
}