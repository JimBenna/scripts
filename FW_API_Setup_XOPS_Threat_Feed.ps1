# This script use 2 json files 
# 1. contains firewall list
# 2. contains a list of IPHOSTS that have to be pushed to firewalls
#
# ---- CLI Parameters ----
param (
    # Param01 is firewalls list.    
    [Parameter(Mandatory = $true, HelpMessage = "Please provide Firewalls list file in JSON format :")]
    [string]$Param01 = "",
    # Param02 is the input JSON file taht contains all URL that have to be pushed to firewalls    
    [Parameter(Mandatory = $true, HelpMessage = "Please provide input file with full path name that contains IPHost to push to firewalls")]
    [string]$Param02 = ""
    # Param03 is the Log filename
    #    [Parameter(Mandatory = $true, HelpMessage = "Please provide Output Log file                    :")]
    #    [string]$Param03 = ""
)
Clear-Host
Write-Output "==================================================================================="
Write-Output "Sophos Firewall API - Setup XOPS Threat Feeds from parameters stored in a json file"
Write-Output "==================================================================================="
Write-Output ""
Write-Output "It requires 3 parameters : "
Write-Output ""
Write-Host $MyInvocation.MyCommand.Name" param01=<firewall_list.json> param02<XOPS_Threat_feed_setup.json> param03<=Ouput Log file.txt>" -ForegroundColor Green
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
function GenearateRandomString {
    param
    (
        [Int16]$NbCharacters
    )
    $UsedCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $RandomString = -join ((1..$NbCharacters) | ForEach-Object { $UsedCharacters[(Get-Random -Maximum $UsedCharacters.Length)] })

    return $RandomString
}
function BuildURLFunction {
    param (
        [string]$FuncFwIP,
        [string]$FuncFwPort
    )
    $FuncUrlLogin = "https://" + $FuncFwIP + ":" + $FuncFwPort + "/webconsole/APIController"
    [string]$WholeCompletedURL = $FuncUrlLogin
    return $WholeCompletedURL
}
function BuildURLPayload {
    param (
        [string]$PayloadFwLogin,
        [string]$PayloadFwPwd,
        [string]$PayloadStrLength,
        [string]$PayloadParameters
    )

    $PayLoadString = "?reqxml="
    $PayLoadLogin = "<Request><Login><Username>" + $PayloadFwLogin + "</Username><Password>" + $PayloadFwPwd + "</Password></Login>"
    $PayloadCommand = "<Set>"
    $PayloadlEnding = "</Set></Request>"

    [string]$WholePayload = $PayLoadString + $PayLoadLogin + $PayloadCommand + $PayloadParameters + $PayloadlEnding
    return $WholePayload
}
function ILookFor {
    param 
    (
        [string]$ThatOne,
        [array]$IntoThat
    )
    [array]$FoundThat
    $FoundThat = $IntoThat | Where-Object { $_.IPAddress -eq $ThatOne }
    #    write-host "I Found that : "$FoundThat
    return $FoundThat
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
        Write-Host "   No Input IpHosts file list has been provided   " -ForegroundColor Red -BackgroundColor Yellow -NoNewline
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
        $Input01Name = $result01.key
        $Input01Value = $result01.Value
        #        Write-Host "Param01 Name        : "$Input01Name
        #        Write-Host "Param01 content     : "$Input01Value
        $result02 = Split-StringAfterEqualSign -inputString $Param02
        $Input02Name = $result02.key
        $Input02Value = $result02.Value
        #        Write-Host "Param02 Name        : "$Input02Name
        #        Write-Host "Param02 content     : "$Input02Value

        #        $result03 = Split-StringAfterEqualSign -inputString $Param03
        #        Write-Host "Param03 Name        : "$Input03Name
        #        Write-Host "Param03 content     : "$Input03Value
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
        try 
        {
            # Phase 01 : Creation of IPHosts Groups in All firewalls 
            $local:ImportJsonFwFile = Get-content -Path $Input01Value -Raw | ConvertFrom-Json
            $local:ArrayFwList = @($local:ImportJsonFwFile)
            $global:SortedArrayFwList = $local:ArrayFwList | Sort-Object -Property IPAddress
            #            $global:SortedArrayFwList | Format-Table -Wrap
            $local:ImportJsonURLFile = Get-content -Path $Input02Value -Raw | ConvertFrom-Json
            $local:ArrayUrlListForFw = @($ImportJsonURLFile)
            $global:SortedArraySetupForFw = $local:ArrayUrlListForFw | Sort-Object -Property Firewall
            #            $global:SortedArraySetupForFw | Format-Table -Wrap

            foreach ($FirewallEntry in $global:SortedArraySetupForFw) 
            {
#            Write-host "Tableau des details des fw :"$global:SortedArrayFwList
#            write-host "Tableau des paramètres     :"$global:SortedArraySetupForFw
#            Write-host "Entrée de Fw               :"$FirewallEntry.Firewall


            }            
            # Phase 01 : Creation of IPHosts Groups in All firewalls should have been done now
            # Let's do the IPHosts and affect them to the right IPHosts Groups that have been previously created in Phase 01
            # Phase 02 : Creation of IPHosts in All firewalls and assign to each IPHost the groups it belongs to.
            # Groups should already exists because they have been created in Phase 01 in each firewall.
            #$SortedArraySetupForFw | Format-Table -AutoSize
            #$SortedArrayFwList | Format-Table -AutoSize

            foreach ($ComputingFw in $SortedArraySetupForFw) 
            {
                write-host "*********************** [ IP Hosts Creation Process ] **************************************"
                    $ComputingFw | Format-Table -AutoSize
                    write-host "Destination firewall        :"$ComputingFw.Firewall
                    $xmlContent = "<ATP>"
                    $xmlContent +="<ThreatProtectionStatus>$($ComputingFw.ATPValues.ThreatProtectionStatus)</ThreatProtectionStatus>"
                    $xmlContent +="<Policy>$($ComputingFw.ATPValues.Policy)</Policy>"
                    $xmlContent +="<HostException>"
                    $TotalNumberOfHostsException  = $($ComputingFw.ATPValues.HostException) | Measure-Object | Select-Object -ExpandProperty Count
                    for ($h = 0; $h -lt $TotalNumberOfHostsException; $h++) 
                    {
                        $xmlContent += "<Host>$($ComputingFw.ATPValues.HostException[$h])</Host>"   
                    }
                    $xmlContent += "</HostException>"
                    $xmlContent += "<ThreatException>"    
                    $TotalNumberOfThreatException = $($ComputingFw.ATPValues.ThreatException) | Measure-Object | Select-Object -ExpandProperty Count                
                    for ($t = 0; $t -lt $TotalNumberOfThreatException; $t++) 
                    {
                        $xmlContent += "<Threat>$($ComputingFw.ATPValues.ThreatException[$t])</Threat>"   
                    }
                    $xmlContent += "</ThreatException>"
                    $xmlContent += "<InspectContent>$($ComputingFw.ATPValues.InspectContent)</InspectContent>"
                    $xmlContent += "</ATP>"                  


                    write-host ""
                                write-host "All Record ready to be used :"$xmlContent
                    $SearchLycos = ILookFor -ThatOne $ComputingFw.Firewall -IntoThat $SortedArrayFwList
                    #            $SearchLycos | Format-Table -Wrap
                    $local:FwAdminIpAddress = $SearchLycos.IPAddress
                    $local:FwAdminListeningPort = $SearchLycos.AccesPortNb
                    $local:EncryptedPassword = $SearchLycos.Password
                    $local:Password = ConvertTo-SecureString -String $EncryptedPassword
                    $local:Credentials = New-Object System.Management.Automation.PSCredential ($SearchLycos.LoginName, $local:Password)
                    $local:AccessTimeOut = $SearchLycos.TimeOut
                    $local:FuncURL = BuildURLFunction -FuncFwIP $local:FwAdminIpAddress -FuncFwPort $local:FwAdminListeningPort
                    $local:FormPayload = BuildURLPayload -PayloadFwLogin $($local:Credentials.UserName) -PayloadFwPwd $($local:Credentials.GetNetworkCredential().Password) -PayloadParameters $xmlContent -PayloadStrLength 8
                    $local:FullURI = $local:FuncURL + $local:FormPayload
                    try 
                    {
                        write-host "URL Passée :" $local:FullURI
                        write-host "-------------------------------------"  
                        $HttpResult = Invoke-RestMethod -Uri $FullURI -Method 'Post' -ContentType "application/xml" -SkipCertificateCheck -TimeoutSec $AccessTimeOut -StatusCodeVariable IPHostURLReply
                        $HttpResult.OuterXml
                        $SelectedIPHostsTags = $HttpResult | Select-Xml -XPath "//Login | //IPHost"
                        write-host "Communication with IP :" $FwAdminIpAddress
                        write-host "Creation of IP Host   :" $UrlListName
                        write-host "Reply Status Code     :" $IPHostURLReply
                        $SelectedIPHostsTags | ForEach-Object { $_.Node.InnerText }
                        write-host "----------------------------------------------"                       
                    }
                    catch 
                    {
                        Write-host "Error calling URL"
                        Write-Host "Error : $($_.Exception.Message)"
                    }
            }            
                            
        }
        catch {
            write-host ""
            Write-Error "An error occurred: $_"
            write-host ""
        }
    }    
}
catch {
    write-host ""
    Write-Error "An error occurred: $_"
    write-host ""
    exit 1
}