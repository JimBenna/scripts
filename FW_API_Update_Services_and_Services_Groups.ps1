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
    [Parameter(Mandatory = $true, HelpMessage = "Please provide input file with full path name that contains SERVICES list to be pushedl to firewalls")]
    [string]$Param02 = ""
    # Param03 is the Log filename
    #    [Parameter(Mandatory = $true, HelpMessage = "Please provide Output Log file                    :")]
    #    [string]$Param03 = ""
)
Clear-Host
Write-Output "========================================================================================"
Write-Output "Sophos Firewall API - Update Services and Services Groups entries to a list of firewalls"
Write-Output "========================================================================================"
Write-Output ""
Write-Output "It requires 3 parameters : "
Write-Output ""
Write-Host $MyInvocation.MyCommand.Name" param01=<firewall_list.json> param02<=Services_list.json> param03<=Ouput Log file.txt>" -ForegroundColor Green
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
    $PayloadCommand = "<Set Operation=`"add`">"
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
        try {
            # Phase 01 : Creation of Services Groups in All firewalls 
            $local:ImportJsonFwFile = Get-content -Path $Input01Value -Raw | ConvertFrom-Json
            $local:ArrayFwList = @($local:ImportJsonFwFile)
            $global:SortedArrayFwList = $local:ArrayFwList | Sort-Object -Property IPAddress
#            $global:SortedArrayFwList | Format-Table -Wrap
            $local:ImportJsonURLFile = Get-content -Path $Input02Value -Raw | ConvertFrom-Json
            $local:ArrayUrlListForFw = @($ImportJsonURLFile)
            $global:SortedArrayUrlListForFw = $local:ArrayUrlListForFw | Sort-Object -Property Firewall
            $global:SortedArrayUrlListForFw | Format-Table -Wrap

            foreach ($FirewallEntry in $global:SortedArrayUrlListForFw) {
#            Write-host "Tableau des details des fw :"$global:SortedArrayFwList
#            write-host "Tableau des paramètres     :"$global:SortedArrayUrlListForFw
#            Write-host "Entrée de Fw               :"$FirewallEntry.Firewall
            $FoundItArray = @{}
            $FoundItArray = $global:SortedArrayUrlListForFw | Where-Object { $_.Firewall -eq $FirewallEntry.Firewall }
            write-host "*********************** [ SERVICES GROUPS creation Process ] **************************************"
            write-host ""
            write-host "---------------------------------"
            write-host "Firewall traité   :"$FoundItArray.Firewall
            write-host "---------------------------------"
#            Select Unique Services Groups In the List
                $EveryServicesGroupList = New-Object System.Data.Datatable
                [void]$EveryServicesGroupList.Columns.Add("ServicesGroupName")
                [void]$EveryServicesGroupList.Columns.Add("ServicesGroupDescription")
                foreach ($GroupListName in $FoundItArray.Service) {
#                    foreach ($List in $GroupListName.ServiceList) 
#                    {
#                        write-host $List
                        write-host $GroupListName
                        [void]$EveryServicesGroupList.Rows.Add($($GroupListName.ServiceList),$($GroupListName.ServiceListDescription))
#                    }
                }
                $UniqueHostGroupListArray = $EveryServicesGroupList | Group-Object -Property ServicesGroupName |  ForEach-Object { $_.Group | Select-Object -First 1 }
                $UniqueHostGroupListArray | Format-Table -Wrap
                write-host ""
                write-host "---------------------------------"
                write-host "Firewall traité   :"$FoundItArray.Firewall
                write-host "---------------------------------"
                foreach ($GroupEntry in $UniqueHostGroupListArray) {
                    $xmlIPHostGroup = "<FQDNHostGroup>"
                    $xmlIPHostGroup += "<Name>$($GroupEntry.FQDNGroupName)</Name>"
                    $xmlIPHostGroup += "</FQDNHostGroup>"
                    $DestinationFirewall = ILookFor -ThatOne $FoundItArray.Firewall -IntoThat $SortedArrayFwList
                    $local:EncryptedPassword = $DestinationFirewall.Password
                    $local:Password = ConvertTo-SecureString -String $local:EncryptedPassword
                    $local:Credentials = New-Object System.Management.Automation.PSCredential ($DestinationFirewall.LoginName, $Password)
                    $AccessTimeOut = $DestinationFirewall.TimeOut
                    $local:FuncURL = BuildURLFunction -FuncFwIP $DestinationFirewall.IPAddress -FuncFwPort $DestinationFirewall.AccesPortNb
                    $local:FormPayloadGroups = BuildURLPayload -PayloadFwLogin $($local:Credentials.UserName) -PayloadFwPwd $($local:Credentials.GetNetworkCredential().Password) -PayloadParameters $xmlIPHostGroup -PayloadStrLength 8
                    $local:FullIpHostGroupsCreation = $local:FuncURL + $local:FormPayloadGroups
                    try {
#                        write-host "Groups URL :"$local:FullIpHostGroupsCreation
#                        $FQDNGroups = Invoke-RestMethod -Uri $local:FullIpHostGroupsCreation -Method 'Post' -ContentType "application/xml" -SkipCertificateCheck -TimeoutSec $AccessTimeOut -StatusCodeVariable HostGroupURLReply
#                        $FQDNGroups.OuterXml

                        write-host "Communication with IP   :" $DestinationFirewall.IPAddress
                        write-host "Creation of Hosts Group :" $($GroupEntry.FQDNGroupName)
                        write-host "Reply Status Code       :" $HostGroupURLReply
#                        $SelectedTags = $FQDNGroups | Select-Xml -XPath "//Login | //Status"
#                        $SelectedTags | ForEach-Object {$_.Node.InnerText}

                        write-host "----------------------------------------------"
                    }
                    catch {
                        Write-host "Error while pushing informations to "$DestinationFirewall.IPAddress
                        Write-Host "Error : $($_.Exception.Message)"
                    }
                }
            }            
            # Phase 01 : Creation of IPHosts Groups in All firewalls should have been done now
            # Let's do the IPHosts and affect them to the right IPHosts Groups that have been previously created in Phase 01
            # Phase 02 : Creation of IPHosts in All firewalls and assign to each IPHost the groups it belongs to.
            # Groups should already exists because they have been created in Phase 01 in each firewall.
            #$SortedArrayUrlListForFw | Format-Table -AutoSize
            #$SortedArrayFwList | Format-Table -AutoSize

            foreach ($ComputingFw in $SortedArrayUrlListForFw) 
            {
                write-host "*********************** [ FQDN Creation Process ] **************************************"
#                $ComputingFw | Format-Table -Wrap
                $TotalNumberOfFQDN = $ComputingFw.FQDN | Measure-Object | Select-Object -ExpandProperty Count
#                write-host "FQDN number :"  $TotalNumberOfFQDN
                for ($fqdn = 0; $fqdn -lt $TotalNumberOfFQDN; $fqdn++) {
#                    write-host "Destination firewall        :"$ComputingFw.Firewall
                    $xmlFQDNContent = "<FQDNHost>"
                    $UrlFqdnName = $($ComputingFw.FQDN[$fqdn].Name)
                    $xmlFQDNContent += "<Name>$UrlFqdnName</Name>"
#                    write-host "Firewall FQDN List          :"$UrlFqdnName
                    $FqdnDescription = $($ComputingFw.FQDN[$fqdn].Description)
                    $xmlFQDNContent += "<Description>$FqdnDescription</Description>"
#                    write-host "Description                 :"$FqdnDescription                    
                    $FqdnEntry = $($ComputingFw.FQDN[$fqdn].FQDN)
                    $xmlFQDNContent += "<FQDN>$FqdnEntry</FQDN>"
#                    write-host "Host Type                   :"$FqdnEntry
                    $xmlFQDNContent += "<FQDNHostGroupList>"                                       
                    [string]$xmlContentObjects = ""
                    $EntriesInListNumber = $ComputingFw.FQDN[$fqdn].FQDNHostGroupList | Measure-Object | Select-Object -ExpandProperty Count
#                    write-host "FQDN Group List number :"  $EntriesInListNumber
                    for ($Group = 0; $Group -lt $EntriesInListNumber; $Group++) 
                    {
                        $xmlContentObjects += "<FQDNHostGroup>$($ComputingFw.FQDN[$fqdn].FQDNHostGroupList[$($Group)])</FQDNHostGroup>"
                    }
                    $xmlFQDNContent += $($xmlContentObjects)
                    $xmlFQDNContent += "</FQDNHostGroupList>"
#                    write-host "FQDN Group List            :"$($xmlContentObjects)  
                    $xmlFQDNContent += "</FQDNHost>"
#                    write-host ""
#                    write-host "All Record ready to be used :"$xmlFQDNContent
                    $SearchLycos = ILookFor -ThatOne $ComputingFw.Firewall -IntoThat $SortedArrayFwList
#                    $SearchLycos | Format-Table -Wrap
                    $local:FwAdminIpAddress = $SearchLycos.IPAddress
                    $local:FwAdminListeningPort = $SearchLycos.AccesPortNb
                    $local:EncryptedPassword = $SearchLycos.Password
                    $local:Password = ConvertTo-SecureString -String $EncryptedPassword
                    $local:Credentials = New-Object System.Management.Automation.PSCredential ($SearchLycos.LoginName, $local:Password)
                    $local:AccessTimeOut = $SearchLycos.TimeOut
                    $local:FuncURL = BuildURLFunction -FuncFwIP $local:FwAdminIpAddress -FuncFwPort $local:FwAdminListeningPort
                    $local:FormPayload = BuildURLPayload -PayloadFwLogin $($local:Credentials.UserName) -PayloadFwPwd $($local:Credentials.GetNetworkCredential().Password) -PayloadParameters $xmlFQDNContent -PayloadStrLength 8
                    $local:FullURI = $local:FuncURL + $local:FormPayload
                    try 
                        {
#                        write-host "URL Passée :" $local:FullURI
#                        write-host "-------------------------------------"  
#                        $HttpResult = Invoke-RestMethod -Uri $FullURI -Method 'Post' -ContentType "application/xml" -SkipCertificateCheck -TimeoutSec $AccessTimeOut -StatusCodeVariable IPHostURLReply
#                        $HttpResult.OuterXml
#                        $SelectedIPHostsTags = $HttpResult | Select-Xml -XPath "//Login | //Status"
                        write-host "Communication with IP :" $FwAdminIpAddress
                        write-host "Creation of FQDN      :" $UrlFqdnName
                        write-host "Reply Status Code     :" $IPHostURLReply
#                        $SelectedIPHostsTags | ForEach-Object { $_.Node.InnerText }
                        write-host "----------------------------------------------"                       
                       }
                    catch {
                        Write-host "Error calling URL"
                        Write-Host "Error : $($_.Exception.Message)"
                    }
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