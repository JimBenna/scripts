<# 
.SYNOPSIS
#This script reads a CSV file that contains firewalls list
.DESCRIPTION
It reads the following columns : IP ADDRESS, LOGIN NAME, PASSWORD, Access TimeOut in seconds
It outputs the IPHosts of each firewalls mentioned in the list
It must be used as follows
.PARAMETER Param01
Description Input file that lists all details about firewalls that have to be requested. Please provide filename with fullpath access
.PARAMETER Param02
Description Ouput file that is generated with all details gathered from firewalls. Please provide filename with fullpath access
.EXAMPLE
<script_name>.ps1 input=<firewalls list> output=<Generated_Servcies_List.json>
#>
# ---- CLI Parameters ----
#
param (
    [Parameter(Mandatory = $true, HelpMessage = "Please provide Firewalls list file in JSON format :")]
    [string]$Param01 = "",
    # Param01 is firewalls list. 
    [Parameter(Mandatory = $true, HelpMessage = "Please provide Output file name with full path    :")]
    [string]$Param02 = ""
    # Param02 is the Input JSON file that contains the Services that are retrieved from each firewall
)
Clear-Host
Write-Output "========================================================================================="
Write-Output "Sophos Firewall API - Retrieve Services and Services Groups lists configured in firewalls"
Write-Output "========================================================================================="
Write-Output ""
Write-Output "It requires 2 parameters : "
Write-Output ""
Write-Host $MyInvocation.MyCommand.Name" param01=<firewall_list.json> param02=<Services_list.json>" -ForegroundColor Green
Write-Output ""

# ---- Functions ----
function BuildURLFunction {
    param (
        [string]$Command,
        [string]$FuncFwIP,
        [string]$FuncFwPort,
        [string]$FuncFwLogin,
        [string]$FuncFwPwd,
        [string]$FuncFwTimeOut
    )
    $FuncUrlLogin = "https://" + $FuncFwIP + ":" + $FuncFwPort + "/webconsole/APIController?reqxml=<Request><Login><Username>" + $FuncFwLogin + "</Username><Password>" + $FuncFwPwd + "</Password></Login><GET>"
    $FuncUrlCommand = $Command
    $FuncUrlEnding = "</GET></Request>"
    $FuncUrlContentType = @{}
    $FuncUrlContentType.Add("content-type", "application/xml")
    [string]$WholeCompletedURL = $FuncUrlLogin + $FuncUrlCommand + $FuncUrlEnding
    return $WholeCompletedURL
}
function Split-StringAfterEqualSign {
    param 
    (
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
    catch 
    {
        Write-Error "An error occurred : $_"
        exit 4
    }
}
function TransformPortsXmlListToArray 
{
    param (
        [xml]$XmlDocument
    )
    $XmlServiceTag = $XmlDocument.SelectNodes("//Services")
    $OutServicesArray = @()
    foreach ($Node in $XmlServiceTag) 
    {
        $OutServices = $Node.OuterXml
#       write-host "Services List :"
#       write-host $OutServices
        $OutServicesArray += [pscustomobject]@{
            Name                    = $Node.Name
            Description             = $Node.Description
            Type                    = $Node.Type
            ServiceList             = $Node.ServiceList
            ServiceListDescription  = $null
            SourcePort              = $Node.ServiceDetails.ServiceDetail.SourcePort
            DestinationPort         = $Node.ServiceDetails.ServiceDetail.DestinationPort
            Protocol                = $Node.ServiceDetails.ServiceDetail.Protocol
            ProtocolName            = $Node.ServiceDetails.ServiceDetail.ProtocolName
            ICMPType                = $Node.ServiceDetails.ServiceDetail.ICMPType
            ICMPCode                = $Node.ServiceDetails.ServiceDetail.ICMPCode
            ICMPv6Type              = $Node.ServiceDetails.ServiceDetail.ICMPv6Type
            ICMPv6Code              = $Node.ServiceDetails.ServiceDetail.ICMPv6Code

        }
    }
    return $OutServicesArray
}

function TransformPortsGroupsXmlListToArray 
{
    param (
        [xml]$XmlDocument
    )
    $XmlGroupsTag = $XmlDocument.SelectNodes("//ServiceGroup")
    $OutGroupsArray = @()
    foreach ($NodeGroup in $XmlGroupsTag) 
    {

 #       $OutServicesGroup = $NodeGroup.OuterXml
 #       write-host "Groups of Services List :"        
 #       write-host $OutServicesGroup
        $OutGroupsArray += [pscustomobject]@{
            Name                = $NodeGroup.Name
            Description         = $NodeGroup.Description
            ServiceList         = $NodeGroup.ServiceList.InnerText.trim() -split '\s+'
        }
    }
  
    return $OutGroupsArray
}
# ---- Main program ----
# Checks if firewalls list can exists and can be read


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
                $MainGroupsTable = [System.Collections.ArrayList]::new()
                foreach ($Item in $ImportJsonFile) {
                    try 
                    {
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
                        try 
                            {
                            $ServiceCommand="<Services/>"
                            $FuncURL = BuildURLFunction -Command $ServiceCommand -FuncFwIP $FwAdminIpAddress -FuncFwPort $FwAdminListeningPort -FuncFwLogin $($Credentials.UserName) -FuncFwPwd $($Credentials.GetNetworkCredential().Password)
#                            Write-Host $FuncURL
                            $HttpResult = (Invoke-RestMethod -Uri $FuncURL -Method Post -ContentType "application/xml" -SkipCertificateCheck -TimeoutSec $AccessTimeOut)
#                            write-host $HttpResult.OuterXml
                            $ServiceListArray = TransformPortsXmlListToArray -XmlDocument $HttpResult
                            $Services_Objects = [PSCustomObject]@{
                                Firewall        = $Item.IPAddress
                                Service         = $ServiceListArray
                            }
                            $MainTable.add($Services_Objects) | Out-Null
                            }
                        catch 
                            {
                            Write-host "Error calling URL"
                            Write-Host "Error : $($_.Exception.Message)"
                            }
                        try 
                            {
                            $GroupsCommand="<ServiceGroup/>"
                            $FuncURL = BuildURLFunction -Command $GroupsCommand -FuncFwIP $FwAdminIpAddress -FuncFwPort $FwAdminListeningPort -FuncFwLogin $($Credentials.UserName) -FuncFwPwd $($Credentials.GetNetworkCredential().Password)
#                            Write-Host $FuncURL
                            $HttpGroupsResult = (Invoke-RestMethod -Uri $FuncURL -Method Post -ContentType "application/xml" -SkipCertificateCheck -TimeoutSec $AccessTimeOut)
                            $GroupsListArray = TransformPortsGroupsXmlListToArray -XmlDocument $HttpGroupsResult
                            $Groups_Objects = [PSCustomObject]@{
                                Firewall        = $Item.IPAddress
                                Groups          = $GroupsListArray
                            }
#                        $Service_Objects
                            $MainGroupsTable.add($Groups_Objects) | Out-Null
                            }
                        catch 
                            {
                            Write-host "Error calling URL"
                            Write-Host "Error : $($_.Exception.Message)"
                            }

                    }
                    catch 
                    {
                        Write-Host "Error encountered while parsing "$InputFile
                        Write-Host "Error $($_.Exception.Message)"
                        exit 1
                    }
                }            
#write-host "Maintable"
#$MainTable | Format-Table -Wrap
#write-host "Groupstable"
#$MainGroupsTable | Format-Table -Wrap

foreach ($ItemInGroup in $MainGroupsTable) 
{
    $ip2 = $ItemInGroup.Firewall
    $serviceListGroup = $ItemInGroup.Groups.ServiceList
    $NameOfGroups = $ItemInGroup.Groups.Name
    $MatchingEntry = $MainTable | Where-Object { $_.Firewall -eq $ip2 }
    if ($MatchingEntry) 
    {
#        write-host ""
#        write-host "On a trouvé : "$MatchingEntry
#        write-host ""        
        $TotalNumberOfServicesGroups = $NameOfGroups | Measure-Object | Select-Object -ExpandProperty Count
        $NumberofEntries=0
        foreach ($ServiceEntry in $NameOfGroups) 
        {
            $ConcernedServicesList = $MainGroupsTable.Groups[$NumberofEntries].ServiceList
            $TotalNumbersOfServicesinGroup = $ConcernedServicesList| Measure-Object | Select-Object -ExpandProperty Count
#            write-host "There is "$TotalNumbersOfServicesinGroup "services in" $MainGroupsTable.Groups[$($NumberofEntries)].Name ":" $ConcernedServicesList            
#            write-host ""
            foreach ($ServiceToUpdate in $ConcernedServicesList) 
            {
#                write-host "I have to update "$ServiceToUpdate" with "$ServiceEntry
#                write-host "Description must also be updated :"$MainGroupsTable.Groups[$($NumberofEntries)].Description
                $index = [array]::IndexOf($MainTable.Service.Name, $ServiceToUpdate)
                if ($index -ne -1) {
#                    Write-Output "Index of "$ServiceToUpdate" is at Index "$index"
                    $MainTable.Service[$($index)].ServiceList             += $ServiceEntry+","
                    $MainTable.Service[$($index)].ServiceListDescription   += ,$MainGroupsTable.Groups[$($NumberofEntries)].Description+"</GroupListDesc>"
                } else {
                    Write-Output $ServiceToUpdate" has not been found"
                }
            }
            $NumberofEntries++
        }
    }
}


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
# Still need to cleanup some entries in GroupList and GroupList description
#$MainTable | Format-Table -Wrap
#$MainGroupsTable | Format-Table -Wrap
$MainTable_In_JSON = $MainTable | Sort-Object -Property IPAddress | ConvertTo-Json -Depth 5
$MainGroupsTable_In_JSON = $MainGroupsTable | Sort-Object -Property IPAddress | ConvertTo-Json -Depth 6
#$Table_In_JSON
$MainTable_In_JSON | Out-File -FilePath $OutputFile utf8

