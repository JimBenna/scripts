# This script creates a firewall list in csv format
# It stores IP ADDRESS, LOGIN NAME, PASSWORD, Access TimeOut in seconds
#


#param (
#    [parameter(Mandatory=$true)]
#    [string]$Secret = ""
#)
function ConvertStringToSecureString {
    param (
        [string]$Text
    )
    $SecureString= New-Object -TypeName System.Security.SecureString
    $Text.ToCharArray() | ForEach-Object {$SecureString.AppendChar($_)}
    $SecureString.MakeReadOnly()
    return $SecureString
}

function ConvertEncodedStringToText {
    param (
        [System.Security.SecureString]$EncodedString
    )
    $ptr=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncodedString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

Clear-Host
Write-Output "---------------------------------------------"
Write-Output "-          Firewalls creation List          -"
Write-Output "---------------------------------------------"
Write-Output "It requires no parameter at all "
Write-Host "Just use the command"
Write-Host $MyInvocation.MyCommand.Name
Write-Host ""
Write-Output "---------------------------------------------"
# Ask file name and path
$FullFileName = Read-Host "Please enter CSV filename with full path "

$Table = @()
user@vm-indus:~/Documents/code$ ls
Basic_Firewall_API.ps1  create_fw_list.ps1  Firewall_Get_IPHosts.ps1  MesTests.ps1
user@vm-indus:~/Documents/code$ cat Basic_Firewall_API.ps1
# This script reads a CSV file that contains firewalls list
# It reads the following columns : IP ADDRESS, LOGIN NAME, PASSWORD, Access TimeOut in seconds
# ---- CLI Parameters ----

param (
    [parameter(Mandatory=$true)]
    [string]$InputFileFirewallList = ""
)
# ---- Functions ----
function BuildURLFunction {
    param (
        [string]$FuncFwIP,
        [string]$FuncFwPort,
        [string]$FuncFwLogin,
        [string]$FuncFwPwd,
        [string]$FuncFwTimeOut
    )
    $FuncUrlLogin="https://"+$FuncFwIP+":"+$FuncFwPort+"/webconsole/APIController?reqxml=<Request><Login><Username>"+$FuncFwLogin+"</Username><Password>"+$FuncFwPwd+"</Password></Login><GET>"
    $FuncUrlCommand="<Interface/>"
    $FuncUrlEnding="</GET></Request>"
    $FuncUrlContentType= @{}
    $FuncUrlContentType.Add("content-type","application/xml")
    [string]$WholeCompletedURL=$FuncUrlLogin+$FuncUrlCommand+$FuncUrlEnding
    return $WholeCompletedURL
}
function TranformInterfacesXmlListToArray {
    param (
        [xml]$XmlDocument
    )
    $XmlTag = $XmlDocument.SelectNodes("//Interface")
                        $OutTagArray=@()
                        foreach ($Node in $XmlTag) {
                            $OutTag=$Node.OuterXml
                            $OutTagArray += [pscustomobject]@{
                            Name                = $Node.Name
                            Hardware            = $Node.Hardware
                            IfStatus            = $Node.InterfaceStatus
                            SecurityZone        = $Node.NetworkZone
                            IPv4Status          = $Node.IPv4Configuration
                            IPv6Status          = $Node.IPv6Configuration
                            IfMTU               = $Node.MTU
                            IfMSSOveride        = $Node.MSS.OverrideMSS
                            IfMSSValue          = $Node.MSS.MSSValue
                            IfCharacteristics   = $Node.Status
                            IfSpeed             = $Node.InterfaceSpeed
                            IfAutoNegotiation   = $Node.AutoNegotiation
                            IfFec               = $Node.FEC
                            IfDHCPRapidCommit   = $Node.DHCPRapidCommit
                            IfBreakoutMembers   = $Node.BreakoutMembers
                            IfBreakoutSource    = $Node.BreakoutSource
                            IfMACAddress        = $Node.MACAddress
                            IfIpv4Assignement   = $Node.IPv4Assignment
                            IfIpv4Address       = $Node.IPAddress
                            IfIpv4NetMask       = $Node.Netmask
                            IfIpv6Assignement   = $Node.IPv6Assignment
                            }
                        }
 return $OutTagArray
}
# ---- Main program ----
# $FullFileName = Read-Host "Please enter CSV filename with full path "
$FullFileName = $InputFileFirewallList
$LinesCount= (Get-Content -Path $FullFileName).Count
Write-Host "The file"$FullFileName" contains "$LinesCount" lines"
if (Test-Path -Path $FullFileName) {
try {
     $file = Get-Item $FullFileName
     $file.OpenRead().Close()
     #File exists and can be read
     $ImportCsvFile = Import-Csv -Path $FullFileName
     $Counter=0
     $MainTable=[System.Collections.ArrayList]::new()

        foreach ($Item in $ImportCsvFile) {

                try {

                Write-Host "---------------------------------------------------------"
                Write-Host "Iteration Number :"$Counter
#                write-host $Item
                $FwAdminIpAddress = $Item.IPAddress
                Write-Host "IP Address                :"$FwAdminIpAddress
                $FwAdminListeningPort = $Item.AccesPortNb
                Write-Host "Port Number               :"$FwAdminListeningPort
                $EncryptedPassword = $Item.Password
                $Password = ConvertTo-SecureString -String $EncryptedPassword
                $Credentials = New-Object System.Management.Automation.PSCredential ($Item.LoginName, $Password
)
                Write-Host "Credentials Login name    : $($Credentials.UserName)"
                Write-Host "Credentials Login Password: $($Credentials.GetNetworkCredential().Password)"
                $AccessTimeOut = $Item.TimeOut
                Write-Host "Access TimeOut            :"$AccessTimeOut



                $FuncURL=BuildURLFunction -FuncFwIP $FwAdminIpAddress -FuncFwPort $FwAdminListeningPort -FuncFw
Login $($Credentials.UserName) -FuncFwPwd $($Credentials.GetNetworkCredential().Password)
#                Write-Host $FuncURL
                try {
                    $HttpResult=(Invoke-RestMethod -Uri $FuncURL -Method Post -ContentType "application/xml" -S
kipCertificateCheck -TimeoutSec $AccessTimeOut)
#                    $HttpResult=(Invoke-RestMethod -Method Post -Uri $UrlLogin$UrlCommand$UrlEnding -Headers $
UrlContentType -ErrorAction SilentlyContinue -ErrorVariable ScriptError -SkipCertificateCheck -OutFile output.x
ml)

    $InterfacesListArray=TranformInterfacesXmlListToArray -XmlDocument $HttpResult
    $Firewalls_Object = [PSCustomObject]@{
        Firewall = $Item.IPAddress
        FirewallInterfaces = $InterfacesListArray
    }

#    $Firewalls_Object
$MainTable.add($Firewalls_Object) | Out-Null
#$Firewalls_List
#    $InterfacesListArray
#                    [xml]$xmlResponse = $HttpResult
#                    $XmlTag = $xmlResponse.SelectNodes("//Interface")
#                    $XmlTag
#                    $OutTagArray=@()
#                    foreach ($Node in $XmlTag) {
#                        $OutTag=$Node.OuterXml
#                        $OutTag
#                            $OutTagArray += [pscustomobject]@{
#                            Name                = $Node.Name
#                            Hardware            = $Node.Hardware
#                            IfStatus            = $Node.InterfaceStatus
#                            SecurityZone        = $Node.NetworkZone
#                            IPv4Status          = $Node.IPv4Configuration
#                            IPv6Status          = $Node.IPv6Configuration
#                            IfMTU               = $Node.MTU
#                            IfMSSOveride        = $Node.MSS.OverrideMSS
#                            IfMSSValue          = $Node.MSS.MSSValue
#                            IfCharacteristics   = $Node.Status
#                            IfSpeed             = $Node.InterfaceSpeed
#                            IfAutoNegotiation   = $Node.AutoNegotiation
#                            IfFec               = $Node.FEC
#                            IfDHCPRapidCommit   = $Node.DHCPRapidCommit
#                            IfBreakoutMembers   = $Node.BreakoutMembers
#                            IfBreakoutSource    = $Node.BreakoutSource
#                            IfMACAddress        = $Node.MACAddress
#                            IfIpv4Assignement   = $Node.IPv4Assignment
#                            IfIpv4Address       = $Node.IPAddress
#                            IfIpv4NetMask       = $Node.Netmask
#                            IfIpv6Assignement   = $Node.IPv6Assignment
#                        }
#                    }
#                    $OutTagArray

}
                catch {
                                Write-Host "Error : $($_.Exception.Message)"
                }

#            }

}
            catch {
                Write-Host "Error encountered while parsing file"
                Write-Host "Error $($_.Exception.Message)"
                exit 1
            }
            Write-Host ""
            $Counter++
            Write-Host "Compteur :" $Counter

        }

    }
catch {
    Write-Host "File "$FullFileName" exists but can not be accessed in Read mode"
    exit 2
    }
}
else {
    Write-Host "File "$FullFileName" does not exist"
    exit 3
}
# END

# $MainTable
$Table_In_JSON= $MainTable | ConvertTo-Json -Depth 3
# $Table_In_JSON