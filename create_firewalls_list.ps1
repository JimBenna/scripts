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
    $SecureString = New-Object -TypeName System.Security.SecureString
    $Text.ToCharArray() | ForEach-Object { $SecureString.AppendChar($_) }
    $SecureString.MakeReadOnly()
    return $SecureString
}

function ConvertEncodedStringToText {
    param (
        [System.Security.SecureString]$EncodedString
    )
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncodedString)
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
do {
    Clear-Host
    Write-Output "-----------------------------------------------------------------"
    Write-Host "Adding one line in file : "$FullFileName
    Write-Output "-----------------------------------------------------------------"
    Write-Host
    # Ask users to fill-up informations
    $IpAddress = Read-Host "Plase type IP Address of Firewall  "
    $PortNumber = Read-Host "Plase type Port Access of Firewall "
    $TimeOutNumber = Read-Host "Plase type TimeOut in Seconds "
    $LoginName = Read-Host "Please type Login Name             "
    $Password = Read-Host "Please type Password to use        " -AsSecureString

    $StoragePwd = $Password | ConvertFrom-SecureString
    $ReadablePwd = ConvertEncodedStringToText $Password
    #    Write-Host "Password                 : "$Password
    #    Write-Host "Password stocke          : "$StoragePwd
    #    Write-Host "Mot de passe en clair    : "$ReadablePwd

    $TableLine = [PSCustomObject]@{
        IPAddress   = $IpAddress
        AccesPortNb = $PortNumber
        LoginName   = $LoginName
        Password    = $StoragePwd
        TimeOut     = $TimeOutNumber
    }
    $Table += $TableLine

    $OneMore = Read-Host "Add another One ? : (yes/no)"

}
while (($OneMore -eq "yes") -or ($OneMore -eq "YES") -or ($OneMore -eq "Yes") -or ($OneMore -eq "Y") -or ($OneM
        ore -eq "y"))

Write-Host "Ok no more line"

if (-Not (Test-Path -Path $FullFileName)) {
    $Table | Export-Csv -Path $FullFileName -NoTypeInformation
}
else {
    $Table | Export-Csv -Path $FullFileName -NoTypeInformation -Append
}
Write-Host "All informations have been written in file : "$FullFileName