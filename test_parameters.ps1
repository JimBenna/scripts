[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$identifier="",

    [Parameter(Mandatory=$true)]
    [string]$token = ""
)

try {
    if (($null -eq $identifier) -or ($identifier -eq "")) {
        Write-Output "No Id provided"
        {break}
    }
        if (($null -eq $token) -or ($token -eq "")){
        Write-Output "No token provided"
        {break}
    }
    else {
        Write-Host "Id    : "$identifier
        Write-Host "Token : "$token
    }
} catch {
    Write-Error "An error occurred: $_"
    exit 1
}