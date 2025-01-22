#! /usr/bin/pwsh
if(!(Get-Module Microsoft.PowerShell.SecretManagement -ListAvailable)) {
    Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore -Force -Scope CurrentUser
    Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault -AllowClobber
}
if(!(Get-Module netbox-rest-module -ListAvailable)) {
    Install-Module netbox-rest-module
}
Import-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore, netbox-rest-module
# Read or create a proxmox config object

try {
    $nbconfig=Import-Clixml $PSScriptRoot\nbconfig.xml
}
catch {
    $nbconfig=@{
        serverAddress = Read-Host -Prompt "IP address or hostname of Netbox server"
    }
    $nbconfig | Export-Clixml $PSScriptRoot\nbconfig.xml
}
# Get or create the API credential
try {
    $NBSecret=Get-Secret -Name $NBConfig.serverAddress -AsPlainText -ErrorAction Stop
}
catch {
    $NBSecret=Read-Host -Prompt "API Key"
    Set-Secret -Name $NBConfig.serverAddress -Secret $NBSecret
}

$NBConnection = New-NBConnection -DeviceAddress $nbconfig.serverAddress -ApiKey $NBSecret -Passthru -SkipCertificateCheck -Verbose
Write-Output "Connection initiated:"
Remove-Variable -Name Secret -ErrorAction SilentlyContinue | Out-Null
$NBConnection|Select-Object -ExcludeProperty ApiKey
