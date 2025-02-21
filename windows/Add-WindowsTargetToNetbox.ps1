. $PSScriptRoot\init.ps1 | Out-Null
. $PSScriptRoot\functions.ps1
#Start-Sleep -Milliseconds 500
Get-Help Add-WindowsTargetToNetbox -Detailed | Out-Host
Write-Host "You can now use Add-WindowsTargetToNetbox as outlined above to document your environment." -ForegroundColor Yellow