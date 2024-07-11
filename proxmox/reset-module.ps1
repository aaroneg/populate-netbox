remove-module proxmox-rest-module
import-module proxmox-rest-module -force
remove-module netbox-rest-module
import-module netbox-rest-module -force
Get-Module proxmox-rest-module
Get-Module netbox-rest-module
. $PSScriptRoot\init