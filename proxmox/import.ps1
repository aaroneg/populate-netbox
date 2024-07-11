[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $ParameterName
)
. $PSScriptRoot\init.ps1
$Cluster = Get-PXCluster -Verbose|Where-Object{$_.type -eq 'cluster'}
$Nodes = Get-PXClusterNodes -Verbose
$PXVMs = Get-PXVMs
if(!($NBSite)) {$NBSite=Get-NBSites|Out-GridView -Title 'Select Netbox Site' -OutputMode Single}
if(!($NBNodeType)) { $NBNodeType = Get-NBDeviceTypes | Out-GridView -Title "Select Hypervisor Device Type" -OutputMode Single}
$NBNodeRole = Get-NBDeviceRoleByName 'Hypervisor'
if($null -eq $NBNodeRole) {
    Write-Warning 'Creating Hypervisor device role'
    $NBNodeRole=New-NBDeviceRole -name 'Hypervisor' -color "2A52BE".ToLower() 
}
$NBVMCluster=Get-NBVMClusterByName $Cluster.Name -Verbose
if($null -eq $NBVMCluster) {
    $NBClusterType=Get-NBVMClusterTypeByName 'Proxmox' -Verbose
    if ($Null -eq $NBClusterType) {
        Write-Warning 'Creating Proxmox VM cluster type'
        $NBClusterType=New-NBVMClusterType -name 'Proxmox' -description 'Proxmox is a hypervisor platform that can host KVM/Qemu VMs and LXC containers' -Verbose
    }
    Write-Warning 'Creating VM cluster'
    $NBVMCluster=New-NBVMCluster -name $Cluster.Name -type $NBClusterType.id -status active -site $NBSite.ID
}
Foreach ($Node in $Nodes) {
    $NBNode=Get-NBDeviceByName $Node.name
    if($null -eq $NBNode) { 
        Write-Warning 'Creating VM host'
        $NBNode = New-NBDevice -name $node.name -device_type $NBNodeType.ID -role $NBNodeRole.ID -site $NBSite.id -status active -Verbose
    }
    if($NBNode.cluster.id -ne $NBVMCluster.id) {
        Write-Warning 'Updating VM host to place it in cluster'
        Set-NBDevice -id $NBNode.id -key cluster -value $NBVMCluster.ID
    }
    
}

Foreach($PXVM in $PXVMs) {
    $NBVM=Get-NBVMByName $PXVM.Name
    if($null -eq $NBVM){
        Write-Warning "$($PXVM.name) is missing, creating"
        $NBVM=New-NBVM -name $PXVM.name -cluster $NBVMCluster.id -status active -vcpus $PXVM.CPUCount -site $NBSite.ID -memory ($PXVM.Memgb*1024) -disk ($PXVM.diskgb)
    }
    ($NBVM|Out-String)| Write-Verbose 
    $NBVMInterfaces=Get-NBVMInterfaceForVM -id $NBVM.ID
    if ($null -eq $NBVMInterfaces){
        Foreach($nic in $PXVM.nics){
            $newNIC = New-NBVMInterface -virtual_machine $NBVM.ID -name $nic.name -mac_address $nic.MAC
            Foreach ($ip in ($nic.ipv4).Split(',')) {
                if ($ip -eq 'dhcp' -or $ip -eq '' -or $null -eq $ip) { 
                    Write-Warning "Skipping non-static IP"
                    continue 
                }
                Write-Verbose $ip
                Write-Verbose ($nic.ipv4).Split(',')[0]
                try {
                    $nbip4obj = Get-NBIPAddressByName $ip
                    if ($null -eq $nbip4obj) {throw 'no IP object present'}
                    Set-NBIPAddressParent -id $nbip4obj.id -InterFaceType virtualization.vminterface -interface $newNIC.id
                }
                catch {
                    $nbip4obj = New-NBIPAddress $ip -assigned_object_type 'virtualization.vminterface' -assigned_object_id $newNIC.ID
                }
                # if ("$ip" -like "$(($nic.ipv4).Split(',')[0])" -and $nic.name -eq $PXVM.nics[0].name) {
                #     Write-Host 'Setting primary IP4' -ForegroundColor Green
                #     Set-NBVM -key primary_ipv4 -value $nbip4obj.ID -id $NBVM.ID -Verbose | Out-Null
                # }
                # else {Write-Host "Not setting primary ip to $($nbip4obj.address), Expected address is $(($nic.ipv4).Split(',')[0])" -ForegroundColor DarkMagenta}
            }
            Foreach ($ip in ($nic.ipv6).Split(',')) {
                if ($ip -eq 'auto' -or $ip -eq '' -or $null -eq $ip) { 
                    Write-Warning "Skipping non-static IP"
                    continue 
                }
                Write-Verbose $ip
                Write-Verbose ($nic.ipv6).Split(',')[0]
                try {
                    $nbip6obj = Get-NBIPAddressByName $ip
                    if ($null -eq $nbip6obj) {throw "No IP object present"}
                    Set-NBIPAddressParent -id $nbip6obj.id -InterFaceType virtualization.vminterface -interface $newNIC.id
                }
                catch {
                    $nbip6obj = New-NBIPAddress $ip -assigned_object_type 'virtualization.vminterface' -assigned_object_id $newNIC.ID
                }
                # if ("$ip" -like "$(($nic.ipv6).Split(',')[0])" -and $nic.name -eq $PXVM.nics[0].name) {
                #     Write-Host "Setting primary IP6 for vm $($NBVM.ID)" -ForegroundColor Green
                #     Set-NBVM -key primary_ipv6 -value $nbip6obj.ID -id $NBVM.ID -Verbose | Out-Null
                # }
                # else {Write-Host "Not setting primary ip to $($nbip6obj.address), Expected address is $(($nic.ipv6).Split(',')[0])" -ForegroundColor DarkMagenta}
            }
        }
    }
    sleep -Seconds 1
    try {Get-nbvmbyname $PXVM.name |Out-Null}
    catch {"Cannot get VM named $($PXVM.name)"}
    #Get-nbvmbyname $PXVM.name -Verbose -Debug
    #Read-Host -Prompt 'Press enter to continue'
}

Foreach ($PXVM in $PXVMs){
    $NBVM=Get-NBVMByName $PXVM.name
    [array]$VMNics=Get-NBVMInterfaceForVM $nbvm.ID
    $TargetNic=$VMNics|Where {$_.Name -eq 'net0'}
    [array]$NicIPs=Get-NBIPAddressForVMInterface $TargetNic.ID
    [array]$IPv4s=$NicIPs|Where-Object {$_.family.value -eq 4}
    [array]$IPv6s=$NicIPs|Where-Object {$_.family.value -eq 6}
    if($IPv4s.Length -ge 1){
        #$NBVM.id
        #$IPv4s[0]|Select address,id
        Set-NBVM -id $NBVM.id -key primary_ip4 $IPv4s[0].id | Out-Null
    }
    if($IPv6s.Length -ge 1){
        #$NBVM.id
        #$IPv6s[0]|Select address,id
        Set-NBVM -id $NBVM.id -key primary_ip6 $IPv6s[0].id | Out-Null
    }
    
    #
    #
}