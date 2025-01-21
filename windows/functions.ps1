# This function just gets some basic information about a machine over WMI/CIM
function Get-BiosInfo ($ComputerName) {
    ## Gather BIOS information
    try { $BiosInfo = Get-CimInstance -ClassName Win32_BIOS -ComputerName $ComputerName }
    catch { throw "Unable to get BIOS information" }
    try { $ModelInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName }
    catch { throw "Unable to get BIOS information" }
    try { $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName }
    catch { throw "Unable to get BIOS information" }
    switch ($BiosInfo.Manufacturer) {
        { ($_ -ieq "HP") -or ($_ -ieq "HPE") } {
            $bios_version = $biosinfo.ReleaseDate | Get-Date -Format "yyyy.MM.dd"
            #$bmc_version = ($BiosInfo.EmbeddedControllerMajorVersion, $BiosInfo.EmbeddedControllerMinorVersion) -join '.'
        }
        "Dell Inc." {
            $bios_version = $biosinfo.SMBIOSBIOSVersion
            continue
        }
        "LENOVO" {
            $bios_version = $biosinfo.SMBIOSBIOSVersion
            continue
        }
    }
    try {
        @{
            Serial          = $BiosInfo.SerialNumber
            BiosVersion     = $bios_version
            Model           = $ModelInfo.Model
            Manufacturer    = $ModelInfo.Manufacturer
            Memory          = $ModelInfo.TotalPhysicalMemory / 1GB
            OperatingSystem = $OSInfo.Caption
            HyperV          = (Get-WindowsFeature -ComputerName $ComputerName -Name hyper-v).Installed
        }
    }
    catch { throw "Unable to get information from remote PC: $ComputerName" }
}
function Get-WindowsNetworkAdapters ($ComputerName) {
    <#
    This function picks one of the addresses that windows doesn't have marked as "Skip as source" to call the primary IP of the nic.
    For IPv4, we use the lowest numbered nic. For IPv6 we use the IP address with the shortest lifetime, as it's likely to be the one
    in use for new connections, though this may be a bad assumption. At any rate, the stakes are low. Anyone processing the output
    of this function shouldn't use anything except the list of static addresses for the NIC when documenting a machine.
#>
    try {
        [array]$NicInfo = (Get-CimInstance -ClassName Win32_NetworkAdapter -ComputerName $ComputerName -ErrorAction Stop | Where-Object { $_.AdapterType })
        [array]$NicConfigInfo = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -ErrorAction Stop)
    }
    catch { throw "Unable to get information from remote PC: $ComputerName" }
    $Output = Foreach ($item in $NicInfo) {
        $nicPhysical = if ($item.Name -eq 'Microsoft Network Adapter Multiplexor Driver') { $false } else { $item.PhysicalAdapter }
        $IPs = Get-NetIPConfiguration -ComputerName $ComputerName
        [array]$IPv4Sources = ($IPs.IPv4Address | Where-Object { $_.SkipAsSource -eq $false -and $_.ifIndex -eq $item.InterfaceIndex }) | sort-object -Property IPAddress
        [array]$IPv6Sources = ($IPs.IPv6Address | Where-Object { $_.SkipAsSource -eq $false -and $_.ifIndex -eq $item.InterfaceIndex }) | sort-object -Property ValidLifetime
        if ($IPv4Sources) { $primary4 = "$($IPv4Sources[0].IPAddress)/$($IPv4Sources[0].PrefixLength)" }
        if ($IPv6Sources) { $primary6 = "$($IPv6Sources[0].IPAddress)/$($IPv6Sources[0].PrefixLength)" }
        #if('Manual' -in $IPs.IPv4Address.PrefixOrigin) {$StaticV4Present=$true} else {$StaticV4Present = $false}
        #if('Manual' -in $IPs.IPv6Address.PrefixOrigin) {$StaticV6Present=$true} else {$StaticV6Present = $false}
        [PSCustomObject]@{
            Name           = $item.NetConnectionID
            Type           = $item.AdapterType
            Model          = $item.ProductName
            MAC            = $item.MacAddress
            Physical       = $nicPhysical
            IPv4CIDRAuto   = ($IPs | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).IPv4Address | Where-Object { $_.PrefixOrigin -ne 'Manual' } | ForEach-Object { if ($_.IPAddress) { "$($_.IPAddress)/$($_.PrefixLength)" } } | Sort-Object -Property IPAddress
            IPv6CIDRAuto   = ($IPs | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).IPv6Address | Where-Object { $_.PrefixOrigin -ne 'Manual' } | ForEach-Object { if ($_.IPAddress) { "$($_.IPAddress)/$($_.PrefixLength)" } } | Sort-Object -Property IPAddress
            IPv4CIDRStatic = ($IPs | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).IPv4Address | Where-Object { $_.PrefixOrigin -eq 'Manual' } | ForEach-Object { if ($_.IPAddress) { "$($_.IPAddress)/$($_.PrefixLength)" } } | Sort-Object -Property IPAddress
            IPv6CIDRStatic = ($IPs | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).IPv6Address | Where-Object { $_.PrefixOrigin -eq 'Manual' } | ForEach-Object { if ($_.IPAddress) { "$($_.IPAddress)/$($_.PrefixLength)" } } | Sort-Object -Property IPAddress
            Primary4       = $primary4
            Primary6       = $primary6
            #StaticV4Present = $StaticV4Present
            #StaticV6Present = $StaticV6Present
            DHCP4Enabled   = ($NicConfigInfo | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).DHCPEnabled
            # The only time this is false is when IPv4 is not bound to the nic, which is so unlikely I doubt you'll see it, so it's disabled here.
            # IPBound = ($NicConfigInfo|Where-Object {$_.InterfaceIndex -eq $item.InterfaceIndex}).IPEnabled
        }
    }
    $Output
}
function Get-WinClusterInfo ($ComputerName) {
    try {
        $ClusterInfo = Get-CimInstance -ClassName MSCluster_Cluster -Namespace 'Root/MSCluster' -ComputerName $ComputerName -ErrorAction Stop
        $ClusterNodes = Get-CimInstance -ClassName MSCluster_Node -Namespace 'Root/MSCluster' -ComputerName $ComputerName -ErrorAction Stop
    }
    catch {
        throw "Unable to find cluster information from $ComputerName"
    }
    #$ClusterBaseInfo|Select-Object Name,Fqdn
    [PSCustomObject]@{
        Name    = $ClusterInfo.Name
        FQDN    = $ClusterInfo.Fqdn
        Members = $ClusterNodes.Name
    }
}

<#
    By default, the function will decline to create most pre-requisite objects, like sites. the -ForceCreatePrereqs argument
    overrides this restriction, so use it wisely.
#>
function Add-WindowsTargetToNetbox {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$SiteName,
        [Parameter(Mandatory = $false)][string]$Role = "Server",
        [Parameter(Mandatory = $false)][switch]$ForceCreatePrereqs,
        [Parameter(Mandatory = $false)][ValidateSet('virtual', 'physical')][string]$ForceType,
        [Parameter(Mandatory = $false)][string]$VMClusterName = 'Default Cluster'
    )
    #region Setup
    # Normalize device name
    $ComputerName = $ComputerName.ToUpper()
    if ($ComputerName -like "*.*") {
        $ComputerName = $ComputerName.Split('.')[0]
        Write-Verbose "Converted FQDN to hostname $ComputerName"
    }
    Write-Verbose "Normalized object name: $ComputerName"

    # Get hardware information over WMI
    Write-Verbose "Acquiring information from WMI"
    try { $BiosInfo = Get-BiosInfo $ComputerName }
    catch { throw "Can't get serial information for $ComputerName. $($MyInvocation.MyCommand.Name) exiting abnormally" }

    # Get Network Information
    try { $NetworkInfo = Get-WindowsNetworkAdapters -ComputerName $ComputerName }
    catch { throw "Can't get serial information for $ComputerName. $($MyInvocation.MyCommand.Name) exiting abnormally" }

    # Get Clustering Information
    try { $ClusterInfo = Get-WinClusterInfo -ComputerName $ComputerName }
    catch { $ClusterInfo = $false }
    
    # Get or create Netbox objects for pre-requisites
    Write-Verbose "Acquiring information from Netbox"

    if (!($SiteObj = Get-NBSiteByName $Site)) {
        if ($ForceCreatePrereqs) {
            $SiteObj = New-NBSite -name $SiteName -status active
        }
        else { throw "Unable to find site object for $Site" }
    }
    if (!($OSObj = Get-NBDevicePlatformByName $BiosInfo.OperatingSystem)) {
        if (!($MFRObj = Get-NBManufacturerByName 'Microsoft')) {
            $MFRObj = New-NBManufacturer 'Microsoft'
        }
        $OSObj = New-NBDevicePlatform -name $BiosInfo.OperatingSystem -manufacturer $MFRObj.id
    }
    #endRegion Setup

    # Determine whether we're documenting this as a VM or Device
    # Obviously not a super robust detection method, it's just based on some things I have on hand I can detect against.
    # Some of these vendor names cribbed from https://github.com/poettering/systemd/blob/main/src/basic/virt.c 
    # Reading some of that code makes me very happy to not be a C developer. Absolute gibberish.
    Switch ($BiosInfo.Manufacturer) {
        { 'virtual' -eq $ForceType } { $isVM = $true }
        { 'physical' -eq $ForceType } { $isVM = $false }
        { $_ -in "QEMU", "KVM", "OpenStack", "Virtualbox", "VMWare, Inc." } {
            $isVM = $true
        }
        { $_ -eq 'Microsoft Corporation' -and $BiosInfo.Model -eq 'Virtual Machine' } {
            $isVM = $true
        }
        else { $isVM = $false }
    }
    ## If it's not a vm:
    if (!($isVM)) {
        # Get or create the device role we've been given
        if (!($RoleObj = Get-NBDeviceRoleByName $Role)) {
            if ($ForceCreatePrereqs) { $RoleObj = New-NBDeviceRole -name $Role -color red }
            else { throw "Unable to find role object for $Role" }
        }
        else { throw "Can't find a role object, not allowed to create one." }
        # Try to get an object that represents the model
        if (!($DeviceTypeObj = Get-NBDeviceTypeByModel -DeviceType $BiosInfo.Model)) {
            # If there's not one, and we're allowed we create one, and the manufacturer too, if needed.
            if ($ForceCreatePrereqs) {
                if (!($DeviceMFRObj = Get-NBManufacturerByName $BiosInfo.Manufacturer)) {
                    $DeviceMFRObj = New-NBManufacturer $BiosInfo.Manufacturer
                }
                $DeviceTypeObj = New-NBDeviceType -manufacturer $DeviceMFRObj.id -model $BiosInfo.Model
            }
        }
        if ($DeviceObj = Get-NBDeviceByName -name $ComputerName) {
            Write-Verbose "Existing object for $ComputerName found"
        }
        else {
            Write-Verbose "Code believes the device object did not exist - creating"
            $DeviceObj = New-NBDevice -name $ComputerName -device_type $DeviceTypeObj.id -role $RoleObj.id -platform $OSObj.id -serial $BiosInfo.serial -site $SiteObj.id -status active
            Write-Verbose $DeviceObj.id
            Write-Verbose "Created device object $($DeviceObj.name)"
        }
        ## Handle networking
        $interfaces=Get-NBDeviceInterfaceForDevice $DeviceObj.id
        Foreach($NetworkConfig in $NetworkInfo) {
            # Get or create the interface
            if ($NetworkConfig.Name -notin $interfaces.Name) {
                $IntObj=New-NBDeviceInterface -device $DeviceObj.id -name $NetworkConfig.Name -type virtual -description $NetworkConfig.Model -mac_address $NetworkConfig.MAC
            }
            else {$IntObj=$interfaces|Where-Object{$_.name -eq $NetworkConfig.name}}
            # Get or create the IP address, if needed
            foreach($IP in $NetworkConfig.IPv4CIDRStatic){
                try {$IPObj = Get-NBIPAddressByName $IP}catch{$IPObj = New-NBIPAddress -address $IP -assigned_object_type dcim.interface -assigned_object_id $DeviceObj -status active}
                if ($IPObj.assigned_object_type -ne 'dcim.interface' -or $IPObj.assigned_object_id -ne $IntObj.id) {
                    Set-NBIPAddressParent -id $IPObj.id -InterFaceType dcim.interface -interface $IntObj.id
                }
            }
        }
        if ($ClusterInfo){Set-NBDevice -id $DeviceObj.id -key comments -value ($DeviceObj.comments + "`n`nMember of Windows cluster $($ClusterInfo.Name), $($ClusterInfo.FQDN)")}
    }

    ## It is a VM, proceed accordingly
    else {
        try {$VMClusterObj=Get-NBVMClusterByName $VMClusterName}
        catch{
            if($ForceCreatePrereqs) {
                try {$VMClusterObj = Get-NBVMClusterTypeByName 'Generic'} catch {$VMClusterTypeObj=New-NBVMClusterType -name 'Generic' -description 'This cluster type was created to allow a VM to be created and assigned to a cluster automatically, please check over clusters assigned to this type and re-assign them to the proper cluster type.'}
                $VMClusterObj = New-NBVMCluster -name $VMClusterName -type $VMClusterTypeObj.id -status active -description 'This cluster was created to allow a VM to be created and assigned to a cluster automatically, please check over this cluster and adjust the properties/type to match reality'
            }
            else {throw "Unable to get cluster '$($VMClusterName)', and -ForceCreatePrereqs not set"}
        }
        try {$VMobj=Get-NBVMByName $ComputerName} catch {$VMobj = New-NBVM -name $ComputerName -status active -site $SiteObj.id -cluster }
        if ($ClusterInfo){Set-NBVM -id $VMobj.id -key comments -value ($VMobj.comments + "`n`nMember of Windows cluster $($ClusterInfo.Name), $($ClusterInfo.FQDN)")}
        $interfaces = Get-NBVMInterfaceForVM $VMobj.id
    }
}
