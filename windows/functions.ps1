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
        [array]$IPv4Sources = (($IPs.IPv4Address | Where-Object { $_.SkipAsSource -eq $false -and $_.ifIndex -eq $item.InterfaceIndex }) | sort-object -Property IPAddress).IPAddress
        [array]$IPv6Sources = (($IPs.IPv6Address | Where-Object { $_.SkipAsSource -eq $false -and $_.ifIndex -eq $item.InterfaceIndex }) | sort-object -Property ValidLifetime).IPAddress
        #$IPv6Sources
        $IPv4Statics=@(($IPs | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).IPv4Address | Where-Object { $_.PrefixOrigin -eq 'Manual' } | ForEach-Object { if ($_.IPAddress) { "$($_.IPAddress)/$($_.PrefixLength)" } } | Sort-Object -Property IPAddress)
        $IPv6Statics=@(($IPs | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).IPv6Address | Where-Object { $_.PrefixOrigin -eq 'Manual' } | ForEach-Object { if ($_.IPAddress) { "$($_.IPAddress)/$($_.PrefixLength)" } } | Sort-Object -Property IPAddress)
        [PSCustomObject]@{
            Name           = $item.NetConnectionID
            Type           = $item.AdapterType
            Model          = $item.ProductName
            MAC            = $item.MacAddress
            Physical       = $nicPhysical
            IPv4CIDRAuto   = @(($IPs | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).IPv4Address | Where-Object { $_.PrefixOrigin -ne 'Manual' } | ForEach-Object { if ($_.IPAddress) { "$($_.IPAddress)/$($_.PrefixLength)" } } | Sort-Object -Property IPAddress)
            IPv6CIDRAuto   = @(($IPs | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).IPv6Address | Where-Object { $_.PrefixOrigin -ne 'Manual' } | ForEach-Object { if ($_.IPAddress) { "$($_.IPAddress)/$($_.PrefixLength)" } } | Sort-Object -Property IPAddress)
            IPv4CIDRStatic = $IPv4Statics
            IPv6CIDRStatic = $IPv6Statics
            Primary4       = (($IPv4Statics|Where-Object{$_ -like "$($IPv4Sources[0].IPAddress)*"}) -split ' ')[0]
            Primary6       = (($IPv6Statics|Where-Object{$_ -like "$($IPv6Sources[0].IPAddress)*"}) -split ' ')[0]
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
    if (!($SiteObj = Get-NBSiteByName $SiteName)) {
        if ($ForceCreatePrereqs) {
            Write-Verbose "Creating Site object for $SiteName"
            $SiteObj = New-NBSite -name $SiteName -status active
        }
        else { throw "Unable to find site object for $SiteName" }
    }
    Write-Verbose "Site ID: $($SiteObj.id)"
    if (!($OSObj = Get-NBDevicePlatformByName $BiosInfo.OperatingSystem)) {
        if (!($MFRObj = Get-NBManufacturerByName 'Microsoft')) {
            Write-Verbose "Creating 'Microsoft' manufacturer"
            $MFRObj = New-NBManufacturer 'Microsoft'
        }
        Write-Verbose "Manufacturer ID: $($MFRObj.id)"
        Write-Verbose "Creating device platform '$($BiosInfo.OperatingSystem)'"
        $OSObj = New-NBDevicePlatform -name $BiosInfo.OperatingSystem -manufacturer $MFRObj.id
    }
    Write-Verbose "Platform '$($BiosInfo.OperatingSystem)' ID: $($OSObj.id)"
    # Get or create the device role we've been given
    Write-Verbose "Acquiring Device role $($Role)"
    try {
        $RoleObj=Get-NBDeviceRoleByName $Role
        if($null -eq $RoleObj){throw}
    }
    catch {
        if($ForceCreatePrereqs){
            Write-Verbose "Creating VM role $($Role)"
            $RoleObj = New-NBDeviceRole -name $Role -color red
        }
        else{throw "Can't find a role object, not allowed to create one."}
    }
    if (!($RoleObj = Get-NBDeviceRoleByName $Role)) {
        
        if ($ForceCreatePrereqs) {  }
        else { throw "Unable to find role object for $Role" }
    }
    else {  }
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
        Write-Verbose "Treating as physical device"
        Write-Verbose "Role ID: $($RoleObj.id)"
        # Try to get an object that represents the model
        Write-Verbose "Acquiring device type object '$($BiosInfo.Model)'"
        if (!($DeviceTypeObj = Get-NBDeviceTypeByModel -DeviceType $BiosInfo.Model)) {
            # If there's not one, and we're allowed we create one, and the manufacturer too, if needed.
            if ($ForceCreatePrereqs) {
                Write-Verbose "Creating device type object for '$($BiosInfo.Model)'"
                if (!($DeviceMFRObj = Get-NBManufacturerByName $BiosInfo.Manufacturer)) {
                    $DeviceMFRObj = New-NBManufacturer $BiosInfo.Manufacturer
                }
                $DeviceTypeObj = New-NBDeviceType -manufacturer $DeviceMFRObj.id -model $BiosInfo.Model
            }
        }
        Write-Verbose "Device Type ID: $($DeviceTypeObj.id)"
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
                try {$IPObj = Get-NBIPAddressByName $IP}catch{$IPObj = New-NBIPAddress -address $IP -assigned_object_type dcim.interface -assigned_object_id $DeviceObj.id -status active}
                if ($IPObj.assigned_object_type -ne 'dcim.interface' -or $IPObj.assigned_object_id -ne $IntObj.id) {
                    Set-NBIPAddressParent -id $IPObj.id -InterFaceType dcim.interface -interface $IntObj.id
                }
            }
        }
        if ($ClusterInfo){Set-NBDevice -id $DeviceObj.id -key comments -value ($DeviceObj.comments + "`n`nMember of Windows cluster $($ClusterInfo.Name), $($ClusterInfo.FQDN)")}
    } # End Physical Device

    ## It is a VM, proceed accordingly
    else {
        Write-Verbose "Treating as virtual machine"
        try {
            $VMClusterObj=Get-NBVMClusterByName $VMClusterName
            if ($null -eq $VMClusterObj){throw}
        }
        catch{
            if($ForceCreatePrereqs) {
                Write-Verbose "`tCluster did not exist, processing pre-reqs as requested."
                try {
                    $VMClusterObj = Get-NBVMClusterTypeByName 'Generic'
                    if ($null -eq $VMClusterObj){throw}
                } 
                catch {
                    Write-Verbose "`t`tCreating 'Generic' VM cluster type"
                    $VMClusterTypeObj=New-NBVMClusterType -name 'Generic' -description 'This cluster type was created to allow a VM to be created and assigned to a cluster automatically, please check over clusters assigned to this type and re-assign them to the proper cluster type.'
                    Write-Verbose "`t`tCluster type 'Generic' ID: $($VMClusterTypeObj.id)"
                }
                Write-Verbose "`tCreating VM cluster '$($VMClusterName)' with type 'Generic'"
                $VMClusterObj = New-NBVMCluster -name $VMClusterName -type $VMClusterTypeObj.id -status active -description 'This cluster was created to allow a VM to be created and assigned to a cluster automatically, please check over this cluster and adjust the properties/type to match reality'
            }
            else {throw "Unable to get cluster '$($VMClusterName)', and -ForceCreatePrereqs not set"}
        }
        Write-Verbose "VM Cluster ID: $($VMClusterObj.id)"
        try {
            $VMobj=Get-NBVMByName $ComputerName
            if($null -eq $VMobj){throw}
        }
        catch {
            Write-Verbose "Creating VM Object for $($ComputerName)"
            $VMobj = New-NBVM -name $ComputerName -status active -site $SiteObj.id -cluster $VMClusterObj.id -platform $OSObj.id -role $RoleObj.id
        }
        Write-Verbose "VM Object ID: $($VMobj.id)"
        if ($ClusterInfo){Set-NBVM -id $VMobj.id -key comments -value ($VMobj.comments + "`n`nMember of Windows cluster $($ClusterInfo.Name), $($ClusterInfo.FQDN)")}
        $interfaces = Get-NBVMInterfaceForVM $VMobj.id
        Write-Verbose "`tInterface count: $($interfaces.count)"
        Write-Verbose "`tNetworkInfo count: $($NetworkInfo.count)"
        Foreach ($NetworkConfig in $NetworkInfo) {
            # Get or create the VM Interface
            if ($NetworkConfig.Name -notin $interfaces.Name) {
                Write-Verbose "`tCreating interface '$($NetworkConfig.Name)'"
                $IntObj=New-NBVMInterface -virtual_machine $VMobj.id -name $NetworkConfig.Name -enabled $true -description $NetworkConfig.Model -mac_address $NetworkConfig.MAC
            }
            else {
                $IntObj=Get-NBVMInterfaceForVM -id $VMobj.id | Where-Object {$_.name -eq $NetworkConfig.name}
            }
            Write-Verbose "VM Interface '$($NetworkConfig.name)' ID: $($IntObj.id)"
            if($NetworkConfig.IPv4CIDRStatic.count -eq 0 ){Write-Verbose "Skipping IPv4 Static Processing for interface '$($NetworkConfig.Name)' - no static IPv4 information found."}
            else{
                # Get or create the IP address, if needed
                Foreach ($IP in $NetworkConfig.IPv4CIDRStatic){
                    Write-Verbose "Processing IP: '$IP'"
                    try {
                        $IPObj = Get-NBIPAddressByName $IP
                        if($null -eq $IPObj){throw}
                    }
                    catch{
                        $IPObj = New-NBIPAddress -address $IP -assigned_object_type virtualization.vminterface -assigned_object_id $IntObj.id -status active
                    }
                    if ($IPObj.assigned_object_type -ne 'virtualization.vminterface' -or $IPObj.assigned_object_id -ne $IntObj.id) {
                        Set-NBIPAddressParent -id $IPObj.id -InterFaceType virtualization.vminterface -interface $IntObj.id
                    }
                }
                if($NetworkInfo.Primary4.length -ge 10){
                    Write-Verbose "Setting Primary IPv4 address to '$($NetworkConfig.Primary4)'"
                    $ipID=(Get-NBIPAddressByName -name $NetworkConfig.Primary4).id
                    Write-Verbose "ID for '$($NetworkConfig.Primary4)': $ipID"
                    Set-NBVM -id $VMobj.id -key primary_ip4 ($ipID)|Out-Null
                }
                else {Write-Verbose "IPv4 '$($NetworkInfo.Primary4)'length less than requirement for primary"}
            }
            if($NetworkConfig.IPv6CIDRStatic.count -eq 0 ){Write-Verbose "Skipping IPv6 Static Processing for interface '$($NetworkConfig.Name)' - no static IPv6 information found."}
            else{
                Foreach ($IP in $NetworkConfig.IPv6CIDRStatic){
                    Write-Verbose "Processing IP: '$IP'"
                    try {
                        $IPObj = Get-NBIPAddressByName $IP
                        if($null -eq $IPObj){throw}
                    }
                    catch{
                        $IPObj = New-NBIPAddress -address $IP -assigned_object_type virtualization.vminterface -assigned_object_id $IntObj.id -status active
                    }
                    if ($IPObj.assigned_object_type -ne 'virtualization.vminterface' -or $IPObj.assigned_object_id -ne $IntObj.id) {
                        Set-NBIPAddressParent -id $IPObj.id -InterFaceType virtualization.vminterface -interface $IntObj.id
                    }
                }
                if($NetworkInfo.Primary6.length -ge 10){
                    Write-Verbose "Setting Primary IPv6 address to '$($NetworkConfig.Primary6)'"
                    $ipID=(Get-NBIPAddressByName -name $NetworkConfig.Primary6).id
                    Write-Verbose "ID for '$($NetworkConfig.Primary6)': $ipID"
                    Set-NBVM -id $VMobj.id -key primary_ip6 ($ipID)|Out-Null
                }
                else {Write-Verbose "IPv6 '$($NetworkConfig.Primary6)' length is $($NetworkInfo.Primary6.length)"}
            }

        }

        
    } # End VMs
}
