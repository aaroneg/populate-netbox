# This function just gets some basic information about a machine over WMI/CIM
function Get-BiosInfo ($ComputerName) {
    ## Gather BIOS information
    try { $BiosInfo = Get-CimInstance -ClassName Win32_BIOS -ComputerName $ComputerName -Verbose:$false }
    catch { throw "Unable to get BIOS information" }
    try { $ModelInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName -Verbose:$false }
    catch { throw "Unable to get BIOS information" }
    try { $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName -Verbose:$false }
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
        [array]$NicInfo = (Get-CimInstance -ClassName Win32_NetworkAdapter -ComputerName $ComputerName -ErrorAction Stop -Verbose:$false | Where-Object { $_.AdapterType })
        [array]$NicConfigInfo = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -ErrorAction Stop -Verbose:$false)
    }
    catch { throw "Unable to get information from remote PC: $ComputerName" }
    $Output = Foreach ($item in $NicInfo) {
        $nicPhysical = if ($item.Name -eq 'Microsoft Network Adapter Multiplexor Driver') { $false } else { $item.PhysicalAdapter }
        $IPs = Get-NetIPConfiguration -ComputerName $ComputerName
        [array]$IPv4Sources = (($IPs.IPv4Address | Where-Object { $_.SkipAsSource -eq $false -and $_.ifIndex -eq $item.InterfaceIndex }) | sort-object -Property IPAddress).IPAddress
        [array]$IPv6Sources = (($IPs.IPv6Address | Where-Object { $_.SkipAsSource -eq $false -and $_.ifIndex -eq $item.InterfaceIndex }) | sort-object -Property ValidLifetime).IPAddress
        #$IPv6Sources
        $IPv4Statics = @(($IPs | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).IPv4Address | Where-Object { $_.PrefixOrigin -eq 'Manual' } | ForEach-Object { if ($_.IPAddress) { "$($_.IPAddress)/$($_.PrefixLength)" } } | Sort-Object -Property IPAddress)
        $IPv6Statics = @(($IPs | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).IPv6Address | Where-Object { $_.PrefixOrigin -eq 'Manual' } | ForEach-Object { if ($_.IPAddress) { "$($_.IPAddress)/$($_.PrefixLength)" } } | Sort-Object -Property IPAddress)
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
            Primary4       = (($IPv4Statics | Where-Object { $_ -like "$($IPv4Sources[0].IPAddress)*" }) -split ' ')[0]
            Primary6       = (($IPv6Statics | Where-Object { $_ -like "$($IPv6Sources[0].IPAddress)*" }) -split ' ')[0]
            DHCP4Enabled   = ($NicConfigInfo | Where-Object { $_.InterfaceIndex -eq $item.InterfaceIndex }).DHCPEnabled
            # The only time this is false is when IPv4 is not bound to the nic, which is so unlikely I doubt you'll see it, so it's disabled here.
            # IPBound = ($NicConfigInfo|Where-Object {$_.InterfaceIndex -eq $item.InterfaceIndex}).IPEnabled
        }
    }
    $Output
}
function Get-WinClusterInfo ($ComputerName) {
    try {
        $ClusterInfo = Get-CimInstance -ClassName MSCluster_Cluster -Namespace 'Root/MSCluster' -ComputerName $ComputerName -ErrorAction Stop -Verbose:$false
        $ClusterNodes = Get-CimInstance -ClassName MSCluster_Node -Namespace 'Root/MSCluster' -ComputerName $ComputerName -ErrorAction Stop -Verbose:$false
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

    #Verify that the connection to Netbox works:
    try{Get-NBStatus|Out-Null}catch{throw "Unable to communicate with Netbox - have you set up the connection?"}

    # Get hardware information over WMI
    Write-Verbose "BEGIN Acquiring information from WMI"
    try { $BiosInfo = Get-BiosInfo $ComputerName }
    catch { throw "Can't get serial information for $ComputerName. $($MyInvocation.MyCommand.Name) exiting abnormally" }

    # Get Network Information
    try { $NetworkInfo = Get-WindowsNetworkAdapters -ComputerName $ComputerName }
    catch { throw "Can't get serial information for $ComputerName. $($MyInvocation.MyCommand.Name) exiting abnormally" }

    # Get Clustering Information
    try { $ClusterInfo = Get-WinClusterInfo -ComputerName $ComputerName }
    catch { $ClusterInfo = $false }
    Write-Verbose "END Acquiring information from WMI"

    # Get or create Netbox objects for pre-requisites
    Write-Verbose "BEGIN Acquiring information from Netbox"
    if (!($SiteObj = Get-NBSiteByName $SiteName)) {
        if ($ForceCreatePrereqs) {
            Write-Verbose "`tCreating Site object for $SiteName"
            $SiteObj = New-NBSite -name $SiteName -status active
        }
        else { throw "Unable to find site object for $SiteName" }
    }
    Write-Verbose "`tSite ID: $($SiteObj.id)"
    if (!($OSObj = Get-NBDevicePlatformByName $BiosInfo.OperatingSystem)) {
        if (!($MFRObj = Get-NBManufacturerByName 'Microsoft')) {
            Write-Verbose "`tCreating 'Microsoft' manufacturer"
            $MFRObj = New-NBManufacturer 'Microsoft'
        }
        Write-Verbose "`tManufacturer ID: $($MFRObj.id)"
        Write-Verbose "`tCreating device platform '$($BiosInfo.OperatingSystem)'"
        $OSObj = New-NBDevicePlatform -name $BiosInfo.OperatingSystem -manufacturer $MFRObj.id
    }
    Write-Verbose "`tPlatform '$($BiosInfo.OperatingSystem)' ID: $($OSObj.id)"
    # Get or create the device role we've been given
    Write-Verbose "`tAcquiring Device role '$($Role)'"
    try {
        $RoleObj = Get-NBDeviceRoleByName $Role
        if ($null -eq $RoleObj) { throw }
    }
    catch {
        if ($ForceCreatePrereqs) {
            Write-Verbose "`tCreating VM role $($Role)"
            $RoleObj = New-NBDeviceRole -name $Role -color red
        }
        else { throw "Can't find a role object, not allowed to create one." }
    }
    Write-Verbose "`tDevice role '$($Role)' ID: $($RoleObj.id)"
    Write-Verbose "END Acquiring information from Netbox"
    #endRegion Setup

    # Determine whether we're documenting this as a VM or Device
    # Obviously not a super robust detection method, it's just based on some things I have on hand I can detect against.
    # Some of these vendor names cribbed from https://github.com/poettering/systemd/blob/main/src/basic/virt.c 
    # Reading some of that code makes me very happy to not be a C developer. Absolute gibberish.
    Switch ($BiosInfo.Manufacturer) {
        { $_ -in "QEMU", "KVM", "OpenStack", "Virtualbox", "VMWare, Inc." } {
            $isVM = $true
        }
        { $_ -eq 'Microsoft Corporation' -and $BiosInfo.Model -eq 'Virtual Machine' } {
            $isVM = $true
        }
        else { $isVM = $false }
    }
    if ($ForceType -eq 'physical'){$isVM=$false}
    elseif ($ForceType -eq 'virtual'){$isVM=$true}
    ## If it's not a vm:
    if (!($isVM)) {
        Write-Verbose "**Treating as physical device**"

        # Try to get an object that represents the model
        Write-Verbose "Acquiring device type object '$($BiosInfo.Model)'"
        $DeviceTypeObj=_GetDeviceType -BiosInfo $BiosInfo -ForceCreatePrereqs $ForceCreatePrereqs
        Write-Verbose "`tDevice Type ID: $($DeviceTypeObj.id)"

        Write-Verbose "Acquiring device object"
        $DeviceObj=_GetDeviceObj -ComputerName $ComputerName -DeviceTypeObj $DeviceTypeObj -RoleObj $RoleObj -OSobj $OSObj -BiosInfo $BiosInfo -SiteObj $SiteObj
        Write-Verbose "`tDevice object $($DeviceObj.name)"

        Write-Verbose "BEGIN processing clustering"
        if ($ClusterInfo) {
            Write-Verbose "`tCluster detected, tagging server with 'Clustered Server'."

            # Get a usable tag object
            $ClusterServerTagObj=_GetOrCreateClusterTag

            # Figure out whether there are already any tags to deal with as we'll have to construct a string due to the way the cmdlet works
            if($DeviceObj.tags.length -gt 0) {$Taglist="$(($DeviceObj.tags).id -join','),$($ClusterServerTagObj.id)"}
            else {$Taglist="$($ClusterServerTagObj.id)"}
            # Save the tag list to the object
            Set-NBDevice -id $DeviceObj.id -key tags -value $Taglist | Out-Null

            # If there's not already a comment about it being a part of a cluster, make one identifying the cluster name & FQDN
            if ($DeviceObj.comments -notlike '*Member of Windows cluster*') {
                Set-NBDevice -id $DeviceObj.id -key comments -value ($DeviceObj.comments + "`n`nMember of Windows cluster $($ClusterInfo.Name) ($($ClusterInfo.FQDN))") | Out-Null
            }
        }
        else {
            Write-Verbose "`tNo Windows failover cluster detected."
        }
        Write-Verbose "END processing clustering"

        Write-Verbose "BEGIN Interface processing"
        # Pull the interface list from Netbox
        $interfaces = Get-NBDeviceInterfaceForDevice $DeviceObj.id
        Write-Verbose "`tInterface count: $($interfaces.count)"
        Write-Verbose "`tNetworkInfo count: $($NetworkInfo.count)"
        # Process the network configs from Windows
        Foreach ($NetworkConfig in $NetworkInfo) {
            # Get or create the VM Interface from Netbox.
            if ($NetworkConfig.model -eq 'Microsoft Failover Cluster Virtual Adapter' -and 'Microsoft Failover Cluster Virtual Adapter' -notin $interfaces.Name ) {
                Write-Verbose "`tCreating Failover cluster virtual adapter"
                $IntObj = New-NBDeviceInterface -device $DeviceObj.id -name 'Microsoft Failover Cluster Virtual Adapter' -enabled $true -description $NetworkConfig.Model -mac_address $NetworkConfig.MAC -type virtual
                continue
            }
            elseif($null -eq $NetworkConfig.name) { 
                Write-Verbose "`tSkipping Interface with no name"
                continue
            }
            elseif ($NetworkConfig.Name -notin $interfaces.Name -and $NetworkConfig.Model) {
                Write-Verbose "`tCreating interface '$($NetworkConfig.Name)'"
                $IntObj = New-NBDeviceInterface -device $DeviceObj.id -name $NetworkConfig.Name -enabled $true -description $NetworkConfig.Model -mac_address $NetworkConfig.MAC -type other
            }
            else {
                $IntObj = Get-NBDeviceInterfaceForDevice -id $DeviceObj.id | Where-Object { $_.name -eq $NetworkConfig.name }
            }
            Write-Verbose "`tDevice Interface '$($NetworkConfig.name)' ID: $($IntObj.id)"
            # If the interface has no static addresses assigned, ignore it
            if ($NetworkConfig.IPv4CIDRStatic.count -eq 0 ) { 
                Write-Verbose "`tSkipping IPv4 Static Processing for interface '$($NetworkConfig.Name)' - no static IPv4 information found." 
            }
            # Get-Or-Create the IP address object in Netbox, assign it to the virtual interface
            else {
                # Get or create the IP address, if needed
                Foreach ($IP in $NetworkConfig.IPv4CIDRStatic) {
                    $IPObj=_GetOrCreateIP -IP $IP -itemType 'dcim.interface'
                    if ($IPObj.assigned_object_type -ne 'dcim.interface' -or $IPObj.assigned_object_id -ne $IntObj.id) {
                        Write-Verbose "`tCorrecting interface assignment for ip $(IPobj.ID)"
                        Set-NBIPAddressParent -id $IPObj.id -InterFaceType dcim.interface -interface $IntObj.id | Out-Null
                    }
                }
                if ($NetworkConfig.Primary4 -is [array]) { $TargetPrimaryIP = $NetworkConfig.Primary4[0] }
                else { $TargetPrimaryIP = $NetworkConfig.Primary4 }
                if ($TargetPrimaryIP.length -ge 10) {
                    Write-Verbose "`tSetting Primary IPv4 address to '$($TargetPrimaryIP)'"
                    $ipID = (Get-NBIPAddressByName -name $TargetPrimaryIP).id
                    Write-Verbose "`tID for primary IP target '$($TargetPrimaryIP)': $ipID"
                    Set-NBDevice -id $DeviceObj.id -key primary_ip4 ($ipID) | Out-Null
                }
                else { Write-Warning "Target Primary IPv4 '$TargetPrimaryIP', $($TargetPrimaryIP.Gettype()) length less than requirement, this is probably a bug" }
            }
            if ($NetworkConfig.IPv6CIDRStatic.count -eq 0 ) { Write-Verbose "`tSkipping IPv6 Static Processing for interface '$($NetworkConfig.Name)' - no static IPv6 information found." }
            else {
                Foreach ($IP in $NetworkConfig.IPv6CIDRStatic) {
                    $IPObj=_GetOrCreateIP -IP $IP -itemType 'dcim.interface'
                    if ($IPObj.assigned_object_type -ne 'dcim.interface' -or $IPObj.assigned_object_id -ne $IntObj.id) {
                        Write-Verbose "`tCorrecting interface assignment for ip $(IPobj.ID)"
                        Set-NBIPAddressParent -id $IPObj.id -InterFaceType dcim.interface -interface $IntObj.id | Out-Null
                    }
                }
                if ($NetworkConfig.Primary6 -is [array]) { $TargetPrimaryIP = $NetworkConfig.Primary6[0] }
                else { $TargetPrimaryIP = $NetworkConfig.Primary6 }
                if ($TargetPrimaryIP.length -ge 10) {
                    Write-Verbose "`tSetting Primary IPv6 address to '$TargetPrimaryIP'"
                    $ipID = (Get-NBIPAddressByName -name $TargetPrimaryIP).id
                    Write-Verbose "`tID for '$($TargetPrimaryIP)': $ipID"
                    Set-NBDevice -id $DeviceObj.id -key primary_ip6 ($ipID) | Out-Null
                }
                else { Write-Warning "IPv6 '$($TargetPrimaryIP)' length is $($NetworkInfo.Primary6.length), You have hit a bug." }
            }

        }
        Write-Verbose "END Interface Processing"
    } # End Physical Device

    ## It is a VM, proceed accordingly
    else {
        Write-Verbose "**Treating as virtual machine**"

        Write-Verbose "Getting cluster object"
        $VMClusterObj=_GetOrCreateVMCluster -VMClusterName $VMClusterName -ForceCreatePrereqs $ForceCreatePrereqs
        Write-Verbose "`tVM Cluster ID: $($VMClusterObj.id)"

        Write-Verbose "Getting VM object for $ComputerName"
        $VMObj= _GetOrCreateVM -ComputerName $ComputerName -SiteObj $SiteObj -VMClusterObj $VMClusterObj -OSObj $OSObj -RoleObj $RoleObj
        Write-Verbose "`tVM Object ID: $($VMobj.id)"

        Write-Verbose "BEGIN processing clustering"
        if ($ClusterInfo) {
            Write-Verbose "`tCluster detected, tagging server with 'Clustered Server'."

            # Get a usable tag object
            $ClusterServerTagObj=_GetOrCreateClusterTag

            # Figure out whether there are already any tags to deal with as we'll have to construct a string due to the way the cmdlet works
            if($VMObj.tags.length -gt 0) {$Taglist="$(($VMObj.tags).id -join','),$($ClusterServerTagObj.id)"}
            else {$Taglist="$($ClusterServerTagObj.id)"}
            # Save the tag list to the object
            Set-NBVM -id $VMobj.id -key tags -value $Taglist | Out-Null

            # If there's not already a comment about it being a part of a cluster, make one identifying the cluster name & FQDN
            if ($VMobj.comments -notlike '*Member of Windows cluster*') {
                Set-NBVM -id $VMobj.id -key comments -value ($VMobj.comments + "`n`nMember of Windows cluster $($ClusterInfo.Name) ($($ClusterInfo.FQDN))") | Out-Null
            }
        }
        else {
            Write-Verbose "`tNo Windows failover cluster detected."
        }
        Write-Verbose "END processing clustering"

        Write-Verbose "BEGIN Interface processing"
        # Pull the interface list from Netbox
        $interfaces = Get-NBVMInterfaceForVM $VMobj.id
        Write-Verbose "`tInterface count: $($interfaces.count)"
        Write-Verbose "`tNetworkInfo count: $($NetworkInfo.count)"
        # Process the network configs from Windows
        Foreach ($NetworkConfig in $NetworkInfo) {
            # Get or create the VM Interface from Netbox.
            if ($NetworkConfig.model -eq 'Microsoft Failover Cluster Virtual Adapter' -and 'Microsoft Failover Cluster Virtual Adapter' -notin $interfaces.Name ) {
                Write-Verbose "`tCreating Failover cluster virtual adapter"
                $IntObj = New-NBVMInterface -virtual_machine $VMObj.id -name 'Microsoft Failover Cluster Virtual Adapter' -enabled $true -description $NetworkConfig.Model -mac_address $NetworkConfig.MAC
                continue
            }
            elseif($null -eq $NetworkConfig.name) { 
                Write-Verbose "`tSkipping Interface with no name"
                continue
            }
            elseif ($NetworkConfig.Name -notin $interfaces.Name -and $NetworkConfig.Model) {
                Write-Verbose "`tCreating interface '$($NetworkConfig.Name)'"
                $IntObj = New-NBVMInterface -virtual_machine $VMobj.id -name $NetworkConfig.Name -enabled $true -description $NetworkConfig.Model -mac_address $NetworkConfig.MAC
            }
            else {
                $IntObj = Get-NBVMInterfaceForVM -id $VMobj.id | Where-Object { $_.name -eq $NetworkConfig.name }
            }
            Write-Verbose "`tVM Interface '$($NetworkConfig.name)' ID: $($IntObj.id)"
            # If the interface has no static addresses assigned, ignore it
            if ($NetworkConfig.IPv4CIDRStatic.count -eq 0 ) { 
                Write-Verbose "`tSkipping IPv4 Static Processing for interface '$($NetworkConfig.Name)' - no static IPv4 information found." 
            }
            # Get-Or-Create the IP address object in Netbox, assign it to the virtual interface
            else {
                # Get or create the IP address, if needed
                Foreach ($IP in $NetworkConfig.IPv4CIDRStatic) {
                    $IPObj=_GetOrCreateIP -IP $IP -itemType 'virtualization.vminterface'
                    if ($IPObj.assigned_object_type -ne 'virtualization.vminterface' -or $IPObj.assigned_object_id -ne $IntObj.id) {
                        Set-NBIPAddressParent -id $IPObj.id -InterFaceType virtualization.vminterface -interface $IntObj.id | Out-Null
                    }
                }
                if ($NetworkConfig.Primary4 -is [array]) { $NetworkConfig = $NetworkInfo.Primary4[0] }
                else { $TargetPrimaryIP = $NetworkConfig.Primary4 }
                if ($TargetPrimaryIP.length -ge 10) {
                    Write-Verbose "`tSetting Primary IPv4 address to '$($TargetPrimaryIP)'"
                    $ipID = (Get-NBIPAddressByName -name $TargetPrimaryIP).id
                    Write-Verbose "`tID for '$($TargetPrimaryIP)': $ipID"
                    Set-NBVM -id $VMobj.id -key primary_ip4 ($ipID) | Out-Null
                }
                else { Write-Warning "IPv4 '$TargetPrimaryIP' length less than requirement, this is probably a bug" }
            }
            if ($NetworkConfig.IPv6CIDRStatic.count -eq 0 ) { Write-Verbose "`tSkipping IPv6 Static Processing for interface '$($NetworkConfig.Name)' - no static IPv6 information found." }
            else {
                Foreach ($IP in $NetworkConfig.IPv6CIDRStatic) {
                    Write-Verbose "`tProcessing IP: '$IP'"
                    $IPObj=_GetOrCreateIP -IP $IP -itemType 'virtualization.vminterface'
                    if ($IPObj.assigned_object_type -ne 'virtualization.vminterface' -or $IPObj.assigned_object_id -ne $IntObj.id) {
                        Set-NBIPAddressParent -id $IPObj.id -InterFaceType virtualization.vminterface -interface $IntObj.id | Out-Null
                    }
                }
                if ($NetworkInfo.Primary6 -is [array]) { $TargetPrimaryIP = $NetworkInfo.Primary6[0] }
                else { $TargetPrimaryIP = $NetworkInfo.Primary6 }
                if ($TargetPrimaryIP.length -ge 10) {
                    Write-Verbose "`tSetting Primary IPv6 address to '$TargetPrimaryIP'"
                    $ipID = (Get-NBIPAddressByName -name $TargetPrimaryIP).id
                    Write-Verbose "`tID for '$($TargetPrimaryIP)': $ipID"
                    Set-NBVM -id $VMobj.id -key primary_ip6 ($ipID) | Out-Null
                }
                else { Write-Warning "IPv6 '$($TargetPrimaryIP)' length is $($NetworkInfo.Primary6.length), You have hit a bug." }
            }

        }
        Write-Verbose "END Interface Processing"
    } # End VMs
}

function _GetOrCreateVMCluster($VMClusterName,$ForceCreatePrereqs) {
    try {
        $VMClusterObj = Get-NBVMClusterByName $VMClusterName
        if ($null -eq $VMClusterObj) { throw }
    }
    catch {
        if ($ForceCreatePrereqs) {
            Write-Verbose "`tCluster did not exist, processing pre-reqs as requested."
            try {
                $VMClusterObj = Get-NBVMClusterTypeByName 'Generic'
                if ($null -eq $VMClusterObj) { throw }
            } 
            catch {
                Write-Verbose "`t`tCreating 'Generic' VM cluster type"
                $VMClusterTypeObj = New-NBVMClusterType -name 'Generic' -description 'This cluster type was created to allow a VM to be created and assigned to a cluster automatically, please check over clusters assigned to this type and re-assign them to the proper cluster type.'
                Write-Verbose "`t`tCluster type 'Generic' ID: $($VMClusterTypeObj.id)"
            }
            Write-Verbose "`tCreating VM cluster '$($VMClusterName)' with type 'Generic'"
            $VMClusterObj = New-NBVMCluster -name $VMClusterName -type $VMClusterTypeObj.id -status active -description 'This cluster was created to allow a VM to be created and assigned to a cluster automatically, please check over this cluster and adjust the properties/type to match reality'
        }
        else { throw "Unable to get cluster '$($VMClusterName)', and -ForceCreatePrereqs not set" }
    }
    $VMClusterObj
}

function _GetOrCreateVM ($ComputerName,$SiteObj,$VMClusterObj,$OSObj,$RoleObj) {
    try {
        $VMobj = Get-NBVMByName $ComputerName
        if ($null -eq $VMobj) { throw }
    }
    catch {
        Write-Verbose "Creating VM Object for $($ComputerName)"
        $VMobj = New-NBVM -name $ComputerName -status active -site $SiteObj.id -cluster $VMClusterObj.id -platform $OSObj.id -role $RoleObj.id
    }
    $VMobj
}

function _GetOrCreateClusterTag {
    try {
        $CLTag=Get-NBTags|Where-Object{$_.Name -eq 'Clustered Server'}
        if ($null -eq $CLTag){throw}
    }
    catch{
        $CLTag=New-NBTag -name 'Clustered Server' -color '007ba7' -description 'This item is a member of a Windows Failover Cluster' -object_types 'dcim.device','virtualization.virtualmachine'
    }
    $CLTag
}

function _GetOrCreateIP ($IP,$itemType){
    Write-Verbose "`tGet-Or-CreateIP IP: '$IP'"
    try {
        $IPObj = Get-NBIPAddressByName $IP
        if ($null -eq $IPObj) { throw }
    }
    catch {
        $IPObj = New-NBIPAddress -address $IP -assigned_object_type $itemType -assigned_object_id $IntObj.id -status active
    }
    $IPObj
}

function _GetDeviceType($BiosInfo,$ForceCreatePrereqs){
    if (!($DeviceTypeObj = Get-NBDeviceTypeByModel -model $BiosInfo.Model)) {
        # If there's not one, and we're allowed we create one, and the manufacturer too, if needed.
        if ($ForceCreatePrereqs) {
            Write-Verbose "`tCreating device type object for '$($BiosInfo.Model)'"
            if (!($DeviceMFRObj = Get-NBManufacturerByName $BiosInfo.Manufacturer)) {
                $DeviceMFRObj = New-NBManufacturer $BiosInfo.Manufacturer
            }
            $DeviceTypeObj = New-NBDeviceType -manufacturer $DeviceMFRObj.id -model $BiosInfo.Model
        }
    }
    $DeviceTypeObj
}

function _GetDeviceObj($ComputerName,$DeviceTypeObj,$RoleObj,$OSobj,$BiosInfo,$SiteObj){
    if ($DeviceObj = Get-NBDeviceByName -name $ComputerName) {
        Write-Verbose "`tExisting Netbox object for $ComputerName found"
    }
    else {
        Write-Verbose "`tCode believes the device object did not exist - creating"
        $DeviceObj = New-NBDevice -name $ComputerName -device_type $DeviceTypeObj.id -role $RoleObj.id -platform $OSObj.id -serial $BiosInfo.serial -site $SiteObj.id -status active
        Write-Verbose $DeviceObj.id

    }
    $DeviceObj
}