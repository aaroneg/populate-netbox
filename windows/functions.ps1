# This function just gets some basic information about a machine over WMI/CIM
function Get-BiosInfo ($ComputerName) {
    ## Gather BIOS information
    try { $BiosInfo = Get-CimInstance -ClassName Win32_BIOS -ComputerName $ComputerName }
    catch { throw "Unable to get BIOS information"}
    try { $ModelInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName}
    catch { throw "Unable to get BIOS information"}
    try { $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName}
    catch { throw "Unable to get BIOS information"}
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
            Serial      = $BiosInfo.SerialNumber
            BiosVersion = $bios_version
            Model = $ModelInfo.Model
            Manufacturer = $ModelInfo.Manufacturer
            Memory = $ModelInfo.TotalPhysicalMemory/1GB
            OperatingSystem = $OSInfo.Caption
            HyperV = (Get-WindowsFeature -ComputerName $ComputerName -Name hyper-v).Installed
        }
    }
    catch {throw "Unable to get information from remote PC: $ComputerName"}
}
function Get-WindowsNetworkAdapters ($ComputerName) {
<#
    This function pics one of the addresses that windows doesn't have marked as "Skip as source" to call the primary IP of the nic.
    For IPv4, we use the lowest numbered nic. For IPv6 we use the IP address with the shortest lifetime, as it's likely to be the one
    in use for new connections, though this may be a bad assumption. At any rate, the stakes are low. Anyone processing the output
    of this function shouldn't use anything except the list of static addresses for the NIC when documenting a machine.
#>
    try {
        [array]$NicInfo = (Get-CimInstance -ClassName Win32_NetworkAdapter -ComputerName $ComputerName -ErrorAction Stop|Where-Object {$_.AdapterType})
        [array]$NicConfigInfo = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $ComputerName -ErrorAction Stop)
    }
    catch {throw "Unable to get information from remote PC: $ComputerName"}
    $Output=Foreach ($item in $NicInfo) {
        $nicPhysical=if($item.Name -eq 'Microsoft Network Adapter Multiplexor Driver'){$false} else {$item.PhysicalAdapter}
        $IPs=Get-NetIPConfiguration -ComputerName $ComputerName
        [array]$IPv4Sources=($IPs.IPv4Address|Where-Object {$_.SkipAsSource -eq $false -and $_.ifIndex -eq $item.InterfaceIndex})|sort-object -Property IPAddress
        [array]$IPv6Sources=($IPs.IPv6Address|Where-Object {$_.SkipAsSource -eq $false -and $_.ifIndex -eq $item.InterfaceIndex})|sort-object -Property ValidLifetime
        if($IPv4Sources){$primary4="$($IPv4Sources[0].IPAddress)/$($IPv4Sources[0].PrefixLength)"}
        if($IPv6Sources){$primary6="$($IPv6Sources[0].IPAddress)/$($IPv6Sources[0].PrefixLength)"}
        #if('Manual' -in $IPs.IPv4Address.PrefixOrigin) {$StaticV4Present=$true} else {$StaticV4Present = $false}
        #if('Manual' -in $IPs.IPv6Address.PrefixOrigin) {$StaticV6Present=$true} else {$StaticV6Present = $false}
        [PSCustomObject]@{
            Name = $item.NetConnectionID
            Type = $item.AdapterType
            Model = $item.ProductName
            MAC = $item.MacAddress
            Physical = $nicPhysical
            IPv4CIDRAuto=($IPs|Where-Object {$_.InterfaceIndex -eq $item.InterfaceIndex}).IPv4Address|Where-Object{$_.PrefixOrigin -ne 'Manual'}|ForEach-Object {if($_.IPAddress){"$($_.IPAddress)/$($_.PrefixLength)"}}|Sort-Object -Property IPAddress
            IPv6CIDRAuto=($IPs|Where-Object {$_.InterfaceIndex -eq $item.InterfaceIndex}).IPv6Address|Where-Object{$_.PrefixOrigin -ne 'Manual'}|ForEach-Object {if($_.IPAddress){"$($_.IPAddress)/$($_.PrefixLength)"}}|Sort-Object -Property IPAddress
            IPv4CIDRStatic=($IPs|Where-Object {$_.InterfaceIndex -eq $item.InterfaceIndex}).IPv4Address|Where-Object{$_.PrefixOrigin -eq 'Manual'}|ForEach-Object {if($_.IPAddress){"$($_.IPAddress)/$($_.PrefixLength)"}}|Sort-Object -Property IPAddress
            IPv6CIDRStatic=($IPs|Where-Object {$_.InterfaceIndex -eq $item.InterfaceIndex}).IPv6Address|Where-Object{$_.PrefixOrigin -eq 'Manual'}|ForEach-Object {if($_.IPAddress){"$($_.IPAddress)/$($_.PrefixLength)"}}|Sort-Object -Property IPAddress
            Primary4=$primary4
            Primary6=$primary6
            #StaticV4Present = $StaticV4Present
            #StaticV6Present = $StaticV6Present
            DHCP4Enabled = ($NicConfigInfo|Where-Object {$_.InterfaceIndex -eq $item.InterfaceIndex}).DHCPEnabled
            # The only time this is false is when IPv4 is not bound to the nic, which is so unlikely I doubt you'll see it, so it's disabled here.
            # IPBound = ($NicConfigInfo|Where-Object {$_.InterfaceIndex -eq $item.InterfaceIndex}).IPEnabled
        }
    }
    $Output
}
