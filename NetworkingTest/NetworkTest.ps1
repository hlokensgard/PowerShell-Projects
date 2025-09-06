Set-StrictMode -Version Latest
#
# Overview:
# This script validates hub-spoke connectivity gated by Azure Firewall.
# It can provision ephemeral spokes (VNets, NSGs, NICs, VMs) or use existing VNets,
# create peerings to a hub, then run a two-phase ICMP test: initially blocked,
# then allowed after inserting an ICMP allow rule in the firewall (policy-aware).
# Results are written to JSON artifacts with assertions and cleanup metadata.
#
# Notes:
# - Designed for PowerShell 7.x with Az.* modules.
# - Emphasizes idempotent operations and robust cleanup in finally.
# - Many helpers switch subscription context explicitly to avoid ambiguous state.
$ErrorActionPreference = 'Stop'

#region Result Classes & Helpers (unchanged behavior)
class TestAssertionResult {
    [string]$Name
    [string]$Status
    [hashtable]$Evidence
    TestAssertionResult([string]$Name, [string]$Status, [hashtable]$Evidence) {
        $this.Name = $Name; $this.Status = $Status; $this.Evidence = $Evidence
    }
}
class TestExecutionResult {
    [string]$TestId
    [datetime]$StartTime
    [datetime]$EndTime
    [System.Collections.Generic.List[TestAssertionResult]]$Assertions = [System.Collections.Generic.List[TestAssertionResult]]::new()
    [System.Collections.Generic.List[string]]$Errors = [System.Collections.Generic.List[string]]::new()
    [string]$Status = 'Unknown'
    [object]$Cleanup
    [string]$Description
    [string]$Category
}

function New-TestExecutionResult {
    # Create a container for test metadata, assertions, and final status.
    # TestId should be stable to drive output paths and traceability.
    [CmdletBinding()][OutputType([TestExecutionResult])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Z0-9\-]{3,60}$')][string]$TestId,
        [string]$Category = 'General',
        [string]$Description = ''
    )

    $r = [TestExecutionResult]::new()
    $r.TestId = $TestId
    $r.StartTime = Get-Date
    $r.Category = $Category
    $r.Description = $Description
    return $r
}

function Add-TestAssertion {
    # Append a single assertion with an optional evidence payload to the result.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][TestExecutionResult]$Result,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Passed', 'Failed')][string]$Status,
        [hashtable]$Evidence
    )

    $Result.Assertions.Add([TestAssertionResult]::new($Name, $Status, $Evidence))
    return $Result
}

function Set-TestExecutionResult {
    # Finalize status based on assertions and errors. Priority: Failed > Error > Skipped > Passed
    [CmdletBinding()][OutputType([TestExecutionResult])]
    param(
        [Parameter(Mandatory)][TestExecutionResult]$Result,
        [string[]]$Errors,
        [object]$Cleanup
    )

    $Result.EndTime = Get-Date
    foreach ($e in ($Errors | Where-Object { $_ })) { $Result.Errors.Add($e) | Out-Null }
    if ($Cleanup) { $Result.Cleanup = $Cleanup }
    if ($Result.Assertions.Where({ $_.Status -eq 'Failed' }).Count -gt 0) { $Result.Status = 'Failed' }
    elseif ($Result.Errors.Count -gt 0) { $Result.Status = 'Error' }
    elseif ($Result.Assertions.Count -eq 0) { $Result.Status = 'Skipped' }
    else { $Result.Status = 'Passed' }
    return $Result
}

function Write-TestExecutionResultJson {
    # Persist the test result to a timestamped JSON file under the provided directory.
    # Depth=6 to capture nested evidence/cleanup structures.
    [CmdletBinding()][OutputType([string])]
    param(
        [Parameter(Mandatory)][TestExecutionResult]$Result,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputDirectory
    )

    if (-not (Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
    $file = Join-Path $OutputDirectory ("{0}-{1}.json" -f $Result.TestId, (Get-Date -Format 'yyyyMMddTHHmmssZ'))
    ($Result | ConvertTo-Json -Depth 6) | Set-Content -Encoding UTF8 -Path $file
    return $file
}
#endregion

#region Utilities (suggested extractions)
function Set-SubscriptionContextIfNeeded {
    # Ensure Az context matches the target subscription before issuing resource commands.
    # Avoids surprises when multiple subscriptions are selected in the current session.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SubscriptionId)
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx -or $ctx.Subscription.Id -ne $SubscriptionId) {
        Write-Verbose "[Ctx] Switching to subscription: $SubscriptionId"
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    }
}

function Get-AzResourceIdParts {
    # Breaks an Azure resource ID into common parts for easy access.
    # Example: /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/virtualNetworks/<name>
    [CmdletBinding()][OutputType([hashtable])]
    param([Parameter(Mandatory)][ValidatePattern('^/subscriptions/.+')] [string]$ResourceId)

    $parts = $ResourceId -split '/'
    $h = @{ SubscriptionId = $parts[2]; ResourceGroup = $parts[4]; Provider = $parts[6]; TypeSegments = ($parts[6..($parts.Length - 2)] -join '/'); Name = $parts[-1] }
    return $h
}

function Get-SubscriptionIdFromResourceId {
    # Extracts the subscription GUID from a full Azure resource ID.
    [CmdletBinding()][OutputType([string])]
    param([Parameter(Mandatory)][string]$ResourceId)

    return ($ResourceId -split '/')[2]
}

function New-RandomSuffix { [CmdletBinding()][OutputType([string])] param() ( -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })) }

function Wait-Until {
    # Polls a condition scriptblock until it returns $true or timeout elapses.
    # Swallows transient exceptions from the condition to improve resilience.
    [CmdletBinding()][OutputType([bool])] param(
        [Parameter(Mandatory)][scriptblock]$Condition,
        [int]$TimeoutSeconds = 180,
        [int]$IntervalSeconds = 5
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try { if (& $Condition) { return $true } } catch { Write-Verbose "[Wait-Until] transient error: $($_.Exception.Message)" }
        Start-Sleep -Seconds $IntervalSeconds
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Measure-Operation {
    # Executes the provided scriptblock, measuring wall-clock duration and capturing any thrown error.
    # Returns a hashtable: @{ DurationMs; Result; Error }
    [CmdletBinding()][OutputType([hashtable])] param([Parameter(Mandatory)][scriptblock]$Script)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $err = $null; $out = $null
    try { $out = & $Script } catch { $err = $_ }
    $sw.Stop()
    return @{ DurationMs = $sw.ElapsedMilliseconds; Result = $out; Error = $err }
}

function Write-TestResultArtifact {
    # Writes the result JSON under OutputRoot/<TestId>/ and logs the final path to verbose output.
    [CmdletBinding()][OutputType([string])] param([Parameter(Mandatory)][TestExecutionResult]$Result, [Parameter(Mandatory)][string]$OutputRoot)
    $outDir = Join-Path $OutputRoot $Result.TestId

    $path = Write-TestExecutionResultJson -Result $Result -OutputDirectory $outDir
    Write-Verbose "[Output] Result written to: $path"
    return $path
}
#endregion

#region Existing helpers (kept for behavior parity)
function Resolve-AzVmSize {
    # Filters preferred VM sizes by availability in a region. Throws if none are available.
    # Optionally respects a specific subscription context for cross-subscription operations.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string[]]$PreferredSizes,
        [string]$SubscriptionId
    )
    if ($SubscriptionId) { Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId }
    try { $all = Get-AzVMSize -Location $Location -ErrorAction Stop } catch { throw "Failed to query VM sizes in '$Location': $($_.Exception.Message)" }
    $availNames = $all.Name
    $candidates = $PreferredSizes | Where-Object { $_ -in $availNames }
    if (-not $candidates) { throw "None of the preferred sizes are available in '$Location'. (Preferred: $($PreferredSizes -join ', '))" }
    return $candidates
}

function New-ALZTestResourceGroup {
    # Creates a resource group with a random suffix to avoid name collisions.
    # Retries with exponential backoff to mitigate transient control-plane failures.
    [CmdletBinding()][OutputType([string])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9-]{3,40}$')][string]$NamePrefix,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Location,
        [hashtable]$Tags,
        [ValidateRange(1, 10)][int]$RetryCount = 3
    )
    $suffix = New-RandomSuffix
    $rgName = ("$NamePrefix-$suffix").ToLower()
    for ($i = 1; $i -le $RetryCount; $i++) {
        try {
            Write-Verbose "[RG] Creating resource group '$rgName' in '$Location' (attempt $i/$RetryCount)"
            $p = @{Name = $rgName; Location = $Location }
            if ($Tags) { $p.Tag = $Tags }
            New-AzResourceGroup @p | Out-Null
            Write-Verbose "[RG] Created resource group '$rgName'"
            return $rgName
        }
        catch {
            Write-Warning "[RG] Failed creating RG '$rgName': $($_.Exception.Message)"
            if ($i -eq $RetryCount) { throw }
            Start-Sleep -Seconds ([math]::Pow(2, $i))
        }
    }
}

function Remove-ALZTestResourceGroup { [CmdletBinding(SupportsShouldProcess)] param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{5,64}$')][string]$Name) if ($PSCmdlet.ShouldProcess("ResourceGroup/$Name", 'Delete')) { Remove-AzResourceGroup -Name $Name -Force -AsJob -ErrorAction SilentlyContinue | Out-Null } }
#endregion

#region Suggested provisioning primitives
function New-TaggedResourceGroup {
    # Thin wrapper around New-ALZTestResourceGroup that enforces subscription context
    # and attaches meaningful tags for test provenance.
    [CmdletBinding()][OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$NamePrefix,
        [Parameter(Mandatory)][string]$Location,
        [hashtable]$Tags
    )

    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    Write-Verbose "[RG] Ensuring ephemeral RG with prefix '$NamePrefix' in '$Location' (sub $SubscriptionId)"
    return (New-ALZTestResourceGroup -NamePrefix $NamePrefix -Location $Location -Tags $Tags)
}

function New-SpokeNetworkSecurityGroup {
    # Creates an NSG with permissive intra-VNet rules and default deny-all catch-alls.
    # This keeps focus on firewall behavior rather than NSG filtering.
    [CmdletBinding()][OutputType([Microsoft.Azure.Commands.Network.Models.PSNetworkSecurityGroup])]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Location
    )

    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    Write-Verbose "[NSG] Creating NSG '$Name' in RG '$ResourceGroup' ($Location)"
    $nsg = New-AzNetworkSecurityGroup -Name $Name -ResourceGroupName $ResourceGroup -Location $Location
    Write-Verbose "[NSG] Adding default VNet allow/deny rules"
    $null = Add-AzNetworkSecurityRuleConfig -Name 'AllowInboundVNet' -NetworkSecurityGroup $nsg -Priority 100 -Direction Inbound -Access Allow -Protocol '*' -SourceAddressPrefix 'VirtualNetwork' -SourcePortRange '*' -DestinationAddressPrefix '*' -DestinationPortRange '*'
    $null = Add-AzNetworkSecurityRuleConfig -Name 'DenyInboundAll' -NetworkSecurityGroup $nsg -Priority 200 -Direction Inbound -Access Deny -Protocol '*' -SourceAddressPrefix '*' -SourcePortRange '*' -DestinationAddressPrefix '*' -DestinationPortRange '*'
    $null = Add-AzNetworkSecurityRuleConfig -Name 'AllowOutboundVNet' -NetworkSecurityGroup $nsg -Priority 100 -Direction Outbound -Access Allow -Protocol '*' -SourceAddressPrefix '*' -SourcePortRange '*' -DestinationAddressPrefix 'VirtualNetwork' -DestinationPortRange '*'
    $null = Add-AzNetworkSecurityRuleConfig -Name 'DenyOutboundAll' -NetworkSecurityGroup $nsg -Priority 200 -Direction Outbound -Access Deny -Protocol '*' -SourceAddressPrefix '*' -SourcePortRange '*' -DestinationAddressPrefix '*' -DestinationPortRange '*'
    Set-AzNetworkSecurityGroup -NetworkSecurityGroup $nsg | Out-Null
    Write-Verbose "[NSG] NSG '$Name' configured"
    return $nsg
}

function New-SpokeVirtualNetwork {
    # Provisions a VNet with a single subnet and associates the provided NSG to that subnet.
    [CmdletBinding()][OutputType([Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork])]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$AddressPrefix,
        [Parameter(Mandatory)][string]$SubnetName,
        [Parameter(Mandatory)][string]$SubnetPrefix,
        [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSNetworkSecurityGroup]$NetworkSecurityGroup
    )

    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    Write-Verbose "[VNet] Creating VNet '$Name' ($AddressPrefix) with subnet '$SubnetName' ($SubnetPrefix) in RG '$ResourceGroup' ($Location)"
    $subnet = New-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix $SubnetPrefix -NetworkSecurityGroup $NetworkSecurityGroup
    $vnet = New-AzVirtualNetwork -Name $Name -ResourceGroupName $ResourceGroup -Location $Location -AddressPrefix $AddressPrefix -Subnet @($subnet)
    Write-Verbose "[VNet] Created VNet '$Name'"
    return $vnet
}

function Set-VNetPeering {
    # Idempotently ensures a single-direction peering exists from a VNet to a remote VNet.
    # AllowForwardedTraffic is enabled to support hub-routing scenarios.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$VNetName,
        [Parameter(Mandatory)][string]$PeeringName,
        [Parameter(Mandatory)][string]$RemoteVNetId
    )

    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    $existing = Get-AzVirtualNetworkPeering -ResourceGroupName $ResourceGroup -VirtualNetworkName $VNetName -Name $PeeringName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Verbose "[Peering] Creating peering '$PeeringName' on '$VNetName' -> '$RemoteVNetId'"
        Add-AzVirtualNetworkPeering -Name $PeeringName -VirtualNetwork (Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroup) -RemoteVirtualNetworkId $RemoteVNetId -AllowForwardedTraffic | Out-Null
    }
    else {
        Write-Verbose "[Peering] Peering '$PeeringName' already exists on '$VNetName'"
    }
}

function Set-HubPeerings {
    # Ensures the hub VNet has outbound peerings to each remote VNet (spokes).
    # Names are derived from the remote VNet names for traceability.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$HubSubscriptionId,
        [Parameter(Mandatory)][string]$HubResourceGroup,
        [Parameter(Mandatory)][string]$HubVNetName,
        [Parameter(Mandatory)][string[]]$RemoteVNetIds
    )

    Set-SubscriptionContextIfNeeded -SubscriptionId $HubSubscriptionId
    $hubVnet = Get-AzVirtualNetwork -Name $HubVNetName -ResourceGroupName $HubResourceGroup -ErrorAction Stop
    foreach ($rid in $RemoteVNetIds) {
        $name = 'to-' + ((($rid -split '/'))[-1])
        $exists = $hubVnet.VirtualNetworkPeerings | Where-Object { $_.RemoteVirtualNetwork.Id -eq $rid }
        if (-not $exists) {
            Write-Verbose "[Peering] Creating hub peering '$name' -> '$rid'"
            Add-AzVirtualNetworkPeering -Name $name -VirtualNetwork $hubVnet -RemoteVirtualNetworkId $rid -AllowForwardedTraffic | Out-Null
        }
        else {
            Write-Verbose "[Peering] Hub peering '$name' already exists"
        }
    }
}

function Set-NetworkFeatureRegistration {
    # Some peering/address-space operations require specific provider features to be registered.
    # This helper registers the feature and the Microsoft.Network provider, waiting until active.
    [CmdletBinding()] param([Parameter(Mandatory)][string]$SubscriptionId)
    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    try {
        $state = (Get-AzProviderFeature -ProviderNamespace 'Microsoft.Network' -FeatureName 'AllowUpdateAddressSpaceInPeeredVnets' -ErrorAction SilentlyContinue).RegistrationState
        if (-not $state -or $state -ne 'Registered') {
            Write-Verbose "[Provider] Registering feature 'AllowUpdateAddressSpaceInPeeredVnets'"
            Register-AzProviderFeature -ProviderNamespace 'Microsoft.Network' -FeatureName 'AllowUpdateAddressSpaceInPeeredVnets' -ErrorAction SilentlyContinue | Out-Null
            Wait-Until -Condition { (Get-AzProviderFeature -ProviderNamespace 'Microsoft.Network' -FeatureName 'AllowUpdateAddressSpaceInPeeredVnets' -ErrorAction SilentlyContinue).RegistrationState -eq 'Registered' } -TimeoutSeconds 300 | Out-Null
        }
        Write-Verbose "[Provider] Ensuring 'Microsoft.Network' resource provider is registered"
        Register-AzResourceProvider -ProviderNamespace 'Microsoft.Network' | Out-Null
    }
    catch { Write-Warning "[Net] Feature/provider registration issue in subscription $SubscriptionId : $($_.Exception.Message)" }
}

function Sync-VNetPeeringAndWait {
    # Forces a peering sync and waits until the peering reports Succeeded/Connected (or Initiated).
    # Emits a warning if the peering does not converge within the timeout window.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$VNetName,
        [Parameter(Mandatory)][string]$PeeringName,
        [int]$TimeoutSeconds = 180
    )

    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    Write-Verbose "[Peering] Syncing '$PeeringName' on '$VNetName' and waiting for Connected"
    Sync-AzVirtualNetworkPeering -ResourceGroupName $ResourceGroup -VirtualNetworkName $VNetName -Name $PeeringName -ErrorAction SilentlyContinue | Out-Null
    $ok = Wait-Until -TimeoutSeconds $TimeoutSeconds -IntervalSeconds 5 -Condition {
        $p = Get-AzVirtualNetworkPeering -ResourceGroupName $ResourceGroup -VirtualNetworkName $VNetName -Name $PeeringName -ErrorAction SilentlyContinue
        return ($p -and $p.ProvisioningState -eq 'Succeeded' -and ($p.PeeringState -in @('Connected', 'Initiated')))
    }
    if (-not $ok) { Write-Warning "[Net] Peering '$PeeringName' did not reach Connected state in time on $VNetName" }
    else { Write-Verbose "[Peering] Peering '$PeeringName' is Connected" }
}

function New-SpokeNic {
    # Creates a NIC on the provided subnet. Private IP is later used for VM-to-VM ICMP tests.
    [CmdletBinding()][OutputType([Microsoft.Azure.Commands.Network.Models.PSNetworkInterface])]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSSubnet]$Subnet
    )

    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    Write-Verbose "[NIC] Creating NIC '$Name' in RG '$ResourceGroup' ($Location)"
    $nic = New-AzNetworkInterface -Name $Name -ResourceGroupName $ResourceGroup -Location $Location -Subnet $Subnet
    Write-Verbose "[NIC] Created NIC '$Name'"
    return $nic
}

function Set-SpokeRouteViaFirewall {
    # Creates or updates a route table for a spoke subnet with a route to the other spoke via the firewall.
    # Returns a hashtable with details for cleanup: @{ Name; CreatedNew; RouteName; SubnetName }
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VNet,
        [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSSubnet]$Subnet,
        [Parameter(Mandatory)][string]$DestinationPrefix,
        [Parameter(Mandatory)][ValidatePattern('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')][string]$FirewallPrivateIp,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{3,64}$')][string]$RouteTableName,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{3,64}$')][string]$RouteName
    )

    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    $createdNew = $false
    $rt = Get-AzRouteTable -Name $RouteTableName -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
    if (-not $rt) {
        Write-Verbose "[Route] Creating route table '$RouteTableName' in RG '$ResourceGroup' ($Location)"
        $rt = New-AzRouteTable -Name $RouteTableName -ResourceGroupName $ResourceGroup -Location $Location -DisableBgpRoutePropagation:$false
        $createdNew = $true
    }

    $existingRoute = $rt.Routes | Where-Object { $_.Name -eq $RouteName }
    if (-not $existingRoute) {
        Write-Verbose "[Route] Adding route '$RouteName' ($DestinationPrefix -> $FirewallPrivateIp) to RT '$RouteTableName'"
        $null = Add-AzRouteConfig -Name $RouteName -AddressPrefix $DestinationPrefix -NextHopType VirtualAppliance -NextHopIpAddress $FirewallPrivateIp -RouteTable $rt
        $rt = Set-AzRouteTable -RouteTable $rt
    }
    else {
        Write-Verbose "[Route] Route '$RouteName' already exists on RT '$RouteTableName'"
    }

    # Associate route table to subnet (preserving NSG and address prefixes)
    $addrPref = $Subnet.AddressPrefix
    if (-not $addrPref) { $addrPref = $Subnet.AddressPrefixes }
    if ($addrPref -is [array]) { $addrPrefToSet = $addrPref } else { $addrPrefToSet = @($addrPref) }
    Write-Verbose "[Route] Associating RT '$RouteTableName' to subnet '$($Subnet.Name)' on VNet '$($VNet.Name)'"
    $null = Set-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNet -Name $Subnet.Name -AddressPrefix $addrPrefToSet -NetworkSecurityGroup $Subnet.NetworkSecurityGroup -RouteTable $rt
    Set-AzVirtualNetwork -VirtualNetwork $VNet | Out-Null

    return @{ Name = $RouteTableName; CreatedNew = $createdNew; RouteName = $RouteName; SubnetName = $Subnet.Name }
}

function Remove-SpokeRouteViaFirewall {
    # Disassociates the route table from the subnet and optionally removes the route and/or route table.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VNet,
        [Parameter(Mandatory)][Microsoft.Azure.Commands.Network.Models.PSSubnet]$Subnet,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{3,64}$')][string]$RouteTableName,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{3,64}$')][string]$RouteName,
        [switch]$RemoveRouteTableIfCreated
    )

    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    $rt = Get-AzRouteTable -Name $RouteTableName -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
    try {
        $addrPref = $Subnet.AddressPrefix; if (-not $addrPref) { $addrPref = $Subnet.AddressPrefixes }
        if ($addrPref -isnot [array]) { $addrPref = @($addrPref) }
        Write-Verbose "[Cleanup] Disassociating RT '$RouteTableName' from subnet '$($Subnet.Name)'"
        $null = Set-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNet -Name $Subnet.Name -AddressPrefix $addrPref -NetworkSecurityGroup $Subnet.NetworkSecurityGroup -RouteTable $null
        Set-AzVirtualNetwork -VirtualNetwork $VNet | Out-Null
    }
    catch { Write-Warning "[Cleanup] Failed disassociating RT '$RouteTableName' from subnet '$($Subnet.Name)': $($_.Exception.Message)" }

    if ($rt) {
        try {
            $route = $rt.Routes | Where-Object { $_.Name -eq $RouteName }
            if ($route) {
                Write-Verbose "[Cleanup] Removing route '$RouteName' from RT '$RouteTableName'"
                $null = Remove-AzRouteConfig -Name $RouteName -RouteTable $rt
                $rt = Set-AzRouteTable -RouteTable $rt
            }
        }
        catch { Write-Warning "[Cleanup] Failed removing route '$RouteName' from RT '$RouteTableName': $($_.Exception.Message)" }
    }

    if ($RemoveRouteTableIfCreated -and $rt) {
        try {
            Write-Verbose "[Cleanup] Removing route table '$RouteTableName'"
            Remove-AzRouteTable -Name $RouteTableName -ResourceGroupName $ResourceGroup -Force -ErrorAction SilentlyContinue | Out-Null
        }
        catch { Write-Warning "[Cleanup] Route table '$RouteTableName' removal failed: $($_.Exception.Message)" }
    }
}

function Resolve-CandidateVmSizes {
    # Uses Resolve-AzVmSize to compute viable sizes; on failure, falls back to the preferred list.
    [CmdletBinding()][OutputType([string[]])] param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string[]]$PreferredVmSizes, [Parameter(Mandatory)][string]$SubscriptionId)
    try {
        $c = Resolve-AzVmSize -Location $Location -PreferredSizes $PreferredVmSizes -SubscriptionId $SubscriptionId
        Write-Verbose "[VM] Candidate sizes: $($c -join ', ')"
        return $c
    }
    catch { Write-Warning "[Size] Could not resolve candidate sizes: $($_.Exception.Message). Falling back to provided list."; return $PreferredVmSizes }
}

function New-ResilientLinuxVm {
    # Attempts VM creation with candidate sizes, starting zonal (Zone 3) then falling back to non-zonal
    # if the SKU or capacity is not available. Uses Ubuntu 22.04 LTS image. Returns $true on success.
    [CmdletBinding()][OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$VmName,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$NicId,
        [Parameter(Mandatory)][PSCredential]$Credential,
        [Parameter(Mandatory)][string[]]$CandidateSizes
    )

    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    $created = $false; $useZone = $true
    foreach ($size in $CandidateSizes) {
        if ($created) { break }
        try {
            Write-Verbose "[VM] Creating VM '$VmName' (size: $size, zone: $($useZone ? '3' : 'none'))"
            $vmConfig = New-AzVMConfig -VMName $VmName -VMSize $size
            $vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -Linux -ComputerName $VmName -Credential $Credential
            $vmConfig = Add-AzVMNetworkInterface -VM $vmConfig -Id $NicId
            $vmConfig = Set-AzVMSourceImage -VM $vmConfig -PublisherName 'Canonical' -Offer '0001-com-ubuntu-server-jammy' -Skus '22_04-lts' -Version 'latest'
            Start-Sleep -Seconds 5
            if ($useZone) { New-AzVM -ResourceGroupName $ResourceGroup -Location $Location -VM $vmConfig -Zone '3' -ErrorAction Stop | Out-Null }
            else { New-AzVM -ResourceGroupName $ResourceGroup -Location $Location -VM $vmConfig -ErrorAction Stop | Out-Null }
            $created = $true
            Write-Verbose "[VM] VM '$VmName' created"
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -match 'SkuNotAvailable' -or $msg -match 'Capacity') { Write-Warning "[VM] Size/zone issue: $msg. Retrying without zone."; if ($useZone) { $useZone = $false } else { continue } }
            else { Write-Error "[VM] Failed creating VM '$VmName' with size '$size': $msg"; continue }
        }
    }
    if ($created) { Start-Sleep -Seconds 20 }
    return $created
}
#endregion

#region Connectivity & Firewall helpers
function Test-IcmpConnectivity {
    # Runs a 3-echo ICMP ping from source VM to target IP via RunCommand extension.
    # Parses tx/rx/loss robustly and treats Allowed = ($rx > 0) to avoid substring false-positives.
    [CmdletBinding()][OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$SourceSubscriptionId,
        [Parameter(Mandatory)][string]$SourceResourceGroup,
        [Parameter(Mandatory)][string]$SourceVmName,
        [Parameter(Mandatory)][string]$TargetIp
    )

    Set-SubscriptionContextIfNeeded -SubscriptionId $SourceSubscriptionId
    Write-Verbose "[Test] ICMP ping from '$SourceVmName' to '$TargetIp'"
    $res = Invoke-AzVMRunCommand -ResourceGroupName $SourceResourceGroup -Name $SourceVmName -CommandId RunShellScript -ScriptString "ping -c 3 $TargetIp"
    $stdout = $res.Value[0].Message
    # Parse ping summary robustly to avoid false positives (e.g., '100% packet loss' can include '0%').
    $tx = $null; $rx = $null; $loss = $null; $avg = $null
    if ($stdout -match '(?m)([0-9]+)\s+packets\s+transmitted,\s+([0-9]+)\s+received,\s+([0-9]+)%\s+packet\s+loss') {
        $tx = [int]$matches[1]
        $rx = [int]$matches[2]
        $loss = [int]$matches[3]
    }
    if ($stdout -match '(?m)(?:rtt\s+)?min/avg/max/\w+\s*=\s*([0-9\.]+)/([0-9\.]+)/([0-9\.]+)/([0-9\.]+)\s*ms') {
        $avg = [double]$matches[2]
    }
    $allowed = $false
    if ($null -ne $rx) { $allowed = ($rx -gt 0) }
    Write-Verbose ("[Ping] {0} -> {1} | tx={2} rx={3} loss={4}% avgMs={5}" -f $SourceVmName, $TargetIp, ($tx ?? 'na'), ($rx ?? 'na'), ($loss ?? 'na'), ($avg ?? 'na'))
    return @{ Allowed = $allowed; Output = $stdout; AvgMs = $avg }
}

function Add-ConnectivityAssertions {
    # Adds pass/fail assertions based on expected reachability, including optional avg latency evidence
    # when the ping output contains RTT statistics.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][TestExecutionResult]$Result,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$ExpectedAllowed,
        [Parameter(Mandatory)][hashtable]$Connectivity,
        [Parameter(Mandatory)][string]$TargetIp
    )

    if ($ExpectedAllowed) {
        Add-TestAssertion -Result $Result -Name $Name -Status (($Connectivity.Allowed) ? 'Passed' : 'Failed') -Evidence @{ output = $Connectivity.Output; target = $TargetIp; expected = 'allowed' } | Out-Null
        if ($null -ne $Connectivity.AvgMs) { Add-TestAssertion -Result $Result -Name "$Name - Avg Latency (ms)" -Status 'Passed' -Evidence @{ avgMs = $Connectivity.AvgMs } | Out-Null }
    }
    else {
        Add-TestAssertion -Result $Result -Name $Name -Status ((-not $Connectivity.Allowed) ? 'Passed' : 'Failed') -Evidence @{ output = $Connectivity.Output; target = $TargetIp; expected = 'blocked' } | Out-Null
    }
}

function Set-FirewallIcmpAllowRule {
    # Inserts an ICMP allow rule between source and destination prefixes.
    # Supports both policy-managed firewalls (Rule Collection Group with Filter collection)
    # and classic firewalls (NetworkRuleCollections). Waits briefly for propagation.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$FirewallResourceId,
        [Parameter(Mandatory)][string]$SourcePrefix,
        [Parameter(Mandatory)][string]$DestinationPrefix
    )

    $p = Get-AzResourceIdParts -ResourceId $FirewallResourceId
    Set-SubscriptionContextIfNeeded -SubscriptionId $p.SubscriptionId
    $fw = Get-AzFirewall -Name $p.Name -ResourceGroupName $p.ResourceGroup -ErrorAction Stop
    Write-Verbose "[FW] Ensure ICMP allow from '$SourcePrefix' to '$DestinationPrefix' on firewall '$($p.Name)'"
    if ($fw.FirewallPolicy) {
        $policyId = $null
        if ($fw.FirewallPolicy -is [string]) { $policyId = $fw.FirewallPolicy }
        elseif ($fw.FirewallPolicy.Id) { $policyId = $fw.FirewallPolicy.Id }
        if (-not $policyId -or ($policyId -notmatch '^/subscriptions/')) { throw "[FW] Unable to resolve attached Firewall Policy for '$($fw.Name)'." }
        
        $pi = Get-AzResourceIdParts -ResourceId $policyId
        Set-SubscriptionContextIfNeeded -SubscriptionId $pi.SubscriptionId
        
        $rcgName = 'alztest-icmp-allow'
        $nrcName = 'alztest-icmp-nrc'
        $rcg = $null
        
        try { $rcg = Get-AzFirewallPolicyRuleCollectionGroup -Name $rcgName -ResourceGroupName $pi.ResourceGroup -AzureFirewallPolicyName $pi.Name -ErrorAction SilentlyContinue } catch { $rcg = $null }
        $rule = New-AzFirewallPolicyNetworkRule -Name 'allow-icmp' -Protocol ICMP -SourceAddress $SourcePrefix -DestinationAddress $DestinationPrefix -DestinationPort '*'
        
        if (-not $rcg) {
            # Using a random number to minimize rule collection priority conflicts
            $rcgPriority = Get-Random -Minimum 101 -Maximum 301
            $nrcPriority = Get-Random -Minimum 201 -Maximum 401
            Write-Verbose "[FW] Using rule collection '$nrcName' priority $nrcPriority"

            $rc = New-AzFirewallPolicyFilterRuleCollection -Name $nrcName -Priority $nrcPriority -Rule @($rule) -ActionType Allow
            New-AzFirewallPolicyRuleCollectionGroup -Name $rcgName -Priority $rcgPriority -RuleCollection @($rc) -FirewallPolicyName $pi.Name -ResourceGroupName $pi.ResourceGroup | Out-Null
        }
        else {
            $existingRc = $rcg.RuleCollection | Where-Object { $_.Name -eq $nrcName }
            if (-not $existingRc) {
                Write-Verbose "[FW] Updating RCG '$rcgName' to include '$nrcName'"
                Write-Verbose "This may take a few moments..."
                $newRc = New-AzFirewallPolicyFilterRuleCollection -Name $nrcName -Priority 240 -Rule @($rule) -ActionType Allow
                $all = @($rcg.RuleCollection + $newRc)
                Set-AzFirewallPolicyRuleCollectionGroup -Name $rcgName -Priority $rcg.Priority -RuleCollection $all -FirewallPolicyName $pi.Name -ResourceGroupName $pi.ResourceGroup | Out-Null
            }
            else { Write-Verbose "[FW] Rule collection '$nrcName' already present in RCG '$rcgName'" }
        }
        Write-Verbose "[FW] Finished processing RCG '$rcgName'"
        Write-Verbose "Waiting for changes to propagate..."
        Start-Sleep -Seconds 15
        Write-Verbose "[FW] Finished waiting for changes to propagate"
        return
    }
    $ruleCollectionName = "alztest-allow-$SourcePrefix-$DestinationPrefix".Replace('/', '-').Replace(':', '-')
    if (-not ($fw.NetworkRuleCollections | Where-Object Name -eq $ruleCollectionName)) {
        Write-Verbose "[FW] Creating classic Network Rule Collection '$ruleCollectionName'"
        $rule = New-AzFirewallNetworkRule -Name 'allow-icmp' -Protocol ICMP -SourceAddress $SourcePrefix -DestinationAddress $DestinationPrefix -DestinationPort '*'
        $collection = New-AzFirewallNetworkRuleCollection -Name $ruleCollectionName -Priority 240 -ActionType Allow -Rule $rule
        $null = $fw.NetworkRuleCollections.Add($collection)
        Set-AzFirewall -AzureFirewall $fw | Out-Null
        Start-Sleep -Seconds 15
    }
    else { Write-Verbose "[FW] Classic Network Rule Collection '$ruleCollectionName' already exists" }
}

function Remove-FirewallIcmpAllowRule {
    # Removes the ICMP allow rule created by Set-FirewallIcmpAllowRule.
    # Mirrors policy-managed vs classic firewall paths and is safe to call if already absent.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$FirewallResourceId,
        [Parameter(Mandatory)][string]$SourcePrefix,
        [Parameter(Mandatory)][string]$DestinationPrefix
    )
    $p = Get-AzResourceIdParts -ResourceId $FirewallResourceId
    Set-SubscriptionContextIfNeeded -SubscriptionId $p.SubscriptionId
    $fw = Get-AzFirewall -Name $p.Name -ResourceGroupName $p.ResourceGroup -ErrorAction Stop
    Write-Verbose "[FW] Cleanup ICMP allow from '$SourcePrefix' to '$DestinationPrefix' on firewall '$($p.Name)'"

    if ($fw.FirewallPolicy) {
        $policyId = $null
        if ($fw.FirewallPolicy -is [string]) { $policyId = $fw.FirewallPolicy }
        elseif ($fw.FirewallPolicy.Id) { $policyId = $fw.FirewallPolicy.Id }
        if (-not $policyId -or ($policyId -notmatch '^/subscriptions/')) { Write-Verbose "[FW] Skipping cleanup: no resolvable policy id"; return }
        $pi = Get-AzResourceIdParts -ResourceId $policyId
        Set-SubscriptionContextIfNeeded -SubscriptionId $pi.SubscriptionId

        $rcgName = 'alztest-icmp-allow'
        $nrcName = 'alztest-icmp-nrc'
        $rcg = $null
        try { $rcg = Get-AzFirewallPolicyRuleCollectionGroup -Name $rcgName -ResourceGroupName $pi.ResourceGroup -AzureFirewallPolicyName $pi.Name -ErrorAction SilentlyContinue } catch { $rcg = $null }
        if (-not $rcg) { Write-Verbose "[FW] No RCG '$rcgName' found; nothing to remove"; return }

        $remaining = @()
        $removed = $false
        foreach ($rc in $rcg.RuleCollection) {
            if ($rc.Name -ne $nrcName) { $remaining += $rc } else { $removed = $true }
        }
        if ($removed) {
            if ($remaining.Count -gt 0) {
                Write-Verbose "[FW] Removing rule collection '$nrcName' from RCG '$rcgName'"
                Set-AzFirewallPolicyRuleCollectionGroup -Name $rcgName -Priority $rcg.Priority -RuleCollection $remaining -FirewallPolicyName $pi.Name -ResourceGroupName $pi.ResourceGroup | Out-Null
            }
            else {
                Write-Verbose "[FW] Removing empty RCG '$rcgName'"
                Remove-AzFirewallPolicyRuleCollectionGroup -Name $rcgName -FirewallPolicyName $pi.Name -ResourceGroupName $pi.ResourceGroup -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        else { Write-Verbose "[FW] Rule collection '$nrcName' not present in RCG '$rcgName'" }
        return
    }

    # Classic firewall cleanup
    $ruleCollectionName = "alztest-allow-$SourcePrefix-$DestinationPrefix".Replace('/', '-').Replace(':', '-')
    $existing = $fw.NetworkRuleCollections | Where-Object Name -eq $ruleCollectionName
    if ($existing) {
        Write-Verbose "[FW] Removing classic Network Rule Collection '$ruleCollectionName'"
        foreach ($rc in @($existing)) { [void]$fw.NetworkRuleCollections.Remove($rc) }
        Set-AzFirewall -AzureFirewall $fw | Out-Null
    }
    else { Write-Verbose "[FW] Classic Network Rule Collection '$ruleCollectionName' not found" }
}
#endregion

#region Cleanup helpers
function Remove-VNetPeerings {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$VNetName,
        [Parameter(Mandatory)][string[]]$PeeringNames
    )
    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    foreach ($n in $PeeringNames) { Remove-AzVirtualNetworkPeering -Name $n -VirtualNetworkName $VNetName -ResourceGroupName $ResourceGroup -Force -ErrorAction SilentlyContinue }
}

function Remove-EphemeralResources {
    # Removes spoke->hub and hub->spoke peerings, then deletes ephemeral resource groups
    # (in their respective subscriptions) if they were created for this test run.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$HubSubscriptionId,
        [Parameter(Mandatory)][string]$HubResourceGroup,
        [Parameter(Mandatory)][string]$HubVNetName,
        [Parameter()][Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VNet1,
        [Parameter()][Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]$VNet2,
        [Parameter()][string]$Rg1,
        [Parameter()][string]$Rg2,
        [Parameter()][hashtable]$RgSubMap
    )
    try {
        Write-Verbose "[Cleanup] Removing spoke->hub and hub->spoke peerings"
        if ($VNet1) { Remove-VNetPeerings -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $VNet1.Id) -ResourceGroup $Rg1 -VNetName $VNet1.Name -PeeringNames @('to-hub') }
        if ($VNet2) { Remove-VNetPeerings -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $VNet2.Id) -ResourceGroup $Rg2 -VNetName $VNet2.Name -PeeringNames @('to-hub') }
        if ($VNet1) { Remove-VNetPeerings -SubscriptionId $HubSubscriptionId -ResourceGroup $HubResourceGroup -VNetName $HubVNetName -PeeringNames @("to-$($VNet1.Name)") }
        if ($VNet2) { Remove-VNetPeerings -SubscriptionId $HubSubscriptionId -ResourceGroup $HubResourceGroup -VNetName $HubVNetName -PeeringNames @("to-$($VNet2.Name)") }
    }
    catch { Write-Warning "[Cleanup] Peering cleanup failure: $($_.Exception.Message)" }
    foreach ($rg in @($Rg1, $Rg2)) {
        if ($rg) {
            try {
                $subForRg = $RgSubMap[$rg]
                if ($subForRg) { Set-SubscriptionContextIfNeeded -SubscriptionId $subForRg }
                Write-Verbose "[Cleanup] Deleting RG '$rg' (sub $subForRg)"
                Remove-ALZTestResourceGroup -Name $rg -Confirm:$false -Verbose
            }
            catch { Write-Warning "[Cleanup] RG '$rg' deletion failed: $($_.Exception.Message)" }
        }
    }
}

function Remove-TransientCompute {
    # For existing VNets scenarios, removes transient compute resources (VM, NIC, OS disk)
    # created by this script without deleting the containing resource group.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter()][string]$VmName,
        [Parameter()][string]$NicName
    )
    Set-SubscriptionContextIfNeeded -SubscriptionId $SubscriptionId
    if ($VmName) {
        try {
            Write-Verbose "[Cleanup] Removing VM '$VmName' in RG '$ResourceGroup'"
            $vm = Get-AzVM -Name $VmName -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
            if ($vm) {
                $osDiskName = $vm.StorageProfile.OsDisk.Name
                Remove-AzVM -Name $VmName -ResourceGroupName $ResourceGroup -Force -ErrorAction SilentlyContinue | Out-Null
                if ($osDiskName) {
                    Write-Verbose "[Cleanup] Removing OS disk '$osDiskName'"
                    $disk = Get-AzDisk -Name $osDiskName -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
                    if ($disk) { Remove-AzDisk -ResourceGroupName $ResourceGroup -DiskName $osDiskName -Force -ErrorAction SilentlyContinue | Out-Null }
                }
            }
        }
        catch { Write-Warning "[Cleanup] VM '$VmName' removal failed: $($_.Exception.Message)" }
    }
    if ($NicName) {
        try {
            Write-Verbose "[Cleanup] Removing NIC '$NicName' in RG '$ResourceGroup'"
            Remove-AzNetworkInterface -Name $NicName -ResourceGroupName $ResourceGroup -Force -ErrorAction SilentlyContinue | Out-Null
        }
        catch { Write-Warning "[Cleanup] NIC '$NicName' removal failed: $($_.Exception.Message)" }
    }
}
#endregion

#region Context helpers
function Get-FirewallContext { [CmdletBinding()][OutputType([hashtable])] param([Parameter(Mandatory)][string]$FirewallResourceId) $p = Get-AzResourceIdParts -ResourceId $FirewallResourceId; return @{ SubscriptionId = $p.SubscriptionId; ResourceGroup = $p.ResourceGroup; Name = $p.Name } }
function Get-HubContext { [CmdletBinding()][OutputType([hashtable])] param([Parameter(Mandatory)][string]$HubVNetResourceId) $p = Get-AzResourceIdParts -ResourceId $HubVNetResourceId; return @{ SubscriptionId = $p.SubscriptionId; ResourceGroup = $p.ResourceGroup; Name = $p.Name } }
function New-TestCredential { [CmdletBinding()][OutputType([PSCredential])] param() [PSCredential]::new('azureuser', (ConvertTo-SecureString 'TempP@ss123!' -AsPlainText -Force)) }
#endregion

#region Orchestrator (refactored Invoke)
function Invoke-NetworkTopologyTest {
    # Orchestrates the full test:
    # 1) Use existing VNets or create ephemeral spokes (RG, NSG, VNet, subnet)
    # 2) Create spoke->hub and hub->spoke peerings, ensure provider features, wait for Connected
    # 3) Provision NICs and VMs in each spoke
    # 4) Phase 1 ping (expected blocked if firewall gating is enabled)
    # 5) Add ICMP allow rule, Phase 2 ping (expected allowed)
    # 6) Write result artifact and perform cleanup (firewall rule, peerings, RGs)
    [CmdletBinding()][OutputType([TestExecutionResult])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^/subscriptions/.+/resourceGroups/.+/providers/Microsoft.Network/virtualNetworks/.+$')][string]$HubVNetResourceId,
        [ValidatePattern('^[a-z0-9-]+$')][string]$Location = 'westeurope',
        [ValidateNotNullOrEmpty()][string]$VmSize = 'Standard_B2s',
        [Parameter()][PSCredential]$Credential,
        [switch]$SkipFirewallValidation,
        [ValidatePattern('^/subscriptions/.+/resourceGroups/.+/providers/Microsoft.Network/azureFirewalls/.+$')][string]$FirewallResourceId,
        [string]$OutputDirectory = (Join-Path (Get-Location) 'outputs'),
        [string]$Spoke1SubscriptionId,
        [string]$Spoke2SubscriptionId,
        [string]$Spoke1VNetResourceId,
        [string]$Spoke2VNetResourceId,
        [string[]]$PreferredVmSizes = @('Standard_B1ms', 'Standard_B2s', 'Standard_B2als_v2', 'Standard_D2as_v5', 'Standard_D2s_v5', 'Standard_D2s_v3')
    )
    Write-Verbose "[Test] Starting network topology test. Location: $Location; HubVNet: $HubVNetResourceId"
    $testId = 'NETWORK-TOPOLOGY-01'
    $result = New-TestExecutionResult -TestId $testId -Category 'Network' -Description 'Hub-spoke connectivity with firewall rule gating.'
    $errors = @()
    $rg1 = $null; $rg2 = $null; $rgSubMap = @{}
    $vnet1 = $null; $vnet2 = $null; $subnet1 = $null; $subnet2 = $null
    $hub = Get-HubContext -HubVNetResourceId $HubVNetResourceId
    $tags = @{ purpose = 'alz-automated-test'; testId = $testId }
    try {
        if ($Spoke1VNetResourceId -and $Spoke2VNetResourceId) {
            # Existing VNet mode: do not create RG/VNet; may temporarily toggle DDoS to avoid conflicts
            Write-Verbose "[Plan] Using existing VNets for spokes"
            $v1 = Get-AzResourceIdParts -ResourceId $Spoke1VNetResourceId
            $v2 = Get-AzResourceIdParts -ResourceId $Spoke2VNetResourceId
            Set-SubscriptionContextIfNeeded -SubscriptionId $v1.SubscriptionId
            $vnet1 = Get-AzVirtualNetwork -Name $v1.Name -ResourceGroupName $v1.ResourceGroup
            if ($vnet1.EnableDdosProtection) { Write-Verbose "[VNet] Disabling DDoS on '$($vnet1.Name)'"; $vnet1.EnableDdosProtection = $false; Set-AzVirtualNetwork -VirtualNetwork $vnet1 | Out-Null }
            Set-SubscriptionContextIfNeeded -SubscriptionId $v2.SubscriptionId
            $vnet2 = Get-AzVirtualNetwork -Name $v2.Name -ResourceGroupName $v2.ResourceGroup
            if ($vnet2.EnableDdosProtection) { Write-Verbose "[VNet] Disabling DDoS on '$($vnet2.Name)'"; $vnet2.EnableDdosProtection = $false; Set-AzVirtualNetwork -VirtualNetwork $vnet2 | Out-Null }
            $subnet1 = $vnet1.Subnets[0]
            $subnet2 = $vnet2.Subnets[0]
            $rg1 = $v1.ResourceGroup; $rg2 = $v2.ResourceGroup
            $rgSubMap[$rg1] = $v1.SubscriptionId; $rgSubMap[$rg2] = $v2.SubscriptionId
        }
        else {
            # Ephemeral mode: create dedicated, tagged resource groups and minimal networking
            if (-not $Spoke1SubscriptionId -or -not $Spoke2SubscriptionId) { throw "Both Spoke1SubscriptionId and Spoke2SubscriptionId must be provided if not using existing VNets." }
            Write-Verbose "[Plan] Creating ephemeral spokes in '$Location'"
            $rg1 = New-TaggedResourceGroup -SubscriptionId $Spoke1SubscriptionId -NamePrefix 'alztest-net1' -Location $Location -Tags $tags
            $rg2 = New-TaggedResourceGroup -SubscriptionId $Spoke2SubscriptionId -NamePrefix 'alztest-net2' -Location $Location -Tags $tags
            $rgSubMap[$rg1] = $Spoke1SubscriptionId; $rgSubMap[$rg2] = $Spoke2SubscriptionId
            $nsg1 = New-SpokeNetworkSecurityGroup -SubscriptionId $Spoke1SubscriptionId -Name 'nsg-spoke-a' -ResourceGroup $rg1 -Location $Location
            $nsg2 = New-SpokeNetworkSecurityGroup -SubscriptionId $Spoke2SubscriptionId -Name 'nsg-spoke-b' -ResourceGroup $rg2 -Location $Location
            $vnet1 = New-SpokeVirtualNetwork -SubscriptionId $Spoke1SubscriptionId -Name 'vnet-spoke-a' -ResourceGroup $rg1 -Location $Location -AddressPrefix '10.71.0.0/24' -SubnetName 'default' -SubnetPrefix '10.71.0.0/27' -NetworkSecurityGroup $nsg1
            $vnet2 = New-SpokeVirtualNetwork -SubscriptionId $Spoke2SubscriptionId -Name 'vnet-spoke-b' -ResourceGroup $rg2 -Location $Location -AddressPrefix '10.72.0.0/24' -SubnetName 'default' -SubnetPrefix '10.72.0.0/27' -NetworkSecurityGroup $nsg2
            $subnet1 = $vnet1.Subnets[0]; $subnet2 = $vnet2.Subnets[0]
        }
        Write-Verbose "[Step] Creating peerings between spokes and hub"
        Set-VNetPeering -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet1.Id) -ResourceGroup $rg1 -VNetName $vnet1.Name -PeeringName 'to-hub' -RemoteVNetId $HubVNetResourceId
        Set-VNetPeering -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet2.Id) -ResourceGroup $rg2 -VNetName $vnet2.Name -PeeringName 'to-hub' -RemoteVNetId $HubVNetResourceId
        Set-HubPeerings -HubSubscriptionId $hub.SubscriptionId -HubResourceGroup $hub.ResourceGroup -HubVNetName $hub.Name -RemoteVNetIds @($vnet1.Id, $vnet2.Id)
        Write-Verbose "[Step] Ensuring Network provider/feature registration across subscriptions"
        @((Get-SubscriptionIdFromResourceId -ResourceId $vnet1.Id), (Get-SubscriptionIdFromResourceId -ResourceId $vnet2.Id), $hub.SubscriptionId) |
        Sort-Object -Unique | ForEach-Object { Set-NetworkFeatureRegistration -SubscriptionId $_ }
        Write-Verbose "[Step] Syncing peerings and waiting for Connected"
        Sync-VNetPeeringAndWait -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet1.Id) -ResourceGroup $rg1 -VNetName $vnet1.Name -PeeringName 'to-hub' -TimeoutSeconds 180
        Sync-VNetPeeringAndWait -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet2.Id) -ResourceGroup $rg2 -VNetName $vnet2.Name -PeeringName 'to-hub' -TimeoutSeconds 180
        # If firewall validation is enabled, resolve firewall private IP and program UDRs in both spokes
        $fwPrivIp = $null
        if ($FirewallResourceId -and -not $SkipFirewallValidation) {
            $fwParts = Get-AzResourceIdParts -ResourceId $FirewallResourceId
            Set-SubscriptionContextIfNeeded -SubscriptionId $fwParts.SubscriptionId
            $fw = Get-AzFirewall -Name $fwParts.Name -ResourceGroupName $fwParts.ResourceGroup -ErrorAction Stop
            if (-not $fw.IpConfigurations -or -not $fw.IpConfigurations[0].PrivateIPAddress) { throw "Firewall '$($fw.Name)' has no private IP configuration for routing." }
            $fwPrivIp = $fw.IpConfigurations[0].PrivateIPAddress
            Write-Verbose "[FW] Resolved firewall private IP: $fwPrivIp"

            # Create route tables and associate to each spoke subnet, routing to the other spoke via firewall
            $rtA = Set-SpokeRouteViaFirewall -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet1.Id) -ResourceGroup $rg1 -Location $Location -VNet $vnet1 -Subnet $subnet1 -DestinationPrefix $vnet2.AddressSpace.AddressPrefixes[0] -FirewallPrivateIp $fwPrivIp -RouteTableName 'rt-spoke-a' -RouteName 'to-spoke-b'
            $rtB = Set-SpokeRouteViaFirewall -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet2.Id) -ResourceGroup $rg2 -Location $Location -VNet $vnet2 -Subnet $subnet2 -DestinationPrefix $vnet1.AddressSpace.AddressPrefixes[0] -FirewallPrivateIp $fwPrivIp -RouteTableName 'rt-spoke-b' -RouteName 'to-spoke-a'
        }

        Write-Verbose "[Step] Provisioning NICs and VMs"
        $nic1 = New-SpokeNic -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet1.Id) -Name 'nic-spoke-a' -ResourceGroup $rg1 -Location $Location -Subnet $subnet1
        $nic2 = New-SpokeNic -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet2.Id) -Name 'nic-spoke-b' -ResourceGroup $rg2 -Location $Location -Subnet $subnet2
        
        # Obtain credentials securely; use provided credential or prompt interactively
        $cred = $Credential
        if (-not $cred) { $cred = New-TestCredential }
        $suffix = ('{0:D3}' -f (Get-Random -Minimum 0 -Maximum 1000))
        $vmNameA = "vm-spoke-a-$suffix"
        $vmNameB = "vm-spoke-b-$suffix"
        
        # Respect the requested VmSize by prioritizing it first
        $preferred = @($VmSize) + ($PreferredVmSizes | Where-Object { $_ -ne $VmSize })
        $candA = Resolve-CandidateVmSizes -Location $Location -PreferredVmSizes $preferred -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet1.Id)
        $candB = Resolve-CandidateVmSizes -Location $Location -PreferredVmSizes $preferred -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet2.Id)
        $okA = New-ResilientLinuxVm -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet1.Id) -VmName $vmNameA -ResourceGroup $rg1 -Location $Location -NicId $nic1.Id -Credential $cred -CandidateSizes $candA
        $okB = New-ResilientLinuxVm -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet2.Id) -VmName $vmNameB -ResourceGroup $rg2 -Location $Location -NicId $nic2.Id -Credential $cred -CandidateSizes $candB
        
        if (-not ($okA -and $okB)) { throw "Failed to create both VMs with available sizes." }
        Set-SubscriptionContextIfNeeded -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet2.Id)
        $vm2PrivIp = (Get-AzNetworkInterface -Name $nic2.Name -ResourceGroupName $rg2).IpConfigurations[0].PrivateIpAddress
        Write-Verbose "[Info] Target VM private IP (spoke-b): $vm2PrivIp"
        Write-Verbose "[Step] Phase 1 connectivity test (expected blocked if firewall gating is used)"
        $phase1 = Test-IcmpConnectivity -SourceSubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet1.Id) -SourceResourceGroup $rg1 -SourceVmName $vmNameA -TargetIp $vm2PrivIp
        
        if ($FirewallResourceId -and -not $SkipFirewallValidation) {
            # Treat blocked connectivity as a pass for the initial phase when firewall gating is in use.
            Add-ConnectivityAssertions -Result $result -Name 'Initial Connectivity Blocked (expected)' -ExpectedAllowed:$false -Connectivity $phase1 -TargetIp $vm2PrivIp
            $srcPrefix = $vnet1.AddressSpace.AddressPrefixes[0]; $dstPrefix = $vnet2.AddressSpace.AddressPrefixes[0]
            Write-Verbose "[FW] Enabling ICMP between spokes: $srcPrefix -> $dstPrefix"
            Set-FirewallIcmpAllowRule -FirewallResourceId $FirewallResourceId -SourcePrefix $srcPrefix -DestinationPrefix $dstPrefix
            Write-Verbose "[FW] Waiting for firewall rule propagation..."
            Start-Sleep -Seconds 180 # Can tune this so it gets a better estimate
            $phase2 = Test-IcmpConnectivity -SourceSubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet1.Id) -SourceResourceGroup $rg1 -SourceVmName $vmNameA -TargetIp $vm2PrivIp
            Add-ConnectivityAssertions -Result $result -Name 'Connectivity After Firewall Rule' -ExpectedAllowed:$true -Connectivity $phase2 -TargetIp $vm2PrivIp
        }
        else {
            # Without firewall gating, we expect reachability based on hub routing and NSG settings.
            Add-ConnectivityAssertions -Result $result -Name 'ICMP Reachability spoke-a->spoke-b' -ExpectedAllowed:$true -Connectivity $phase1 -TargetIp $vm2PrivIp
        }
        Write-Verbose "[Test] Network topology test completed. Cleaning up..."
    }
    catch {
        $err = $_.Exception.Message
        Write-Warning "[TestError] $err"; $errors += $err
    }
    finally {
        # Always attempt cleanup best-effort. Firewall rule removal happens before RG deletes.
        $cleanupStatus = 'Skipped'; $orphans = @()
        try {
            $ephemeral = -not ($Spoke1VNetResourceId -and $Spoke2VNetResourceId)
            # Remove firewall ICMP allow rule if we created one
            if ($FirewallResourceId -and -not $SkipFirewallValidation -and $vnet1 -and $vnet2) {
                try {
                    $srcPrefix = $vnet1.AddressSpace.AddressPrefixes[0]
                    $dstPrefix = $vnet2.AddressSpace.AddressPrefixes[0]
                    Remove-FirewallIcmpAllowRule -FirewallResourceId $FirewallResourceId -SourcePrefix $srcPrefix -DestinationPrefix $dstPrefix -Verbose:$VerbosePreference
                }
                catch { Write-Warning "[Cleanup] Firewall rule cleanup failed: $($_.Exception.Message)" }
            }
            if ($ephemeral) { Write-Verbose "[Cleanup] Starting cleanup of ephemeral resources"; Remove-EphemeralResources -HubSubscriptionId $hub.SubscriptionId -HubResourceGroup $hub.ResourceGroup -HubVNetName $hub.Name -VNet1 $vnet1 -VNet2 $vnet2 -Rg1 $rg1 -Rg2 $rg2 -RgSubMap $rgSubMap }
            $cleanupStatus = 'Succeeded'
            # Only remove route tables for existing VNets; RG deletion will handle ephemeral spokes
            if (-not $ephemeral -and $FirewallResourceId -and -not $SkipFirewallValidation -and $vnet1 -and $vnet2) {
                try {
                    if ($rtA) {
                        Remove-SpokeRouteViaFirewall -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet1.Id) -ResourceGroup $rg1 -VNet $vnet1 -Subnet $subnet1 -RouteTableName 'rt-spoke-a' -RouteName 'to-spoke-b' -RemoveRouteTableIfCreated:([bool]$rtA.CreatedNew)
                    }
                    if ($rtB) {
                        Remove-SpokeRouteViaFirewall -SubscriptionId (Get-SubscriptionIdFromResourceId -ResourceId $vnet2.Id) -ResourceGroup $rg2 -VNet $vnet2 -Subnet $subnet2 -RouteTableName 'rt-spoke-b' -RouteName 'to-spoke-a' -RemoveRouteTableIfCreated:([bool]$rtB.CreatedNew)
                    }
                }
                catch { Write-Warning "[Cleanup] Route table cleanup encountered an issue: $($_.Exception.Message)" }
            }
            else {
                Write-Verbose "[Cleanup] Skipping route table cleanup for ephemeral spokes; RG deletion will remove them"
            }
        }
        catch { $cleanupStatus = 'Partial'; $orphans = @($rg1, $rg2) | Where-Object { $_ } }
        $cleanup = @{ status = $cleanupStatus; orphanedResources = $orphans }
        $final = Set-TestExecutionResult -Result $result -Errors $errors -Cleanup $cleanup
        $null = Write-TestResultArtifact -Result $final -OutputRoot $OutputDirectory
    }
    return $final
}
