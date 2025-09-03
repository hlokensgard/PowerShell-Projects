# NetworkingTest — Hub-Spoke Connectivity gated by Azure Firewall

## Goal

Validate that traffic between two spokes must traverse the hub’s Azure Firewall and is blocked by default, then becomes reachable only after adding an explicit ICMP allow rule. The script provisions temporary spokes (optional) and performs a two‑phase ping test to prove the control path end‑to‑end.

## What it does

- Optionally creates ephemeral spoke VNets (with subnet, NSG, NIC, and a small Linux VM) in one or two subscriptions
- Ensures hub↔spoke VNet peerings and provider feature registration are in place
- Programs a spoke route table to send inter‑spoke traffic to the Azure Firewall
- Phase 1: Runs an ICMP test expected to be blocked by the firewall
- Inserts a policy‑aware or classic firewall ICMP allow rule (source→destination prefixes)
- Phase 2: Re‑runs the ICMP test and verifies it succeeds; records latency when available
- Writes a timestamped JSON artifact with assertions, evidence, and cleanup metadata
- Cleans up: removes the firewall rule, peerings and route table bindings; deletes ephemeral resources if they were created

## High‑level architecture

Components (per the script `NetworkTest.ps1`):

- Hub VNet (existing) with Azure Firewall (policy‑managed preferred, classic supported)
- Spoke 1 and Spoke 2 VNets (existing or ephemeral)
	- Subnet with NSG (allow VirtualNetwork, default deny catch‑alls)
	- Route table to forward inter‑spoke traffic to the firewall
	- NIC + Ubuntu 22.04 LTS VM (size dynamically resolved with fallbacks)
- VNet peerings: Spoke→Hub and Hub→Spoke (AllowForwardedTraffic enabled)
- Optional provider feature/registration sync for Microsoft.Network

ASCII view

```
 [Spoke 1 VNet]                    [Spoke 2 VNet]
		 Subnet + NSG                      Subnet + NSG
		 NIC + VM (S1)                     NIC + VM (S2)
					|                                 |
	 RT: 0.0.0.0/0 -> FW IP           RT: 0.0.0.0/0 -> FW IP (when needed)
					|                                 |
			 Peering ——> [ Hub VNet + Azure Firewall ] <—— Peering
```


## Script structure (orientation)

- Result types: TestAssertionResult, TestExecutionResult, and helpers to record and persist results
- Utilities: subscription context guard, resource ID parsing, timers, polling, random suffix, artifact writer
- Provisioning primitives: RG, NSG, VNet, NIC, route table via firewall, peering setup/sync, feature registration
- Compute: VM size resolution with fallback; resilient Ubuntu VM creation
- Connectivity & firewall: VM RunCommand ICMP test; firewall ICMP allow rule add/remove (policy or classic)
- Cleanup: peerings, route tables, ephemeral RGs or transient compute resources
- Orchestrator: `Invoke-NetworkTopologyTest` ties it all together in two phases and produces a JSON artifact

## Prerequisites

- PowerShell 7.x
- Az PowerShell modules installed and account logged in with sufficient RBAC in the target subscriptions
- Existing Hub VNet and Azure Firewall (policy‑managed preferred) with resource IDs

## Running it (example)

The script includes an example invocation at the bottom you can adapt. Run in PowerShell 7 with Verbose for trace output.

```powershell
# Example (adjust resource IDs and subscription IDs)
Invoke-NetworkTopologyTest -HubVNetResourceId \
	'/subscriptions/<hub-sub>/resourceGroups/<hub-rg>/providers/Microsoft.Network/virtualNetworks/<hub-vnet>' `
	-FirewallResourceId \
	'/subscriptions/<hub-sub>/resourceGroups/<hub-rg>/providers/Microsoft.Network/azureFirewalls/<fw-name>' `
	-Spoke1SubscriptionId '<spoke1-sub>' `
	-Spoke2SubscriptionId '<spoke2-sub>' -Verbose
```

## Notes and design choices

- Idempotent operations: most creators are “ensure” style; safe to re‑run
- Strict subscription context switching to avoid cross‑subscription leakage
- Conservative waits/retries to handle control‑plane eventual consistency
- Tagged ephemeral resources to make cleanup easier and auditable

