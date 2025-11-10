# VM Migration

# Table of Contents
- [1. Overview](#1-overview)
- [2. Mechanism](#2-mechanism)
- [3. Recommendations](#3-recommendations)

## 1. Overview

This functionality supports VM migrations of cluster nodes from one host to another, either on same
or different leaf pairs. The scope of this document is limited to single ACI pod, for migrations between mulitple ACI pods refer [multipod VM migration](multipod-vm-migration.md).

## 2. Mechanism

Below are the events that happen when a vm is migrated:
* When  the opflex-agent comes up on the destination hypervisor and  there is a grat-ARP for the agent's IP. 
* This is detected by the Endpoint Manager (EPM), which sends a message to COOP to update the inventory.
* COOP provides updates to the source and destination leafs.
* The destination gets an ODev for the new agent, while the source gets a "bounce" entry
* The opflex-proxy listens for these events, and when it sees the change in Dev, it sends a message to the agent to delete the PlatformConfig (i.e. the VMM domain)
* This triggers the agent to do a reconnect and re-download of things like the PlatformConfig, along with related policies
* If the VM is migrating to a host connected to a different leaf-pair, when the agent requests the related policy (e.g. EPGs, BDs, etc.), the destination leaf-pair may have to download all the new policies. How much it has to download depends on the VMs that it's currently hosting (e.g. if it already has a VM on the same EPG, then the EPG doesn't need to be downloaded again).
* Traffic that hits the leaf will be dropped until EPGs/contracts/etc. are downloaded

## 3. Recommendations

### Enable opflex-agent reconnect
For detailed instructions on enabling and verifying this feature, refer [enable opflex agent reconnect](enable-opflex-agent-reconnect.md).

> **Note:** Controller Pod Migration - If the Kubernetes node hosting the aci-containers-controller pod needs to be migrated, it is highly recommended to manually move the controller pod to a stable, non-migrating node before initiating the VM migration.
