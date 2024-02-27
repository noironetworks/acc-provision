# Enable opflex-agent reconnect after vm migration is complete 

# Table of contents
* [Overview](#overview)
* [Motivation](#motivation)
* [Mechanism](#mechanism)  
* [Troubleshooting](#troubleshooting)
    

## Overview

The process of VM migration plays out as follows:

1. When  the opflex-agent comes up on the destination hypervisor and  there is a grat-ARP for the agent's IP.
2. This is detected by the Endpoint Manager (EPM), which sends a message to COOP(Council of Oracles Protocol) to update the inventory.
3. COOP provides updates to the source and destination leafs.
4. The destination gets an ODev for the new agent, while the source gets a "bounce" entry
5. The opflex-proxy listens for these events, and when it sees the change in Dev, it sends a message to the agent to delete the PlatformConfig (i.e. the VMM domain)
6. This triggers the agent to do a reconnect and re-download of things like the PlatformConfig, along with related policies
7. If the VM is migrating to a host connected to a different leaf-pair, when the agent requests the related policy (e.g. EPGs, BDs, etc.), the destination leaf-pair may have to download all the new policies. How much it has to download depends on the VMs that it's currently hosting (e.g. if it already has a VM on the same EPG, then the EPG doesn't need to be downloaded again).
8. Traffic that hits the leaf will be dropped until EPGs/contracts/etc. are downloaded

Sometimes, there is a chance that it takes too much time for the destination to get the ODev for the new agent and this causes delay for the opflex-agent to reconnect to the new leaf and download related policies. The feature to enable opflex-agent reconnect after vm migration is complete is introduced so that the host-agent will inform opflex-agent that the vm migration is complete so that it can reconnect.
 
## Motivation

For a case where it takes too much time for the destination to get the ODev for the new agent, it causes traffic disruption till new ODev for new agent is created. If we set `enable_opflex_agent_reconnect` flag to True, then the opflex-agent reconnect and re-download of things like the PlatformConfig, along with related policies immediately after ODev of the source leaf is deleted which makes the VM migration to converge much faster and thereby decreasing the time period of traffic disruption.

## Mechanism

This feature can be enabled by giving the following configuration in the acc-provision input file:

```yaml
kube_config:
  enable_opflex_agent_reconnect: True
```

If we set `enable_opflex_agent_reconnect` flag to True, whenever a vm Migration is completed, controller informs this to host-agent and host-agent updates the /usr/local/var/lib/opflex-agent-ovs/reboot-conf.d/reset.conf file. When opflex-agent gets notification of the file update, it reconnect to the new leaf and re-download PlatformConfig along with related policies.

Controller relies on the opflexOdev delete notification to detect that the vm migration is completed. When either primary or secondary opflexOdev of the source leaf of the cluster node is deleted, it indicates that the node is migrated and contoller informs this to host-agent and thereby opflex-agent.

## Troubleshooting

1. Check configuration is applied properly

    Once newly generated aci deployment yaml is applied, `enable_opflex_agent_reconnect` configuration should be reflected in the controller-config and host-agent-config data of aci-containers-config configmap:

```sh
$ kubectl get cm -n aci-containers-system aci-containers-config -oyaml
apiVersion: v1
data:
  controller-config: |-
    {
	...
	"enable-opflex-agent-reconnect": true,
	...
    },
  host-agent-config: |-
    {
        ...
        "enable-opflex-agent-reconnect": true,
        ...
    },
    ...
```

2. When vm migration is completed, the aci-containers-host container of corresponding aci-containers-host pod will have below logs:

```sh
$ kubectl logs -n aci-containers-system aci-containers-host-7txxv -c aci-containers-host | grep -i "Informed opflex-agent"
time="2024-02-27T07:07:37Z" level=debug msg="Informed opflex-agent about opflexOdev disconnect"
```

3. When opflex-agent gets the notification that reset.conf is updated by the host-agent, the opflex-agent container of corresponding aci-containers-host pod will have below logs:

```sh
$ kubectl logs -n aci-containers-system aci-containers-host-7txxv -c opflex-agent
[2023-Nov-21 18:11:27.914968] [info] [cmd/opflex_agent.cpp:154:updated] Triggering peer reset because of change to "/usr/local/var/lib/opflex-agent-ovs/reboot-conf.d/reset.conf"
[2023-Nov-21 18:11:27.915009] [info] [cmd/opflex_agent.cpp:121:run] Disconnect from existing peers and fallback to configured list because of configuration update
[2023-Nov-21 18:11:27.915030] [debug] [OpflexClientConnection.cpp:104:close] [10.0.80.66:8009] Closing
[2023-Nov-21 18:11:27.915046] [debug] [CommunicationPeer.cpp:126:onDisconnect] {0x7fe0fc0010b0}[3];handle@0x7fe0fc0010c8;HD:0x7fe0fc0010b0] connected_ = 1
[2023-Nov-21 18:11:27.915079] [debug] [CommunicationPeer.cpp:95:stopKeepAlive] {0x7fe0fc0010b0}[3];handle@0x7fe0fc0010c8;HD:0x7fe0fc0010b0]
[2023-Nov-21 18:11:27.915094] [info] [OpflexClientConnection.cpp:161:on_state_change] [10.0.80.66:8009] Disconnected
[2023-Nov-21 18:11:27.915099] [debug] [CommunicationPeer.cpp:152:onDisconnect] {0x7fe0fc0010b0}[3];handle@0x7fe0fc0010c8;HD:0x7fe0fc0010b0] already destroying
[2023-Nov-21 18:11:27.915118] [debug] [OpflexClientConnection.cpp:104:close] [10.0.80.64:8009] Closing
[2023-Nov-21 18:11:27.915122] [debug] [OpflexPool.cpp:239:updatePeerStatus] Health updated to: DEGRADED
[2023-Nov-21 18:11:27.915127] [debug] [CommunicationPeer.cpp:126:onDisconnect] {0x7fe0fc021740}[3];handle@0x7fe0fc021758;HD:0x7fe0fc021740] connected_ = 1
[2023-Nov-21 18:11:27.915148] [debug] [CommunicationPeer.cpp:95:stopKeepAlive] {0x7fe0fc021740}[3];handle@0x7fe0fc021758;HD:0x7fe0fc021740]
[2023-Nov-21 18:11:27.915160] [info] [OpflexClientConnection.cpp:161:on_state_change] [10.0.80.64:8009] Disconnected
[2023-Nov-21 18:11:27.915164] [debug] [CommunicationPeer.cpp:152:onDisconnect] {0x7fe0fc021740}[3];handle@0x7fe0fc021758;HD:0x7fe0fc021740] already destroying
[2023-Nov-21 18:11:27.915169] [info] [OpflexPool.cpp:277:doAddPeer] Adding peer 10.0.0.30:8009
[2023-Nov-21 18:11:27.915190] [debug] [OpflexPool.cpp:239:updatePeerStatus] Health updated to: DOWN
[2023-Nov-21 18:11:27.915196] [info] [active_connection.cpp:53:create] 10.0.0.30:8009
[2023-Nov-21 18:11:27.915260] [debug] [loopdata.cpp:179:up] {0x563c4f0f8a70}[3] LoopRefCnt: 3 -> 4
[2023-Nov-21 18:11:27.915269] [debug] [common.cpp:98:on_close] {0x7fe0fc021740}[2];handle@0x7fe0fc021758;HD:0x7fe0fc021740] down() for an on_close(0x7fe0fc021860) keepAliveTimer handle of type timer
[2023-Nov-21 18:11:27.915282] [debug] [common.cpp:98:on_close] {0x7fe0fc021740}[1];handle@0x7fe0fc021758;HD:0x7fe0fc021740] down() for an on_close(0x7fe0fc021758) TCP handle of type tcp
[2023-Nov-21 18:11:27.915286] [info] [OpflexClientConnection.cpp:189:on_state_change] [10.0.80.64:8009] Connection closed
[2023-Nov-21 18:11:27.915540] [debug] [common.cpp:98:on_close] {0x7fe0fc0010b0}[2];handle@0x7fe0fc0010c8;HD:0x7fe0fc0010b0] down() for an on_close(0x7fe0fc0011d0) keepAliveTimer handle of type timer
[2023-Nov-21 18:11:27.915551] [debug] [common.cpp:98:on_close] {0x7fe0fc0010b0}[1];handle@0x7fe0fc0010c8;HD:0x7fe0fc0010b0] down() for an on_close(0x7fe0fc0010c8) TCP handle of type tcp
[2023-Nov-21 18:11:27.915555] [info] [OpflexClientConnection.cpp:189:on_state_change] [10.0.80.66:8009] Connection closed
[2023-Nov-21 18:11:27.915885] [debug] [CommunicationPeer.cpp:113:onConnect] {0x7fe0fc03ed40}[2];handle@0x7fe0fc03ed58;HD:0x7fe0fc03ed40] up() for a timer init
[2023-Nov-21 18:11:27.915896] [info] [OpflexClientConnection.cpp:144:on_state_change] [10.0.0.30:8009] New client connection
[2023-Nov-21 18:11:27.915917] [debug] [transport/ZeroCopyOpenSSL.cpp:560:infoCallback]  Handshake start!
[2023-Nov-21 18:11:27.916051] [debug] [CommunicationPeer.cpp:85:startKeepAlive] {0x7fe0fc03ed40}[3];handle@0x7fe0fc03ed58;HD:0x7fe0fc03ed40] timeoutAfter=120000 begin=10000 repeat=15000
[2023-Nov-21 18:11:27.917615] [debug] [transport/ZeroCopyOpenSSL.cpp:563:infoCallback]  Handshake done!
[2023-Nov-21 18:11:27.952342] [info] [OpflexPool.cpp:277:doAddPeer] Adding peer 10.0.80.64:8009
[2023-Nov-21 18:11:27.952357] [info] [OpflexPool.cpp:277:doAddPeer] Adding peer 10.0.80.66:8009
[2023-Nov-21 18:11:27.952366] [info] [OpflexPEHandler.cpp:336:handleSendIdentityRes] [10.0.0.30:8009] Current peer not found in peer list; closing
[2023-Nov-21 18:11:27.952371] [debug] [OpflexClientConnection.cpp:104:close] [10.0.0.30:8009] Closing
[2023-Nov-21 18:11:27.952378] [debug] [CommunicationPeer.cpp:126:onDisconnect] {0x7fe0fc03ed40}[3];handle@0x7fe0fc03ed58;HD:0x7fe0fc03ed40] connected_ = 1
[2023-Nov-21 18:11:27.952420] [debug] [CommunicationPeer.cpp:95:stopKeepAlive] {0x7fe0fc03ed40}[3];handle@0x7fe0fc03ed58;HD:0x7fe0fc03ed40]
[2023-Nov-21 18:11:27.952427] [info] [OpflexClientConnection.cpp:161:on_state_change] [10.0.0.30:8009] Disconnected
[2023-Nov-21 18:11:27.952432] [debug] [CommunicationPeer.cpp:152:onDisconnect] {0x7fe0fc03ed40}[3];handle@0x7fe0fc03ed58;HD:0x7fe0fc03ed40] already destroying
[2023-Nov-21 18:11:27.952441] [debug] [common.cpp:98:on_close] {0x7fe0fc03ed40}[2];handle@0x7fe0fc03ed58;HD:0x7fe0fc03ed40] down() for an on_close(0x7fe0fc03ee60) keepAliveTimer handle of type timer
[2023-Nov-21 18:11:27.952445] [debug] [common.cpp:98:on_close] {0x7fe0fc03ed40}[1];handle@0x7fe0fc03ed58;HD:0x7fe0fc03ed40] down() for an on_close(0x7fe0fc03ed58) TCP handle of type tcp
[2023-Nov-21 18:11:27.952449] [info] [OpflexClientConnection.cpp:189:on_state_change] [10.0.0.30:8009] Connection closed
[2023-Nov-21 18:11:27.952544] [info] [active_connection.cpp:53:create] 10.0.80.66:8009
[2023-Nov-21 18:11:27.952662] [debug] [loopdata.cpp:179:up] {0x563c4f0f8a70}[1] LoopRefCnt: 1 -> 2
[2023-Nov-21 18:11:27.952673] [info] [active_connection.cpp:53:create] 10.0.80.64:8009
[2023-Nov-21 18:11:27.952722] [debug] [loopdata.cpp:179:up] {0x563c4f0f8a70}[2] LoopRefCnt: 2 -> 3
[2023-Nov-21 18:11:27.952981] [debug] [CommunicationPeer.cpp:113:onConnect] {0x7fe0fc0010b0}[2];handle@0x7fe0fc0010c8;HD:0x7fe0fc0010b0] up() for a timer init
[2023-Nov-21 18:11:27.952993] [info] [OpflexClientConnection.cpp:144:on_state_change] [10.0.80.66:8009] New client connection
[2023-Nov-21 18:11:27.953061] [debug] [transport/ZeroCopyOpenSSL.cpp:560:infoCallback]  Handshake start!
[2023-Nov-21 18:11:27.953182] [debug] [CommunicationPeer.cpp:85:startKeepAlive] {0x7fe0fc0010b0}[3];handle@0x7fe0fc0010c8;HD:0x7fe0fc0010b0] timeoutAfter=120000 begin=10000 repeat=15000
[2023-Nov-21 18:11:27.953240] [debug] [CommunicationPeer.cpp:113:onConnect] {0x7fe0fc021610}[2];handle@0x7fe0fc021628;HD:0x7fe0fc021610] up() for a timer init
[2023-Nov-21 18:11:27.953248] [info] [OpflexClientConnection.cpp:144:on_state_change] [10.0.80.64:8009] New client connection
[2023-Nov-21 18:11:27.953259] [debug] [transport/ZeroCopyOpenSSL.cpp:560:infoCallback]  Handshake start!
[2023-Nov-21 18:11:27.953348] [debug] [CommunicationPeer.cpp:85:startKeepAlive] {0x7fe0fc021610}[3];handle@0x7fe0fc021628;HD:0x7fe0fc021610] timeoutAfter=120000 begin=10000 repeat=15000
[2023-Nov-21 18:11:27.954917] [debug] [transport/ZeroCopyOpenSSL.cpp:563:infoCallback]  Handshake done!
[2023-Nov-21 18:11:27.957902] [info] [OpflexPEHandler.cpp:154:ready] [10.0.80.66:8009] Handshake succeeded
[2023-Nov-21 18:11:27.957943] [debug] [OpflexPool.cpp:239:updatePeerStatus] Health updated to: DEGRADED
[2023-Nov-21 18:11:27.957976] [debug] [Processor.cpp:340:declareObj] Declaring local endpoint /EprL3Universe/EprL3Ep/%2fPolicyUniverse%2fPolicySpace%2fcommon%2fGbpRoutingDomain%2frke1_vrf%2f/10.2.0.133/
[2023-Nov-21 18:11:27.958010] [debug] [Processor.cpp:288:resolveObj] Resolving policy /PolicyUniverse/PolicySpace/common/GbpeL24Classifier/37%7c2%7cIPv4/
[2023-Nov-21 18:11:27.958149] [debug] [Processor.cpp:288:resolveObj] Resolving policy /PolicyUniverse/PolicySpace/common/GbpRoutingDomain/rke1_vrf/
[2023-Nov-21 18:11:27.958230] [debug] [Processor.cpp:288:resolveObj] Resolving policy /PolicyUniverse/PolicySpace/common/GbpeL24Classifier/1%7c0%7cIPv6/
[2023-Nov-21 18:11:27.958514] [debug] [Processor.cpp:288:resolveObj] Resolving policy /PolicyUniverse/PolicySpace/common/GbpeL24Classifier/1%7c0%7cIPv4/
[2023-Nov-21 18:11:27.958571] [debug] [Processor.cpp:340:declareObj] Declaring local endpoint /EprL2Universe/EprL2Ep/%2fPolicyUniverse%2fPolicySpace%2frke1%2fGbpBridgeDomain%2faci-containers-rke1-pod-bd%2f/0a%3a58%3a0a%3a02%3a00%3a83/
[2023-Nov-21 18:11:27.958585] [debug] [Processor.cpp:288:resolveObj] Resolving policy /PolicyUniverse/PolicySpace/common/GbpeL24Classifier/13%7c3%7cIPv4/
[2023-Nov-21 18:11:27.958674] [debug] [Processor.cpp:288:resolveObj] Resolving policy /PolicyUniverse/PolicySpace/rke1/GbpBridgeDomain/aci-containers-rke1-pod-bd/
[2023-Nov-21 18:11:27.958685] [debug] [Processor.cpp:288:resolveObj] Resolving policy /PolicyUniverse/PolicySpace/common/GbpeL24Classifier/12%7c3%7cIPv4/
[2023-Nov-21 18:11:27.958695] [debug] [Processor.cpp:288:resolveObj] Resolving policy /PolicyUniverse/PolicySpace/common/GbpeL24Classifier/13%7c0%7cIPv4/
