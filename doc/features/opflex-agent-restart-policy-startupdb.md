
# Opflex agent restart using policy file

## Overview

This feature allows the opflex-agent to resolve policies with the startup db which is a policy state that persisted before the opflex-agent restart. The opflex-agent will start resolving the policies from the startup db and once the leaf connects to the agent, it will catch up with the leaf over the time 

## Motivation

In the face of heavy load, if the opflex-agent restarts (due to upgrade or other reasons), it may not be able to download all policy instantenously after connecting with the leaf. This can lead to partial programming of the data path until full policy is downloaded. By enabling this feature, the oflex-agent upon restart will start resolving the policies using a previously persisted policy file (most likely from the time just before it was restarted) and complete the OVS flow programming. Once sufficient time has elapsed (the time is configurable), the agent will assume it now has had time to catch up with the full policy in the leaf and it will start updating the OVS flows to reflect that. 

## Mechanism

```yaml
kube_config:
  opflex_startup_enabled: True
  opflex_startup_policy_duration: 80
  opflex_startup_resolve_aft_conn: True
  opflex_switch_sync_delay: 10
  opflex_switch_sync_dynamic: 5
```
1. If we set the opflex_startup_enabled to True, it will enable the opflex-agent to use the startup db to resolve the policies. Agent will look for policy file under the /usr/local/var/lib/opflex-agent-ovs/startup/ path. This policy file is the policy state that persisted prior to the agent restart and this policy file is used to build the startup db. Default value is False.
2. opflex_startup_policy_duration is the duration for which agent should keep using policy file during startup after agent connects to the leaf. Default value is 60 seconds.
3. opflex_startup_resolve_aft_conn is to wait till the opflex-agent connects to leaf before using the local policy. Default value is False. 
4. opflex_switch_sync_delay is the duration for which opflex-agent has to wait to start the switch sync from the PlatformConfig resolution. Default value is 5 seconds
5. opflex_switch_sync_dynamic is the Subsequent switch sync delay. For any pending policy resolves, the max retries is hardcoded to 5. Default value is 10 seconds

## Troubleshooting

Once newly generated aci deployment yaml is applied, opflex_startup_enabled configuration should be reflected in the opflex-agent-config data of aci-containers-config configmap:

 kubectl get cm -n aci-containers-system aci-containers-config -oyaml

```sh
$ kubectl get cm -n aci-containers-system aci-containers-config -oyaml
apiVersion: v1
data:
  opflex-agent-config: |-
    {
        ...
        "startup": {
                    "enabled": true
            },
        ...
    },
    ...
```

2.   "policy-file": "/usr/local/var/lib/opflex-agent-ovs/startup/pol.json" should be visible in the opflex-agent-config data of aci-containers-config configmap:


```sh
$ kubectl get cm -n aci-containers-system aci-containers-config -oyaml
apiVersion: v1
data:
  opflex-agent-config: |-
    {
        ...
        "startup": {
                    "enabled": true,
		    "policy-file": "/usr/local/var/lib/opflex-agent-ovs/startup/pol.json"
            },
        ...
    },
    ...
```

3. The policy file should consist of the policy dump of the policy state before the opflex-agent restart 
4. The opflex-agent  should have below logs if the feature is enabled and the flags are set:


```sh
[2024-May-29 18:13:28.733813] [info] [lib/Agent.cpp:536:setProperties] Startup policy is enabled
[2024-May-29 18:13:28.733829] [info] [lib/Agent.cpp:543:setProperties] Startup policy file set to  /usr/local/var/lib/opflex-agent-ovs/startup/pol.json
[2024-May-29 18:13:28.733846] [info] [lib/Agent.cpp:550:setProperties] Startup policy duration set to 60000 ms
[2024-May-29 18:13:28.733862] [info] [lib/Agent.cpp:557:setProperties] Startup policy resolve after connection set to 0
```
5. If the feature is enabled you should see the platform config resolution soon after the agent restart 

```sh
[2024-May-29 18:13:29.255400] [debug] [Processor.cpp:133:addRef] Tracking new nonlocal item /PolicyUniverse/PlatformConfig/comp%2fprov-OpenShift%2fctrlr-%5bopenupi%5d-openupi%2fsw-InsiemeLSOid/ from reference
[2024-May-29 18:13:29.255417] [debug] [Processor.cpp:140:addRef] addref /PolicyUniverse/PlatformConfig/comp%2fprov-OpenShift%2fctrlr-%5bopenupi%5d-openupi%2fsw-InsiemeLSOid/ (from /DomainConfig/DomainConfigToConfigRSrc/) 1 state unresolved
[2024-May-29 18:13:29.255431] [debug] [Processor.cpp:479:processItem] Processing nonlocal item /PolicyUniverse/PlatformConfig/comp%2fprov-OpenShift%2fctrlr-%5bopenupi%5d-openupi%2fsw-InsiemeLSOid/ of class PlatformConfig and type 0 in state unresolved
[2024-May-29 18:13:29.255439] [debug] [Processor.cpp:371:resolveObj] Resolving policy /PolicyUniverse/PlatformConfig/comp%2fprov-OpenShift%2fctrlr-%5bopenupi%5d-openupi%2fsw-InsiemeLSOid/
[2024-May-29 18:13:29.255450] [debug] [Processor.cpp:303:resolveObjLocal] Local policy resolved for 48 /PolicyUniverse/PlatformConfig/comp%2fprov-OpenShift%2fctrlr-%5bopenupi%5d-openupi%2fsw-InsiemeLSOid/
```
