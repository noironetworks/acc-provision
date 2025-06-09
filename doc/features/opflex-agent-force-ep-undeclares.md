# Opflex agent force EP undeclare

# Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)  
    

## Overview

When an existing EP is updated, instead of simply resending epdeclare, send a undeclare followed by declare.
The new behavior will be default unless disabled via flag.

Old (non default behaviour)
```
[2025-May-08 13:53:04.696491] [info] [lib/Agent.cpp:670:applyProperties] Setting force_ep_undeclares to 0

Update
[2025-May-08 13:53:34.708020] [debug] [Processor.cpp:433:declareObj] Declaring local endpoint /EprL3Universe/EprL3Ep/%2fPolicyUniverse%2fPolicySpace%2fcommon%2fGbpRoutingDomain%2frke-setup3-vrf%2f/10.2.0.204/ [2025-May-08 13:53:34.708752] [debug] [Processor.cpp:433:declareObj] Declaring local endpoint /EprL2Universe/EprL2Ep/%2fPolicyUniverse%2fPolicySpace%2frkesetup3%2fGbpBridgeDomain%2faci-containers-rkesetup3-pod-bd%2f/0a%3a58%3a0a%3a02%3a00%3acc/

Delete
[2025-May-08 13:53:47.748789] [debug] [Processor.cpp:631:processItem] Undeclaring /EprL2Universe/EprL2Ep/%2fPolicyUniverse%2fPolicySpace%2frkesetup3%2fGbpBridgeDomain%2faci-containers-rkesetup3-pod-bd%2f/0a%3a58%3a0a%3a02%3a00%3acc/ [2025-May-08 13:53:47.748989] [debug] [Processor.cpp:631:processItem] Undeclaring /EprL3Universe/EprL3Ep/%2fPolicyUniverse%2fPolicySpace%2fcommon%2fGbpRoutingDomain%2frke-setup3-vrf%2f/10.2.0.204/

Add
[2025-May-08 13:53:59.512911] [debug] [Processor.cpp:433:declareObj] Declaring local endpoint /EprL3Universe/EprL3Ep/%2fPolicyUniverse%2fPolicySpace%2fcommon%2fGbpRoutingDomain%2frke-setup3-vrf%2f/10.2.0.204/ [2025-May-08 13:53:59.513669] [debug] [Processor.cpp:433:declareObj] Declaring local endpoint /EprL2Universe/EprL2Ep/%2fPolicyUniverse%2fPolicySpace%2frkesetup3%2fGbpBridgeDomain%2faci-containers-rkesetup3-pod-bd%2f/0a%3a58%3a0a%3a02%3a00%3acc/
```

New (default behaviour)
```
[2025-May-08 13:57:01.248363] [info] [lib/Agent.cpp:670:applyProperties] Setting force_ep_undeclares to 1

Update
[2025-May-08 13:58:11.825316] [debug] [Processor.cpp:592:processItem] Undeclaring /EprL3Universe/EprL3Ep/%2fPolicyUniverse%2fPolicySpace%2fcommon%2fGbpRoutingDomain%2frke-setup3-vrf%2f/10.2.0.130/ [2025-May-08 13:58:11.825402] [debug] [Processor.cpp:433:declareObj] Declaring local endpoint /EprL3Universe/EprL3Ep/%2fPolicyUniverse%2fPolicySpace%2fcommon%2fGbpRoutingDomain%2frke-setup3-vrf%2f/10.2.0.130/ [2025-May-08 13:58:11.826056] [debug] [Processor.cpp:592:processItem] Undeclaring /EprL2Universe/EprL2Ep/%2fPolicyUniverse%2fPolicySpace%2frkesetup3%2fGbpBridgeDomain%2faci-containers-rkesetup3-pod-bd%2f/0a%3a58%3a0a%3a02%3a00%3a82/ [2025-May-08 13:58:11.826134] [debug] [Processor.cpp:433:declareObj] Declaring local endpoint /EprL2Universe/EprL2Ep/%2fPolicyUniverse%2fPolicySpace%2frkesetup3%2fGbpBridgeDomain%2faci-containers-rkesetup3-pod-bd%2f/0a%3a58%3a0a%3a02%3a00%3a82/

Delete
[2025-May-08 13:59:27.158017] [debug] [Processor.cpp:631:processItem] Undeclaring /EprL2Universe/EprL2Ep/%2fPolicyUniverse%2fPolicySpace%2frkesetup3%2fGbpBridgeDomain%2faci-containers-rkesetup3-pod-bd%2f/0a%3a58%3a0a%3a02%3a00%3a82/ [2025-May-08 13:59:27.158615] [debug] [Processor.cpp:631:processItem] Undeclaring /EprL3Universe/EprL3Ep/%2fPolicyUniverse%2fPolicySpace%2fcommon%2fGbpRoutingDomain%2frke-setup3-vrf%2f/10.2.0.130/

Add
[2025-May-08 13:59:37.922854] [debug] [Processor.cpp:433:declareObj] Declaring local endpoint /EprL3Universe/EprL3Ep/%2fPolicyUniverse%2fPolicySpace%2fcommon%2fGbpRoutingDomain%2frke-setup3-vrf%2f/10.2.0.130/ [2025-May-08 13:59:37.923454] [debug] [Processor.cpp:433:declareObj] Declaring local endpoint /EprL2Universe/EprL2Ep/%2fPolicyUniverse%2fPolicySpace%2frkesetup3%2fGbpBridgeDomain%2faci-containers-rkesetup3-pod-bd%2f/0a%3a58%3a0a%3a02%3a00%3a82/
```

## Mechanism

Add following configuration in the acc provision input file to enable old behaviour:
```sh
kube_config:
    force_ep_undeclares: false # default is true
```

Run `acc-provision` tool on updated acc provision input file to generate new `aci_deployment.yaml`
```sh
acc-provision -c <acc_provision_input_file> -f <flavor> -u <apic_username> -p <apic_password> -o aci_deployment.yaml
```

Delete old aci_deployment.yaml and wait till all the pods in the `aci-containers-system` namespace are deleted
```sh
$ oc delete -f aci_deployment.yaml
$ oc get pods -n aci-containers-system
```

Apply newly generated aci_deployment.yaml and wait till all pods in `aci-containers-system` namespace are running
```sh
$ oc apply -f aci_deployment.yaml
$ oc get pods -n aci-containers-system
```


Verify parameter is changed in aci-containers-config config map:

```sh
noiro@oshift3-ext-rtr:~$ oc get cm -n aci-containers-system aci-containers-config -oyaml | less
apiVersion: v1
data:
  ...
  ...
  opflex-agent-config: |-
    {
        "log": {
            "level": "debug"
        },
        "opflex": {
            "notif" : { "enabled" : "false" },
            "asyncjson": { "enabled" : "false" }
            "force-ep-undeclares": { "enabled": "false" }
        },
        "ovs": {
            "asyncjson": { "enabled" : "false" }
        },
        "prometheus": {
            "enabled": "false"
        }
    }
```