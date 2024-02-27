# Opflex agent asyncjson

# Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)  
    

## Overview

`asyncjson` enables parsing of json stream in chunks. Opflex gets json objects from ovs and from leaf via opflex protocol and the normal parser assumes its a complete json object. So if the server sends the object in chunks the parse would fail. This was seen on opflex-agent bring up when ovs side has many endpoints (over 100).


## Mechanism

Two separate flags are introduced in acc provision input file one for ovs and another for opflex to handle above mentioned issue.

1. The ovs section of asyncjson

    The ovs section of the asyncjson independently controls how the parse is done on ovs side. It should be enabled if you have over 100 endpoints.

    Add following configuration in the acc provision input file:
    ```sh
    kube_config:
        opflex_agent_ovs_asyncjson_enabled: true # default is false
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

2. The opflex section of asyncjson

    The opflex section of asyncjson is for future use and should not be enabled now, its disabled by default.

    ```sh
    kube_config:
        opflex_agent_opflex_asyncjson_enabled: true # default is false
    ```


3. Check ovs asyncjson enabled from config map and from opflex-agent pod

    ```sh
    noiro@oshift3-ext-rtr:~$ oc get cm -n aci-containers-system aci-containers-config -o yaml | less
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
            },
            "ovs": {
                "asyncjson": { "enabled" : true }
            },
            "prometheus": {
                "enabled": "false"
            }
        }
    ...
    ...

    noiro@oshift3-ext-rtr:~$ oc logs -n aci-containers-system aci-containers-host-xbm64 -c opflex-agent | grep async
    [2024-Feb-26 04:16:37.005979] [debug] [CommunicationPeer.cpp:208:asyncDocParserCb] Success Parsing, count 17105({"error":null,"result":[{"count":1}],"id":["transact",56]}), instance 0
    , allocs 3
    [2024-Feb-26 04:16:37.006223] [debug] [CommunicationPeer.cpp:208:asyncDocParserCb] Success Parsing, count 17163({"error":null,"result":[{"count":1}],"id":["transact",57]}), instance 0
    , allocs 3
    [2024-Feb-26 04:16:37.008253] [debug] [CommunicationPeer.cpp:208:asyncDocParserCb] Success Parsing, count 17221({"error":null,"result":[{"count":1}],"id":["transact",58]}{"error":null
    ,"result":[{"count":1}],"id":["transact",59]}), instance 0, allocs 3
    [2024-Feb-26 04:16:37.008481] [debug] [CommunicationPeer.cpp:208:asyncDocParserCb] Success Parsing, count 17279({"error":null,"result":[{"count":1}],"id":["transact",58]}{"error":null
    ,"result":[{"count":1}],"id":["transact",59]}), instance 0, allocs 3
    [2024-Feb-26 04:16:37.008684] [debug] [CommunicationPeer.cpp:208:asyncDocParserCb] Success Parsing, count 17337({"error":null,"result":[{"count":1}],"id":["transact",60]}), instance 0
    , allocs 3
    ```