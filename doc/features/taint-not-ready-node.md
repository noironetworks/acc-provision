# Taint "NotReady" Node

## Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)  


## Overview

To avoid scheduling of pods before the host agent is running on a node we can use the following configuration: 

```yaml
kube_config:		     
  taint_not_ready_node: True 
```

This will make node unschedulable by adding a taint if it's not in **Ready** state. Taint will be removed when the node becomes **Ready** and **host-agent** pod initialization is complete and it is **Running** on that node. Below taint is added to facilitate this:

`aci-containers-host/unavailable:NoSchedule` 


## Mechanism

Add following configuration in the acc provision input file:
```yaml
kube_config:		     
  taint_not_ready_node: True  # default is False
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

Verify the flag is set in aci-containers-config config map:

```sh
$ oc get cm -n aci-containers-system aci-containers-config -oyaml | less
apiVersion: v1
data:
  ...
  controller-config: |-
    {
        ...
         "taint-not-ready-node": true,
        ...
    }
  host-agent-config: |-
    {
        ...
        "taint-not-ready-node": true,
        ...
    }
```


When Node is in **NotReady** state, a taint `aci-containers-host/unavailable:NoSchedule` is added on the node.

```sh
$ oc get nodes
NAME             STATUS     ROLES                  AGE   VERSION
k8s-xyz-node-1   Ready      control-plane,master   18d   v1.29.7
k8s-xyz-node-2   Ready      worker                 18d   v1.29.7
k8s-xyz-node-3   NotReady   worker                 18d   v1.29.7

$ oc get node k8s-xyz-node-3 -oyaml | grep taint -A5
  taints:
  - effect: NoSchedule
    key: aci-containers-host/unavailable
  - effect: NoSchedule
    key: node.kubernetes.io/unreachable
    timeAdded: "2024-08-23T07:34:57Z"
```

When Node goes into **Ready** state and **host-agent** pod is Running, the taint `aci-containers-host/unavailable:NoSchedule` is removed from the node.

```sh
$ oc get nodes
NAME             STATUS     ROLES                  AGE   VERSION
k8s-xyz-node-1   Ready      control-plane,master   18d   v1.29.7
k8s-xyz-node-2   Ready      worker                 18d   v1.29.7
k8s-xyz-node-3   Ready      worker                 18d   v1.29.7

$ oc get node k8s-xyz-node-3 -oyaml | grep taint -A5
$
```
