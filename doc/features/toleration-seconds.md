# Toleration Seconds Configuration 

# Table of Contents

- [1. Overview](#1-overview)
- [2. Motivation](#2-motivation)
- [3. Mechanism](#3-mechanism)

## 1. Overview

This feature allows the configuration of the `tolerationSeconds` field of the NoExecute toleration for the controller pod. This allows the pod to be run on a node with a NoExecute taint for the user specified duration. After this time the pod will be evicted and rescheduled on another node, if available.

## 2. Motivation

The default value used for the toleration seconds field is 600 seconds for RKE and 60 seconds for other clusters. This allows the controller pod to run on a node for a period of 60 or 600 seconds respectively even when the node has a NoExecute taint. In certain cases the other (worker) nodes may not become ready in this default time and this may cause failures as the controller pod has been evicted before the setup is complete and there are no other nodes to which it can be scheduled. 

Making this field configurable allows for a custom value to be specified according to the user's requirements.

## 3. Mechanism

In the acc-provision input file, set the following configuration to override the default values and set a custom `tolerationSeconds` value for the controller pod's NoExecute toleration.

```sh
kube_config:
  toleration_seconds: <value>
```

Run the `acc-provision` tool on this acc-provision input file to generate `aci_deployment.yaml`.

```sh
acc-provision -c <acc_provision_input_file> -f <flavor> -u <apic_username> -p <apic_password> -o aci_deployment.yaml
```

Use this file to deploy the cni while provisioning the cluster. 

The controller pod would have the specified toleration_seconds value. This can be verified in the aci-containers-controller deployment.

get controller deployment:
```sh
kubectl get deployment -n aci-containers-system aci-containers-controller -o yaml
```

sample deployment:
```yaml
  ….
  tolerations:
  - effect: NoExecute
    operator: Exists
    tolerationSeconds: 100
  - effect: NoSchedule
    key: node.kubernetes.io/not-ready
    operator: Exists
  - effect: NoSchedule
  ….
```

This would allow the controller pod to remain on a node with a NoExecute taint (for instance etcd or control-plane node) for the specified time (100 seconds in the above example) before being evicted.
