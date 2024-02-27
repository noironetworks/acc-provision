# Configure ACI Pod container's memory request and limit

# Table of contents
* [Overview](#overview)
* [Motivation](#motivation)
* [Mechanism](#mechanism)
    - [1. Open vSwitch container](#1-open-vswitch-container)
    - [2. All pods of `aci-containers-system` namespace (except openvswitch container)](#2-all-pods-of-aci-containers-system-namespace-except-openvswitch-container)
    - [3. Other ACI pod container specific](#3-other-aci-pod-container-specific)
* [Examples](#examples)
    - [1. Default memory request and limit](#1-default-memory-request-and-limit)
    - [2. Openvswitch container non default memory request and limit](#2-openvswitch-container-non-default-memory-request-and-limit)
    - [3. Namespace `aci-containers-system` wide non default memory request and limit](#3-namespace-aci-containers-system-wide-non-default-memory-request-and-limit)
    - [4. Other ACI pod container specific non default memory request and limit](#4-other-aci-pod-container-specific-non-default-memory-request-and-limit)


## Overview

Limits and Requests are important settings when working with Kubernetes.

#### Kubernetes Limits

- Kubernetes defines Limits as the maximum amount of a resource to be used by a container. This means that the container can never consume more than the memory amount indicated.
Limits are used
    -   When allocating Pods to a Node. If no requests are set, by default, Kubernetes will assign requests = limits.
    -   At runtime, Kubernetes will check that the containers in the Pod are not consuming a higher amount of resources than indicated in the limit.

#### Kubernetes Requests
- Requests on the other hand, are the minimum guaranteed amount of a resource that is reserved for a container. Basically, it will set the minimum amount of the resource for the container to consume. When a Pod is scheduled, kube-scheduler will check the Kubernetes requests in order to allocate it to a particular Node that can satisfy at least that amount for all containers in the Pod. If the requested amount is higher than the available resource, the Pod will not be scheduled and remain in Pending status.

The memory request and limit for a Container is set by including the `resources:requests` and `resources:limits` field respectively in the Container's resource manifest.

**Here we are introducing different flags in acc provision input file to enable user to set different memory request and limit to aci pods as per need.**

## Motivation

By configuring memory requests and limits for the Containers that run in your cluster, you can make efficient use of the memory resources available on your cluster's Nodes. By keeping a Pod's memory request low, you give the Pod a good chance of being scheduled. By having a memory limit that is greater than the memory request, you accomplish two things:

1. The Pod can have bursts of activity where it makes use of memory that happens to be available.
2. The amount of memory a Pod can use during a burst is limited to some reasonable amount.


## Mechanism

Following are the ways to set memory request and limit for different aci pods

#### 1. Open vSwitch container

The default memory request and limit value for the `Open vSwitch container` is 128Mi and 1Gi respectively. It can be changed by configuring the acc provision input file as follows:

```yaml
kube_config:
    ovs_memory_request: "512Mi"     # default is "128Mi"
    ovs_memory_limit: "2Gi"         # default is "1Gi"
```

#### 2. All pods of `aci-containers-system` namespace (except openvswitch container)

The default memory request and limit value for `aci-containers-system` namespace pods is 128Mi and 3Gi respectively. It can be changed by configuring the acc provision input file as follows.

```yaml
kube_config:
    aci_containers_memory_request: "512Mi"     # default is "128Mi"
    aci_containers_memory_limit: "5Gi"         # default is "3Gi"
```

This namespace wide memory request-limit setting is not applied to `Open vSwitch container`. As mentioned in previous point #1, please use ovs_memory_request and ovs_memory_limit to change openvswitch container memory request and limit respectively.

This configuration internally creates LimitRange resource named `memory-limit-range` in aci-containers-system namespace.

```sh    
noiro@oshift3-ext-rtr:~$ oc get limitrange memory-limit-range -n aci-containers-system -oyaml
apiVersion: v1
kind: LimitRange
metadata:
    annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
        {"apiVersion":"v1","kind":"LimitRange","metadata":{"annotations":{},"name":"memory-limit-range", "namespace":"aci-containers-system"},"spec":{"limits":[{"default":{"memory":"3Gi"},"defaultRequest":{"memory":"128Mi"},"type":"Container"}]}}
    creationTimestamp: "2024-02-19T11:40:01Z"
    name: memory-limit-range
    namespace: aci-containers-system
    resourceVersion: "13422381"
    uid: 7312c9d3-2ef6-4012-96f2-b9c22254ca07
spec:
    limits:
    - default:
        memory: 3Gi
    defaultRequest:
        memory: 128Mi
    type: Container
```

#### 3. Other ACI pod container specific

Apart from above options to set namespace wide memory request and limit, user can choose to configure container specific memory request and limit values through acc provision input file as follows:

```yaml
kube_config:
    aci_containers_controller_memory_request: "256Mi"  # default is aci_containers_memory_request
    aci_containers_controller_memory_limit: "5Gi"      # default is aci_containers_memory_limit
    aci_containers_host_memory_request: "256Mi"        # default is aci_containers_memory_request
    aci_containers_host_memory_limit: "5Gi"            # default is aci_containers_memory_limit
    mcast_daemon_memory_request: "256Mi"               # default is aci_containers_memory_request
    mcast_daemon_memory_limit: "5Gi"                   # default is aci_containers_memory_limit
    opflex_agent_memory_request: "256Mi"               # default is aci_containers_memory_request
    opflex_agent_memory_limit: "5Gi"                   # default is aci_containers_memory_limit
    acc_provision_operator_memory_request: "256Mi"     # default is aci_containers_memory_request
    acc_provision_operator_memory_limit: "5Gi"         # default is aci_containers_memory_limit
    aci_containers_operator_memory_request: "256Mi"    # default is aci_containers_memory_request
    aci_containers_operator_memory_limit: "5Gi"        # default is aci_containers_memory_limit
```
This container specific configuration takes priority over the namespace wide configuration.

If any of these mentioned option is not configured then aci_containers_memory_request / aci_containers_memory_limit namespace wide value is set accordingly.
E.g
- if `mcast_daemon_memory_request` option is not configured then `aci_containers_memory_request` value will be set for aci-containers-host pod's container `mcast-daemon` memory request.
- if `mcast_daemon_memory_limit` option is not configured then `aci_containers_memory_limit` value will be set for aci-containers-host pod's container `mcast-daemon` memory limit.


## Examples

#### Following table is helpful to understand total memory allocated for an aci pod.
E.g if memory request is 128Mi and total running containers for a pod are 3 then total memory request allocated for that pod is 128Mi * 3 = 384Mi

|        ACI POD              | No. of running containers |
| --------------------------- | :-----------------------: |
|  aci-containers-controller  |           1               |
|  aci-containers-host        |           3               |
|  aci-containers-openvswitch |           1               |
|  aci-containers-operator    |           2               |


-----

#### 1. Default memory request and limit

```sh
noiro@oshift3-ext-rtr:~$ oc describe node ocp413-worker1
Name:               ocp413-worker1
Roles:              worker
...
...
...
Non-terminated Pods:                      (22 in total)
  Namespace                               Name                                                      CPU Requests  CPU Limits  Memory Requests  Memory Limits  Age
  ---------                               ----                                                      ------------  ----------  ---------------  -------------  ---
  aci-containers-system                   aci-containers-controller-d78cd4d45-n7h55                 0 (0%)        0 (0%)      128Mi (0%)       3Gi (20%)      23m
  aci-containers-system                   aci-containers-host-vjlcc                                 0 (0%)        0 (0%)      384Mi (2%)       9Gi (62%)      23m
  aci-containers-system                   aci-containers-openvswitch-4hldw                          0 (0%)        0 (0%)      128Mi (0%)       1Gi (6%)       23m


noiro@oshift3-ext-rtr:~$ oc describe node  ocp413-worker2
Name:               ocp413-worker2
Roles:              worker
...
...
...
    Non-terminated Pods:                      (22 in total)
  Namespace                               Name                                                      CPU Requests  CPU Limits  Memory Requests  Memory Limits  Age
  ---------                               ----                                                      ------------  ----------  ---------------  -------------  ---
  aci-containers-system                   aci-containers-host-jcndd                                 0 (0%)        0 (0%)      384Mi (2%)       9Gi (62%)      18m
  aci-containers-system                   aci-containers-openvswitch-spbnz                          0 (0%)        0 (0%)      128Mi (0%)       1Gi (6%)       18m
  aci-containers-system                   aci-containers-operator-7698cdb46d-xtwgc                  0 (0%)        0 (0%)      256Mi (1%)       6Gi (41%)      18m
```


#### 2. Openvswitch container non default memory request and limit

Add following configuration in the acc provision input file:

```yaml
kube_config:
    ovs_memory_request: "512Mi"
    ovs_memory_limit: "2Gi"
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

Check openvswitch container memroy request and limit allocated which will be Request=512Mi, Limit=2Gi

```sh
noiro@oshift3-ext-rtr:~$ oc get pods -n aci-containers-system aci-containers-openvswitch-584pr -o yaml | grep "memory:" -B2
    resources:
      limits:
        memory: 2Gi
      requests:
        memory: 512Mi

noiro@oshift3-ext-rtr:~$ oc describe node ocp413-worker1
Name:               ocp413-worker1
Roles:              worker
...
...
...
Non-terminated Pods:                      (22 in total)
  Namespace                               Name                                                      CPU Requests  CPU Limits  Memory Requests  Memory Limits  Age
  ---------                               ----                                                      ------------  ----------  ---------------  -------------  ---
  aci-containers-system                   aci-containers-controller-d78cd4d45-xsb82                 0 (0%)        0 (0%)      128Mi (0%)       3Gi (20%)      <invalid>
  aci-containers-system                   aci-containers-host-kqw2v                                 0 (0%)        0 (0%)      384Mi (2%)       9Gi (62%)      <invalid>
  aci-containers-system                   aci-containers-openvswitch-584pr                          0 (0%)        0 (0%)      512Mi (3%)       2Gi (13%)      <invalid>
```


#### 3. Namespace `aci-containers-system` wide non default memory request and limit

Add following configuration in the acc provision input file:

```yaml
kube_config:
    aci_containers_memory_request: "512Mi"
    aci_containers_memory_limit: "4Gi"
```

Run `acc-provision` tool on updated acc provision input file, delete old aci_deployment.yaml and apply newly generated aci_deployment.yaml

Check aci pod container memroy request and limit allocated

```sh
noiro@oshift3-ext-rtr:~$ oc describe node ocp413-worker1
Name:               ocp413-worker1
Roles:              worker
...
...
...
Non-terminated Pods:                      (22 in total)
  Namespace                               Name                                                      CPU Requests  CPU Limits  Memory Requests  Memory Limits  Age
  ---------                               ----                                                      ------------  ----------  ---------------  -------------  ---
  aci-containers-system                   aci-containers-controller-d994d58b9-lqgx8                 0 (0%)        0 (0%)      512Mi (3%)       4Gi (27%)      5m15s
  aci-containers-system                   aci-containers-host-6qk67                                 0 (0%)        0 (0%)      1536Mi (10%)     12Gi (82%)     4m44s
  aci-containers-system                   aci-containers-openvswitch-slr8c                          0 (0%)        0 (0%)      128Mi (0%)       1Gi (6%)       5m14s
```

From the output you can see this configuration does not get applied on openvswitch container memory request and limit values


#### 4. Other ACI pod container specific non default memory request and limit

Add following configuration in the acc provision input file:

```yaml
kube_config:
    aci_containers_controller_memory_request: "256Mi"
    aci_containers_controller_memory_limit: "5Gi"
    aci_containers_host_memory_request: "256Mi"
    aci_containers_host_memory_limit: "5Gi"
    mcast_daemon_memory_request: "256Mi"
    mcast_daemon_memory_limit: "5Gi"
    opflex_agent_memory_request: "256Mi"
    opflex_agent_memory_limit: "5Gi"
    acc_provision_operator_memory_request: "256Mi"
    acc_provision_operator_memory_limit: "5Gi"
    aci_containers_operator_memory_request: "256Mi"
    aci_containers_operator_memory_limit: "5Gi"
```

Run `acc-provision` tool on updated acc provision input file, delete old aci_deployment.yaml and apply newly generated aci_deployment.yaml

Check container's memroy request and limit allocated
```sh
noiro@oshift3-ext-rtr:~$ oc describe node ocp413-worker1
Name:               ocp413-worker1
Roles:              worker
...
...
...
Non-terminated Pods:                      (22 in total)
  Namespace                               Name                                                      CPU Requests  CPU Limits  Memory Requests  Memory Limits  Age
  ---------                               ----                                                      ------------  ----------  ---------------  -------------  ---
  aci-containers-system                   aci-containers-controller-78c84fb6f4-gttgx                0 (0%)        0 (0%)      256Mi (1%)       5Gi (34%)      <invalid>
  aci-containers-system                   aci-containers-host-l7g4b                                 0 (0%)        0 (0%)      768Mi (5%)       15Gi (103%)    <invalid>
  aci-containers-system                   aci-containers-openvswitch-nj6gx                          0 (0%)        0 (0%)      128Mi (0%)       1Gi (6%)       <invalid>
```
