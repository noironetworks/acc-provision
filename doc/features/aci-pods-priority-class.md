# Use system node critical priority class for ACI pods

# Table of contents
* [Overview](#overview)
* [Motivation](#motivation)
* [Mechanism](#mechanism)  
* [Examples](#examples)
    

## Overview

1. Pods can have priority. Priority indicates the importance of a Pod relative to other Pods. If a Pod cannot be scheduled, the scheduler tries to preempt (evict) lower priority Pods to make scheduling of the pending Pod possible.

2. How to use priority and preemption
    - Add one or more `PriorityClasses`
    - Create Pods with `priorityClassName` set to one of the added PriorityClasses.
    - The higher the value of the priority class, the higher the priority.
    - A PriorityClass object can have any 32-bit integer value smaller than or equal to 1 billion
    - Larger numbers are reserved for critical system Pods that should not normally be preempted or evicted.

3. acc-provision tool creates PriorityClass `acicni-priority`

    ```sh
    noiro@oshift3-ext-rtr:~$ oc get priorityclass acicni-priority -oyaml
    apiVersion: scheduling.k8s.io/v1
    description: This priority class is used for ACI-CNI resources
    kind: PriorityClass
    metadata:
      annotations:
        kubectl.kubernetes.io/last-applied-configuration: |
          {"apiVersion":"scheduling.k8s.io/v1","description":"This priority class is used for ACI-CNI resources","globalDefault":false,"kind":"PriorityClass","metadata":{"annotations":{},"name":"acicni-priority"},"value":1000000000}
      creationTimestamp: "2024-02-20T06:27:44Z"
      generation: 1
      name: acicni-priority
      resourceVersion: "13806438"
      uid: 1189f6bd-103d-4f7f-aae7-5b5c864f138d
    preemptionPolicy: PreemptLowerPriority
    value: 1000000000
    ``` 

4. Kubernetes already ships with two PriorityClasses: `system-cluster-critical` and `system-node-critical`. These are common classes and are used to ensure that critical components are always scheduled first.


**Here we are introducing an option in acc provision input file to assign `system-node-critical` priorityClass to ACI Pods.**


## Motivation

Guaranteed Scheduling For Critical ACI Pods

ACI Pods are critical to a fully functional cluster. A cluster may stop working properly if a critical aci pod is evicted (either manually or as a side effect of another operation like upgrade) and becomes pending (for example when the cluster is highly utilized and either there are other pending pods that schedule into the space vacated by the evicted critical aci pod or the amount of resources available on the node changed for some other reason).

Assigning `acicni-priority` to aci pods does not gurantee pod availability but assigning priorityClass `system-node-critical` to aci pods will make sure aci pods are always scheduled first even after eviction.
> Note that marking a pod as critical is not meant to prevent evictions entirely; it only prevents the pod from becoming permanently unavailable


## Mechanism

Flag `use_system_node_priority_class` flag is introduced in acc provision input file.
```yaml
kube_config:
    use_system_node_priority_class: True
```

When user configures this flag and run acc-provision tool, it will generate aci pod containers manifests with `spec.priority` set to `2000001000` and `spec.priorityClassName` set to `system-node-critical`


## Examples

1. Add following configuration in the acc provision input file:
    ```yaml
    kube_config:
        use_system_node_priority_class: True
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

    Check priority class value and name set on all the aci pods

    ```sh
    noiro@oshift3-ext-rtr:~$ oc get pods -n aci-containers-system -o custom-columns="POD NAME":.metadata.name,"PRIORITY CLASS NAME":.spec.priorityClassName,"PRIORITY CLASS VALUE":.spec.priority

    POD NAME                                    PRIORITY CLASS NAME    PRIORITY CLASS VALUE
    aci-containers-controller-d78cd4d45-ctrzs   system-node-critical   2000001000
    aci-containers-host-4nmxx                   system-node-critical   2000001000
    aci-containers-host-84gxp                   system-node-critical   2000001000
    aci-containers-host-vhhft                   system-node-critical   2000001000
    aci-containers-host-xl8p8                   system-node-critical   2000001000
    aci-containers-host-zf4dj                   system-node-critical   2000001000
    aci-containers-openvswitch-29sw5            system-node-critical   2000001000
    aci-containers-openvswitch-6z68l            system-node-critical   2000001000
    aci-containers-openvswitch-8qnlw            system-node-critical   2000001000
    aci-containers-openvswitch-lcltp            system-node-critical   2000001000
    aci-containers-openvswitch-s6wks            system-node-critical   2000001000
    ```

2. Openshift Container Platform default priority class

    For OCP platform if `use_system_node_priority_class` is not configured in acc provision input file then automatically priorityClass `acicni-priority` is used 

    ```sh
    noiro@oshift3-ext-rtr:~$ oc get pods -n aci-containers-system -o custom-columns="POD NAME":.metadata.name,"PRIORITY CLASS NAME":.spec.priorityClassName,"PRIORITY CLASS VALUE":.spec.priority

    POD NAME                                    PRIORITY CLASS NAME   PRIORITY CLASS VALUE
    aci-containers-controller-d994d58b9-dqnqg   acicni-priority       1000000000
    aci-containers-host-mx5bh                   acicni-priority       1000000000
    aci-containers-host-px526                   acicni-priority       1000000000
    aci-containers-host-sbcjk                   acicni-priority       1000000000
    aci-containers-host-v6mrd                   acicni-priority       1000000000
    aci-containers-host-xr9tv                   acicni-priority       1000000000
    aci-containers-openvswitch-jssgm            acicni-priority       1000000000
    aci-containers-openvswitch-lfbff            acicni-priority       1000000000
    aci-containers-openvswitch-m84qn            acicni-priority       1000000000
    aci-containers-openvswitch-qp9ft            acicni-priority       1000000000
    aci-containers-openvswitch-vkdqv            acicni-priority       1000000000
    ```

3. Kubernetes platform default priority class

    For Kubernetes platform if `use_system_node_priority_class` is not configured in acc provision input file then automatically priorityClass
    - `system-node-critical` is used for aci-containers-controller pod and
    - `system-cluster-critical` is used for other aci pods


    ```sh
    noiro@k8s13-ext-rtr:~$ kubectl get pods -n aci-containers-system -o custom-columns="POD NAME":.metadata.name,"PRIORITY CLASS NAME":.spec.priorityClassName,"PRIORITY CLASS VALUE":.spec.priority

    POD NAME                                     PRIORITY CLASS NAME       PRIORITY CLASS VALUE
    aci-containers-controller-54496bc7fb-6rgl9   system-node-critical      2000001000
    aci-containers-host-j82qt                    system-cluster-critical   2000000000
    aci-containers-host-p5gxp                    system-cluster-critical   2000000000
    aci-containers-host-vxsng                    system-cluster-critical   2000000000
    aci-containers-openvswitch-ht7km             system-cluster-critical   2000000000
    aci-containers-openvswitch-pb8td             system-cluster-critical   2000000000
    aci-containers-openvswitch-skpj8             system-cluster-critical   2000000000
    ```
