# Exclude acc provision operator

## Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)

## Overview

The aci-containers-operator deployment contains an acc-provision-operator container. The container is not essential for the functioning of ACI CNI and is provided as an experimental feature for ease of configuration. This feature enables to exclude acc-provision-operator from the deployment.


## Mechanism

Add following configuration in the acc provision input file:

```yaml
acc_provision_operator:
  exclude: true # default is false
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

Verify acc-provision-operator container is excluded:

```sh
$ kubectl get pods -n aci-containers-system
NAME                                        READY   STATUS    RESTARTS   AGE
aci-containers-controller-6496488b7-k94ks   1/1     Running   0          10m
aci-containers-host-8swb2                   3/3     Running   0          10m
aci-containers-host-lmf85                   3/3     Running   0          10m
aci-containers-host-zjd98                   3/3     Running   0          10m
aci-containers-openvswitch-6htdj            1/1     Running   1          10m
aci-containers-openvswitch-9dxkn            1/1     Running   0          10m
aci-containers-openvswitch-q8szw            1/1     Running   0          10m
aci-containers-operator-7598f786fc-db9tl    1/1     Running   0          10m
```


