# Add External Subnets To Rdconfig Feature

# Table of Contents

- [1. Overview](#1-overview)
- [2. Motivation](#2-motivation)
- [3. Mechanism](#3-mechanism)

## 1. Overview

This feature, if enabled, adds the subnets used for dynamic external IPs and static external IPs to the RdConfig (Routing Domain Config), which excludes the traffic from these subnets from SNAT (Source Network Address Translation).

## 2. Motivation

Providing access to applications which are exposed outside via route requires traffic from them to not be SNATed. For instance, providing access to applications from pods inside of the cluster, through routers in Openshift or Ingress in Rancher, will not work if the traffic from the application pods is SNATed. In this case, SNAT should not be performed. 

This can be achieved by adding the external service subnets used by these applications in an RdConfig CR. Setting `add_external_subnets_to_rdconfig` to true would add the `extern_dynamic` and `extern_static` subnets specified in the acc-provision input file to RdConfig without the user having to manually configure this.


## 3. Mechanism

The Routing Domain CRD allows you to specify one or more subnets for which Source Network Address Translation (SNAT) should not be performed (when traffic originates from a pod in the cluster). If `add_external_subnets_to_rdconfig` is set to true, the `extern_dynamic` and `extern_static` subnets, which are used for dynamic external IPs and static external IPs respectively, will be added as user subnets in the RdConfig CR (Custom Resource).

With `add_external_subnets_to_rdconfig` enabled, SNAT is not done on traffic from these two subnets, and communication with applications exposed with external service IPs function as expected as the traffic from these IPs are no longer SNATed.

The feature can be enabled by adding this config in the acc-provision input yaml file -

```yaml
kube_config:
  add_external_subnets_to_rdconfig: True
```

This will add a field: `"add-external-subnets-to-rdconfig": true` in the controller config in the aci-containers-config Config Map:

```sh
kubectl get config -n aci-containers-system aci-containers-config
```

```yaml
data:
controller-config: |-
 …
 "add-external-subnets-to-rdconfig": true
 …
```

The controller picks up this config and creates/updates the RdConfig with the `extern_dynamic` and `extern_static` subnet values:

```sh
kubectl get rdconfig -n aci-containers-system -o yaml
```

```yaml
apiVersion: v1
…
spec:
discoveredsubnets:
- 192.168.0.1/17
- 192.168.128.1/17

usersubnets:
- 10.16.129.192/28
- 10.16.129.208/28
```

where `10.16.129.192/28` and `10.16.129.208/28` represent the `extern_dynamic` and `extern_static` subnets.
