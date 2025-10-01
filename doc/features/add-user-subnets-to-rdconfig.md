# Add User Subnets To Rdconfig Feature

# Table of Contents

- [1. Overview](#1-overview)
- [2. Motivation](#2-motivation)
- [3. Mechanism](#3-mechanism)

## 1. Overview

This feature adds the user subnets to the RdConfig (Routing Domain Config), which excludes the traffic from these subnets from SNAT (Source Network Address Translation).

## 2. Motivation

Providing access to applications which are exposed outside via route requires traffic from them not to be SNATed. For instance, providing access to applications from pods inside of the cluster, through routers in Openshift or Ingress in Rancher, will not work if the traffic from the application pods is SNATed. In this case, SNAT should not be performed. 

This can be achieved by adding the user subnets used by these applications in the `routingdomain-config` RdConfig CR in `aci-containers-systems` namespace.

## 3. Mechanism

The Routing Domain CRD allows you to specify one or more subnets for which Source Network Address Translation (SNAT) should not be performed (when traffic originates from a pod in the cluster).

To manually exclude user subnets from SNAT, update the `usersubnets` section in the RdConfig.


```sh
kubectl edit rdconfig -n aci-containers-system routingdomain-config
```
Add the `usersubnets` section as shown in the example below:
```yaml
spec:
  discoveredsubnets:
  - 10.2.0.1/16
  - 192.168.1.1/24
  - 10.5.0.1/24
  usersubnets:
  - 15.0.0.0/16
  - 18.0.0.0/24
```

In this example, the subnets `15.0.0.0/16` and `18.0.0.0/24` represent external service ranges. Since they are listed under `usersubnets`, traffic to these networks will bypass SNAT.

The controller picks up this config and creates/updates the RdConfig with the `15.0.0.0/16` and `18.0.0.0/24` subnet values

Note: If you prefer external subnets to be added automatically to RdConfig instead of configuring them manually, refer to the [Add External Subnets to RdConfig Feature](./add-external-subnets-to-rdconfig.md).


