# Pre-existing Tenant Feature

# Table of Contents

- [1. Overview](#1-overview)
- [2. Motivation](#2-motivation)
- [3. Mechanism](#3-mechanism)
- [4. Lifecycle](#4-lifecycle)
- [5. Example](#5-example)

## 1. Overview

This feature is introduced to enable adding a Kubernetes cluster to a pre-existing tenant like for example the common tenant or any other user created ones on APIC. The APIC objects provisioned for different clusters should be uniquely named and distinguishable. When deleting a cluster, the objects created by other clusters won't be affected.

## 2. Motivation

By enabling the pre-existing tenant feature it is possible to provision the Kubernetes cluster under a given tenant. This overrides the default behaviour where a tenant is created with the same name as the cluster. This includes creating application profile, EPGs, BDs and required contracts under the existing tenant. If this tenant isn’t already manually created on the APIC, acc-provision will create it during provisioning, but will not delete it in the un-provision step if it's pre-existing. Only the objects created during provisioning for this cluster will be deleted. The only case the tenant gets deleted is when it was created by acc-provision.

## 3. Mechanism

acc-provision support 2 mode of handling tenant:
1. It can create a dedicated tenant for the cluster
2. A shared/pre-existing tenant when the tenant name is specified

Depending on the mode the following behaviours are expected when the config is de-provisioned by using the `-d` option -

1. The whole tenant is deleted
2. Only the config added by acc-provision is deleted

In case 1 scenario, if the "tenant name" is not specified in the acc provision input file the whole tenant should be deleted as everything is handled by acc-provision.

In case 2 scenario, when it's pre-existing-tenant i.e when the tenant name is specified in the acc provision input file in aci_config section, the manually created tenant on the APIC before provisioning is not being deleted when unprovisioning i.e -d option but only the config added by provisioning i.e -a is deleted. Any additional config that are not managed directly by acc-provision are not deleted.

## 4. Lifecycle

A Kubernetes cluster can be provisioned under a tenant by adding this config in the input yaml file -

```yaml
aci_config:
  tenant:
    name: pre_existing_tenant
```

acc-provision will create this tenant if not present but will never delete this tenant. Additionally, this instructs acc-provision to create application profile, EPGs, BDs and required contracts under the existing tenant. The “system_id” field provided in the acc-provision input file is used to construct names of these APIC objects. For example, application profile for the cluster with ID “cluster1” will be called “aci-containers-cluster1” and contract for DNS will be called “aci-containers-cluster1-dns”. This naming convention change is for all kinds of clusters provisioned by acc-provision, not just pre-existing tenant ones. Aci-prefix is only tied to systemid but not to a tenant. If a null or blank value is provided in the tenant name field, its value will default to the system_id provided in the input config file. To summarize - if tenant is manually created on the APIC before provisioning have tenant name in acc provision input file under aci_config section.


## 5. Example

You can create new Tenant or use pre-existing one:
```yaml
aci_config:
  system_id: test    # Unique cluster name, if the Tenant is not specified this is also the tenant name
  tenant:
    name: pre_existing_tenant    # Add pre_existing_tenant name if it's manually created on the APIC
```

The annotation - orchestrator:aci-containers-controller is being added to the tenant (disk badge on the tenant is visible on the APIC) when we do acc-provision -a in both the scenarios but handling of acc-provision -d is different as explained above in mechanism.

When selecting the tenant and system ID name keep in mind that if your nodes are deployed as VMs on VMware the maximum port-group name is 80 characters and will be composed by the concatenation of - Tenant + App Profile + EPG Name.

One can use this pre-existing-tenant feature depending on the use case.