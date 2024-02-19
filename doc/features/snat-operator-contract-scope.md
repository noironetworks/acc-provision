# SNAT service graph contract scope

# Table of contents
* [Overview](#overview)
* [Mechanism](#mechanism)  
* [Examples](#examples)
    

## Overview

The scope of the SNAT service graph contract can be configured in acc provision input file as follows:
```yaml
kube_config:
  snat_operator:
    contract_scope: <scope-name>
```
Valid values (as allowed by Cisco APIC) are "global", "tenant" and "context", if not specified default is set to "global"

## Mechanism

Add following configuration in the acc provision input file:
```yaml
kube_config:
  snat_operator:
    contract_scope: tenant
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

Verify conrtact scop set in aci-containers-config config map:

```sh
noiro@oshift3-ext-rtr:~$ oc get cm -n aci-containers-system aci-containers-config -oyaml | grep snat-contract-scope
        "snat-contract-scope": "tenant",
```

## Examples
