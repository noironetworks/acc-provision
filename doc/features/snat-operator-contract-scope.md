# SNAT service graph contract scope

# Table of contents
* [Overview](#overview)
* [Mechanism](#mechanism)
    

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
Run `acc-provision` tool to generate new aci_deployment.yaml
```sh
acc-provision --upgrade -c <acc_provision_input_file> -f <flavor> -u <apic_username> -p <apic_password> -o aci_deployment.yaml
```

Apply newly generated aci_deployment.yaml and restart controller pod.
```sh
$ kubectl apply -f aci_deployment.yaml
$ kubectl delete po <controller_pod> -n aci-containers-system
```

Verify contract scope set in aci-containers-config config map:

```sh
noiro@rke-rketest135-ext-rtr:~$ kubectl get cm -n aci-containers-system aci-containers-config -oyaml | grep snat-contract-scope
        "snat-contract-scope": "tenant",
```
