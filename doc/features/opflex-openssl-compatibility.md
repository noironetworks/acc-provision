# Opflex agent openssl compatibility

# Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)  
    

## Overview

The opflex-agent builds with the latest version of openssl (3.x) which causes compatibility issues when FIPS is enabled on the host running opflex-agent. This happens because the leaf filters out the ciphers needed for openssl 3.x to work properly. Until this is fixed on the leaf side the workaround is to run opflex-agent in openssl 1.1 compatibility mode so the connectivity to leaf is not broken when FIPS is enabled on the host running opflex-agent.

## Mechanism

Add following configuration in the acc provision input file:
```sh
kube_config:
    opflex_openssl_compat: true # default is false
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

Enabling this features internally sets environment variable `OPENSSL_CONF=/etc/pki/tls/openssl11.cnf` in opflex-agent

```sh
noiro@oshift3-ext-rtr:~$ oc exec -it -n aci-containers-system aci-containers-host-2kg44 -c opflex-agent -- env
...
...
OPENSSL_CONF=/etc/pki/tls/openssl11.cnf
```
