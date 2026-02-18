# SNAT operator port range configuration

# Table of contents
* [Overview](#overview)
* [Mechanism](#mechanism)

## Overview

The SNAT port range and per-node port allocation can be configured in the acc provision input file as follows:
```yaml
kube_config:
  snat_operator:
    port_range:
      start: <start-port>
      end: <end-port>
      ports_per_node: <count>
```
Default values:
- start: 5000
- end: 65000
- ports_per_node: 3000

The max number of nodes in the service graph can be configured using:
```yaml
kube_config:
  max_nodes_svc_graph: <value>
```
Max number supported is 64 and default value is 32.

For configuring the SNAT service graph contract scope, refer to [snat-operator-contract-scope.md](snat-operator-contract-scope.md).

## Mechanism

The SNAT port range can be configured in the acc provision input file:
```yaml
kube_config:
  snat_operator:
    port_range:
      start: 50000
      end: 59999
      ports_per_node: 1000
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

Verify port range set in snat-operator-config config map:

```sh
$ kubectl get cm -n aci-containers-system snat-operator-config -oyaml
apiVersion: v1
data:
  end: "59999"
  ports-per-node: "1000"
  start: "50000"
kind: ConfigMap
```
