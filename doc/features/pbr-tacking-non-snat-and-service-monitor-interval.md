# PBR tracking for non snat, service monitor interval

# Table of contents
* [Overview](#overview)
* [Mechanism](#mechanism)  
* [Examples](#examples)
    

## Overview

1. Policy Based Routing (PBR) tracking can be enabled for the Cisco APIC service graph created for supporting  SNAT feature. One HealthGroup for each node is created, and it is associated with the redirect policy of the SNAT service graph with the internet protocol service level agreement (IPSLA) interval set to 5 seconds. This interval is configurable through the acc provision input file

    ```yaml
    net_config:
      service_monitor_interval: 10 # default is 5 seconds
    ```

    If the service_monitor_interval is set to zero, PBR tracking is disabled.

2. PBR tracking can be also be enabled for other Cisco APIC service graphs created for each Kubernetes external service, setting the following configuration in the acc-provision input file:

    ```yaml
    net_config:
      pbr_tracking_non_snat: true  # 
    ```
    If enabled, `service_monitoring_interval` described earlier applies here as well.


## Mechanism

Add following configuration in the acc provision input file:
```yaml
net_config:
  service_monitor_interval: 10
  pbr_tracking_non_snat: true
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

Verify flags set in aci-containers-config config map:

```sh
noiro@oshift3-ext-rtr:~$ oc get cm -n aci-containers-system aci-containers-config -oyaml | less
apiVersion: v1
data:
  controller-config: |-
    {
        "flavor": "openshift-4.13-esx",
        "apic-hosts": [
            "10.30.120.180"
        ],
        "aci-service-monitor-interval": 5,
        "aci-pbr-tracking-non-snat": true,
        ...
        ...
```

## Examples



