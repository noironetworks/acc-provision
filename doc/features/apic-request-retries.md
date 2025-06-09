# Enable retries for APIC requests on failure

# Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)  

    
## Overview

This feature introduces 2 configuration parameters to enable retries for APIC requests when a 503 Service Unavailable error is encountered.

1. `enable_apic_request_retry_delay` to control retry behavior.
  Default: True (enabled). To disable retries, set "enable_apic_request_retry_delay: False" in the acc provision input file.

2. `apic_request_retry_delay` to configure the delay between retry attempts in minutes.
  Default: 2 (minutes). To change the delay, set "apic_request_retry_delay: <required_value>" in the input file.
  This request retry delay is applicable only when `enable_apic_request_retry_delay` is enabled.


## Mechanism

Add following configuration in the acc provision input file:

```yaml
kube_config:
  enable_apic_request_retry_delay: True
  apic_request_retry_delay: 5 # Sets the retry delay to 5 minutes
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


Verify configuration in aci-containers-config config map:

```sh
noiro@oshift3-ext-rtr:~$ oc get cm -n aci-containers-system aci-containers-config -oyaml | less
apiVersion: v1
data:
  controller-config: |-
    {
        "flavor": "openshift-4.13-esx",
        "log-level": "debug",
        "apic-hosts": [
            "10.30.120.180"
        ],
        "apic-request-retry-delay": 5,
        "enable-apic-request-retry-delay": true
```
