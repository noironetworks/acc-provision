# APIC refresh time and refresh ticker

# Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)  

    
## Overview

The aci-containers-controller pod subscribes for notifications on certain objects to the Cisco APIC. There is a timeout associated with this subscription. A shorter timeout requires more frequent subscription renewals. It can be configured in the acc-provision input file:

```yaml
aci_config:
  apic_refreshtime: <seconds>
```

To ensure the subscription renewal happens in time before the subscription timeout expires on the APIC side, the aci-containers-controller pod starts the renewal process a little earlier (default 150 Seconds). If the system is heavily loaded and you notice subscriptions are not renewed in time (this requires examining the aci-containers-controller and Nginx APIC logs), this period can be altered by adjusting the following configuration in the acc-provision input file:

```yaml
aci_config:
  apic_refreshticker_adjust: <seconds>
```


## Mechanism

Add following configuration in the acc provision input file:

```yaml
kube_config:
    apic_refreshtime: 1200
    apic_refreshticker_adjust: 150
```

`apic_refreshtime`: The number of seconds that APIC should wait before timing out a subscription on a websocket connection. If not explicitly set, then a default of 1800 seconds will be sent in websocket subscriptions. If it is set to 0, then a timeout will not be sent in websocket subscriptions, and APIC will use it's default timeout of 80 seconds. If set to a non-zero value, then the timeout value will be provided when we subscribe to a URL on APIC. NOTE: the subscription timeout is not supported by APIC versions before 3.2(3), so this

`apic_refreshticker_adjust`: How early (seconds) the subscriptions to be refreshed than actual subscription refresh-timeout. Defaulted to 150 Seconds.


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


Verify refresh timeout set from aci-containers-controller pod logs and aci-containers-config config map:

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
        "apic-refreshtime": "1200",
        "apic-refreshticker-adjust": "150",
...
...

noiro@oshift3-ext-rtr:~$ oc logs -n aci-containers-system aci-containers-controller-d994d58b9-4bntl | grep refresh
time="2024-02-23T09:47:19Z" level=info msg="APIC connection URL: https://10.30.120.180/api/mo/uni/tn-common/out-oshift3.json?subscription=yes&refresh-timeout=1200&query-target=subtree&rsp-subtree=full&target-subtree-class=fvRsCons&rsp-subtree-class=,tagAnnotation" mod=APICAPI

```
