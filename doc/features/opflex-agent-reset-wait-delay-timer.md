# Opflex agent reset wait delay timer

# Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)  


## Overview

The opflex-agent trigger disconnect to leaf either when reset.conf is updated by host-agent or when opflex-agent receives PlatformConfig delete notification. If reset.conf comes within 5s after PlatformConfig delete, opflex-agent do not trigger disconnect twice. We can increase the time of delay using this parameter.


## Mechanism

Add following configuration in the acc provision input file:
```yaml
kube_config:
  opflex_agent_reset_wait_delay: 60  # default is 30 seconds
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

Verify timer is changed aci-containers-config config map:

```sh
noiro@oshift3-ext-rtr:~$ oc get cm -n aci-containers-system aci-containers-config -oyaml | less
apiVersion: v1
data:
  ...
  ...
  opflex-agent-config: |-
    {
        "log": {
            "level": "debug"
        },
        "opflex": {
            "notif" : { "enabled" : "false" },
            "asyncjson": { "enabled" : "false" }
            ,"timers" : { "reset-wait-delay" : 60 }
        },
        "ovs": {
            "asyncjson": { "enabled" : "false" }
        },
        "prometheus": {
            "enabled": "false"
        }
    }
```
