# Set port-group uplink to enhanced LAG when configured in nested VMware setups

# Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)  

## Overview

VMware vSphere DVS >= 6.6.0 requires enhanced LAG always and acc-provision tool doesn't set port-group uplink to enhanced LAG when configured in nested VMware setup.

When provisioning ACI K8S configuration using acc-provision in a nested VMware environment, if the DVS uplink policy is configured with enhanced LAG, there will be connectivity issue between the k8s nodes and ACI. This is due to acc-provision script not configuring the proper Teaming and Failover policies on the DVS port-group.

Workaround : manually configure the eLag policy on the port-group pushed by the APIC.
1. On vSphere, go to Networking -> {your DVS} -> {k8s port-group} 
2. Go to Configure -> Policies, click edit
3. Under "Teaming and Failover" move the eLag policy to the Active Uplink and lower the other Uplinks to the Inactive Uplink


## Mechanism

Add following configuration in the acc provision input file:
```sh
aci_config::
  vmm_domain:
    nested_inside
      elag_name: "fab-elag"  # elag name on APIC, this is required for ESXi vDS >= 6.6.0
```

Run `acc-provision` tool on updated acc provision input file

```sh
acc-provision -a -c <acc_provision_input_file> -f <flavor> -u <apic_username> -p <apic_password> -o aci_deployment.yaml
```

When `elag_name` is configured in acc provision input, now we are adding enhaced LAG policy to the Custom Trunk Port Group and also for vmm-vmware domain attachment under aci-containers-node EPG. This setting is set per port-group and consistently set for both Port-Groups.
Its recommended to set Load Balancing Mode for ELAG VSwitch Policy to `Source and Destination IP Address and TCP/UDP Port` in APIC.
