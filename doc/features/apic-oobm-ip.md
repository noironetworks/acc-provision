# ACI day-zero provision using APIC Out Of Band management(oobm) IP

# Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)  

    
## Overview

Out-band managent IP of APICs can be used to perform day-zero provision ACI fabric and in-band management IP for aci controller pod to talk to APIC. If there are multiple APICs in aci input file, the first APIC is always taken by aci controller pod to establish websocket connection.

A new command line parameter `--apic-oobm-ip <ip>` is introduced to use APIC oobm IP to perform day-zero provision ACI fabric.


## Mechanism

When `--apic-oobm-ip <ip>` is passed as an argument to acc provision tool, this IP is used to perform day-zero provision ACI fabric. Acc provision tool will ignore IPs configured in acc provision input file under `aci_config -> apic_hosts: []` for provisioning ACI fabric


Run `acc-provision` tool with acc provision input file and `--apic-oobm-ip <ip>`
```sh
acc-provision -a -c <acc_provision_input_file> -f <flavor> -u <apic_username> -p <apic_password> -o aci_deployment.yaml --apic-oobm-ip <ip>
```
