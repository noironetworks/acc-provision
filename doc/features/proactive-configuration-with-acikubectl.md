
# Proactive Configuration with acikubectl
- [Overview](#overview)
- [Commands](#command)
- [Examples](#examples)

# Overview
Kubernetes integrations supported by this solution can be run on OpenStack or vSphere managed Virtual Machines (VM). These VMs are often live migrated between hosts during upgrades or during other operational workflows. For the VM moves to converge faster, you can proactively trigger the download of fabric policy on the relevant ACI switches and ports using a variation of the acikubectl command. This works by indentifying all the EPGs used in the given cluster, and then updates the VMM association's "Deploy immediacy" to "Immediate", and "Resolution immediacy" to "Pre-provision". The recommendation is to use this tool during a designated maintenance window during which the VM moves are planned.

There are scale aspects to be considered before using this tool, notably, the (ports x VLANs) per leaf should not exceed 64,000 (refer to the ACI scale guide). Each EPG in usage corresponds to a VLAN, and this tool will deploy all EPGs for the given K8s cluster on all the leaf ports where the Kubernetes nodes are connected. If the number of EPGs in a given cluster is large, it will add to the prevailing count of EPGs deployed on each of those ports and thus push the count closer to the limit. The configuration introduced by the tool is per cluster, and can be reversed at the end of the VM move window, at which point any additional impact on the scale will gradually get reversed closer to the state prior to using the tool.

acikubectl requires access to the kubeconfig for a given cluster. In addition, this tool also requires access to the certificate and key pair that acc-provision generates to talk to communicate with the APIC. Just like acc-provision, this tool will look for the certificate and key pair in the location from where acikubectl is invoked.

The workflow is as follows:

1. Prior to starting the VM moves for the nodes of a given Kubernetes cluster, run the following command:

```
./acikubectl proactive_policy create
```
2. You can optionally check if the relevant policy has been deployed.

```
./acikubectl proactive_policy verify
```
3. After all the VM moves are completed, revert the proactive policy configuration:

```
./acikubectl proactive_policy delete
```

# Command
```
acikubectl proactive_policy --help
Do override configuration like changing vmm epg attachment mode

Usage:
acikubectl proactive_policy create/delete/verify [flags]

Examples:
proactive_policy create/delete

Flags:
-a, --apic-hosts strings          APIC Hosts
-p, --apic-passwd string          APIC password
-u, --apic-user string            APIC username
-h, --help                        help for proactive_policy
-e, --vmm-epg-attachment string   Enable immediate/on-demand deployment and resolution immediacy on vmm-epg-attachment (default "immediate")

Global Flags:
--context string      Kubernetes context to use for CLI requests.
--kubeconfig string   Path to the kubeconfig file to use for CLI requests. (default "/home/noiro/kubeconfig")
```

# Examples
If the kubconfig is not present in the default location, it can be explicilty specified using the --kubeconfig argument.

If the acc-provision created certificate and key pair is not available in working directory, the username and password to access the APIC can be explicitly provided using the -u and -p arguments. The APIC user needs to have admin level access to the cluster's tenant.

## Create Proactive Policy

### Immediate
#### Command
```acikubectl proactive_policy create```
#### Output
```
[{"fvRsDomAtt":{"attributes":{"dn":"uni/tn-ocp412/ap-aci-containers-ocp412/epg-aci-containers-default/rsdomAtt-[uni/vmmp-OpenShift/dom-ocp412]","instrImedcy":"immediate","resImedcy":"pre-provision","tDn":"uni/vmmp-OpenShift/dom-ocp412"}}}]
applied!
```

### On-Demand
#### Command:
```acikubectl proactive_policy create -e on-demand```
#### Output:
```
[{"fvRsDomAtt":{"attributes":{"dn":"uni/tn-ocp412/ap-aci-containers-ocp412/epg-aci-containers-default/rsdomAtt-[uni/vmmp-OpenShift/dom-ocp412]","instrImedcy":"lazy","resImedcy":"lazy","tDn":"uni/vmmp-OpenShift/dom-ocp412"}}}]
applied!
```

## Verify policy has been deployed
### Command
```
acikubectl proactive_policy verify
 ```

### Output
```
Found pv attachment(topology/pod-2/protpaths-401-402/pathep-[esx-3-HX_vC-vpc],node-401,uni/tn-ocp412/ap-aci-containers-mpod4/epg-aci-containers-default)
Found pv attachment(topology/pod-2/protpaths-401-402/pathep-[esx-3-HX_vC-vpc],node-402,uni/tn-ocp412/ap-aci-containers-mpod4/epg-aci-containers-default)
VERIFY SUCCESS!
```
## Delete proactive policy
### Command
    ```
    acikubectl proactive_policy delete
    ```
### Output
    ```
    [{"fvRsDomAtt":{"attributes":{"dn":"uni/tn-ocp412/ap-aci-containers-ocp412/epg-aci-containers-default/rsdomAtt-[uni/vmmp-OpenShift/dom-ocp412]","instrImedcy":"lazy","resImedcy":"lazy","tDn":"uni/vmmp-OpenShift/dom-ocp412"}}}]
    applied!
    ```

## With username/password
* ```acikubectl proactive_policy create  -e immediate -u <username> -p <password>```
* ```acikubectl proactive_policy create  -e on-demand -u <username> -p <password>```
* ``` acikubectl proactive_policy delete -u <username> -p <password>```
* ```acikubectl proactive_policy verify -u <username> -p <password>```
* ```acikubectl proactive_policy delete -u <username> -p <password>```
