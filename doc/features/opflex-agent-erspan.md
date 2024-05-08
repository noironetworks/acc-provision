
# OpFlex support for ERSPAN with OVS

## Table of contents

- [Overview ](#overview)
- [Benefits of OpFlex support for ERSPAN with OVS](#benefits-of-opflex-support-for-erspan-with-ovs)
- [OpFlex support for ERSPAN with OVS Limitations and Restrictions](#opflex-support-for-erspan-with-ovs-limitations-and-restrictions)
- [Prerequisites](#prerequisites)
- [OpFlex support for ERSPAN with OVS Configuration Workflow](#opflex-support-for-erspan-with-ovs-configuration-workflow)
- [Configuring the OpFlex support for ERSPAN with OVS on OpenStack setups](#configuring-the-opflex-support-for-erspan-with-ovs-on-openstack-setups)
- [Configuring OpFlex Support for ERSPAN with OVS on Kubernetes Setups](#configuring-opflex-support-for-erspan-with-ovs-on-kubernetes-setups)
- [Verify the OpFlex support for ERSPAN with OVS](#verify-the-opflex-support-for-erspan-with-ovs)


## Overview
The OpFlex support for ERSPAN with OVS feature extends the basic port mirroring capability from Layer 2 to Layer 3 which allows the mirrored traffic to be sent through a routable IP network from specific interfaces.


## Benefits of OpFlex support for ERSPAN with OVS
The OpFlex support for ERSPAN with OVS provides several benefits:
- The ability to get mirrored traffic directly from specific interfaces providing visibility of local traffic.
- Debugging network issues by tracking the control and data frames and security analysis.


## OpFlex support for ERSPAN with OVS Limitations and Restrictions
Be aware of the following issues when configuring OpFlex support for ERSPAN with OVS:
- Red Hat Enterprise Linux 7 (RHEL7) is not supported.


## Prerequisites
You must complete the following tasks before you configure OpFlex support for ERSPAN with OVS on OpenStack/Kubernetes setups:
- ERSPAN leverages support added to Open vSwitch (OVS). ERSPAN sessions are initialized on ports connected to a switch in OVS. In order to support ERSPAN, the hosts running OVS must meet the following requirements:
    - Linux kernel version 4.18 or later
    - OVS version 2.10 or later

    **&#9432; Note**
    > Red Hat Enterprise Linux 7 (RHEL7) does not meet these requirements, but Red Hat Enterprise Linux 8 (RHEL8) or later does.

- You must have OS RHEL8 or later installed.
- The host where OpenStack CLI commands are run must also have the Group Based Policy (GBP) python client library installed.
- You must have basic working knowledge of an OpenStack environment.
- (applicable only for ERSPAN with OVS on Kubernetes setups) You must have Ubuntu 20 installed.


## OpFlex support for ERSPAN with OVS Configuration Workflow
This section describes a high-level overview of the tasks you perform to configure OpFlex support for ERSPAN with OVS:

**Procedure**
1. Get the neutron port that is used to create the ERSPAN source. The MAC address of this port will be the source of the configuration.
For more information, see [Configuring the OpFlex support for ERSPAN with OVS on OpenStack setups.](#configuring-the-opflex-support-for-erspan-with-ovs-on-openstack-setups)

2. Run the OpenStack CLI commands described in the next section to configure erspan source and destination sessions.
For more information, see [Configuring the OpFlex support for ERSPAN with OVS on OpenStack setups.](#configuring-the-opflex-support-for-erspan-with-ovs-on-openstack-setups)

3. Verify the configuration.
For more information, see [Verify the OpFlex support for ERSPAN with OVS.](#verify-the-opflex-support-for-erspan-with-ovs)


## Configuring the OpFlex support for ERSPAN with OVS on OpenStack setups

**Procedure**

1. Configuring ERSPAN sessions.

    ERSPAN sessions are configured using the --apic-erspan-config option in the OpenStack python client/CLI. This option is supported both when creating and updating a port in OpenStack.

    ```sh
    openstack port create --apic-erspan-config <apic_erspan_config> --network <network> <name>
    openstack port set --apic-erspan-config <apic_erspan_config> <port>
    ```

    The <apic_erspan_config> field consists of the following comma-separated parameters:
    - 'dest-ip': the ERSPAN destination IP address
    - 'flow-id': the flow ID to use for the session (1-1023)
    - 'direction': 'in', 'out', or 'both' (port-centric)

    The dest-ip and flow-id fields are mandatory, while the direction is optional (default value is "both"). The OpenStack port UUID plus direction define a unique ERSPAN source, while the destination IP and flow ID define a unique ERSPAN destination. ERSPAN sessions can only be active when the port is bound to an opflex type segment. This means that hierarchical port binding (HPB) and 'vlan' type segments are not supported, nor are SVI networks. Ports must also have a vnic_type of "normal", and have a device_owner prefix of "compute:". Multiple ERSPAN sessions can be applied to a single OpenStack port, simply by adding additional --apic-erspan-config options.

2. Verifying ERSPAN configuration in OpenStack.

    The status of the ERSPAN session can be examined through the `apic:synchronization_state` property of the port. Run the following command to see the state:

    `openstack port show UUID or name-of-port`


    The aggregate state of the ERSPAN configuration is reflected in the port's `apic_synchronization_state`. This field can have the following values:

    - `N/A`:
        Either:
        - The state has not yet been synced with ACI; or
        - There either is no ERSPAN state, or the port is not bound

    - `build`: ERSPAN state is being synchronized with ACI

    - `error`: ERSPAN state could not be synchronized with ACI

    - `synced`: All ERSPAN state is synchronized with ACI. ERSPAN sessions should now be active

    ERSPAN traffic is sent from the local vSwitch to the host and the host's IP stack forwards the encapsulated packet. ERSPAN sessions may experience some drop-out when live-migrating the ports with ERSPAN configuration, due to port rebinding.

3. Verifying ERSPAN configuration in Open vSwitch.

    You can confirm the ERSPAN sessions on host vSwitches using the "ovs-vsctl show" command:

    ```sh
    [root@overcloud-novacompute-0 heat-admin] ovs-vsctl show
    021cf127-1978-4096-9897-a5d0e0b20b23
        Manager "ptcp:6640:127.0.0.1"
            is_connected: true
    ....
        Bridge br-int
            fail_mode: secure
            Port "172.28.184.58-2"
                Interface "172.28.184.58-2"
                    type: erspan
                    options: {erspan_dir="1", erspan_hwid="4", erspan_ver="2", key="2", remote_ip="172.28.184.58"}
            Port "172.28.184.58-3"
                Interface "172.28.184.58-3"
    ```

4. Removing ERSPAN configuration in OpenStack.

    When the port is unbound, the ERSPAN session is terminated. However, the ERSPAN configuration is still present in the port, and if the port is bound again, then the ERSPAN session will be resumed. The ERSPAN configuration state can only be removed explicitly or when the port is deleted. To remove all the ERSPAN configuration from the port, enter the following command:

    `openstack port set --no-apic-erspan-config <port>`

    **&#9432; Note**
    > There is a known issue, which prevents ERSPAN state from being cleaned up on the vSwitch. The workaround is to manually remove ERSPAN ports from the vSwitch:

    Example:

    `sudo ovs-vsctl del-port br-int 172.28.184.58-2`


## Configuring OpFlex Support for ERSPAN with OVS on Kubernetes Setups

This section describes how to configure the OpFlex support for ERSPAN with OVS on Kubernetes setups.

**Procedure**

1. Enable ERSPAN feature

    Add following configuration in the acc provision input file:
    ```sh
    nodepodif_config::
        enable: True     # default is False, set to True to enable ERSPAN feature
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

2. Verify if the Custom Resources Definition (CRD) is available:

    ```sh
    $ kubectl get crd
    $ kubectl describe crd erspanpolicies.aci.erspan
    ```

3. Apply the CRD yaml file with valid inputs; using the `kubectl apply -f <yaml_file>` command. A sample CRD yaml file is shown below:

    ```yaml
    apiVersion: aci.erspan/v1alpha
    kind: ErspanPolicy
    metadata:
      name: erspan-policy
      namespace: default
    spec:
      selector:
        labels:
          app: consul
        namespace: default
      source:
        adminState: "start"
        direction: "both"
      destination:
        destIP: "1.1.1.1"
        flowID: 1
    ```

## Verify the OpFlex support for ERSPAN with OVS

This section describes how to verify the OpFlex support for ERSPAN with OVS on OpenStack setups.

**Procedure**

1. Log in to the Cisco APIC GUI, on the menu bar, choose **Fabric > Access Policies.**

2. You need to verify the successful creation of ERSPAN Source. In the Navigation pane, choose **Policies > Troubleshooting > VSPAN > VSPAN Sessions** and click on a **VSPAN session**.

3. You need to verify the successful creation of ERSPAN Destination. In the Navigation pane, choose **Policies > Troubleshooting > VSPAN > VSPAN Destination Groups** and click on a **VSPAN Destination Group**.

4. You need to verify the successful binding of ERSPAN session with VPCs. In the Navigation pane, choose **Interfaces > Leaf Interfaces > Policy Groups > VPC Interface** and click on the **VPC interface policy group**.

5. Inside the opflex_agent container, enter the following command:

    `gbp_inspect -prq SpanSession`

6. On the compute nodes, check for the mirror, enter the following command:

    `ovs-vsctl list mirror`
