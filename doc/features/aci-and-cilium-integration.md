# Cilium-1.15.x Integration with ACI-CNI

- [Overview](#overview)
- [Installation](#installation)
    * [Assumptions](#assumptions)
    * [Prerequisites](#prerequisites)
- [Kubernetes](#kubernetes)
- [OpenShift](#openshift)
- [Hubble](#hubble)
    * [Hubble API Access](#hubble-api-access)
    * [Hubble GUI Access](#hubble-gui-access)
- [Validation](#validation)
- [Troubleshooting](#troubleshooting)
- [Appendix](#appendix)
- [References](#references)
  




## Overview
In this guide, we'll demonstrate how to integrate Cilium with ACI-CNI using CNI-chaining on both Kubernetes and OpenShift platforms. The aim is to delegate network policy enforcement to Cilium, thereby offloading this enforcement from ACI CNI.



<div style="display: flex; flex-direction: column; align-items: center;">
    <div style="display: flex; justify-content: center;">
        <img src="images/aci-and-cilium-integration/1.png" alt="Figure 1" style="max-width: 100%; max-height: 100vh;">
    </div>
    <p style="text-align: center;">Architecture</p>
</div>



## Installation

### Assumptions
The steps are executed as post-installation procedures once the cluster is operational with ACI CNI. While it's possible to generate the CNI chaining manifests before installation, here Cilium is installed as a post-installation step.

### Prerequisites

- Install Cilium CLI for Linux distribution: [Cilium Getting Started](https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/)
- Install Hubble CLI for Linux distribution: [Hubble Setup](https://docs.cilium.io/en/stable/gettingstarted/hubble_setup/)

## Kubernetes
**Install Accprovision**
```sh
git clone https://github.com/noironetworks/acc-provision.git
cd acc-provision/provision/
python3 setup.py install
```

**Configuration**

Add the following configuration to acc_provision_input.yaml file:

```
# Configuration for ACI Fabric
kube_config
  disable_hpp_rendering: True

cilium_chaining:
  enable: True

```

This configuration enables the addition of Cilium custom configuration required for any available flavor. It also disables any HPP rendering by ACI as a result of applying the network policy over the cluster, ensuring the policy enforcement is not done by ACI.

**Run the acc_provision command**
```
acc-provision -a -c acc_provision_input.yaml  -f kubernetes-1.27 -u <user> -p <password> -o aci_deployment.yaml -z aci deployment.yaml.tar.gz
```

**Replace opflex conf file (Skip for new install)** 

Rename the file "01-opflex.conf" to "10-opflex.conf" in the directory "/etc/cni/net.d" on each node. This ensures that the kubelet picks the configuration file lexicographically and once cilum 05-cilium.conflist is deployed , it will be picked first which have cni-chaining configuration. 

**Apply the aci_deployment.yaml manifest**
```
kubectl apply -f aci_deployment.yaml
```


**Run cilium install command**

```
cilium install --version 1.15.3 --set cni.chainingMode=generic-veth --set cni.customConf=true --set cni.configMap=cni-configuration --set enableIPv4Masquerade=false --set routingMode=native --set hubble.relay.enabled=true --set hubble.ui.enabled=true
```


After running the above command, the Cilium agent will be running on every node. Hubble will be installed as an observability tool.

Arguments Description
- cni.chainingMode=generic-veth: This is based on a generic veth device model that our CNI plugin is based on.
- cni.customConf=true: To enable Cilium CNI configuration management.
- cni.configMap: Name of a ConfigMap containing a source CNI configuration file.
- enableIPv4Masquerade=false: Disables masquerading of IPv4 traffic leaving the node from endpoints.
- routingMode=native: Enables native-routing mode leveraging the native Linux networking and routing capabilities. Employs BPF (Berkeley Packet Filter) programs to interact with the networking stack enhancing performance and efficiency.
- hubble.relay.enabled=true: When enabled, Cilium deploys Hubble Relay alongside Cilium agents, collecting and forwarding network flow data for centralized monitoring and analysis.
- hubble.ui.enabled=true: Enables Hubble UI.

**Restart pods under tests to enforce Cilium CNI.**


# OpenShift

**Install acc-provision**

```sh
git clone https://github.com/noironetworks/acc-provision.git
cd acc-provision/provision/
python3 setup.py install
```

**Configuration**

Add the following configuration to acc_provision_input.yaml file:

```
# Configuration for ACI Fabric
kube_config
  disable_hpp_rendering: True

cilium_chaining:
  enable: True
  
```

The above configuration enables the addition of cilium custom configuration required for any available flavor. Also it will disables any hpp rendering by aci as a result of applying the network policy over the cluster. This will ensure the policy enforcement is not done by ACI.  

**Run the acc_provision command**
```
acc-provision -a -c acc_provision_input.yaml  -f openshift-4.14 -esx -u <user> -p <password> -o aci_deployment.yaml -z aci deployment.yaml.tar.gz 
```

**Replace opflex conf file (Skip for new install)** 

Rename the file "01-opflex.conf" to "10-opflex.conf" in the directory "/etc/kubernetes/cni/net.d" on each node. This ensures that the kubelet picks the configuration file lexicographically and once cilum 05-cilium.conflist is deployed , it will be picked first which have cni-chaining configuration. 

**Apply the aci_deployment.yaml manifest**
```
kubectl apply -f aci_deployment.yaml
```


**Run cilium install command**

```
cilium install  --version 1.15.3   --set cni.chainingMode=generic-veth --set cni.customConf=true --set cni.configMap=cni-configuration  --set enableIPv4Masquerade=false  --set routingMode=native --set hubble.relay.enabled=true --set hubble.ui.enabled=true --set cni.binPath=/var/lib/cni/bin --set cni.confPath=/etc/kubernetes/cni/net.d 
```


After running the above command, the Cilium agent will be running on every node. Hubble will be installed as an observability tool.

Arguments Description
- cni.chainingMode=generic-veth: This is based on a generic veth device model that our CNI plugin is based on.
- cni.customConf=true: To enable Cilium CNI configuration management.
- cni.configMap: Name of a ConfigMap containing a source CNI configuration file.
- enableIPv4Masquerade=false: Disables masquerading of IPv4 traffic leaving the node from endpoints.
- routingMode=native: Enables native-routing mode leveraging the native Linux networking and routing capabilities. Employs BPF (Berkeley Packet Filter) programs to interact with the networking stack enhancing performance and efficiency.
- hubble.relay.enabled=true: When enabled, Cilium deploys Hubble Relay alongside Cilium agents, collecting and forwarding network flow data for centralized monitoring and analysis.
- hubble.ui.enabled=true: Enables Hubble UI.
- cni.binPath=/var/lib/cni/bin: Setting custom cni binary path for openshift 
- cni.confPath=/etc/kubernetes/cni/net.d: Setting custom cni conf path for openshift 

**Restart pods under tests to enforce Cilium CNI.**

# Hubble

Observability is provided by **Hubble** which enables deep visibility into the communication and behavior of services as well as the networking infrastructure in a completely transparent manner. **Hubble** is able to provide visibility at the node level, cluster level or even across clusters in a **Multi-Cluster (Cluster Mesh)** scenario.

Traffic can be validated on both cli and UI level.

## Hubble API Access:

* Port Forwarding of hubble relay
    ```
    cilium hubble port-forward&
    ```

* Check hubble status
    ```
    hubble status
    ```

* Query API and look for flows: 
    ```
    hubble observe -n <namespace> -f  
    ```

More information for inspecting flows via cli can be found here: https://docs.cilium.io/en/stable/gettingstarted/hubble_cli/#hubble-cli 

 
## Hubble GUI Access
* Port forwarding of hubble UI service

    ```
    cilium hubble ui --port-forward 12000& 
    ```

* SSH tunnel to Orch Node
    ```
    ssh -L 5905:localhost:5905 user@ip ssh -t -L 5905:127.0.0.1:12000 user@ip
    ```
* Access via local browser
    ```
    http://localhost:5905
    ```



# Validation

## Cilium & Hubble Installation Check

- ```cilium status```

```
    /¯¯\
 /¯¯\__/¯¯\    Cilium:             OK
 \__/¯¯\__/     Operator:           OK
 /¯¯\__/¯¯\    Envoy DaemonSet:    disabled (using embedded mode)
 \__/¯¯\__/     Hubble Relay:       OK
    \__/               ClusterMesh:        disabled

DaemonSet              cilium             Desired: 4, Ready: 4/4, Available: 4/4
Deployment             cilium-operator    Desired: 1, Ready: 1/1, Available: 1/1
Deployment             hubble-ui          Desired: 1, Ready: 1/1, Available: 1/1
Deployment             hubble-relay       Desired: 1, Ready: 1/1, Available: 1/1

Containers:            cilium             Running: 4
                       cilium-operator    Running: 1
                       hubble-ui          Running: 1
                       hubble-relay       Running: 1

Cluster Pods:          6/6 managed by Cilium
Helm chart version:    1.15.1

```

- ```hubble status```
```
Healthcheck (via localhost:4245): Ok
Current/Max Flows: 13,449/16,380 (82.11%)
Flows/s: 6.75
Connected Nodes: 4/4
```

# Troubleshooting

**Issue**: Multus Pods Crashing

**Root Cause**: Multus is not able to pick up 05-cilium-conflist file automatically after cni chaining

**Solution**: Ensure multus mounts on the host has correct conf files:

- OpenShift Platform
  1. Copy 05-cilium-conflist to /var/run/multus/cni/net.d for every node
  ```
  sudo cp /etc/kubernetes/cni/net.d/05-cilium.conflist /var/run/multus/cni/net.d/
  ```
  2. Restart multus pods so that it comes up with correct config in `/etc/kubernetes/cni/net.d/00-multus.conf`
  
      ```
      oc logs -f -n openshift-multus multus-md8n5
      2024-10-01T18:51:57+00:00 [cnibincopy] Successfully copied files in /usr/src/multus-cni/rhel9/bin/ to /host/opt/cni/bin/upgrade_0283ce13-d27b-4255-afc5-6f0b6c1b2796
      2024-10-01T18:51:57+00:00 [cnibincopy] Successfully moved files in /host/opt/cni/bin/upgrade_0283ce13-d27b-4255-afc5-6f0b6c1b2796 to /host/opt/cni/bin/
      2024-10-01T18:51:57Z [verbose] multus-daemon started
      I1001 18:51:57.728330 3828171 certificate_store.go:130] Loading cert/key pair from "/etc/cni/multus/certs/multus-client-current.pem".
      2024-10-01T18:51:57Z [verbose] Waiting for certificate
      I1001 18:51:58.729912 3828171 certificate_store.go:130] Loading cert/key pair from "/etc/cni/multus/certs/multus-client-current.pem".
      2024-10-01T18:51:58Z [verbose] Certificate found!
      2024-10-01T18:51:58Z [verbose] server configured with chroot: /hostroot
      2024-10-01T18:51:58Z [verbose] Filtering pod watch for node "ocp412-worker2"
      2024-10-01T18:51:58Z [verbose] API readiness check
      2024-10-01T18:51:58Z [verbose] API readiness check done!
      2024-10-01T18:51:58Z [verbose] Generated MultusCNI config: {"binDir":"/var/lib/cni/bin","capabilities":{"portMappings":true},"cniVersion":"0.3.1","logLevel":"verbose","logToStderr":true,"name":"multus-cni-network","clusterNetwork":"/host/run/multus/cni/net.d/05-cilium.conflist","namespaceIsolation":true,"globalNamespaces":"default,openshift-multus,openshift-sriov-network-operator","type":"multus-shim","daemonSocketDir":"/run/multus/socket"}
      2024-10-01T18:51:58Z [verbose] started to watch file /host/run/multus/cni/net.d/05-cilium.conflist
      2024-10-01T18:52:28Z [verbose] DEL starting CNI request ContainerID:"2f727c0743f0e90a7bfa42143433c2eb7f16df638c53d4e82be3a827b4874989" Netns:"/var/run/netns/7b034108-a34a-4aab-9370-79c09752137f" IfName:"eth0" Args:"IgnoreUnknown=1;K8S_POD_NAMESPACE=openshift-image-registry;K8S_POD_NAME=image-pruner-28791360-rzhs7;K8S_POD_INFRA_CONTAINER_ID=2f727c0743f0e90a7bfa42143433c2eb7f16df638c53d4e82be3a827b4874989;K8S_POD_UID=aeb1b83e-f4aa-4ff4-bb71-619d1821718a" Path:""
      2024-10-01T18:52:28Z [verbose] Del: openshift-image-registry:image-pruner-28791360-rzhs7:aeb1b83e-f4aa-4ff4-bb71-619d1821718a:generic-veth:eth0 {
      "name": "generic-veth",
      "cniVersion": "0.3.1",
      "plugins": [
      {
      "cniVersion": "0.3.1",
      "supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ],
      "type": "opflex-agent-cni",
      "wait-for-network": true,
      "wait-for-network-duration": 210,
      "ipam": {"type": "opflex-agent-cni-ipam"}
      },
      {
      "type": "portmap",
      "snat": true,
      "capabilities": {"portMappings": true}
      },
      {
      "type": "cilium-cni"
      }
      ]
      }
     ```

**Issue**: Traffic not getting denied by deny networkpolicy

**Root Cause**: kubelet didn’t picked chaining cni conf. 

**Solution**: Ensure that cni conf files are present as show below on every node

- Kubernetes Platform  
  ```
  user@k8s24-node-4:ls /etc/cni/net.d/ 

  05-cilium.conflist  10-opflex-cni.conf  200-loopback.conf 
  ```
 

- OpenShift Platform 
  ```
  ssh core@192.168.52.5 

  [core@ocp412-master3 ~]$ls /etc/kubernetes/cni/net.d/ 

  05-cilium.conflist  10-opflex-cni.conf 
  ```
 

The configuration file should be in lexicographical order. If there is 01-opflex.conf file is present, remove it from every node and ensure that you are using custom aci-containers-host-agent container image that deploys 10-opflex-cni.conf. 


# Appendix
- cni config 
  ```
  apiVersion: v1 

  kind: ConfigMap 

  metadata: 

    name: cni-configuration 

    namespace: kube-system 

  data: 

    cni-config: |- 

      { 

        "name": "generic-veth", 

        "cniVersion": "0.3.1", 

        "plugins": [ 

          { 

            "cniVersion": "0.3.1", 

            "supportedVersions": [ "0.3.0", "0.3.1", "0.4.0" ], 

            "type": "opflex-agent-cni", 

            "wait-for-network": true, 

            "wait-for-network-duration": 210, 

            "ipam": {"type": "opflex-agent-cni-ipam"} 

          }, 

          { 

            "type": "portmap", 

            "snat": true, 

            "capabilities": {"portMappings": true} 

          }, 

          { 

            "type": "cilium-cni" 

          } 

        ] 

      } 
  ```


- Disable KubeProxy in OpenShift 

  ```
  apiVersion: operator.openshift.io/v1 # change config.openshift.io/v1 to operator.openshift.io/v1 

  kind: Network 

  metadata: 

    creationTimestamp: null 

    name: cluster 

  spec: 

    clusterNetwork: 

    - cidr: 10.254.0.0/16 

      hostPrefix: 24 

    externalIP: 

      policy: {} 

    networkType: Cilium 

    deployKubeProxy: false # add the new deployKubeProxy: false line.  

    serviceNetwork: 

    - 172.30.0.0/16 

  status: {} 
  ```

# References 

- https://docs.cilium.io/en/latest/ 

- https://kube-ovn.readthedocs.io/zh-cn/stable/en/advance/with-cilium/ 

- https://hackmd.io/@mauilion/openshift_install 
