# ACI Pods Image Registry

# Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)
* [Example](#example)


## Overview

All released ACI container images are posted on quay.io/noiro. You can point to these images, image pull secret, image version, image digest etc by setting approrpiate configuration in the acc provision input file. Instead of quay.io, the images can also be loaded into a local registry and that local registry can be specified in the configuration.


## Mechanism

Add following configuration in the acc provision input file:
```yaml
registry:
  image_prefix: <registry.example.com/noiro>
  image_pull_secret: <secret_name>              # if required
  use_digest: true                              # option to pull images using digest, default is false.
  aci_containers_controller_version: <version>  # can be image version or sha256 digest
  aci_containers_host_version: <version>        # can be image version or sha256 digest
  cnideploy_version: <version>                  # can be image version or sha256 digest
  opflex_agent_version: <version>               # can be image version or sha256 digest
  openvswitch_version: <version>                # can be image version or sha256 digest
  acc_provision_operator_version: <version>     # can be image version or sha256 digest
  aci_containers_operator_version: <version>    # can be image version or sha256 digest
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

## Example

1. Default container image version

    ```yaml
    registry:
        image_prefix: quay.io/noiro
        image_pull_secret: noiro-docker-registry-secret
    ```

    This will pull image with the latest tag like below

    ```sh
    noiro@oshift3-ext-rtr:~$ cat aci_deployment.yaml | grep image -B2
    ...
    ...
      - name: cnideploy
        image: quay.io/noiro/cnideploy:6.0.4.1.81c2369.z

      - name: aci-containers-host
        image: quay.io/noiro/aci-containers-host:6.0.4.1.81c2369.z

      - name: mcast-daemon
        image: quay.io/noiro/opflex:6.0.4.1.81c2369.z

      - name: aci-containers-openvswitch
        image: quay.io/noiro/openvswitch:6.0.4.1.81c2369.z

      - name: aci-containers-controller
        image: quay.io/noiro/aci-containers-controller:6.0.4.1.81c2369.z

      - image: quay.io/noiro/aci-containers-operator:6.0.4.1.81c2369.z
        imagePullPolicy: Always
   ```

2. Specific container image version

    ```yaml
    registry:
        image_prefix: quay.io/noiro
        image_pull_secret: noiro-docker-registry-secret
        aci_containers_controller_version: 6.0.3.2.81c2369.z
        aci_containers_host_version: 6.0.3.2.81c2369.z
        cnideploy_version: 6.0.3.2.81c2369.z
        opflex_agent_version: 6.0.3.2.81c2369.z
        openvswitch_version: 6.0.3.2.81c2369.z
        acc_provision_operator_version: 6.0.3.2.81c2369.z
        aci_containers_operator_version: 6.0.3.2.81c2369.z
    ```

    This will pull image with specific tag like below

    ```sh
    noiro@oshift3-ext-rtr:~$ cat aci_deployment.yaml | grep image -B2
    ...
    ...
      - name: aci-containers-host
        image: quay.io/noiro/aci-containers-host:6.0.3.2.81c2369.z

      - name: mcast-daemon
        image: quay.io/noiro/opflex:6.0.3.2.81c2369.z

      - name: aci-containers-openvswitch
        image: quay.io/noiro/openvswitch:6.0.3.2.81c2369.z

      - name: aci-containers-controller
        image: quay.io/noiro/aci-containers-controller:6.0.3.2.81c2369.z

      - image: quay.io/noiro/aci-containers-operator:6.0.3.2.81c2369.z
        imagePullPolicy: Always
   ```

3. Use sha256 image digest to pull container image

    ```yaml
    registry:
        image_prefix: quay.io/noiro
        image_pull_secret: noiro-docker-registry-secret
        use_digest: true
        aci_containers_controller_version: d4dbc0aa9c5d016cbd98b19765ee9d253cf5a1297bd76c6a6425857de372cae9
        aci_containers_host_version: 48149b9c0ddae55de1e97e5d09da593e298a5c5d8094713dfe1d37b41c5378d5
        cnideploy_version: bf8bba20ef76267c3ebc29fd8f79ef8083da40c455d2f716678a102dbd23f0c1
        opflex_agent_version: de65620afddc12441bc57e8b8b22f4ec6a5d2bb3e441784210cb83a5943fcd9f
        openvswitch_version: fcbbcbed3ffcafdcb471b96b69fe7163e9136882d1d5d1bb52c27dca4676a9c0
        aci_containers_operator_version: 4e0e8264d77e324481be4b33cae5b80980cc9282f39f6ed3d4e64f034098108d
        acc_provision_operator_version: 4ec93f84fc99533b1e53f35b712b6dfc5c29494da5b03abc6d2bf66add5e5e2f
    ```

    This will pull image with sha256 digest like below

    ```sh
    noiro@oshift3-ext-rtr:~$ cat aci_deployment.yaml | grep image -B2
    ...
    ...
      - name: aci-containers-host
        image: quay.io/noiro/aci-containers-host:48149b9c0ddae55de1e97e5d09da593e298a5c5d8094713dfe1d37b41c5378d5

      - name: mcast-daemon
        image: quay.io/noiro/opflex:de65620afddc12441bc57e8b8b22f4ec6a5d2bb3e441784210cb83a5943fcd9f

      - name: aci-containers-openvswitch
        image: quay.io/noiro/openvswitch:fcbbcbed3ffcafdcb471b96b69fe7163e9136882d1d5d1bb52c27dca4676a9c0

      - name: aci-containers-controller
        image: quay.io/noiro/aci-containers-controller:d4dbc0aa9c5d016cbd98b19765ee9d253cf5a1297bd76c6a6425857de372cae9

      - image: quay.io/noiro/aci-containers-operator:4ec93f84fc99533b1e53f35b712b6dfc5c29494da5b03abc6d2bf66add5e5e2f
        imagePullPolicy: Always
   ```
