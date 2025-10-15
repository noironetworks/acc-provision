# APIC TLS Certificate Validation

## Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)
* [Configuration](#configuration)

## Overview

The APIC TLS Certificate Validation feature enhances the security of the communication between ACI CNI components and the APIC. By default, verification is disabled. This feature allows to provide a specific CA certificate as acc-provision parameter to ensure all connections to the APIC are secure and trusted.

The main improvements include:

1.  **Enhanced Security:**
    Enables validation for all API calls to the APIC. This prevents man-in-the-middle (MITM) attacks by ensuring the controller and acc-provision are communicating with a legitimate APIC.

2.  **Support for Internal CAs:**
    Seamlessly integrates with enterprise environments that use an internal Certificate Authority (CA) to sign their APIC certificates.

3.  **Full Lifecycle Validation:**
    Validation is enforced during both the provisioning & the unprovision phases (by the `acc-provision`) and during runtime operations (by the `aci-containers-controller`).

## Mechanism

To enable this feature, a new `apic_tls_cert` parameter is added to the `aci_config` section of the `acc-provision-input.yaml` file. The mechanism involves three stages:

1.  **acc-provision:**
    *   When the acc-provision is run (e.g., with `-a` or `-d` flags), it uses the file **path** provided in `apic_tls_cert` to perform its own verification for any API calls it makes to the APIC.
    *   The acc-provision also reads the **content** of the certificate file and prepares it to be embedded in the generated Kubernetes manifests.

2.  **Kubernetes Manifest Generation:**
    *   A new Kubernetes Secret named `apic-ca-cert` is created in the `aci-containers-system` namespace. The content of the user's certificate file is stored in this Secret under the key `root_ca.pem`.
    *   The `aci-containers-controller` Deployment is modified to mount this new Secret as a volume into the pod at `/usr/local/etc/apic-ca-cert/`.
    *   The `aci-containers-config` ConfigMap is updated with a new key, `apic-cert-path`, which points to the full path of the certificate inside the aci-containers-controller pod (e.g., `/usr/local/etc/apic-ca-cert/root_ca.pem`).

3.  **Runtime Controller (`aci-containers-controller`):**
    *   On startup, the controller reads the `aci-containers-config` ConfigMap.
    *   It detects the `apic-cert-path` key and uses the file at that path as the trusted CA for all subsequent API connections it establishes with the APIC.

## Configuration

To enable APIC TLS validation, add the `apic_tls_cert` parameter to your `acc-provision-input.yaml` file.

1.  **Update `acc-provision-input.yaml`:**

    Add the `apic_tls_cert` key under `aci_config` and provide the path to your APIC's root CA certificate file.

    ```yaml
    # acc-provision-input.yaml

    aci_config:
      apic_hosts:
        - "10.0.0.1"
        - "10.0.0.2"
        - "10.0.0.3"
      # ... other aci_config parameters ...

      # Add this line with the path to the certificate file
      apic_tls_cert: '/path/to/apic_ca.pem'
    ```

2.  **Run the acc-provision:**

    Execute the acc-provision as usual to generate the new deployment YAML.

    ```sh
    acc-provision -c acc-provision-input.yaml -f <your-flavor> -o aci-deployment.yaml
    ```

3.  **Apply and Verify:**

    Apply the generated manifest. You can verify that the resources were created correctly.

    *   **Check for the new Secret:**
        ```sh
        $ kubectl -n aci-containers-system get secret apic-ca-cert
        NAME           TYPE     DATA   AGE
        apic-ca-cert   Opaque   1      2m
        ```

    *   **Check the ConfigMap for the new path:**
        ```sh
        $ kubectl -n aci-containers-system get cm aci-containers-config -o yaml
        ```
        The output should contain the `apic-cert-path` in the `controller-config` data:
        ```yaml
        apiVersion: v1
        data:
          controller-config: |-
            {
                ...
                "apic-username": "your-user",
                "apic-private-key-path": "/usr/local/etc/aci-cert/user.key",
                "apic-cert-path": "/usr/local/etc/apic-ca-cert/root_ca.pem",
                ...
            }
        kind: ConfigMap
        ...
        ```

    *   **Check the controller pod for the mounted file:**
        ```sh
        $ kubectl -n aci-containers-system exec -it <aci-containers-controller-pod-name> -- ls /usr/local/etc/apic-ca-cert/root_ca.pem
        ```