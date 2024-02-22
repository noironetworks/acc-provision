# ACI Pods log level 

# Table of contents

* [Overview](#overview)
* [Mechanism](#mechanism)  
* [Examples](#examples)
    

## Overview

ACI Pods logs information with default log level `info`. But during times like analyzing a bug, detailed information is needed. Here different options are provided in acc provision input file to change log level of aci pods.


## Mechanism

Add following configuration in the acc provision input file:
```yaml
logging:
  controller_log_level: <level>
  hostagent_log_level: <level>
  opflexagent_log_level: <level>
  operator_log_level: <level>
```

Different `level` options supported.
- info  : General operational entries about what's going on inside the application.
- debug : Usually only enabled when debugging. Very verbose logging.
- warn  : Non-critical entries that deserve eyes.
- error : Used for errors that should definitely be noted.
- trace : Designates finer-grained informational events than the Debug.
- panic : Highest level of severity. Logs and then calls panic with the message passed to Debug, Info, ...
- fatal : Logs and then calls exit. It will exit even if the logging level is set to Panic.

`Note: Suggested log level is "debug" to analyze an issue.`

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

## Examples

Set log level `debug` for all the pods using following configuration in acc provision input file

```yaml
logging:
  controller_log_level: debug
  hostagent_log_level: debug
  opflexagent_log_level: debug
  operator_log_level: debug
```

Verify log level updated in configmap `aci-containers-config`

```sh
noiro@oshift3-ext-rtr:~$ oc get cm -n aci-containers-system aci-containers-config -oyaml
apiVersion: v1
data:
  controller-config: |-
    {
        "flavor": "openshift-4.13-esx",
        "log-level": "debug",
  ...
  ...
  ...
  host-agent-config: |-
    {
        "flavor": "openshift-4.13-esx",
        "app-profile": "aci-containers-ocp413",
        "opflex-mode": null,
        "log-level": "debug",
  ...
  ...
  ...
  opflex-agent-config: |-
    {
        "log": {
            "level": "debug"
        },
```

Check log level updated for `aci-containers-controller` pod (and for other aci pods)
```sh
noiro@oshift3-ext-rtr:~$ oc logs -n aci-containers-system aci-containers-controller-d994d58b9-gqzbd  | less
time="2024-02-22T10:11:36Z" level=info msg="Loading configuration from /usr/local/etc/aci-containers/controller.conf"
time="2024-02-22T10:11:36Z" level=info msg=Starting logLevel=debug vmm-domain-type=OpenShift
time="2024-02-22T10:11:36Z" level=info msg="Setting up Kubernetes environment" kubeconfig=
time="2024-02-22T10:11:36Z" level=debug msg="Initializing kubernetes client"
time="2024-02-22T10:11:36Z" level=debug msg="Initializing snat client"
time="2024-02-22T10:11:36Z" level=info msg="Running controller built from git commit ID 192e81306efb2fefdc67f46ccea49ffd37a5a53b at build time 02-21-2024.18:12:01.UTC"
time="2024-02-22T10:11:36Z" level=debug msg="Initializing IPAM"
time="2024-02-22T10:11:36Z" level=info msg="Initializing ServiceEndpointSlices"
time="2024-02-22T10:11:36Z" level=debug msg="Initializing informers"
time="2024-02-22T10:11:36Z" level=debug msg="Initializing Snat Policy Informers"
time="2024-02-22T10:11:36Z" level=debug msg="Initializing Node Informers: "
time="2024-02-22T10:11:36Z" level=debug msg="Initializing RdConfig Informers"
time="2024-02-22T10:11:36Z" level=info msg="Initializing SnatCfg Informers: "
time="2024-02-22T10:11:36Z" level=debug msg="Initializing indexes"
time="2024-02-22T10:11:36Z" level=info msg="ApicRefreshTimer conf is set to: 1800"
time="2024-02-22T10:11:36Z" level=info msg="ApicSubscriptionDelay conf is set to: 100"
time="2024-02-22T10:11:36Z" level=debug msg="OpflexDeviceReconnectWaitTimeout set to: 25"
time="2024-02-22T10:11:36Z" level=info msg="PodIpPoolChunkSize conf is set to: 32"
time="2024-02-22T10:11:36Z" level=debug msg="ApicConnectionRetryLimit set to: 5"
time="2024-02-22T10:11:36Z" level=info msg="Max number of nodes per svc graph is set to: 32"
time="2024-02-22T10:11:36Z" level=debug msg="Connecting to APIC to determine the Version" host=10.30.120.180 mod=APICAPI
time="2024-02-22T10:11:41Z" level=info msg="Req: &{Method:GET URL:https://10.30.120.180/api/webtokenSession.json Proto:HTTP/1.1 ProtoMajor:1 ProtoMinor:1 Header:map[] Body:<nil> GetBody:<nil> ContentLength:0 TransferEncoding:[] Close:false Host:10.30.120.180 Form:map[] PostForm:map[] MultipartForm:<nil> Trailer:map[] RemoteAddr: RequestURI: TLS:<nil> Cancel:<nil> Response:<nil> ctx:{emptyCtx:{}}}" mod=APICAPI
time="2024-02-22T10:11:41Z" level=info msg="Actual APIC version:4.2(7f) Stripped out version:4.2" mod=APICAPI
time="2024-02-22T10:11:41Z" level=debug msg="SnatPbrFltrChain set to:true"
```

