# Delay service graph programming when new endoint is added 

# Table of contents
* [Overview](#overview)
* [Motivation](#motivation)
* [Mechanism](#mechanism)  
* [Example](#example)
* [Troubleshooting](#troubleshooting)
    

## Overview

When an endpoint of loadbalancer service is added, the programming of service graph is done immediately after the endoint is in Ready state. Delay service graph programming feature provides user an option to delay the service graph programming by some configurable amount of time after the endoint is in Ready state.

## Motivation

If user has applications which are exposed via openshift routers, the traffic towards the application was blackholing when new router pod comes up(This can happen during a router patching where the router pods are restarted one after the other). When a router pod comes up, the router service is up with active endpoints, but the application itself (HA proxy) is not yet ready to process the traffic. To allow an application to bootstrap completely, we added this feature to delay the service graph programming by a configurable amount of time when an endpoint comes up.

## Mechanism

Service graph programming of a list of loadbalancer services can be delayed by providing the following configuration in the acc-provision input file:

```yaml
service_graph_endpoint_add_delay:
  delay: 30 #Delay in seconds
  services: #List of services for which delay should be added
  - name: "service-name1"
    namespace: "service-ns1"
  - name: "service-name2"
    namespace: "service-ns2"
    delay: 60 #Override delay of service-name2 service
```

If we give the above configuration, whenever a new endoint is added to the existing endpointslice of the loadbalancer services service-name1 in namespace service-ns1  or service-name2 in service-ns2 namespace, then the service graph programming will be delayes by 30 and 60 seconds  respectively after the endoint is in Ready state. If we don't specify the per-service delay, it will consider the common delay (30 in above case). If we specify per-service delay (60 for service-name2 in above case), priority will be given to per-service delay.

A new endpoint addition to the existing endpointslice happens when a pod of a loadbalancer service is deleted and created again or a new pod is added to existing list of pods.

## Example

Let’s consider an example with following loadbalancer service(router-default) and its deployment in openshift:

```sh
$ oc get service -n openshift-ingress
NAME                      TYPE           CLUSTER-IP       EXTERNAL-IP   PORT(S)                      AGE
router-default            LoadBalancer   172.30.238.87    151.9.1.2     80:31351/TCP,443:31254/TCP   53d
router-internal-default   ClusterIP      172.30.127.238   <none>        80/TCP,443/TCP,1936/TCP      53d
```

```sh
$ oc get deploy -n openshift-ingress
NAME             READY   UP-TO-DATE   AVAILABLE   AGE
router-default   2/2     2            2           53d
```

```sh
$ oc get po -n openshift-ingress
NAME                              READY   STATUS    RESTARTS          AGE   IP             NODE                           NOMINATED NODE   
router-default-6b6ccf74d8-2xh45   1/1     Running   0                 22d   15.128.0.188   openupi-6hdfb-worker-0-9s7xv   <none>           
router-default-6b6ccf74d8-557dn   1/1     Running   0                 53d   15.128.1.181   openupi-6hdfb-worker-0-qdpjz   <none>           
```

```sh
$ oc get endpointslice -n openshift-ingress
NAME                            ADDRESSTYPE   PORTS         ENDPOINTS                   AGE
router-default-rqnb9            IPv4          80,443        15.128.0.188,15.128.1.181   53d
router-internal-default-85mj5   IPv4          80,1936,443   15.128.0.188,15.128.1.181   53d
```

```sh
$ oc get endpoints -n openshift-ingress
NAME                      ENDPOINTS                                                          AGE
router-default            15.128.0.188:443,15.128.1.181:443,15.128.0.188:80 + 1 more...      53d
router-internal-default   15.128.0.188:1936,15.128.1.181:1936,15.128.0.188:443 + 3 more...   53d
```

Now, the endpointslice of router-default loadbalancer service has 2 endpoints - 15.128.0.188 and 15.128.1.181.

Add the following configuration in the acc-provision-input file:

```yaml
service_graph_endpoint_add_delay:
  delay: 90
  services:
  - name: "router-default"
    namespace: "openshift-ingress"
```

Now, if we apply the generated deployment.yaml file after doing acc-provision, whenever we delete the router-default deployment pod(ie, when the endpoint of the enpointslice of router-default service in openshift-ingress namespace is updated), the service graph programming of the new pod thats comes up will be delayed by 90s after the endoint is in Ready state.

```sh
$ oc delete po -n openshift-ingress router-default-6b6ccf74d8-2xh45

$ oc get po -n openshift-ingress -owide
NAME                              READY   STATUS    RESTARTS   AGE   IP             NODE                           NOMINATED NODE  
router-default-6b6ccf74d8-557dn   1/1     Running   0          53d   15.128.1.181   openupi-6hdfb-worker-0-qdpjz   <none>          
router-default-6b6ccf74d8-csfxl   1/1     Running   0          96s   15.128.0.192   openupi-6hdfb-worker-0-9s7xv   <none>           
```

```sh
$ oc get endpointslice -n openshift-ingress
NAME                            ADDRESSTYPE   PORTS         ENDPOINTS                   AGE
router-default-rqnb9            IPv4          80,443        15.128.1.181,15.128.0.192   53d
router-internal-default-85mj5   IPv4          80,1936,443   15.128.1.181,15.128.0.192   53d
```

We can see the following log in controller pod when we delete the router-default deployment pod:

```
time="2024-02-27T07:42:29Z" level=debug msg="Deleting Dn" dn="uni/tn-common/svcCont/svcRedirectPol-openupi_svc_openshift-ingress_router-default/RedirectDest_ip-[15.5.168.6]" mod=APICAPI
...
...
time="2024-02-27T07:43:48Z" level=debug msg="Delay of 90 seconds is applicable for svc :router-default in ns: openshift-ingress"
...
...
time="2024-02-27T07:45:18Z" level=debug msg="Processing update of epslice : &EndpointSlice{ObjectMeta:{router-default-rqnb9 router-default- openshift-ingress  9d98fa89-101e-4581-9c80-046b632a3e61 25877891 239 2024-01-04 11:03:03 +0000 UTC <nil> <nil> map[app:router endpointslice.kubernetes.io/managed-by:endpointslice-controller.k8s.io ingresscontroller.operator.openshift.io/owning-ingresscontroller:default kubernetes.io/service-name:router-default router:router-default] map[endpoints.kubernetes.io/last-change-trigger-time:2024-02-27T07:44:01Z] [{v1 Service router-default 3ef52bbf-1309-43fd-aa77-afb090e68a1b 0xc00178f677 0xc00178f678}] [] [{kube-controller-manager Update discovery.k8s.io/v1 2024-02-27 07:43:50 +0000 UTC FieldsV1 {\n\"f:addressType\": {},\n\"f:endpoints\": {},\n\"f:metadata\": {\n\"f:annotations\": {\n\".\": {},\n\"f:endpoints.kubernetes.io/last-change-trigger-time\": {}\n},\n\"f:generateName\": {},\n\"f:labels\": {\n\".\": {},\n\"f:app\": {},\n\"f:endpointslice.kubernetes.io/managed-by\": {},\n\"f:ingresscontroller.operator.openshift.io/owning-ingresscontroller\": {},\n\"f:kubernetes.io/service-name\": {},\n\"f:router\": {}\n},\n\"f:ownerReferences\": {\n\".\": {},\n\"k:{\\\"uid\\\":\\\"3ef52bbf-1309-43fd-aa77-afb090e68a1b\\\"}\": {}\n}\n},\n\"f:ports\": {}\n} }]},Endpoints:[]Endpoint{Endpoint{Addresses:[15.128.0.224],Conditions:EndpointConditions{Ready:*true,Serving:*true,Terminating:*false,},Hostname:nil,TargetRef:&v1.ObjectReference{Kind:Pod,Namespace:openshift-ingress,Name:router-default-6b6ccf74d8-td84f,UID:11a48feb-eff5-4541-9202-664e4ce8dcb6,APIVersion:,ResourceVersion:,FieldPath:,},DeprecatedTopology:map[string]string{},NodeName:*openupi-6hdfb-worker-0-9s7xv,Zone:*nova,Hints:nil,},Endpoint{Addresses:[15.128.1.167],Conditions:EndpointConditions{Ready:*true,Serving:*true,Terminating:*false,},Hostname:nil,TargetRef:&v1.ObjectReference{Kind:Pod,Namespace:openshift-ingress,Name:router-default-6b6ccf74d8-6cxxr,UID:e837d631-66e1-438e-bcdc-1bdf7dbd385d,APIVersion:,ResourceVersion:,FieldPath:,},DeprecatedTopology:map[string]string{},NodeName:*openupi-6hdfb-worker-0-qdpjz,Zone:*nova,Hints:nil,},},Ports:[]EndpointPort{EndpointPort{Name:*http,Protocol:*TCP,Port:*80,AppProtocol:nil,},EndpointPort{Name:*https,Protocol:*TCP,Port:*443,AppProtocol:nil,},},AddressType:IPv4,}"
...
...
time="2024-02-27T07:45:20Z" level=debug msg="Processing queue for:uni/tn-common/svcCont/svcRedirectPol-openupi_svc_openshift-ingress_router-default/RedirectDest_ip-[15.5.168.6]/annotationKey-[aci-containers-controller-tag]" mod=APICAPI
...
time="2024-02-27T07:45:21Z" level=debug msg="Object updated on APIC" dn="uni/tn-common/svcCont/svcRedirectPol-openupi_svc_openshift-ingress_router-default/RedirectDest_ip-[15.5.168.6]/annotationKey-[aci-containers-controller-tag]" mod=APICAPI obj="{\"tagAnnotation\":{\"attributes\":{\"childAction\":\"\",\"dn\":\"uni/tn-common/svcCont/svcRedirectPol-openupi_svc_openshift-ingress_router-default/RedirectDest_ip-[15.5.168.6]/annotationKey-[aci-containers-controller-tag]\",\"key\":\"aci-containers-controller-tag\",\"lcOwn\":\"local\",\"modTs\":\"2024-02-27T07:35:55.815+00:00\",\"status\":\"\",\"uid\":\"13796\",\"userdom\":\":all:common:\",\"value\":\"openupi-c386c228d9998542d8329bbc513e0d7b\"}}}"
```
In above logs, we can see that, delete of service redirect policy happened immediately when the pod is deleted and the processing of update of new endpoint happened only after 90s.
 
## Troubleshooting

1. Check configuration is applied properly

    Once newly generated aci deployment yaml is applied, `service_graph_endpoint_add_delay` configuration should be reflected in the controller-config data of aci-containers-config configmap:

```sh
$ kubectl get cm -n aci-containers-system aci-containers-config -oyaml
apiVersion: v1
data:
  controller-config: |-
    {
	...
	"service-graph-endpoint-add-delay": {
            "delay": 90,
            "services": [
                    {
                        "name": "router-default",
                        "namespace": "openshift-ingress"
                    }
            ]
        },
	...
    }
    ...
```

2. Check if the common service graph delay is set in the controller log:

```sh
$ kubectl logs -n aci-containers-system aci-containers-controller-77b78fddbf-jk4gj | grep -i "ServiceGraphEndpointAddDelay"
time="2024-02-27T07:07:37Z" level=info msg="ServiceGraphEndpointAddDelay set to: 90"
```
