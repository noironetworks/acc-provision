# OpFlex Drop Log Feature

# Table of Contents

- [1. About OpFlex Drop Log](#1-about-opflex-drop-log)
- [2. Benefits of OpFlex Drop Log](#2-benefits-of-opflex-drop-log)
- [3. OpFlex Drop Log Limitations and Restrictions](#3-opflex-drop-log-limitations-and-restrictions)
- [4. Enabling OpFlex Drop Log](#4-enabling-opflex-drop-log)
- [5. Test OpFlex Drop Log](#5-test-opflex-drop-log)
- [6. Disable packet event](#6-disable-packet-event)
- [7. Test disable event](#7-test-disable-event)
- [8. Redirect droplogs to user defined file](#8-redirect-droplogs-to-user-defined-file)
- [9. Cleanup](#8-cleanup)
- [10. Reference](#9-reference)


## 1. About OpFlex Drop Log

1. The OpFlex Drop Log feature logs any packet that gets dropped in the datapath. It is useful to know what policy dropped a packet while debugging flow drops. Overall policy logging can be useful to understand the policies in a datapath without looking at the configuration.
2. Currently tools such as ovs-appctl ofproto/trace that are provided by Open vSwitch (which allow tracing of a specific packet through the datapath) are being used to debug drops. The Drop log feature makes it easy to monitor drops at scale.
3. Policy logging is already available on ACI as an action in addition to permit and deny while specifying filters.
4. This feature extends the functionality to the compute, while adding policy-miss logging.


## 2. Benefits of OpFlex Drop Log

The OpFlex Drop Log provides several benefits:
1. Allows logging of all dropped packets in the datapath due to policy miss.
2. In Kubernetes, events are published to the corresponding pods, and from there any issue in traffic for which datapath is dropping can be noticed easily.
3. If not on Kubernetes, then OpFlex logs will have all the packet drops logged and the IP addresses can be used to map the VMs involved in traffic.
4. Support IPv4 (not option processing), IPv6, TCP, UDP, and Geneve with custom TLVs.


## 3. OpFlex Drop Log Limitations and Restrictions

Be aware of the following issues when configuring OpFlex Drop Log:
1. Permit Logging is not supported.
2. Drop action for policy is not available as a CRD in Kubernetes.
3. Events are not supported on OpenStack, but OpFlex logs should be available.


## 4. Enabling OpFlex Drop Log

This section describes procedure to configure the OpFlex Drop Log.

Add following configuration in the acc provision input file:
```sh
drop_log_config:
  enable: true
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

Verify the flag is activated from aci-containers-host pod logs
```sh
$ oc logs aci-containers-host-lkvvf -n aci-containers-system -c aci-containers-host | grep 'packet event'
time="2024-02-20T07:48:21Z" level=info msg="Listening for packet events on unix socket /usr/local/var/run/aci-containers-packet-event-notification.sock"
```


## 5. Test OpFlex Drop Log

Run a nginx Pod with labels `app=web`  and expose it at port 80:
```sh
$ kubectl run web --image=nginx --labels="app=web" --expose --port=80
```

Run a test Pod and make a request to `web` Service:
```sh
$ kubectl run -it --image=alpine test-1 -- wget -qO- http://web
<!DOCTYPE html>
<html>
<head>
...
```

It works !! Now save the following manifest to `web-deny-all.yaml` and apply to the cluster. In the manifest below, we target Pods with `app=web` label to police the network. This manifest file is missing the `spec.ingress` field. Therefore it is not allowing any traffic into the Pod.

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: web-deny-all
spec:
  podSelector:
    matchLabels:
      app: web
  ingress: []
```

Apply `web-deny-all.yaml`
```sh
$ kubectl apply -f web-deny-all.yaml
networkpolicy "web-deny-all" created
```

From test pod, again make a request to `web` Service:
```sh
$ kubectl exec -it  test-1 -- wget -qO- --timeout=2 http://web
wget: download timed out
command terminated with exit code 1
```

***Traffic dropped !!***


Check packet drop log and event
```sh
noiro@oshift3-ext-rtr:~$ oc get pods -owide
NAME     READY   STATUS    RESTARTS      AGE   IP           NODE             NOMINATED NODE   READINESS GATES
test-1   1/1     Running   1 (20h ago)   20h   10.2.0.229   ocp413-worker2   <none>           <none>
web      1/1     Running   0             12m   10.2.0.195   ocp413-worker1   <none>           <none>


noiro@oshift3-ext-rtr:~$ oc logs -f  -n aci-containers-system aci-containers-host-wl9ml -c opflex-agent | grep '10.2.0.195\|10.2.0.229'
[2024-Feb-20 07:59:16.845663] [info] [ovs/PacketLogHandler.cpp:262:parseLog] Acc-SEC_GROUP_IN_TABLE MISS  SMAC=00:22:bd:f8:19:ff DMAC=0a:58:0a:02:00:c3 ETYP=IPv4 SRC=10.2.0.229 DST=10.2.0.195 LEN=60 DSCP=0 TTL=62 ID=58352 FLAGS=2 FRAG=0 PROTO=TCP SPT=42934 DPT=80 SEQ=2794802783 ACK=0 LEN=10 WINDOWS=62020 SYN  URGP=0
[2024-Feb-20 07:59:17.856653] [info] [ovs/PacketLogHandler.cpp:262:parseLog] Acc-SEC_GROUP_IN_TABLE MISS  SMAC=00:22:bd:f8:19:ff DMAC=0a:58:0a:02:00:c3 ETYP=IPv4 SRC=10.2.0.229 DST=10.2.0.195 LEN=60 DSCP=0 TTL=62 ID=58353 FLAGS=2 FRAG=0 PROTO=TCP SPT=42934 DPT=80 SEQ=2794802783 ACK=0 LEN=10 WINDOWS=62020 SYN  URGP=0


noiro@oshift3-ext-rtr:~$ oc describe pod web
Name:             web
Namespace:        default
...
...
...
...
Events:
  Type     Reason                                      Age                  From                 Message
  ----     ------                                      ----                 ----                 -------
  Normal   Scheduled                                   10m                  default-scheduler    Successfully assigned default/web to ocp413-worker1
  Normal   Pulling                                     10m                  kubelet              Pulling image "nginx"
  Normal   Pulled                                      9m59s                kubelet              Successfully pulled image "nginx" in 1.60875126s (1.608763117s including waiting)
  Normal   Created                                     9m58s                kubelet              Created container web
  Normal   Started                                     9m58s                kubelet              Started container web
  Warning  Acc-SEC_GROUP_IN_TABLE MISS(Security Drop)  2m2s (x3 over 9m3s)  aci-containers-host  IPv4 packet from 10.2.0.229 to default/web was dropped
  ```

In addition to the logs getting printed under opflex-agent, the event will be logged to the pod in question. If both source and destination pods are present on the same node, only the source pod will have the event. Repeated events to the same pod are rate limited to one every 2 minutes and dropped before publishing if the event could not be published within 10 minutes of the event timestamp.

---

## 6. Disable packet event

This section describes procedure to disable packet event recording. Enabling this flag will stop packet drop event logging under `describe pod`

Add following configuration in the acc provision input file:
```sh
drop_log_config:
  enable: true
  disable_events: true
```

Run `acc-provision` tool on updated acc provision input file, delete old aci_deployment.yaml and apply newly generated aci_deployment.yaml

Verify the flag is activated from aci-containers-host pod logs
```sh
$ oc logs aci-containers-host-zdlm9 -n aci-containers-system  -c aci-containers-host | grep 'Packet event'
time="2024-02-19T12:17:45Z" level=info msg="Packet event recording is disabled"
```

## 7. Test disable event

From test pod, again make a request to `web` Service:
```sh
$ kubectl exec -it  test-1 -- wget -qO- --timeout=2 http://web
wget: download timed out
command terminated with exit code 1
```

This time we can see packet drop log in opflex-agent but will not see packet drop event logging under `oc describe pod web`


## 8. Redirect droplogs to user defined file

By default, droplogs are written to the opflex-agent container logs within the aci-containers-host pod. This can cause the logs to grow quickly, leading to frequent rotations and potential loss of important opflex-agent log entries. To prevent this, the logs can be redirected to a separate file by adding the following configuration in the input file:
```yaml
drop_log_config:
    opflex_redirect_drop_logs: <filename>
```
The file is created with the provided filename in `/usr/local/var/log/' directory of the opflex-agent container in the containers-host pod.


## 9. Cleanup

```sh
kubectl delete pod web
kubectl delete service web
kubectl delete networkpolicy web-deny-all
```

## 10. Reference

1. [Enabling the OpFlex Drop Log Feature](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/use-case/enabling-the-opflex-drop-log-feature.html#Cisco_Reference.dita_f9b8d10f-3db3-4d7b-a2ef-68343d406748)
2. [DENY all traffic to an application](https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/01-deny-all-traffic-to-an-application.md)
