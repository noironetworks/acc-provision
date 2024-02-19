# OpFlex Drop Log Feature

- [1. About OpFlex Drop Log](#1-about-opflex-drop-log)
- [2. Benefits of OpFlex Drop Log](#2-benefits-of-opflex-drop-log)
- [3. OpFlex Drop Log Limitations and Restrictions](#3-opflex-drop-log-limitations-and-restrictions)
- [4. Enabling OpFlex Drop Log](#4-enabling-opflex-drop-log)
- [5. Test OpFlex Drop Log](#5-test-opflex-drop-log)
- [6. Disable packet event](#6-disable-packet-event)
- [7. Test disable event](#7-test-disable-event)
- [8. Cleanup](#8-cleanup)
- [9. Reference](#9-reference)


## 1. About OpFlex Drop Log <a name="1-about-opflex-drop-log"></a>

1. The OpFlex Drop Log feature logs any packet that gets dropped in the datapath. It is useful to know what policy dropped a packet while debugging flow drops. Overall policy logging can be useful to understand the policies in a datapath without looking at the configuration.
2. Currently tools such as ovs-appctl ofproto/trace that are provided by Open vSwitch (which allow tracing of a specific packet through the datapath) are being used to debug drops. The Drop log feature makes it easy to monitor drops at scale.
3. Policy logging is already available on ACI as an action in addition to permit and deny while specifying filters.
4. This feature extends the functionality to the compute, while adding policy-miss logging.


## 2. Benefits of OpFlex Drop Log <a name="2-benefits-of-opflex-drop-log"></a>

The OpFlex Drop Log provides several benefits:
1. Allows logging of all dropped packets in the datapath due to policy miss.
2. In Kubernetes, events are published to the corresponding pods, and from there any issue in traffic for which datapath is dropping can be noticed easily.
3. If not on Kubernetes, then OpFlex logs will have all the packet drops logged and the IP addresses can be used to map the VMs involved in traffic.
4. Support IPv4 (not option processing), IPv6, TCP, UDP, and Geneve with custom TLVs.


## 3. OpFlex Drop Log Limitations and Restrictions <a name="3-opflex-drop-log-limitations-and-restrictions"></a>

Be aware of the following issues when configuring OpFlex Drop Log:
1. Permit Logging is not supported.
2. Drop action for policy is not available as a CRD in Kubernetes.
3. Events are not supported on OpenStack, but OpFlex logs should be available.


## 4. Enabling OpFlex Drop Log <a name="4-enabling-opflex-drop-log"></a>

This section describes procedure to configure the OpFlex Drop Log.

Add following configuration in the acc provision input file:
```sh
drop_log_config:
  enable: true
```

Run `acc-provision` tool on updated acc provision input file to generate new `aci_deployment.yaml`

`acc-provision -c <acc_provision_input_file> -f <flavor> -u <apic_username> -p <apic_password> -o aci_deployment.yaml`

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
$ oc logs aci-containers-host-lkvvf -n aci-containers-system  | grep 'packet event'
Defaulted container "aci-containers-host" out of: aci-containers-host, opflex-agent, mcast-daemon, cnideploy (init)
time="2024-02-19T12:01:04Z" level=info msg="Listening for packet events on unix socket /usr/local/var/run/aci-containers-packet-event-notification.sock"
```


## 5. Test OpFlex Drop Log <a name="5-test-opflex-drop-log"></a>

Run a nginx Pod with labels `app=web`  and expose it at port 80:
`$ kubectl run web --image=nginx --labels="app=web" --expose --port=80`

Run a test Pod and make a request to `web` Service:
```sh
$ kubectl run -it --image=alpine test-1 -- sh
/ # wget -qO- http://web
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
NAME     READY   STATUS    RESTARTS   AGE    IP           NODE             NOMINATED NODE   READINESS GATES
test-1   1/1     Running   0          96m    10.2.0.254   ocp413-worker2   <none>           <none>
web      1/1     Running   0          102m   10.2.0.198   ocp413-worker1   <none>           <none>

noiro@oshift3-ext-rtr:~$ aci-logs aci-containers-host-nqpgd | grep 'default/web was dropped'
Defaulted container "aci-containers-host" out of: aci-containers-host, opflex-agent, mcast-daemon, cnideploy (init)
time="2024-02-15T12:08:23Z" level=debug msg="Posting event IPv4 packet from 10.2.0.254 to default/web was dropped"

noiro@oshift3-ext-rtr:~$ oc describe pod web
...
...
...
...
Events:
  Type     Reason                                      Age                        From                 Message
  ----     ------                                      ----                       ----                 -------
  Normal   Scheduled                                   100m                       default-scheduler    Successfully assigned default/web to ocp413-worker1
  Normal   Pulling                                     100m                       kubelet              Pulling image "nginx"
  Normal   Pulled                                      99m                        kubelet              Successfully pulled image "nginx" in 8.168595183s (8.168605055s including waiting)
  Normal   Created                                     99m                        kubelet              Created container web
  Normal   Started                                     99m                        kubelet              Started container web
  Warning  Acc-SEC_GROUP_IN_TABLE MISS(Security Drop)  93m                        aci-containers-host  IPv4 packet from 10.2.0.254 to default/web was dropped
  ```

In addition to the logs getting printed under opflex-agent, the event will be logged to the pod in question. If both source and destination pods are present on the same node, only the source pod will have the event. Repeated events to the same pod are rate limited to one every 2 minutes and dropped before publishing if the event could not be published within 10 minutes of the event timestamp.

---

## 6. Disable packet event <a name="6-disable-packet-event"></a>

This section describes procedure to disable packet event recording

Add following configuration in the acc provision input file:
```sh
drop_log_config:
  enable: true
  disable_event: true
```

Run `acc-provision` tool on updated acc provision input file to generate new `aci_deployment.yaml`

`acc-provision -c <acc_provision_input_file> -f <flavor> -u <apic_username> -p <apic_password> -o aci_deployment.yaml`

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
$ oc logs aci-containers-host-zdlm9 -n aci-containers-system  | grep 'Packet event'
Defaulted container "aci-containers-host" out of: aci-containers-host, opflex-agent, mcast-daemon, cnideploy (init)
time="2024-02-19T12:17:45Z" level=info msg="Packet event recording is disabled"
```

## 7. Test disable event <a name="7-test-disable-event"></a>

From test pod, again make a request to `web` Service:
```sh
$ kubectl exec -it  test-1 -- wget -qO- --timeout=2 http://web
wget: download timed out
command terminated with exit code 1
```

This time we will not see packet drop log in aci-containers-host pod or as an event under `oc describe pod web`


## 8. Cleanup <a name="8-cleanup"></a>

```sh
kubectl delete pod web
kubectl delete service web
kubectl delete networkpolicy web-deny-all
```

## 9. Reference <a name="#9-reference"></a>

1. [Enabling the OpFlex Drop Log Feature](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/use-case/enabling-the-opflex-drop-log-feature.html#Cisco_Reference.dita_f9b8d10f-3db3-4d7b-a2ef-68343d406748)
2. [DENY all traffic to an application](https://github.com/ahmetb/kubernetes-network-policy-recipes/blob/master/01-deny-all-traffic-to-an-application.md)
