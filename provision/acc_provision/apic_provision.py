from __future__ import print_function, unicode_literals
import collections
import json
import sys
import re
import requests
import urllib3
import ipaddress
from distutils.version import StrictVersion

debug_http = False
if debug_http:
    import logging
    import http.client as http_client
    http_client.HTTPConnection.debuglevel = 1
    # You must initialize logging, otherwise you'll not see debug output.
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass
# Try importing Mapping for python 3.10, if it fails default to the older version
try:
    from collections.abc import Mapping
except ImportError:
    from collections import Mapping

apic_debug = False
apic_cookies = {}
apic_default_timeout = (15, 90)
aciContainersOwnerAnnotation = "orchestrator:aci-containers-controller"
aci_prefix = "aci-containers-"


def err(msg):
    print("ERR:  " + msg, file=sys.stderr)


def warn(msg):
    print("WARN: " + msg, file=sys.stderr)


def dbg(msg):
    if apic_debug:
        print("DBG:  " + msg, file=sys.stderr)


def yesno(flag):
    if flag:
        return "yes"
    return "no"


def aci_obj(klass, pair_list):
    kwargs = collections.OrderedDict(pair_list)
    children = kwargs.pop("_children", None)
    data = collections.OrderedDict(
        [(klass, collections.OrderedDict([("attributes", kwargs)]))]
    )
    if children:
        data[klass]["children"] = children
    return data


class Apic(object):

    TENANT_OBJECTS = ["ap-kubernetes", "BD-kube-node-bd", "BD-kube-pod-bd", "brc-kube-api", "brc-health-check", "brc-dns", "brc-icmp", "flt-kube-api-filter", "flt-dns-filter", "flt-health-check-filter-out", "flt-icmp-filter", "flt-health-check-filter-in"]
    ACI_PREFIX = aci_prefix

    def __init__(
        self,
        addr,
        username,
        password,
        ssl=True,
        verify=False,
        timeout=None,
        debug=False,
        capic=False,
        save_to=None
    ):
        global apic_debug
        apic_debug = debug
        self.addr = addr
        self.ssl = ssl
        self.username = username
        self.password = password
        self.cookies = apic_cookies.get((addr, username, ssl))
        self.errors = 0
        self.verify = verify
        self.timeout = timeout if timeout else apic_default_timeout
        self.debug = debug
        self.capic = capic
        # this is for generating replay data for tests
        self.save_to = save_to
        self.saved_responses = {}
        self.saved_deletes = {}

        if self.cookies is None:
            self.login()
            if self.cookies is not None:
                apic_cookies[(addr, username, ssl)] = self.cookies
        self.apic_version = self.get_apic_version()

    def url(self, path):
        if self.ssl:
            return "https://%s%s" % (self.addr, path)
        return "http://%s%s" % (self.addr, path)

    def get(self, path, data=None, params=None):
        args = dict(data=data, cookies=self.cookies, verify=self.verify, params=params)
        args.update(timeout=self.timeout)
        dbg("getting path: {} {}".format(path, json.dumps(args)))
        resp = requests.get(self.url(path), **args)
        if self.save_to:
            self.saved_responses[path] = json.loads(resp.content)
        return resp

    def post(self, path, data):
        if self.capic:
            args = dict(json=data, cookies=self.cookies, verify=self.verify)
        else:
            # APIC seems to accept request body as form-encoded
            args = dict(data=data, cookies=self.cookies, verify=self.verify)
        args.update(timeout=self.timeout)
        dbg("posting {}".format(json.dumps(args)))
        return requests.post(self.url(path), **args)

    def delete(self, path, data=None):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        args.update(timeout=self.timeout)
        if self.save_to:
            self.saved_deletes[path] = True
        return requests.delete(self.url(path), **args)

    def login(self):
        data = '{"aaaUser":{"attributes":{"name": "%s", "pwd": "%s"}}}' % (
            self.username,
            self.password,
        )
        path = "/api/aaaLogin.json"
        req = requests.post(self.url(path), data=data, verify=False)
        if req.status_code == 200:
            resp = json.loads(req.text)
            dbg("Login resp: {}".format(req.text))
            token = resp["imdata"][0]["aaaLogin"]["attributes"]["token"]
            self.cookies = collections.OrderedDict([("APIC-Cookie", token)])
        else:
            print("Login failed - {}".format(req.text))
            print("Addr: {} u: {} p: {}".format(self.addr, self.username, self.password))
        return req

    def save(self):
        if self.save_to:
            apic_data = {
                "gets": self.saved_responses,
                "deletes": self.saved_deletes,
            }

            with open(self.save_to, "w") as write_file:
                json.dump(apic_data, write_file)
                write_file.close()

    def check_resp(self, resp):
        respj = json.loads(resp.text)
        if len(respj["imdata"]) > 0:
            ret = respj["imdata"][0]
            if "error" in ret:
                raise Exception("APIC REST Error: %s" % ret["error"])
        return resp

    def get_path(self, path, multi=False):
        ret = None
        try:
            resp = self.get(path)
            self.check_resp(resp)
            respj = json.loads(resp.text)
            if len(respj["imdata"]) > 0:
                if multi:
                    ret = respj["imdata"]
                else:
                    ret = respj["imdata"][0]
        except Exception as e:
            self.errors += 1
            err("Error in getting %s: %s: " % (path, str(e)))
        return ret

    def get_infravlan(self):
        infra_vlan = None
        path = (
            "/api/node/mo/uni/infra/attentp-default/provacc" +
            "/rsfuncToEpg-[uni/tn-infra/ap-access/epg-default].json"
        )
        data = self.get_path(path)
        if data:
            encap = data["infraRsFuncToEpg"]["attributes"]["encap"]
            infra_vlan = int(encap.split("-")[1])
        return infra_vlan

    def get_aep(self, aep_name):
        path = "/api/mo/uni/infra/attentp-%s.json" % aep_name
        return self.get_path(path)

    def get_vrf(self, dn):
        path = "/api/mo/%s.json" % dn
        return self.get_path(path)

    def get_l3out(self, tenant, name):
        path = "/api/mo/uni/tn-%s/out-%s.json" % (tenant, name)
        return self.get_path(path)

    def get_vmmdom_vlanpool_tDn(self, vmmdom):
        path = "/api/node/mo/uni/vmmp-VMware/dom-%s.json?query-target=children&target-subtree-class=infraRsVlanNs" % (vmmdom)
        return self.get_path(path)["infraRsVlanNs"]["attributes"]["tDn"]

    def check_l3out_vrf(self, tenant, name, vrf_name, vrf_dn):
        path = "/api/mo/uni/tn-%s/out-%s/rsectx.json?query-target=self" % (tenant, name)
        res = False
        try:
            tDn = self.get_path(path)["l3extRsEctx"]["attributes"]["tDn"]
            res = (tDn == vrf_dn)
        except Exception as e:
            err("Error in getting configured vrf for %s/%s: %s" % (tenant, name, str(e)))
        return res

    def get_user(self, name):
        path = "/api/node/mo/uni/userext/user-%s.json" % name
        return self.get_path(path)

    def get_ap(self, tenant):
        path = "/api/mo/uni/tn-%s/ap-kubernetes.json" % tenant
        return self.get_path(path)

    def get_configured_node_dns(self, tenant, l3out, node_prof):
        path = "/api/node/mo/uni/tn-%s/out-%s/lnodep-%s.json?query-target=children&target-subtree-class=l3extRsNodeL3OutAtt" % (tenant, l3out, node_prof)
        configured_node_dns = []
        node_ids = self.get_path(path, multi=True)
        if node_ids is None:
            return configured_node_dns
        if type(node_ids) is list:
            for node_id in node_ids:
                configured_node_dns.append(node_id["l3extRsNodeL3OutAtt"]["attributes"]["tDn"])
        else:
            configured_node_dns.append(node_ids["l3extRsNodeL3OutAtt"]["attributes"]["tDn"])
        return configured_node_dns

    def provision(self, data, sync_login):
        ignore_list = []
        if self.get_user(sync_login):
            warn("User already exists (%s), recreating user" % sync_login)
            user_path = "/api/node/mo/uni/userext/user-%s.json" % sync_login
            resp = self.delete(user_path)
            dbg("%s: %s" % (user_path, resp.text))

        for path, config in data:
            try:
                if path in ignore_list:
                    continue
                if config is not None:
                    resp = self.post(path, config)
                    self.check_resp(resp)
                    dbg("%s: %s" % (path, resp.text))
            except Exception as e:
                # log it, otherwise ignore it
                self.errors += 1
                err("Error in provisioning %s: %s" % (path, str(e)))

    def unprovision(self, data, system_id, tenant, vrf_tenant, cluster_tenant, old_naming, cfg, l3out_name=None, lnodep=None, lifp=None):
        cluster_tenant_path = "/api/mo/uni/tn-%s.json" % cluster_tenant
        shared_resources = ["/api/mo/uni/infra.json", "/api/mo/uni/tn-common.json", cluster_tenant_path]

        if vrf_tenant not in ["common", system_id]:
            shared_resources.append("/api/mo/uni/tn-%s.json" % vrf_tenant)

        try:
            if "calico" in cfg['flavor']:
                fsvi_path = "/api/node/mo/uni/tn-%s/out-%s/lnodep-%s/lifp-%s.json" % (tenant, l3out_name, lnodep, lifp)
                fsvi_path += "?query-target=children&target-subtree-class=l3extVirtualLIfP"
                resp = self.get(fsvi_path)
                self.check_resp(resp)
                respj = json.loads(resp.text)
                respj = respj["imdata"]
                for resp in respj:
                    for val in resp.values():
                        del_path = "/api/node/mo/" + val['attributes']['dn'] + ".json"
                        resp = self.delete(del_path)
                        self.check_resp(resp)
                        dbg("%s: %s" % (del_path, resp.text))
                conf_node_path = "/api/node/mo/uni/tn-%s/out-%s/lnodep-%s.json" % (tenant, l3out_name, lnodep)
                conf_node_path += "?query-target=children&target-subtree-class=l3extRsNodeL3OutAtt"
                resp = self.get(conf_node_path)
                self.check_resp(resp)
                respj = json.loads(resp.text)
                respj = respj["imdata"]
                for resp in respj:
                    for val in resp.values():
                        del_path = "/api/node/mo/" + val['attributes']['dn'] + ".json"
                        resp = self.delete(del_path)
                        self.check_resp(resp)
                        dbg("%s: %s" % (del_path, resp.text))
                bgp_prot_path = "/api/node/mo/uni/tn-%s/out-%s/lnodep-%s/protp.json" % (tenant, l3out_name, lnodep)
                resp = self.delete(bgp_prot_path)
                self.check_resp(resp)
                dbg("%s: %s" % (bgp_prot_path, resp.text))
                bgp_res_path = "/api/node/mo/uni/tn-%s.json" % tenant
                bgp_res_path += "?query-target=children&target-subtree-class=bgpCtxPol,bgpCtxAfPol,bgpBestPathCtrlPol,bgpPeerPfxPol"
                resp = self.get(bgp_res_path)
                self.check_resp(resp)
                respj = json.loads(resp.text)
                respj = respj["imdata"]
                for resp in respj:
                    for val in resp.values():
                        if l3out_name in val['attributes']['dn']:
                            del_path = "/api/node/mo/" + val['attributes']['dn'] + ".json"
                            resp = self.delete(del_path)
                            self.check_resp(resp)
                            dbg("%s: %s" % (del_path, resp.text))
                bgp_route_path = "/api/node/mo/uni/tn-%s/out-%s.json" % (tenant, l3out_name)
                bgp_route_path += "?query-target=children&target-subtree-class=rtctrlProfile"
                resp = self.get(bgp_route_path)
                self.check_resp(resp)
                respj = json.loads(resp.text)
                respj = respj["imdata"]
                for resp in respj:
                    for val in resp.values():
                        del_path = "/api/node/mo/" + val['attributes']['dn'] + ".json"
                        resp = self.delete(del_path)
                        self.check_resp(resp)
                        dbg("%s: %s" % (del_path, resp.text))
            else:
                for path, config in data:
                    if path.split("/")[-1].startswith("instP-"):
                        continue
                    if path not in shared_resources:
                        resp = self.delete(path)
                        self.check_resp(resp)
                        dbg("%s: %s" % (path, resp.text))
                    else:
                        if path == cluster_tenant_path:
                            path += "?query-target=children"
                            resp = self.get(path)
                            self.check_resp(resp)
                            respj = json.loads(resp.text)
                            respj = respj["imdata"]
                            for resp in respj:
                                for val in resp.values():
                                    if 'rsTenantMonPol' not in val['attributes']['dn'] and 'svcCont' not in val['attributes']['dn']:
                                        del_path = "/api/node/mo/" + val['attributes']['dn'] + ".json"
                                        if 'name' in val['attributes']:
                                            name = val['attributes']['name']
                                            if (not old_naming) and (system_id in name):
                                                resp = self.delete(del_path)
                                                self.check_resp(resp)
                                                dbg("%s: %s" % (del_path, resp.text))

            if old_naming:
                for object in self.TENANT_OBJECTS:
                    del_path = "/api/node/mo/uni/tn-%s/%s.json" % (cluster_tenant, object)
                    resp = self.delete(del_path)
                    self.check_resp(resp)
                    dbg("%s: %s" % (del_path, resp.text))

        except Exception as e:
            # log it, otherwise ignore it
            self.errors += 1
            err("Error in un-provisioning %s: %s" % (path, str(e)))

        # Clean the cluster tenant iff it has our annotation and does
        # not have any application profiles
        if self.check_valid_annotation(cluster_tenant_path) and self.check_no_ap(cluster_tenant_path):
            self.delete(cluster_tenant_path)

        # Finally clean any stray resources in common
        self.clean_tagged_resources(system_id, tenant)

    def process_apic_version_string(self, raw):
        # Given the APIC version for example 5.2(3e), convert it to 5.2.3 for comparison
        split_string = raw.split('(')
        major_version = split_string[0]
        minor_string = split_string[1]
        numeric_filter = filter(str.isdigit, minor_string)
        minor_version = "".join(numeric_filter)
        return (major_version + '.' + minor_version)

    def get_apic_version(self):
        path = "/api/node/class/firmwareCtrlrRunning.json"
        version = "1.0"
        try:
            data = self.get_path(path)
            versionStr = data['firmwareCtrlrRunning']['attributes']['version']
            version = self.process_apic_version_string(versionStr)
            dbg("APIC version obtained: %s, processed version: %s" % (versionStr, version))
        except Exception as e:
            dbg("Unable to get APIC version object %s: %s" % (path, str(e)))
        return version

    def check_valid_annotation(self, path):
        try:
            data = self.get_path(path)
            if data['fvTenant']['attributes']['annotation'] == aciContainersOwnerAnnotation:
                return True
        except Exception as e:
            dbg("Unable to find APIC object %s: %s" % (path, str(e)))
        return False

    def check_no_ap(self, path):
        path += "?query-target=children"
        if 'fvAp' in self.get_path(path):
            return False
        return True

    def valid_tagged_resource(self, tag, system_id, tenant):
        ret = False
        prefix = "%s-" % system_id
        if tag.startswith(prefix):
            tagid = tag[len(prefix):]
            if len(tagid) == 32:
                try:
                    int(tagid, base=16)
                    ret = True
                except ValueError:
                    ret = False
        return ret

    def clean_tagged_resources(self, system_id, tenant):

        try:
            mos = collections.OrderedDict([])
            # collect tagged resources
            tags = collections.OrderedDict([])
            tags_path = "/api/node/mo/uni/tn-%s.json" % (tenant,)
            tags_path += "?query-target=subtree&target-subtree-class=tagInst"
            tags_list = self.get_path(tags_path, multi=True)
            if tags_list is not None:
                for tag_mo in tags_list:
                    tag_name = tag_mo["tagInst"]["attributes"]["name"]
                    if self.valid_tagged_resource(tag_name, system_id, tenant):
                        tags[tag_name] = True
                        dbg("Deleting tag: %s" % tag_name)
                    else:
                        dbg("Ignoring tag: %s" % tag_name)

            for tag in tags.keys():
                dbg("Objcts selected for tag: %s" % tag)
                mo_path = "/api/tag/%s.json" % tag
                mo_list = self.get_path(mo_path, multi=True)
                for mo_dict in mo_list:
                    for mo_key in mo_dict.keys():
                        mo = mo_dict[mo_key]
                        mo_dn = mo["attributes"]["dn"]
                        mos[mo_dn] = True
                        dbg("    - %s" % mo_dn)

            # collect resources with annotation
            annot_path = "/api/node/mo/uni/tn-%s.json" % (tenant,)
            annot_path += "?query-target=subtree&target-subtree-class=tagAnnotation"
            annot_list = self.get_path(annot_path, multi=True)
            if annot_list is not None:
                for tag_mo in annot_list:
                    tag_name = tag_mo["tagAnnotation"]["attributes"]["value"]
                    if self.valid_tagged_resource(tag_name, system_id, tenant):
                        dbg("Deleting tag: %s" % tag_name)
                        parent_dn = tag_mo["tagAnnotation"]["attributes"]["dn"]
                        reg = re.search('(.*)(/annotationKey.*)', parent_dn)
                        dn_name = reg.group(1)
                        dn_path = "/api/node/mo/" + dn_name + ".json"
                        resp = self.get(dn_path)
                        self.check_resp(resp)
                        respj = json.loads(resp.text)
                        ret = respj["imdata"][0]
                        for obj, att in ret.items():
                            if att["attributes"]["annotation"] == "orchestrator:aci-containers-controller":
                                mos[dn_name] = True
                            else:
                                dbg("Ignoring tag: %s" % tag_name)

            for mo_dn in sorted(mos.keys(), reverse=True):
                mo_path = "/api/node/mo/%s.json" % mo_dn
                dbg("Deleting object: %s" % mo_dn)
                self.delete(mo_path)

        except Exception as e:
            self.errors += 1
            err("Error in deleting tags: %s" % str(e))


class ApicKubeConfig(object):

    ACI_PREFIX = aci_prefix

    def __init__(self, config, apic):
        self.config = config
        self.apic = apic if apic else None
        self.use_kubeapi_vlan = True
        self.tenant_generator = "kube_tn"
        self.associate_aep_to_nested_inside_domain = False

    def get_nested_domain_type(self):
        inside = self.config["aci_config"]["vmm_domain"].get("nested_inside")
        if not inside:
            return None
        t = inside.get("type")
        if t and t.lower() == "vmware":
            return "VMware"
        return t

    @staticmethod
    def save_config(config, outfilep):
        for path, data in config:
            print(path, file=outfilep)
            print(data, file=outfilep)

    def is_newer_version(self, new, old):
        # Expects string arg like "5.2.0"
        return (StrictVersion(new) >= StrictVersion(old))

    def get_config(self, apic_version):
        def assert_attributes_is_first_key(data):
            """Check that attributes is the first key in the JSON."""
            if isinstance(data, Mapping) and "attributes" in data:
                assert next(iter(data.keys())) == "attributes"
                for item in data.items():
                    assert_attributes_is_first_key(item)
            elif isinstance(data, (list, tuple)):
                for item in data:
                    assert_attributes_is_first_key(item)

        def update(data, x):
            if x:
                assert_attributes_is_first_key(x)
                data.append((x[0], json.dumps(
                    x[1],
                    indent=4,
                    separators=(",", ": "))))
                for path in x[2:]:
                    data.append((path, None))

        data = []
        if "calico" not in self.config['flavor']:
            update(data, self.pdom_pool())
            update(data, self.vdom_pool())
            update(data, self.mcast_pool())
            update(data, self.phys_dom())
            update(data, self.kube_dom(apic_version))
            update(data, self.nested_dom())
            update(data, self.associate_aep())
            update(data, self.opflex_cert(apic_version))
            self.apic_version = apic_version
            if self.is_newer_version(apic_version, "5.0"):
                update(data, self.cluster_info())

            update(data, self.l3out_tn())
            update(data, getattr(self, self.tenant_generator)(self.config['flavor']))
            update(data, self.add_apivlan_for_second_portgroup())
            update(data, self.nested_dom_second_portgroup())
            for l3out_instp in self.config["aci_config"]["l3out"]["external_networks"]:
                update(data, self.l3out_contract(l3out_instp))

        else:
            # l3out has to be updated with "L3 Domain". Also ensure that the VRF is correct
            update(data, self.logical_node_profile())
            node_ids = None
            if self.apic is not None:
                node_ids = self.apic.get_configured_node_dns(self.config["aci_config"]["vrf"]["tenant"], self.config["aci_config"]["l3out"]["name"], self.config["aci_config"]["l3out"]["svi"]["node_profile_name"])
            else:
                # For "calico" flavor based UT
                node_ids = ["topology/pod-1/node-101", "topology/pod-1/node-102"]
            for rack in self.config["topology"]["rack"]:
                for leaf in rack["leaf"]:
                    if "local_ip" in leaf:
                        update(data, self.calico_floating_svi(rack["aci_pod_id"], leaf["id"], leaf["local_ip"]))
                    if "id" in leaf and ("topology/pod-%s/node-%s" % (rack["aci_pod_id"], leaf["id"])) not in node_ids:
                        update(data, self.add_configured_nodes(rack["aci_pod_id"], leaf["id"]))

            update(data, self.ext_epg_svc())
            update(data, self.add_subnets_to_ext_epg())
            update(data, self.enable_bgp())
            update(data, self.bgp_route_control())
            update(data, self.bgp_timers())
            update(data, self.bgp_relax_as_policy())
            update(data, self.bgp_prot_pfl())
            update(data, self.bgp_addr_family_context())
            update(data, self.bgp_addr_family_context_to_vrf())
            update(data, self.bgp_addr_family_context_to_vrf_v6())
            update(data, self.export_match_rule())
            update(data, self.attach_rule_to_default_export_pol())
            update(data, self.import_match_rule())
            update(data, self.attach_rule_to_default_import_pol())
            update(data, self.bgp_peer_prefix())
        update(data, self.kube_user())
        update(data, self.kube_cert())
        return data

    def annotateApicObjects(self, data, pre_existing_tenant=False, ann=aciContainersOwnerAnnotation):
        # apic objects are dicts of length 1
        assert(len(data) <= 1)
        for key, value in data.items():
            if "children" in value.keys():
                children = value["children"]
                for i in range(len(children)):
                    self.annotateApicObjects(children[i], ann=ann)
            break
        if not key == "fvTenant":
            data[key]["attributes"]["annotation"] = ann
        elif not (data[key]["attributes"]["name"] == "common") and not (pre_existing_tenant):
            data[key]["attributes"]["annotation"] = ann

    def cluster_info(self):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vmm_type = self.config["aci_config"]["vmm_domain"]["type"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        vmm_inj_cluster_type = self.config["aci_config"]["vmm_domain"]["injected_cluster_type"]
        vmm_inj_cluster_provider = self.config["aci_config"]["vmm_domain"]["injected_cluster_provider"]
        accProvisionInput = self.config["user_input"]
        key_data = cert_data = ''
        if self.config["aci_config"]["sync_login"]["key_data"]:
            key_data = self.config["aci_config"]["sync_login"]["key_data"].decode('ascii')
        if self.config["aci_config"]["sync_login"]["cert_data"]:
            cert_data = self.config["aci_config"]["sync_login"]["cert_data"].decode('ascii')

        path = "/api/node/mo/comp/prov-%s/ctrlr-[%s]-%s/injcont/info.json" % (vmm_type, vmm_name, vmm_name)
        data = collections.OrderedDict(
            [
                (
                    "vmmInjectedClusterInfo",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", vmm_name),
                                        ("accountName", tn_name),
                                        ("type", vmm_inj_cluster_type),
                                        ("provider", vmm_inj_cluster_provider)
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vmmInjectedClusterDetails",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "accProvisionInput",
                                                                        accProvisionInput,
                                                                    ),
                                                                    (
                                                                        "userKey",
                                                                        key_data,
                                                                    ),
                                                                    (
                                                                        "userCert",
                                                                        cert_data,
                                                                    ),
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ]
                            ),
                        ]
                    )
                )
            ]
        )
        return path, data

    def pdom_pool(self):
        pool_name = self.config["aci_config"]["physical_domain"]["vlan_pool"]
        service_vlan = self.config["net_config"]["service_vlan"]

        path = "/api/mo/uni/infra/vlanns-[%s]-static.json" % pool_name
        data = collections.OrderedDict(
            [
                (
                    "fvnsVlanInstP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [("name", pool_name), ("allocMode", "static")]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "fvnsEncapBlk",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "allocMode",
                                                                        "static",
                                                                    ),
                                                                    (
                                                                        "from",
                                                                        "vlan-%s"
                                                                        % service_vlan,
                                                                    ),
                                                                    (
                                                                        "to",
                                                                        "vlan-%s"
                                                                        % service_vlan,
                                                                    ),
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                ),
                                            )
                                        ]
                                    )
                                ],
                            ),
                        ]
                    ),
                )
            ]
        )
        # To avoid kubeapi_vlan from being added to the vlan_pool for ESX install
        if not self.config["aci_config"]["no_physdom_for_node_epg"]:
            if self.use_kubeapi_vlan:
                kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
                data["fvnsVlanInstP"]["children"].insert(
                    0,
                    collections.OrderedDict(
                        [
                            (
                                "fvnsEncapBlk",
                                collections.OrderedDict(
                                    [
                                        (
                                            "attributes",
                                            collections.OrderedDict(
                                                [
                                                    ("allocMode", "static"),
                                                    ("from", "vlan-%s" % kubeapi_vlan),
                                                    ("to", "vlan-%s" % kubeapi_vlan),
                                                ]
                                            ),
                                        )
                                    ]
                                ),
                            )
                        ]
                    ),
                )
        self.annotateApicObjects(data)
        return path, data

    def vdom_pool(self):
        encap_type = self.config["aci_config"]["vmm_domain"]["encap_type"]
        vpool_name = self.config["aci_config"]["vmm_domain"]["vlan_pool"]
        vlan_range = self.config["aci_config"]["vmm_domain"]["vlan_range"]

        if encap_type != "vlan":
            return None

        path = "/api/mo/uni/infra/vlanns-[%s]-dynamic.json" % vpool_name
        data = collections.OrderedDict(
            [
                (
                    "fvnsVlanInstP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [("name", vpool_name), ("allocMode", "dynamic")]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "fvnsEncapBlk",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "allocMode",
                                                                        "dynamic",
                                                                    ),
                                                                    (
                                                                        "from",
                                                                        "vlan-%s"
                                                                        % vlan_range[
                                                                            "start"
                                                                        ],
                                                                    ),
                                                                    (
                                                                        "to",
                                                                        "vlan-%s"
                                                                        % vlan_range[
                                                                            "end"
                                                                        ],
                                                                    ),
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                ),
                                            )
                                        ]
                                    )
                                ],
                            ),
                        ]
                    ),
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def mcast_pool(self):
        mpool_name = self.config["aci_config"]["vmm_domain"]["mcast_pool"]
        mcast_start = self.config["aci_config"]["vmm_domain"]["mcast_range"]["start"]
        mcast_end = self.config["aci_config"]["vmm_domain"]["mcast_range"]["end"]

        path = "/api/mo/uni/infra/maddrns-%s.json" % mpool_name
        data = collections.OrderedDict(
            [
                (
                    "fvnsMcastAddrInstP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", mpool_name),
                                        ("dn", "uni/infra/maddrns-%s" % mpool_name),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "fvnsMcastAddrBlk",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "from",
                                                                        mcast_start,
                                                                    ),
                                                                    ("to", mcast_end),
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                ),
                                            )
                                        ]
                                    )
                                ],
                            ),
                        ]
                    ),
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def phys_dom(self):
        phys_name = self.config["aci_config"]["physical_domain"]["domain"]
        pool_name = self.config["aci_config"]["physical_domain"]["vlan_pool"]

        path = "/api/mo/uni/phys-%s.json" % phys_name
        data = collections.OrderedDict(
            [
                (
                    "physDomP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("dn", "uni/phys-%s" % phys_name),
                                        ("name", phys_name),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "infraRsVlanNs",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "tDn",
                                                                        "uni/infra/vlanns-[%s]-static"
                                                                        % pool_name,
                                                                    )
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                ),
                                            )
                                        ]
                                    )
                                ],
                            ),
                        ]
                    ),
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def kube_dom(self, apic_version):
        vmm_type = self.config["aci_config"]["vmm_domain"]["type"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        encap_type = self.config["aci_config"]["vmm_domain"]["encap_type"]
        mcast_fabric = self.config["aci_config"]["vmm_domain"]["mcast_fabric"]
        mpool_name = self.config["aci_config"]["vmm_domain"]["mcast_pool"]
        vpool_name = self.config["aci_config"]["vmm_domain"]["vlan_pool"]
        kube_controller = self.config["kube_config"]["controller"]
        cluster_provider = self.config["aci_config"]["vmm_domain"]["injected_cluster_provider"]

        mode = "k8s"
        scope = "kubernetes"
        if vmm_type == "OpenShift":
            mode = "openshift"
            scope = "openshift"
        elif self.is_newer_version(apic_version, "5.1") and cluster_provider == "Rancher":
            mode = "rancher"

        path = "/api/mo/uni/vmmp-%s/dom-%s.json" % (vmm_type, vmm_name)
        data = collections.OrderedDict(
            [
                (
                    "vmmDomP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", vmm_name),
                                        ("mode", mode),
                                        ("enfPref", "sw"),
                                        ("encapMode", encap_type),
                                        ("prefEncapMode", encap_type),
                                        ("mcastAddr", mcast_fabric),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vmmCtrlrP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("name", vmm_name),
                                                                    ("mode", mode),
                                                                    ("scope", scope),
                                                                    (
                                                                        "hostOrIp",
                                                                        kube_controller,
                                                                    ),
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vmmRsDomMcastAddrNs",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "tDn",
                                                                        "uni/infra/maddrns-%s"
                                                                        % mpool_name,
                                                                    )
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    ),
                )
            ]
        )
        if encap_type == "vlan":
            vlan_pool_data = collections.OrderedDict(
                [
                    (
                        "infraRsVlanNs",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [
                                            (
                                                "tDn",
                                                "uni/infra/vlanns-[%s]-dynamic"
                                                % vpool_name,
                                            )
                                        ]
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            )
            data["vmmDomP"]["children"].append(vlan_pool_data)
        self.annotateApicObjects(data)
        return path, data

    def capic_kube_dom(self):
        vmm_type = "Kubernetes"
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        kube_controller = self.config["kube_config"]["controller"]

        mode = "k8s"
        scope = "kubernetes"

        path = "/api/mo/uni/vmmp-%s/dom-%s.json" % (vmm_type, vmm_name)
        data = collections.OrderedDict(
            [
                (
                    "vmmDomP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", vmm_name),
                                        ("mode", mode),
                                        ("enfPref", "sw"),
                                        ("prefEncapMode", "vxlan"),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vmmCtrlrP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("name", vmm_name),
                                                                    ("mode", mode),
                                                                    ("scope", scope),
                                                                    ("rootContName", vmm_name),
                                                                    (
                                                                        "hostOrIp",
                                                                        kube_controller,
                                                                    ),
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ],
                    ),
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def make_entry(self, e_spec):
        name = e_spec["name"]
        data = aci_obj("vzEntry", [('name', name)])

        if 'prot' in e_spec.keys():
            data["vzEntry"]["attributes"]["etherT"] = "ipv4"
            data["vzEntry"]["attributes"]["prot"] = e_spec['prot']

        if 'range' in e_spec.keys():
            data["vzEntry"]["attributes"]["dFromPort"] = str(e_spec['range'][0])
            data["vzEntry"]["attributes"]["dToPort"] = str(e_spec['range'][1])

        return data

    def vmm_scoped_name(self, name):
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        return "{}_{}".format(vmm_name, name)

    def make_contract(self, c_spec):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        name = self.vmm_scoped_name(c_spec["name"])
        path = "/api/mo/uni/tn-%s/brc-%s.json" % (tn_name, name)
        filts = []

        fname = self.vmm_scoped_name(c_spec["filter"])
        filts.append(aci_obj("vzRsSubjFiltAtt", [('tnVzFilterName', fname)]))
        subj = aci_obj(
            "vzSubj",
            [('name', name + "_sub"),
             ('consMatchT', "AtleastOne"),
             ('provMatchT', "AtleastOne"),
             ('_children', filts)],
        )

        children = []
        children.append(subj)
        p_list = []
        if "scope" in c_spec:
            p_list.append(('scope', c_spec["scope"]))
        p_list = p_list + [('name', name), ('_children', children)]
        return path, aci_obj("vzBrCP", p_list)

    def make_filter(self, f_spec):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        name = self.vmm_scoped_name(f_spec["name"])
        path = "/api/mo/uni/tn-%s/flt-%s.json" % (tn_name, name)
        children = []
        for e in f_spec["entries"]:
            emo = self.make_entry(e)
            children.append(emo)

        return path, aci_obj("vzFilter", [('name', name), ('_children', children)])

    def capic_epg(self, name, vrf_name):
        provider = self.config["cloud"]["provider"]
        children = []
        children.append(aci_obj("cloudRsCloudEPgCtx", [('tnFvCtxName', vrf_name)]))
        self.add_configured_contracts(name, children)
        if name == "ul-nodes" and provider == "azure":
            return aci_obj("cloudSvcEPg", [('name', name), ('deploymentType', "CloudNativeManaged"), ('type', "Azure-AksCluster"), ('accessType', "public&private"), ('_children', children)])
        return aci_obj("cloudEPg", [('name', name), ('_children', children)])

    def capic_cloudApp(self, ap_name):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        path = "/api/mo/uni/tn-%s/cloudapp-%s.json" % (tn_name, ap_name)
        data = collections.OrderedDict(
            [
                (
                    "cloudApp",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", ap_name),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )
        return path, data

    def capic_overlay_cloudApp(self):
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        path, data = self.capic_cloudApp(vmm_name)
        overlayVrfName = self.get_overlay_vrf_name()

        epg_list = ["default", "system", "nodes", "inet-out"]
        for epg in epg_list:
            epg_obj = self.capic_epg(self.ACI_PREFIX + epg, overlayVrfName)
            data["cloudApp"]["children"].append(epg_obj)
        # add custom epgs
        for epg in self.config["aci_config"].get("custom_epgs", []):
            epg_obj = self.capic_epg(epg, overlayVrfName)
            data["cloudApp"]["children"].append(epg_obj)

        return path, data

    def add_configured_contracts(self, name, children):
        for c in self.config["aci_config"]["contracts"]:
            if name in c["consumed"]:
                c_name = self.vmm_scoped_name(c['name'])
                children.append(aci_obj("fvRsCons", [('tnVzBrCPName', c_name)]))
        for c in self.config["aci_config"]["contracts"]:
            if name in c["provided"]:
                c_name = self.vmm_scoped_name(c['name'])
                children.append(aci_obj("fvRsProv", [('tnVzBrCPName', c_name)]))

    def capic_underlay_epg(self, name, ipsel):
        provider = self.config["cloud"]["provider"]
        vrf_name = self.config["aci_config"]["vrf"]["name"]
        children = []
        children.append(aci_obj("cloudRsCloudEPgCtx", [('tnFvCtxName', vrf_name)]))
        count = 0
        for sel in ipsel:
            match = "IP==\'{}\'".format(sel)
            count = count + 1
            sel_id = "sel{}".format(count)
            if name == "ul-nodes" and provider == "azure":
                children.append(aci_obj("cloudSvcEPSelector", [('name', sel_id), ("matchExpression", match)]))
            else:
                children.append(aci_obj("cloudEPSelector", [('name', sel_id), ("matchExpression", match)]))

        self.add_configured_contracts(name, children)

        if name == "ul-nodes" and provider == "azure":
            return aci_obj("cloudSvcEPg", [('name', name), ('deploymentType', "CloudNativeManaged"), ('type', "Azure-AksCluster"), ('accessType', "PublicAndPrivate"), ('_children', children)])

        epg = aci_obj(
            "cloudEPg",
            [('name', name),
             ('_children', children)],
        )

        return epg

    def capic_ext_epg(self, name, subnet):
        vrf_name = self.config["aci_config"]["vrf"]["name"]
        children = []
        children.append(aci_obj("cloudRsCloudEPgCtx", [('tnFvCtxName', vrf_name)]))
        children.append(aci_obj("cloudExtEPSelector", [('name', "sel1"), ("subnet", subnet)]))
        self.add_configured_contracts(name, children)
        attr = [('name', name)]
        if subnet == "0.0.0.0/0":
            attr = attr + [('routeReachability', 'internet')]

        attr = attr + [('_children', children)]

        epg = aci_obj(
            "cloudExtEPg",
            attr,
        )

        return epg

    def capic_underlay_cloudApp(self):
        appName = self.vmm_scoped_name("ul_ap")
        path, data = self.capic_cloudApp(appName)

        boot_epg_obj = self.capic_underlay_epg("ul-boot", [self.config["net_config"]["bootstrap_subnet"]])
        data["cloudApp"]["children"].append(boot_epg_obj)
        node_epg_obj = self.capic_underlay_epg("ul-nodes", [self.config["net_config"]["node_subnet"]])
        data["cloudApp"]["children"].append(node_epg_obj)

        cidr_epg_obj = self.capic_ext_epg("cidr-ext", self.config["net_config"]["machine_cidr"])
        data["cloudApp"]["children"].append(cidr_epg_obj)
        inet_epg_obj = self.capic_ext_epg("inet-ext", "0.0.0.0/0")
        data["cloudApp"]["children"].append(inet_epg_obj)

        return path, data

    def capic_underlay_p(self, underlay_ccp_dn):
        data = collections.OrderedDict(
            [
                (
                    "cloudCtxUnderlayP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )

        rsToUnderlay = collections.OrderedDict(
            [
                (
                    "cloudRsToUnderlayCtxProfile",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("tDn", underlay_ccp_dn),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )

        data["cloudCtxUnderlayP"]["children"].append(rsToUnderlay)
        return data

    def get_overlay_vrf_name(self):
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        overlay_vrf_name = vmm_name + "_overlay"
        return overlay_vrf_name

    def vrf_object(self, vrf_name):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        path = "/api/mo/uni/tn-%s/ctx-%s.json" % (tn_name, vrf_name)
        data = collections.OrderedDict(
            [
                (
                    "fvCtx",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", vrf_name),
                                    ]
                                ),
                            ),
                        ]
                    )
                ),
            ]
        )
        return path, data

    def capic_overlay_vrf(self):
        overlay_vrf_name = self.get_overlay_vrf_name()
        return self.vrf_object(overlay_vrf_name)

    def capic_underlay_vrf(self):
        underlay_vrf_name = self.config["aci_config"]["vrf"]["name"]
        return self.vrf_object(underlay_vrf_name)

    def capic_rsToRegion(self):
        region = self.config["aci_config"]["vrf"]["region"]
        provider = self.config["cloud"]["provider"]
        regionDn = "uni/clouddomp/provp-{}/region-{}".format(provider, region)
        rsToRegion = collections.OrderedDict(
            [
                (
                    "cloudRsCtxProfileToRegion",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("tDn", regionDn),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )
        return rsToRegion

    def capic_underlay_ccp(self, subnets):
        underlay_cidr = self.config["net_config"]["machine_cidr"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        underlay_vrf_name = self.config["aci_config"]["vrf"]["name"]
        ccp_name = underlay_vrf_name + "_ccp"
        path = "/api/mo/uni/tn-%s/ctxprofile-%s.json" % (tn_name, ccp_name)
        data = collections.OrderedDict(
            [
                (
                    "cloudCtxProfile",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", ccp_name),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )

        rsToCtx = collections.OrderedDict(
            [
                (
                    "cloudRsToCtx",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("tnFvCtxName", underlay_vrf_name),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )
        rsToRegion = self.capic_rsToRegion()
        _, cidr = self.cloudCidr(ccp_name, underlay_cidr, subnets, "yes")
        child_list = [rsToRegion, rsToCtx, cidr]
        if "transit_subnet" in self.config["net_config"]:
            assert "routerP" in self.config["oper"]
            # add transit subnet
            t_net = self.config["net_config"]["transit_subnet"]
            region = self.config["aci_config"]["vrf"]["region"]
            zone = self.config["cloud"]["zone"]
            z_attach = self.zoneAttach(region, zone)
            t_subnet = aci_obj("cloudSubnet", [('ip', t_net), ('usage', 'gateway'), ('scope', "public,shared"), ('_children', [z_attach]), ])
            cidr["cloudCidr"]["children"].append(t_subnet)
            # attach routerP
            rp = self.config["oper"]["routerP"]
            rsToTouterP = aci_obj("cloudRsCtxProfileToGatewayRouterP", [('tDn', rp), ])
            child_list.append(rsToTouterP)

        for child in child_list:
            data["cloudCtxProfile"]["children"].append(child)

        return path, data

    def capic_overlay(self, underlay_ccp_dn):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        overlay_vrf_name = self.get_overlay_vrf_name()
        path = "/api/mo/uni/tn-%s/ctxprofile-%s.json" % (tn_name, vmm_name)
        data = collections.OrderedDict(
            [
                (
                    "cloudCtxProfile",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", vmm_name),
                                        ("type", "container-overlay"),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )

        rsToCtx = collections.OrderedDict(
            [
                (
                    "cloudRsToCtx",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("tnFvCtxName", overlay_vrf_name),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )

        rsToRegion = self.capic_rsToRegion()
        underlay_ref = self.capic_underlay_p(underlay_ccp_dn)
        pod_subnet = self.config["net_config"]["pod_subnet"]
        cidr = pod_subnet.replace(".1/", ".0/")
        snets = []
        snet_info = {"cidr": cidr, "zone": self.config["cloud"]["zone"]}
        snets.append(snet_info)
        _, cidrMo = self.cloudCidr(vmm_name, cidr, snets, "yes")

        child_list = [rsToRegion, underlay_ref, rsToCtx, cidrMo]

        for child in child_list:
            data["cloudCtxProfile"]["children"].append(child)

        return path, data

    def cloudCidr(self, ccp, cidr, subnets, primary):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        path = "/api/mo/uni/tn-{}/ctxprofile-{}/cidr-[{}].json".format(tn_name, ccp, cidr)
        cidrMo = collections.OrderedDict(
            [
                (
                    "cloudCidr",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("addr", cidr),
                                        ("primary", primary),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )

        for subnet in subnets:
            cidrMo["cloudCidr"]["children"].append(self.cloudSubnet(subnet))
        return path, cidrMo

    def cloudSubnet(self, snet_info):
        region = self.config["aci_config"]["vrf"]["region"]
        zone = snet_info["zone"]
        cidr = snet_info["cidr"]
        props = [("ip", cidr)]
        subnetMo = collections.OrderedDict(
            [
                (
                    "cloudSubnet",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    props,
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )

        subnetMo["cloudSubnet"]["children"].append(self.zoneAttach(region, zone))
        return subnetMo

    def zoneAttach(self, region, zone):
        provider = self.config["cloud"]["provider"]
        tDn = "uni/clouddomp/provp-{}/region-{}/zone-{}".format(provider, region, zone)
        zaMo = collections.OrderedDict(
            [
                (
                    "cloudRsZoneAttach",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("tDn", tDn),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )

        return zaMo

    def capic_overlay_dn_query(self):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        ctxProfDN = "uni/tn-%s/ctxprofile-%s" % (tn_name, vmm_name)
        filter = "eq(hcloudCtx.delegateDn, \"{}\")".format(ctxProfDN)
        query = '/api/node/class/hcloudCtx.json?query-target=self&query-target-filter={}'.format(filter)
        return query

    def capic_subnet_dn_query(self):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        pod_gw = self.config["net_config"]["pod_subnet"]
        pod_subnet = pod_gw.replace(".1/", ".0/")
        ctxProfDN = "uni/tn-%s/ctxprofile-%s" % (tn_name, vmm_name)
        subnetDN = "{}/cidr-[{}]/subnet-[{}]".format(ctxProfDN, pod_subnet, pod_subnet)
        filter = "eq(hcloudSubnet.delegateDn, \"{}\")".format(subnetDN)
        query = '/api/node/class/hcloudSubnet.json?query-target=self&query-target-filter={}'.format(filter)
        return query

    def capic_cluster_info(self, overlay_dn):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vmm_type = "Kubernetes"
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]

        path = "/api/node/mo/comp/prov-%s/ctrlr-[%s]-%s/injcont/info.json" % (vmm_type, vmm_name, vmm_name)
        data = collections.OrderedDict(
            [
                (
                    "vmmInjectedClusterInfo",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", vmm_name),
                                        ("overlayDn", overlay_dn),
                                        ("accountName", tn_name),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )
        return path, data

    def capic_vmm_host(self, hostname, ip, id):
        vmm_type = "Kubernetes"
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]

        path = "/api/node/mo/comp/prov-%s/ctrlr-[%s]-%s/injcont.json" % (vmm_type, vmm_name, vmm_name)
        data = collections.OrderedDict(
            [
                (
                    "vmmInjectedHost",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", "{}.{}".format(vmm_name, hostname)),
                                        ("id", id),
                                        ("mgmtIp", ip),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )
        return path, data

    def hostGen(self):
        return self.capic_vmm_host("node1", "192.168.101.12", "9876543210")

    def capic_kafka_topic(self):
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        path = "/api/node/mo/uni/userext/kafkaext/kafkatopic-%s.json" % (vmm_name)
        data = collections.OrderedDict(
            [
                (
                    "aaaKafkaTopic",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", "{}".format(vmm_name)),
                                        ("partition", "1"),
                                        ("replica", "3"),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )
        return path, data

    def capic_kafka_acl(self, cn):
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        path = "/api/node/mo/uni/userext/kafkaext/kafkaacl-%s.%s.json" % (vmm_name, cn)
        data = collections.OrderedDict(
            [
                (
                    "aaaKafkaAcl",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", "{}.{}".format(vmm_name, cn)),
                                        ("certdn", cn),
                                        ("topic", vmm_name),
                                        ("opr", "0"),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                []
                            ),
                        ]
                    )
                )
            ]
        )
        return path, data

    def nested_dom(self):
        nvmm_type = self.get_nested_domain_type()
        if nvmm_type != "VMware":
            return

        system_id = self.config["aci_config"]["system_id"]
        nvmm_portgroup = self.config["aci_config"]["vmm_domain"]["nested_inside"]["portgroup"]
        if nvmm_portgroup is None:
            nvmm_portgroup = system_id
        path, data = self.build_nested_dom_data(nvmm_portgroup, True, True, True)
        return path, data

    def add_apivlan_for_second_portgroup(self):
        nvmm_type = self.get_nested_domain_type()
        if nvmm_type != "VMware" or not self.config["net_config"]["second_kubeapi_portgroup"] or not self.config["net_config"]["kubeapi_vlan"]:
            return

        path, data = self.add_apivlan_to_vmm_vlanpool()
        return path, data

    def add_apivlan_to_vmm_vlanpool(self):
        # url: https://10.30.120.180/api/node/mo/uni/infra/vlanns-[hypf-vswitch-vlan-pool]-dynamic/from-[vlan-35]-to-[vlan-35].json
        # payload{"fvnsEncapBlk":{"attributes":{"dn":"uni/infra/vlanns-[hypf-vswitch-vlan-pool]-dynamic/from-[vlan-35]-to-[vlan-35]","from":"vlan-35","to":"vlan-35","rn":"from-[vlan-35]-to-[vlan-35]","status":"created"},"children":[]}}

        # nvmm_name = self.config["aci_config"]["vmm_domain"]["nested_inside"]["name"]
        kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
        # vpath = apic.get_vmmdom_vlanpool_tDn(nvmm_name)
        vpath = self.config['aci_config']['vmm_domain']['nested_inside']['vlan_pool']

        path = "/api/node/mo/%s/from-[vlan-%s]-to-[vlan-%s].json" % (vpath, kubeapi_vlan, kubeapi_vlan)
        data = collections.OrderedDict(
            [
                (
                    "fvnsEncapBlk",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("dn", "%s/from-[vlan-%s]-to-[vlan-%s]" % (vpath, kubeapi_vlan, kubeapi_vlan)),
                                        ("allocMode", "static"),
                                        ("from", "vlan-%s" % kubeapi_vlan),
                                        ("to", "vlan-%s" % kubeapi_vlan),
                                        ("rn", "from-[vlan-%s]-to-[vlan-%s]" % (kubeapi_vlan, kubeapi_vlan))
                                    ]
                                ),
                            ),
                        ]
                    ),
                ),
            ]
        )
        data["fvnsEncapBlk"]["children"] = []

        # self.annotateApicObjects(data)
        return path, data

    def nested_dom_second_portgroup(self):
        nvmm_type = self.get_nested_domain_type()
        if nvmm_type != "VMware" or not self.config["net_config"]["second_kubeapi_portgroup"] or not self.config["net_config"]["kubeapi_vlan"]:
            return

        path, data = self.add_vmm_domain_association()
        return path, data

    def add_vmm_domain_association(self):
        # url: https://10.30.120.180/api/node/mo/uni/tn-ocp4aci/ap-aci-containers-ocp4aci/epg-aci-containers-nodes.json
        # payload{"fvRsDomAtt":{"attributes":{"resImedcy":"immediate","tDn":"uni/vmmp-VMware/dom-hypflex-vswitch","instrImedcy":"immediate","encap":"vlan-35","status":"created"},"children":[{"vmmSecP":{"attributes":{"status":"created"},"children":[]}}]}}

        system_id = self.config["aci_config"]["system_id"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
        custom_epg_name = "%s_vlan_%d" % (system_id, kubeapi_vlan)
        nvmm_name = self.config["aci_config"]["vmm_domain"]["nested_inside"]["name"]
        tdn = "uni/vmmp-VMware/dom-%s" % (nvmm_name)
        vlan_encap = "vlan-%s" % (kubeapi_vlan)

        path = "/api/node/mo/uni/tn-%s/ap-aci-containers-%s/epg-aci-containers-nodes.json" % (
            tn_name,
            system_id
        )

        data = collections.OrderedDict(
            [
                (
                    "fvRsDomAtt",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("resImedcy", "immediate"),
                                        ("tDn", tdn),
                                        ("instrImedcy", "immediate"),
                                        ("customEpgName", custom_epg_name),
                                        ("encap", vlan_encap),
                                    ]
                                ),
                            ),
                        ]
                    ),
                ),
            ]
        )
        data["fvRsDomAtt"]["children"] = []

        self.annotateApicObjects(data)
        return path, data

    def build_nested_dom_data(self, nvmm_portgroup, infravlan, servicevlan, kubeapivlan):
        # Build a nested dom object based on the portgroup name and the
        # VLANs required(using booleans arguments for each VLAN)
        nvmm_type = self.get_nested_domain_type()
        nvmm_name = self.config["aci_config"]["vmm_domain"]["nested_inside"]["name"]
        nvmm_elag_name = self.config["aci_config"]["vmm_domain"]["nested_inside"]["elag_name"]
        encap_type = self.config["aci_config"]["vmm_domain"]["encap_type"]

        promMode = "Disabled"
        if encap_type == "vlan":
            promMode = "Enabled"

        path = "/api/mo/uni/vmmp-%s/dom-%s/usrcustomaggr-%s.json" % (
            nvmm_type,
            nvmm_name,
            nvmm_portgroup,
        )

        data = collections.OrderedDict(
            [
                (
                    "vmmUsrCustomAggr",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [("name", nvmm_portgroup),
                                     ("promMode", promMode)]
                                ),
                            ),
                        ]
                    ),
                )
            ]
        )
        data["vmmUsrCustomAggr"]["children"] = []

        if infravlan:
            infra_vlan = self.config["net_config"]["infra_vlan"]
            data["vmmUsrCustomAggr"]["children"].append(
                collections.OrderedDict(
                    [
                        (
                            "fvnsEncapBlk",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [
                                                ("from", "vlan-%d" % infra_vlan),
                                                ("to", "vlan-%d" % infra_vlan),
                                            ]
                                        ),
                                    )
                                ]
                            ),
                        )
                    ]
                )
            )

        if servicevlan:
            service_vlan = self.config["net_config"]["service_vlan"]
            data["vmmUsrCustomAggr"]["children"].append(
                collections.OrderedDict(
                    [
                        (
                            "fvnsEncapBlk",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [
                                                ("from", "vlan-%d" % service_vlan),
                                                ("to", "vlan-%d" % service_vlan),
                                            ]
                                        ),
                                    )
                                ]
                            ),
                        )
                    ]
                )
            )

        if kubeapivlan:
            kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
            data["vmmUsrCustomAggr"]["children"].append(
                collections.OrderedDict(
                    [
                        (
                            "fvnsEncapBlk",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [
                                                ("from", "vlan-%d" % kubeapi_vlan),
                                                ("to", "vlan-%d" % kubeapi_vlan),
                                            ]
                                        ),
                                    )
                                ]
                            ),
                        )
                    ]
                )
            )

        if encap_type == "vlan":
            vlan_range = self.config["aci_config"]["vmm_domain"]["vlan_range"]
            data["vmmUsrCustomAggr"]["children"].append(
                collections.OrderedDict(
                    [
                        (
                            "fvnsEncapBlk",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [
                                                (
                                                    "from",
                                                    "vlan-%d" % vlan_range["start"],
                                                ),
                                                ("to", "vlan-%d" % vlan_range["end"]),
                                            ]
                                        ),
                                    )
                                ]
                            ),
                        )
                    ]
                )
            )
        if nvmm_elag_name:
            nvmm_elag_dn = "uni/vmmp-VMware/dom-%s/vswitchpolcont/enlacplagp-%s" % (
                nvmm_name,
                nvmm_elag_name,
            )
            data["vmmUsrCustomAggr"]["children"].append(
                collections.OrderedDict(
                    [
                        (
                            "vmmRsUsrCustomAggrLagPolAtt",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [
                                                ("status", ""),
                                                ("tDn", nvmm_elag_dn),
                                            ]
                                        ),
                                    )
                                ]
                            ),
                        )
                    ]
                )
            )
        self.annotateApicObjects(data)
        return path, data

    def associate_aep(self):
        aep_name = self.config["aci_config"]["aep"]
        phys_name = self.config["aci_config"]["physical_domain"]["domain"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        infra_vlan = self.config["net_config"]["infra_vlan"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vmm_type = self.config["aci_config"]["vmm_domain"]["type"]
        system_id = self.config["aci_config"]["system_id"]
        aci_system_id = self.ACI_PREFIX + system_id

        path = "/api/mo/uni/infra.json"
        data = collections.OrderedDict(
            [
                (
                    "infraAttEntityP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict([("name", aep_name)]),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "infraRsDomP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "tDn",
                                                                        "uni/vmmp-%s/dom-%s"
                                                                        % (
                                                                            vmm_type,
                                                                            vmm_name,
                                                                        ),
                                                                    )
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "infraRsDomP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "tDn",
                                                                        "uni/phys-%s"
                                                                        % phys_name,
                                                                    )
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "infraProvAcc",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [("name", "provacc")]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "infraRsFuncToEpg",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "encap",
                                                                                                    "vlan-%s"
                                                                                                    % str(
                                                                                                        infra_vlan
                                                                                                    ),
                                                                                                ),
                                                                                                (
                                                                                                    "mode",
                                                                                                    "regular",
                                                                                                ),
                                                                                                (
                                                                                                    "tDn",
                                                                                                    "uni/tn-infra/ap-access/epg-default",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "dhcpInfraProvP",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "mode",
                                                                                                    "controller",
                                                                                                )
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    ),
                )
            ]
        )
        if self.use_kubeapi_vlan:
            kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
            kubeapi_vlan_mode = self.config["net_config"]["kubeapi_vlan_mode"]
            if self.config["aci_config"]["use_legacy_kube_naming_convention"]:
                data["infraAttEntityP"]["children"].append(
                    collections.OrderedDict(
                        [
                            (
                                "infraGeneric",
                                collections.OrderedDict(
                                    [
                                        (
                                            "attributes",
                                            collections.OrderedDict([("name", "default")]),
                                        ),
                                        (
                                            "children",
                                            [
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "infraRsFuncToEpg",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "attributes",
                                                                        collections.OrderedDict(
                                                                            [
                                                                                (
                                                                                    "tDn",
                                                                                    "uni/tn-%s/ap-kubernetes/epg-kube-nodes"
                                                                                    % (
                                                                                        tn_name,
                                                                                    ),
                                                                                ),
                                                                                (
                                                                                    "encap",
                                                                                    "vlan-%s"
                                                                                    % (
                                                                                        kubeapi_vlan,
                                                                                    ),
                                                                                ),
                                                                                (
                                                                                    "mode",
                                                                                    kubeapi_vlan_mode
                                                                                ),
                                                                            ]
                                                                        ),
                                                                    )
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                )
                                            ],
                                        ),
                                    ]
                                ),
                            )
                        ]
                    )
                )
            else:
                data["infraAttEntityP"]["children"].append(
                    collections.OrderedDict(
                        [
                            (
                                "infraGeneric",
                                collections.OrderedDict(
                                    [
                                        (
                                            "attributes",
                                            collections.OrderedDict([("name", "default")]),
                                        ),
                                        (
                                            "children",
                                            [
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "infraRsFuncToEpg",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "attributes",
                                                                        collections.OrderedDict(
                                                                            [
                                                                                (
                                                                                    "tDn",
                                                                                    "uni/tn-%s/ap-%s/epg-%snodes"
                                                                                    % (
                                                                                        tn_name,
                                                                                        aci_system_id,
                                                                                        self.ACI_PREFIX,
                                                                                    ),
                                                                                ),
                                                                                (
                                                                                    "encap",
                                                                                    "vlan-%s"
                                                                                    % (
                                                                                        kubeapi_vlan,
                                                                                    ),
                                                                                ),
                                                                                (
                                                                                    "mode",
                                                                                    kubeapi_vlan_mode
                                                                                ),
                                                                            ]
                                                                        ),
                                                                    )
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                )
                                            ],
                                        ),
                                    ]
                                ),
                            )
                        ]
                    )
                )

        base = "/api/mo/uni/infra/attentp-%s" % aep_name
        rsvmm = base + "/rsdomP-[uni/vmmp-%s/dom-%s].json" % (vmm_type, vmm_name)
        rsphy = base + "/rsdomP-[uni/phys-%s].json" % phys_name

        if self.associate_aep_to_nested_inside_domain:
            nvmm_name = self.config["aci_config"]["vmm_domain"]["nested_inside"]["name"]
            nvmm_type = self.get_nested_domain_type()
            data["infraAttEntityP"]["children"].append(
                collections.OrderedDict(
                    [
                        (
                            "infraRsDomP",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [
                                                (
                                                    "tDn",
                                                    "uni/vmmp-%s/dom-%s"
                                                    % (nvmm_type, nvmm_name),
                                                )
                                            ]
                                        ),
                                    )
                                ]
                            ),
                        )
                    ]
                )
            )
            rsnvmm = base + "/rsdomP-[uni/vmmp-%s/dom-%s].json" % (nvmm_type, nvmm_name)
            self.annotateApicObjects(data)
            return path, data, rsvmm, rsnvmm, rsphy
        else:
            if self.config["aci_config"]["use_legacy_kube_naming_convention"]:
                rsfun = (
                    base + "/gen-default/rsfuncToEpg-"
                    "[uni/tn-%s/ap-kubernetes/epg-kube-nodes].json" % (tn_name)
                )
            else:
                rsfun = (
                    base + "/gen-default/rsfuncToEpg-"
                    "[uni/tn-%s/ap-%s/epg-%snodes].json" % (tn_name, aci_system_id, aci_prefix)
                )
            self.annotateApicObjects(data)
            return path, data, rsvmm, rsphy, rsfun

    def opflex_cert(self, apic_version):
        client_cert = self.config["aci_config"]["client_cert"]
        client_ssl = self.config["aci_config"]["client_ssl"]

        path = "/api/mo/uni/infra.json"

        if self.is_newer_version(apic_version, "5.2.3"):
            authenticate_object = "leafOpflexpAuthenticateClients"
            ssl_object = "leafOpflexpUseSsl"
        else:
            authenticate_object = "opflexpAuthenticateClients"
            ssl_object = "opflexpUseSsl"

        data = collections.OrderedDict(
            [
                (
                    "infraSetPol",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        (
                                            "%s" % authenticate_object,
                                            yesno(client_cert),
                                        ),
                                        ("%s" % ssl_object, yesno(client_ssl)),
                                    ]
                                ),
                            )
                        ]
                    ),
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def l3out_tn(self):
        system_id = self.config["aci_config"]["system_id"]
        vrf_tenant = self.config["aci_config"]["vrf"]["tenant"]

        path = "/api/mo/uni/tn-%s.json" % vrf_tenant
        data = collections.OrderedDict(
            [
                (
                    "fvTenant",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", "%s" % vrf_tenant),
                                        ("dn", "uni/tn-%s" % vrf_tenant),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzFilter",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        "%s-allow-all-filter"
                                                                        % system_id,
                                                                    )
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "allow-all",
                                                                                                )
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                )
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzBrCP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        "%s-l3out-allow-all"
                                                                        % system_id,
                                                                    )
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzSubj",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "allow-all-subj",
                                                                                                ),
                                                                                                (
                                                                                                    "consMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                                (
                                                                                                    "provMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                    (
                                                                                        "children",
                                                                                        [
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "vzRsSubjFiltAtt",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzFilterName",
                                                                                                                                "%s-allow-all-filter"
                                                                                                                                % system_id,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            )
                                                                                        ],
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                )
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    ),
                )
            ]
        )

        flt = "/api/mo/uni/tn-%s/flt-%s-allow-all-filter.json" % (vrf_tenant, system_id)
        brc = "/api/mo/uni/tn-%s/brc-%s-l3out-allow-all.json" % (vrf_tenant, system_id)
        self.annotateApicObjects(data)
        return path, data, flt, brc

    def l3out_contract(self, l3out_instp):
        system_id = self.config["aci_config"]["system_id"]
        vrf_tenant = self.config["aci_config"]["vrf"]["tenant"]
        l3out = self.config["aci_config"]["l3out"]["name"]
        l3out_rsprov_name = "%s-l3out-allow-all" % system_id

        pathc = (vrf_tenant, l3out, l3out_instp)
        path = "/api/mo/uni/tn-%s/out-%s/instP-%s.json" % pathc
        data = collections.OrderedDict(
            [
                (
                    "fvRsProv",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("matchT", "AtleastOne"),
                                        ("tnVzBrCPName", l3out_rsprov_name),
                                    ]
                                ),
                            )
                        ]
                    ),
                )
            ]
        )

        rsprovc = (vrf_tenant, l3out, l3out_instp, l3out_rsprov_name)
        rsprov = "/api/mo/uni/tn-%s/out-%s/instP-%s/rsprov-%s.json" % rsprovc
        self.annotateApicObjects(data)
        return path, data, rsprov

    def kube_user(self):
        name = self.config["aci_config"]["sync_login"]["username"]
        password = self.config["aci_config"]["sync_login"]["password"]

        path = "/api/node/mo/uni/userext/user-%s.json" % name
        data = collections.OrderedDict(
            [
                (
                    "aaaUser",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [("name", name), ("accountStatus", "active")]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "aaaUserDomain",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [("name", "all")]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "aaaUserRole",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "admin",
                                                                                                ),
                                                                                                (
                                                                                                    "privType",
                                                                                                    "writePriv",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                )
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    )
                                ],
                            ),
                        ]
                    ),
                )
            ]
        )

        if password is not None:
            data["aaaUser"]["attributes"]["pwd"] = password
        self.annotateApicObjects(data)
        return path, data

    def kube_cert(self):
        name = self.config["aci_config"]["sync_login"]["username"]
        certfile = self.config["aci_config"]["sync_login"]["certfile"]

        if certfile is None:
            return None

        cert = None
        try:
            with open(certfile, "r") as cfile:
                cert = cfile.read()
        except IOError:
            # Ignore error in reading file, it will be logged if/when used
            pass

        path = "/api/node/mo/uni/userext/user-%s.json" % name
        data = collections.OrderedDict(
            [
                (
                    "aaaUser",
                    collections.OrderedDict(
                        [
                            ("attributes", collections.OrderedDict([("name", name)])),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "aaaUserCert",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        "%s.crt" % name,
                                                                    ),
                                                                    ("data", cert),
                                                                ]
                                                            ),
                                                        )
                                                    ]
                                                ),
                                            )
                                        ]
                                    )
                                ],
                            ),
                        ]
                    ),
                )
            ]
        )
        if cert is None:
            data = None
        if data:
            self.annotateApicObjects(data)
        return path, data

    def isV6(self):
        pod_cidr = self.config["net_config"]["pod_subnet"]
        rtr, mask = pod_cidr.split("/")
        ip = ipaddress.ip_address(rtr)
        if ip.version == 4:
            return False
        else:
            return True

    def editItems(self, config, old_naming):
        items = self.config["aci_config"]["items"]
        if items is None or len(items) == 0:
            err("Error in getting items for flavor")
        for idx in range(len(items)):
            if "consumed" in items[idx].keys():
                cons = items[idx]["consumed"]
                for idx1 in range(len(cons)):
                    if old_naming:
                        cons[idx1] = "kube-" + cons[idx1]
                    else:
                        cons[idx1] = self.ACI_PREFIX + cons[idx1]
                config["aci_config"]["items"][idx]["consumed"] = cons
            if "provided" in items[idx].keys():
                prov = items[idx]["provided"]
                for idx1 in range(len(prov)):
                    if old_naming:
                        prov[idx1] = "kube-" + prov[idx1]
                    else:
                        prov[idx1] = self.ACI_PREFIX + prov[idx1]
                config["aci_config"]["items"][idx]["provided"] = prov

    def kube_tn(self, flavor):
        system_id = self.config["aci_config"]["system_id"]
        app_profile = self.config["aci_config"]["app_profile"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        pre_existing_tenant = self.config["aci_config"]["use_pre_existing_tenant"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        phys_name = self.config["aci_config"]["physical_domain"]["domain"]
        kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
        kube_vrf = self.config["aci_config"]["vrf"]["name"]
        kube_l3out = self.config["aci_config"]["l3out"]["name"]
        node_subnet = self.config["net_config"]["node_subnet"]
        pod_subnet = self.config["net_config"]["pod_subnet"]
        kade = self.config["kube_config"].get("allow_kube_api_default_epg") or \
            self.config["kube_config"].get("allow_pods_kube_api_access")
        eade = self.config["kube_config"].get("allow_pods_external_access")
        vmm_type = self.config["aci_config"]["vmm_domain"]["type"]
        v6subnet = self.isV6()
        aci_prefix = "%s%s-" % (self.ACI_PREFIX, system_id)
        kube_prefix = "kube-"
        old_naming = self.config["aci_config"]["use_legacy_kube_naming_convention"]
        disable_node_subnet_creation = self.config["aci_config"]["disable_node_subnet_creation"]
        if old_naming:
            contract_prefix = ""
            api_contract_prefix = kube_prefix
            bd_prefix = kube_prefix
            filter_prefix = ""
            api_filter_prefix = kube_prefix
            fil_entry_prefix = kube_prefix
            epg_prefix = kube_prefix
            subj_prefix = kube_prefix
            v6_sub_prefix = kube_prefix
        else:
            contract_prefix = aci_prefix
            api_contract_prefix = aci_prefix
            bd_prefix = aci_prefix
            filter_prefix = aci_prefix
            api_filter_prefix = filter_prefix
            fil_entry_prefix = self.ACI_PREFIX
            epg_prefix = self.ACI_PREFIX
            subj_prefix = self.ACI_PREFIX
            v6_sub_prefix = aci_prefix

        node_bd_name = "%snode-bd" % bd_prefix
        node_epg_name = "%snodes" % epg_prefix

        kube_default_children = [
            collections.OrderedDict(
                [
                    (
                        "fvRsDomAtt",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [
                                            (
                                                "tDn",
                                                "uni/vmmp-%s/dom-%s"
                                                % (vmm_type, vmm_name),
                                            )
                                        ]
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            ),
            collections.OrderedDict(
                [
                    (
                        "fvRsCons",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict([("tnVzBrCPName", "%sdns" % contract_prefix)]),
                                )
                            ]
                        ),
                    )
                ]
            ),
            collections.OrderedDict(
                [
                    (
                        "fvRsProv",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [("tnVzBrCPName", "%shealth-check" % contract_prefix)]
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            ),
            collections.OrderedDict(
                [
                    (
                        "fvRsCons",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict([("tnVzBrCPName", "%sicmp" % contract_prefix)]),
                                )
                            ]
                        ),
                    )
                ]
            ),
            collections.OrderedDict(
                [
                    (
                        "fvRsCons",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict([("tnVzBrCPName", "%sistio" % contract_prefix)]),
                                )
                            ]
                        ),
                    )
                ]
            ),
            collections.OrderedDict(
                [
                    (
                        "fvRsBd",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [("tnFvBDName", "%spod-bd" % bd_prefix)]
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            ),
        ]

        if kade is True:
            kube_default_children.append(
                collections.OrderedDict(
                    [
                        (
                            "fvRsCons",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [("tnVzBrCPName", "%sapi" % api_contract_prefix)]
                                        ),
                                    )
                                ]
                            ),
                        )
                    ]
                )
            )

        if eade is True:
            kube_default_children.append(
                collections.OrderedDict(
                    [
                        (
                            "fvRsCons",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [("tnVzBrCPName",
                                              "%s-l3out-allow-all" % system_id)]
                                        ),
                                    )
                                ]
                            ),
                        )
                    ]
                )
            )

        node_subnet_obj = collections.OrderedDict(
            [
                (
                    "attributes",
                    collections.OrderedDict([("ip", node_subnet), ("scope", "public")]),
                )
            ]
        )

        pod_subnet_obj = collections.OrderedDict(
            [("attributes", collections.OrderedDict([("ip", pod_subnet)]))]
        )
        if eade is True:
            pod_subnet_obj["attributes"]["scope"] = "public"

        if v6subnet:
            ipv6_nd_policy_rs = [
                collections.OrderedDict(
                    [
                        (
                            "fvRsNdPfxPol",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [("tnNdPfxPolName", "%snd-ra-policy" % v6_sub_prefix)]
                                        ),
                                    )
                                ]
                            ),
                        )
                    ]
                )
            ]
            node_subnet_obj["attributes"]["ctrl"] = "nd"
            node_subnet_obj["children"] = ipv6_nd_policy_rs
            pod_subnet_obj["attributes"]["ctrl"] = "nd"
            pod_subnet_obj["children"] = ipv6_nd_policy_rs

        path = "/api/mo/uni/tn-%s.json" % tn_name
        data = collections.OrderedDict(
            [
                (
                    "fvTenant",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [("name", tn_name), ("dn", "uni/tn-%s" % tn_name)]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "fvAp",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [("name", app_profile)]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "fvAEPg",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "%sdefault" % epg_prefix,
                                                                                                )
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                    (
                                                                                        "children",
                                                                                        kube_default_children,
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "fvAEPg",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "%ssystem" % epg_prefix,
                                                                                                )
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                    (
                                                                                        "children",
                                                                                        [
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsProv",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%sdns" % contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsProv",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%sicmp" % contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsProv",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%shealth-check" % contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsCons",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%sicmp" % contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsCons",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%sapi" % api_contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsCons",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%s-l3out-allow-all"
                                                                                                                                % system_id,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsDomAtt",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tDn",
                                                                                                                                "uni/vmmp-%s/dom-%s"
                                                                                                                                % (
                                                                                                                                    vmm_type,
                                                                                                                                    vmm_name,
                                                                                                                                ),
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsBd",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnFvBDName",
                                                                                                                                "%spod-bd" % bd_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                        ],
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "fvAEPg",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    node_epg_name,
                                                                                                )
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                    (
                                                                                        "children",
                                                                                        [
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsProv",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%sdns" % contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsProv",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%sapi" % api_contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsProv",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%sicmp" % contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsCons",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%shealth-check" % contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsCons",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%s-l3out-allow-all"
                                                                                                                                % system_id,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsDomAtt",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tDn",
                                                                                                                                "uni/vmmp-%s/dom-%s"
                                                                                                                                % (vmm_type, vmm_name),
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsBd",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnFvBDName",
                                                                                                                                node_bd_name,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                        ],
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "fvAEPg",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "%sistio" % epg_prefix,
                                                                                                )
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                    (
                                                                                        "children",
                                                                                        [
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsProv",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%sistio" % contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsCons",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%sapi" % api_contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsCons",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%sicmp" % contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsProv",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%shealth-check" % contract_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsCons",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzBrCPName",
                                                                                                                                "%sdns" % contract_prefix
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsDomAtt",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tDn",
                                                                                                                                "uni/vmmp-%s/dom-%s"
                                                                                                                                % (vmm_type, vmm_name),
                                                                                                                            ),
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "fvRsBd",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnFvBDName",
                                                                                                                                "%spod-bd" % bd_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                        ],
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "fvBD",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        "%snode-bd" % bd_prefix,
                                                                    ),
                                                                    (
                                                                        "arpFlood",
                                                                        yesno(True),
                                                                    ),
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "fvSubnet",
                                                                            node_subnet_obj,
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "fvRsCtx",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "tnFvCtxName",
                                                                                                    kube_vrf,
                                                                                                )
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "fvRsBDToOut",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "tnL3extOutName",
                                                                                                    kube_l3out,
                                                                                                )
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "fvBD",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        "%spod-bd" % bd_prefix,
                                                                    )
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "fvSubnet",
                                                                            pod_subnet_obj,
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "fvRsCtx",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "tnFvCtxName",
                                                                                                    kube_vrf,
                                                                                                )
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            )
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "fvRsBDToOut",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "tnL3extOutName",
                                                                                                    kube_l3out,
                                                                                                )
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzFilter",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        "%sicmp-filter" % filter_prefix,
                                                                    )
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "icmp",
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ipv4",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "icmp",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "icmp6",
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ipv6",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "icmpv6",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzFilter",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        "%shealth-check-filter-in" % filter_prefix,
                                                                    )
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "health-check",
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ip",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "tcp",
                                                                                                ),
                                                                                                (
                                                                                                    "stateful",
                                                                                                    "no",
                                                                                                ),
                                                                                                (
                                                                                                    "tcpRules",
                                                                                                    "",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                )
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzFilter",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        "%shealth-check-filter-out" % filter_prefix,
                                                                    )
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "health-check",
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ip",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "tcp",
                                                                                                ),
                                                                                                (
                                                                                                    "stateful",
                                                                                                    "no",
                                                                                                ),
                                                                                                (
                                                                                                    "tcpRules",
                                                                                                    "est",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                )
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzFilter",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [("name", "%sdns-filter" % filter_prefix)]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "dns-udp",
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ip",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "udp",
                                                                                                ),
                                                                                                (
                                                                                                    "dFromPort",
                                                                                                    "dns",
                                                                                                ),
                                                                                                (
                                                                                                    "dToPort",
                                                                                                    "dns",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "dns-tcp",
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ip",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "tcp",
                                                                                                ),
                                                                                                (
                                                                                                    "dFromPort",
                                                                                                    "dns",
                                                                                                ),
                                                                                                (
                                                                                                    "dToPort",
                                                                                                    "dns",
                                                                                                ),
                                                                                                (
                                                                                                    "stateful",
                                                                                                    "no",
                                                                                                ),
                                                                                                (
                                                                                                    "tcpRules",
                                                                                                    "",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzFilter",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        "%sapi-filter" % api_filter_prefix,
                                                                    )
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "%sapi" % fil_entry_prefix,
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ip",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "tcp",
                                                                                                ),
                                                                                                (
                                                                                                    "dFromPort",
                                                                                                    "6443",
                                                                                                ),
                                                                                                (
                                                                                                    "dToPort",
                                                                                                    "6443",
                                                                                                ),
                                                                                                (
                                                                                                    "stateful",
                                                                                                    "no",
                                                                                                ),
                                                                                                (
                                                                                                    "tcpRules",
                                                                                                    "",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "%sapi2" % fil_entry_prefix,
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ip",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "tcp",
                                                                                                ),
                                                                                                (
                                                                                                    "dFromPort",
                                                                                                    "8443",
                                                                                                ),
                                                                                                (
                                                                                                    "dToPort",
                                                                                                    "8443",
                                                                                                ),
                                                                                                (
                                                                                                    "stateful",
                                                                                                    "no",
                                                                                                ),
                                                                                                (
                                                                                                    "tcpRules",
                                                                                                    "",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzFilter",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        "%sistio-filter" % filter_prefix,
                                                                    )
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "istio-9080",
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ip",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "tcp",
                                                                                                ),
                                                                                                (
                                                                                                    "sFromPort",
                                                                                                    "9080",
                                                                                                ),
                                                                                                (
                                                                                                    "sToPort",
                                                                                                    "9080",
                                                                                                ),
                                                                                                (
                                                                                                    "stateful",
                                                                                                    "no",
                                                                                                ),
                                                                                                (
                                                                                                    "tcpRules",
                                                                                                    "",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "istio-mixer-9090:91",
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ip",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "tcp",
                                                                                                ),
                                                                                                (
                                                                                                    "dFromPort",
                                                                                                    "9090",
                                                                                                ),
                                                                                                (
                                                                                                    "dToPort",
                                                                                                    "9091",
                                                                                                ),
                                                                                                (
                                                                                                    "stateful",
                                                                                                    "no",
                                                                                                ),
                                                                                                (
                                                                                                    "tcpRules",
                                                                                                    "",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "istio-prometheus-15090",
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ip",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "tcp",
                                                                                                ),
                                                                                                (
                                                                                                    "sFromPort",
                                                                                                    "15090",
                                                                                                ),
                                                                                                (
                                                                                                    "sToPort",
                                                                                                    "15090",
                                                                                                ),
                                                                                                (
                                                                                                    "stateful",
                                                                                                    "no",
                                                                                                ),
                                                                                                (
                                                                                                    "tcpRules",
                                                                                                    "",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "istio-pilot-15010:12",
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ip",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "tcp",
                                                                                                ),
                                                                                                (
                                                                                                    "dFromPort",
                                                                                                    "15010",
                                                                                                ),
                                                                                                (
                                                                                                    "dToPort",
                                                                                                    "15012",
                                                                                                ),
                                                                                                (
                                                                                                    "stateful",
                                                                                                    "no",
                                                                                                ),
                                                                                                (
                                                                                                    "tcpRules",
                                                                                                    "",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzEntry",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "istio-pilot2-15014",
                                                                                                ),
                                                                                                (
                                                                                                    "etherT",
                                                                                                    "ip",
                                                                                                ),
                                                                                                (
                                                                                                    "prot",
                                                                                                    "tcp",
                                                                                                ),
                                                                                                (
                                                                                                    "dFromPort",
                                                                                                    "15014",
                                                                                                ),
                                                                                                (
                                                                                                    "dToPort",
                                                                                                    "15014",
                                                                                                ),
                                                                                                (
                                                                                                    "stateful",
                                                                                                    "no",
                                                                                                ),
                                                                                                (
                                                                                                    "tcpRules",
                                                                                                    "",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzBrCP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [("name", "%sapi" % api_contract_prefix)]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzSubj",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "%sapi-subj" % subj_prefix,
                                                                                                ),
                                                                                                (
                                                                                                    "consMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                                (
                                                                                                    "provMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                    (
                                                                                        "children",
                                                                                        [
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "vzRsSubjFiltAtt",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzFilterName",
                                                                                                                                "%sapi-filter" % api_filter_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            )
                                                                                        ],
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                )
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzBrCP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        "%shealth-check" % contract_prefix,
                                                                    )
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzSubj",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "health-check-subj",
                                                                                                ),
                                                                                                (
                                                                                                    "revFltPorts",
                                                                                                    "yes",
                                                                                                ),
                                                                                                (
                                                                                                    "consMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                                (
                                                                                                    "provMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                    (
                                                                                        "children",
                                                                                        [
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "vzOutTerm",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "name",
                                                                                                                                "",
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                ),
                                                                                                                (
                                                                                                                    "children",
                                                                                                                    [
                                                                                                                        collections.OrderedDict(
                                                                                                                            [
                                                                                                                                (
                                                                                                                                    "vzRsFiltAtt",
                                                                                                                                    collections.OrderedDict(
                                                                                                                                        [
                                                                                                                                            (
                                                                                                                                                "attributes",
                                                                                                                                                collections.OrderedDict(
                                                                                                                                                    [
                                                                                                                                                        (
                                                                                                                                                            "tnVzFilterName",
                                                                                                                                                            "%shealth-check-filter-out" % filter_prefix,
                                                                                                                                                        )
                                                                                                                                                    ]
                                                                                                                                                ),
                                                                                                                                            )
                                                                                                                                        ]
                                                                                                                                    ),
                                                                                                                                )
                                                                                                                            ]
                                                                                                                        )
                                                                                                                    ],
                                                                                                                ),
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "vzInTerm",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "name",
                                                                                                                                "",
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                ),
                                                                                                                (
                                                                                                                    "children",
                                                                                                                    [
                                                                                                                        collections.OrderedDict(
                                                                                                                            [
                                                                                                                                (
                                                                                                                                    "vzRsFiltAtt",
                                                                                                                                    collections.OrderedDict(
                                                                                                                                        [
                                                                                                                                            (
                                                                                                                                                "attributes",
                                                                                                                                                collections.OrderedDict(
                                                                                                                                                    [
                                                                                                                                                        (
                                                                                                                                                            "tnVzFilterName",
                                                                                                                                                            "%shealth-check-filter-in" % filter_prefix,
                                                                                                                                                        )
                                                                                                                                                    ]
                                                                                                                                                ),
                                                                                                                                            )
                                                                                                                                        ]
                                                                                                                                    ),
                                                                                                                                )
                                                                                                                            ]
                                                                                                                        )
                                                                                                                    ],
                                                                                                                ),
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                        ],
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                )
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzBrCP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [("name", "%sdns" % contract_prefix)]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzSubj",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "dns-subj",
                                                                                                ),
                                                                                                (
                                                                                                    "consMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                                (
                                                                                                    "provMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                    (
                                                                                        "children",
                                                                                        [
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "vzRsSubjFiltAtt",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzFilterName",
                                                                                                                                "%sdns-filter" % filter_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            )
                                                                                        ],
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                )
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzBrCP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [("name", "%sicmp" % contract_prefix)]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzSubj",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "icmp-subj",
                                                                                                ),
                                                                                                (
                                                                                                    "consMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                                (
                                                                                                    "provMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                    (
                                                                                        "children",
                                                                                        [
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "vzRsSubjFiltAtt",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzFilterName",
                                                                                                                                "%sicmp-filter" % filter_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            )
                                                                                        ],
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                )
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzBrCP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [("name", "%sistio" % contract_prefix)]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzSubj",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "name",
                                                                                                    "istio-subj",
                                                                                                ),
                                                                                                (
                                                                                                    "consMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                                (
                                                                                                    "provMatchT",
                                                                                                    "AtleastOne",
                                                                                                ),
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                    (
                                                                                        "children",
                                                                                        [
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "vzRsSubjFiltAtt",
                                                                                                        collections.OrderedDict(
                                                                                                            [
                                                                                                                (
                                                                                                                    "attributes",
                                                                                                                    collections.OrderedDict(
                                                                                                                        [
                                                                                                                            (
                                                                                                                                "tnVzFilterName",
                                                                                                                                "%sistio-filter" % filter_prefix,
                                                                                                                            )
                                                                                                                        ]
                                                                                                                    ),
                                                                                                                )
                                                                                                            ]
                                                                                                        ),
                                                                                                    )
                                                                                                ]
                                                                                            )
                                                                                        ],
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                )
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    ),
                )
            ]
        )

        # If flavor requires adding kubeapi VLAN, add corresponding
        # fvRsDomAtt object to node-epg
        # To avoid association of physdom with node EPG for ESX install
        if not self.config["aci_config"]["no_physdom_for_node_epg"]:
            if self.use_kubeapi_vlan:
                kubeapi_dom_obj = collections.OrderedDict(
                    [
                        (
                            "fvRsDomAtt",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [
                                                (
                                                    "encap",
                                                    "vlan-%s"
                                                    % kubeapi_vlan,
                                                ),
                                                (
                                                    "tDn",
                                                    "uni/phys-%s"
                                                    % phys_name,
                                                ),
                                            ]
                                        ),
                                    )
                                ]
                            ),
                        )
                    ]
                )
                for i, child in enumerate(data["fvTenant"]["children"]):
                    if "fvAp" in child.keys():
                        for j, ap_child in enumerate(child["fvAp"]["children"]):
                            if "fvAEPg" in ap_child.keys() and ap_child["fvAEPg"]["attributes"]["name"] == node_epg_name:
                                epg_object = ap_child["fvAEPg"]["children"]
                                epg_object.append(kubeapi_dom_obj)

        # If flavor requires not creating node subnet, remove it from
        # the data object
        if disable_node_subnet_creation:
            for i, child in enumerate(data["fvTenant"]["children"]):
                if "fvBD" in child.keys() and child["fvBD"]["attributes"]["name"] == node_bd_name:
                    bd_object = child["fvBD"]["children"]
                    for bd_child in bd_object:
                        if 'fvSubnet' in bd_child.keys():
                            bd_object.remove(bd_child)

        if eade is not True:
            del data["fvTenant"]["children"][2]["fvBD"]["children"][2]

        if v6subnet is True:
            data["fvTenant"]["children"].append(
                collections.OrderedDict(
                    [
                        (
                            "ndPfxPol",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [
                                                ("ctrl", "on-link,router-address"),
                                                ("lifetime", "2592000"),
                                                ("name", "%snd-ra-policy" % v6_sub_prefix),
                                                ("prefLifetime", "604800"),
                                            ]
                                        ),
                                    )
                                ]
                            ),
                        )
                    ]
                )
            )

        # If dhcp_relay_label is present, attach the label to the kube-node-bd
        if "dhcp_relay_label" in self.config["aci_config"]:
            dbg("Handle DHCP Relay Label")
            children = data["fvTenant"]["children"]
            dhcp_relay_label = self.config["aci_config"]["dhcp_relay_label"]
            attr = collections.OrderedDict(
                [
                    (
                        "dhcpLbl",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [("name", dhcp_relay_label), ("owner", "infra")]
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            )
            # lookup kube-node-bd data
            for child in children:
                if "fvBD" in child:
                    if child["fvBD"]["attributes"]["name"] == "%snode-bd" % bd_prefix:
                        child["fvBD"]["children"].append(attr)
                        break

        for epg in self.config["aci_config"].get("custom_epgs", []):
            data["fvTenant"]["children"][0]["fvAp"]["children"].append(
                {
                    "fvAEPg": {
                        "attributes": {
                            "name": epg
                        },
                        "children": kube_default_children
                    }
                })

        if "items" in self.config["aci_config"].keys():
            self.editItems(self.config, old_naming)
            items = self.config["aci_config"]["items"]
            default_provide_api = self.config["aci_config"]["kube_default_provide_kube_api"]
            kube_api_entries = []
            dns_entries = []
            if 'kube_api_entries' in self.config["aci_config"]:
                kube_api_entries = self.config["aci_config"]["kube_api_entries"]
            if 'dns_entries' in self.config["aci_config"]:
                dns_entries = self.config["aci_config"]["dns_entries"]
            if vmm_type == "OpenShift":
                openshift_flavor_specific_handling(data, items, system_id, old_naming, self.ACI_PREFIX, default_provide_api,
                                                   kube_api_entries, api_filter_prefix, dns_entries, filter_prefix)
            elif flavor == "docker-ucp-3.0":
                dockerucp_flavor_specific_handling(data, items, api_filter_prefix)
            elif flavor == "RKE-1.2.3":
                rke_flavor_specific_handling(aci_prefix, data, items, api_filter_prefix, self.config["rke_config"])
            elif flavor == "RKE-1.3.13":
                rke_flavor_specific_handling(aci_prefix, data, items, api_filter_prefix, self.config["rke_config"])

        # Adding prometheus opflex-agent contract for all flavors
        add_prometheus_opflex_agent_contract(data, epg_prefix, contract_prefix, filter_prefix)

        self.annotateApicObjects(data, pre_existing_tenant)
        return path, data

    def epg(
        self, name, bd_name, provides=[], consumes=[], phy_domains=[], vmm_domains=[]
    ):
        children = []
        if bd_name:
            children.append(aci_obj("fvRsBd", [('tnFvBDName', bd_name)]))
        for c in consumes:
            children.append(aci_obj("fvRsCons", [('tnVzBrCPName', c)]))
        for p in provides:
            children.append(aci_obj("fvRsProv", [('tnVzBrCPName', p)]))
        for (d, e) in phy_domains:
            children.append(
                aci_obj("fvRsDomAtt", [('encap', "vlan-%s" % e), ('tDn', "uni/phys-%s" % d)]))
        for (t, n) in vmm_domains:
            children.append(aci_obj("fvRsDomAtt", [('tDn', "uni/vmmp-%s/dom-%s" % (t, n))]))
        return aci_obj("fvAEPg", [('name', name), ('_children', children)])

    def bd(self, name, vrf_name, subnets=[], l3outs=[]):
        children = []
        for sn in subnets:
            children.append(aci_obj("fvSubnet", [('ip', sn), ('scope', "public")]))
        if vrf_name:
            children.append(aci_obj("fvRsCtx", [('tnFvCtxName', vrf_name)]))
        for l in l3outs:
            children.append(aci_obj("fvRsBDToOut", [('tnL3extOutName', l)]))
        return aci_obj("fvBD", [('name', name), ('_children', children)])

    def filter(self, name, entries=[]):
        children = []
        for e in entries:
            children.append(aci_obj("vzEntry", e))
        return aci_obj("vzFilter", [('name', name), ('_children', children)])

    def contract(self, name, subjects=[]):
        children = []
        for s in subjects:
            filts = []
            for f in s.get("filters", []):
                filts.append(aci_obj("vzRsSubjFiltAtt", [('tnVzFilterName', f)]))
            subj = aci_obj(
                "vzSubj",
                [('name', s["name"]),
                 ('consMatchT', "AtleastOne"),
                 ('provMatchT', "AtleastOne"),
                 ('_children', filts)],
            )
            children.append(subj)
        return aci_obj("vzBrCP", [('name', name), ('_children', children)])

    def logical_node_profile(self):
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        lnodep = self.config["aci_config"]["l3out"]["svi"]["node_profile_name"]
        lifp = self.config["aci_config"]["l3out"]["svi"]["int_prof_name"]
        path = "/api/mo/uni/tn-%s/out-%s/lnodep-%s.json" % (l3out_tn, l3out_name, lnodep)
        data = collections.OrderedDict(
            [
                (
                    "l3extLNodeP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", lnodep),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "l3extLIfP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("name", lifp),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def add_configured_nodes(self, pod_id, node_id):
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        lnodep = self.config["aci_config"]["l3out"]["svi"]["node_profile_name"]
        node_dn = "topology/pod-%s/node-%s" % (pod_id, node_id)
        router_id = "1.1.4." + str(node_id)
        path = "/api/mo/uni/tn-%s/out-%s/lnodep-%s/rsnodeL3OutAtt-[%s].json" % (l3out_tn, l3out_name, lnodep, node_dn)
        data = collections.OrderedDict(
            [
                (
                    "l3extRsNodeL3OutAtt",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("rtrId", router_id),
                                        ("tDn", node_dn),
                                    ]
                                ),
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def calico_floating_svi(self, pod_id, node_id, primary_ip):
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        node_dn = "topology/pod-%s/node-%s" % (pod_id, node_id)
        vlan_id = self.config["aci_config"]["l3out"]["svi"]["vlan_id"]
        mtu = self.config["aci_config"]["l3out"]["svi"]["mtu"]
        node_subnet = self.config["net_config"]["node_subnet"]
        primary_addr = primary_ip + "/" + node_subnet.split("/")[-1]
        floating_ip = self.config["aci_config"]["l3out"]["svi"]["floating_ip"]
        secondary_ip = self.config["aci_config"]["l3out"]["svi"]["secondary_ip"]
        physical_domain_name = self.config["aci_config"]["physical_domain"]["domain"]
        remote_asn = self.config["aci_config"]["l3out"]["bgp"]["peering"]["remote_as_number"]
        local_asn = self.config["aci_config"]["l3out"]["bgp"]["peering"]["aci_as_number"]
        if "secret" in self.config["aci_config"]["l3out"]["bgp"]:
            password = self.config["aci_config"]["l3out"]["bgp"]["secret"]
        else:
            password = None
        logical_node_profile = self.config["aci_config"]["l3out"]["svi"]["node_profile_name"]
        int_prof = self.config["aci_config"]["l3out"]["svi"]["int_prof_name"]
        path = "/api/mo/uni/tn-%s/out-%s/lnodep-%s/lifp-%s/vlifp-[%s]-[vlan-%s].json" % (l3out_tn, l3out_name, logical_node_profile, int_prof, node_dn, vlan_id)
        data = collections.OrderedDict(
            [
                (
                    "l3extVirtualLIfP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("dn", "uni/tn-%s/out-%s/lnodep-%s/lifp-%s/vlifp-[%s]-[vlan-%s]" % (l3out_tn, l3out_name, logical_node_profile, int_prof, node_dn, vlan_id)),
                                        ("addr", primary_addr),
                                        ("encap", "vlan-%s" % vlan_id),
                                        ("nodeDn", node_dn),
                                        ("ifInstT", "ext-svi"),
                                        ("autostate", "enabled"),
                                        ("encapScope", "local"),
                                        ("mtu", str(mtu)),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                # relation_l3ext_rs_dyn_path_att
                                                "l3extRsDynPathAtt",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("tDn", "uni/phys-%s" % physical_domain_name),
                                                                    ("floatingAddr", floating_ip),
                                                                    ("forgedTransmit", "Disabled"),
                                                                    ("promMode", "Disabled"),
                                                                    ("macChange", "Disabled")
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                # secondary IP
                                                "l3extIp",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("addr", secondary_ip)
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                # BGP Peer Connectivity Profile
                                                "bgpPeerP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("addr", node_subnet),
                                                                    ("ctrl", "as-override,dis-peer-as-check")
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "bgpAsP",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                ("asn", str(remote_asn)),
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "bgpLocalAsnP",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                ("asnPropagate", "replace-as"),
                                                                                                ("localAsn", str(local_asn))
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "bgpRsPeerPfxPol",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                ("tnBgpPeerPfxPolName", l3out_name),
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    )
                )
            ]
        )
        if password is not None:
            data["l3extVirtualLIfP"]["children"][2]["bgpPeerP"]["attributes"].update(
                collections.OrderedDict(
                    [
                        ("password", password)
                    ]
                ),
            ),
        self.annotateApicObjects(data)
        return path, data

    # Set BGP Route Control Enforcement to Import/Export
    def bgp_route_control(self):
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        path = "/api/mo/uni/tn-%s/out-%s.json" % (l3out_tn, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "l3extOut",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("enforceRtctrl", "export,import"),
                                    ]
                                ),
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def ext_epg_svc(self):
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        external_svc_subnet = self.config["net_config"]["extern_dynamic"]
        ext_epg = self.config["aci_config"]["l3out"]["svi"]["external_network_svc"]
        path = "/api/mo/uni/tn-%s/out-%s/instP-%s.json" % (l3out_tn, l3out_name, ext_epg)
        data = collections.OrderedDict(
            [
                (
                    "l3extInstP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", ext_epg),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                # provide l3out-allow-all contract
                                                "fvRsProv",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("tnVzBrCPName", "common-l3out-allow-all"),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Add external svc subnet
                                                "l3extSubnet",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("ip", external_svc_subnet),
                                                                    ("aggregate", "shared-rtctrl"),
                                                                    ("scope", "export-rtctrl,import-rtctrl,import-security"),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    # Add subnets to svi ext EPG
    def add_subnets_to_ext_epg(self):
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        pod_subnet = self.config["net_config"]["pod_subnet"]
        node_subnet = self.config["net_config"]["node_subnet"]
        cluster_svc_subnet = self.config["net_config"]["cluster_svc_subnet"]
        ext_epg = self.config["aci_config"]["l3out"]["svi"]["external_network"]
        path = "/api/mo/uni/tn-%s/out-%s/instP-%s.json" % (l3out_tn, l3out_name, ext_epg)
        data = collections.OrderedDict(
            [
                (
                    "l3extInstP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", ext_epg),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Consume l3out-allow-all contract provided by l3out ext EPG
                                                "fvRsCons",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("tnVzBrCPName", "common-l3out-allow-all"),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Add pod subnet
                                                "l3extSubnet",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("ip", pod_subnet),
                                                                    ("aggregate", "shared-rtctrl"),
                                                                    ("scope", "export-rtctrl,import-rtctrl,import-security"),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Add node subnet
                                                "l3extSubnet",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("ip", node_subnet),
                                                                    ("scope", "export-rtctrl,import-rtctrl,import-security"),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Add cluster subnet
                                                "l3extSubnet",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("ip", cluster_svc_subnet),
                                                                    ("aggregate", "shared-rtctrl"),
                                                                    ("scope", "export-rtctrl,import-rtctrl,import-security"),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def enable_bgp(self):
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        path = "/api/mo/uni/tn-%s/out-%s/bgpExtP.json" % (l3out_tn, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "bgpExtP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    []
                                ),
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    # Create bgp timer
    def bgp_timers(self):
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        path = "/api/mo/uni/tn-%s/bgpCtxP-%s-Timers.json" % (l3out_tn, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "bgpCtxPol",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("holdIntvl", "3"),
                                        ("staleIntvl", "6"),
                                        ("kaIntvl", "1"),
                                        ("maxAsLimit", "1"),
                                        ("name", "%s-Timers" % l3out_name),
                                        ("grCtrl", "helper"),
                                    ]
                                ),
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    # Create BGP Best Path Policy
    def bgp_relax_as_policy(self):
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        path = "/api/mo/uni/tn-%s/bestpath-%s-Relax-AS.json" % (l3out_tn, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "bgpBestPathCtrlPol",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", "%s-Relax-AS" % l3out_name),
                                        ("ctrl", "asPathMultipathRelax"),
                                    ]
                                ),
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    # Create BGP Protocol Profile
    def bgp_prot_pfl(self):
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        logical_node_profile = self.config["aci_config"]["l3out"]["svi"]["node_profile_name"]
        path = "/api/mo/uni/tn-%s/out-%s/lnodep-%s/protp.json" % (l3out_tn, l3out_name, logical_node_profile)
        data = collections.OrderedDict(
            [
                (
                    "bgpProtP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", "default"),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "bgpRsBgpNodeCtxPol",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("tnBgpCtxPolName", "%s-Timers" % l3out_name),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                "bgpRsBestPathCtrlPol",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("tnBgpBestPathCtrlPolName", "%s-Relax-AS" % l3out_name),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    # Create BGP Address Family Context Policy
    def bgp_addr_family_context(self):
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        path = "/api/mo/uni/tn-%s/bgpCtxAfP-%s.json" % (l3out_tn, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "bgpCtxAfPol",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", l3out_name),
                                        ("maxEcmpIbgp", "64"),
                                        ("maxEcmp", "64")
                                    ]
                                ),
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    # Map BGP Address Family Context Policy to Calico VRF for V4
    def bgp_addr_family_context_to_vrf(self):
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_vrf = self.config["aci_config"]["vrf"]["name"]
        path = "/api/mo/uni/tn-%s/ctx-%s/rsctxToBgpCtxAfPol-[%s]-ipv4-ucast.json" % (l3out_tn, l3out_vrf, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "fvRsCtxToBgpCtxAfPol",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("tnBgpCtxAfPolName", l3out_name),
                                        ("af", "ipv4-ucast"),
                                    ]
                                ),
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    # Map BGP Address Family Context Policy to Calico VRF for V6
    def bgp_addr_family_context_to_vrf_v6(self):
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        l3out_vrf = self.config["aci_config"]["vrf"]["name"]
        path = "/api/mo/uni/tn-%s/ctx-%s/rsctxToBgpCtxAfPol-[%s]-ipv6-ucast.json" % (l3out_tn, l3out_vrf, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "fvRsCtxToBgpCtxAfPol",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("tnBgpCtxAfPolName", l3out_name),
                                        ("af", "ipv6-ucast"),
                                    ]
                                ),
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def export_match_rule(self):
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        pod_subnet = self.config["net_config"]["pod_subnet"]
        path = "/api/mo/uni/tn-%s/subj-%s-export-match.json" % (l3out_tn, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "rtctrlSubjP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", "%s-export-match" % l3out_name),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Create Match Rule Subnet
                                                "rtctrlMatchRtDest",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("ip", pod_subnet),
                                                                    ("aggregate", "yes"),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def attach_rule_to_default_export_pol(self):
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        path = "/api/mo/uni/tn-%s/out-%s/prof-default-export.json" % (l3out_tn, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "rtctrlProfile",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", "default-export"),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Create permit rule
                                                "rtctrlCtxP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("name", "export_pod_subnet"),
                                                                    ("order", "0"),
                                                                    ("action", "permit"),
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            # Add Match Rule to Permit Rule
                                                                            "rtctrlRsCtxPToSubjP",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                ("tnRtctrlSubjPName", "%s-export-match" % l3out_name),
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def import_match_rule(self):
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        pod_subnet = self.config["net_config"]["pod_subnet"]
        node_subnet = self.config["net_config"]["node_subnet"]
        cluster_svc_subnet = self.config["net_config"]["cluster_svc_subnet"]
        external_svc_subnet = self.config["net_config"]["extern_dynamic"]
        path = "/api/mo/uni/tn-%s/subj-%s-import-match.json" % (l3out_tn, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "rtctrlSubjP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", "%s-import-match" % l3out_name),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Create Pod Match Rule Subnet
                                                "rtctrlMatchRtDest",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("ip", pod_subnet),
                                                                    ("aggregate", "yes"),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Create Node Match Rule Subnet
                                                "rtctrlMatchRtDest",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("ip", node_subnet),
                                                                    ("aggregate", "yes"),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Create Svc Match Rule Subnet
                                                "rtctrlMatchRtDest",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("ip", cluster_svc_subnet),
                                                                    ("aggregate", "yes"),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Create Ext Svc Match Rule Subnet
                                                "rtctrlMatchRtDest",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("ip", external_svc_subnet),
                                                                    ("aggregate", "yes"),
                                                                ]
                                                            ),
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def attach_rule_to_default_import_pol(self):
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        path = "/api/mo/uni/tn-%s/out-%s/prof-default-import.json" % (l3out_tn, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "rtctrlProfile",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("name", "default-import"),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Create permit rule
                                                "rtctrlCtxP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("name", "import_cluster_subnets"),
                                                                    ("order", "0"),
                                                                    ("action", "permit"),
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            # Add Match Rule to Permit Rule
                                                                            "rtctrlRsCtxPToSubjP",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                ("tnRtctrlSubjPName", "%s-import-match" % l3out_name),
                                                                                            ]
                                                                                        ),
                                                                                    ),
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                ),
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    ),
                                ],
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def bgp_peer_prefix(self):
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        l3out_name = self.config["aci_config"]["l3out"]["name"]
        path = "/api/mo/uni/tn-%s/bgpPfxP-%s.json" % (l3out_tn, l3out_name)
        data = collections.OrderedDict(
            [
                (
                    "bgpPeerPfxPol",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("action", "reject"),
                                        ("maxPfx", "500"),
                                        ("name", l3out_name)
                                    ]
                                ),
                            ),
                        ]
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data


def add_prometheus_opflex_agent_contract(data, epg_prefix, contract_prefix, filter_prefix):

    consumer_contract = collections.OrderedDict(
        [
            (
                "fvRsCons",
                collections.OrderedDict(
                    [
                        (
                            "attributes",
                            collections.OrderedDict(
                                [
                                    (
                                        "tnVzBrCPName",
                                        "%sprometheus-opflex-agent" % contract_prefix
                                    )
                                ]
                            ),
                        )
                    ]
                ),
            )
        ]
    )
    for epg in ["%sdefault" % epg_prefix, "%ssystem" % epg_prefix]:
        for i, child in enumerate(data['fvTenant']['children'][0]['fvAp']['children']):
            if data['fvTenant']['children'][0]['fvAp']['children'][i]['fvAEPg']['attributes']['name'] == epg:
                data['fvTenant']['children'][0]['fvAp']['children'][i]['fvAEPg']['children'].append(consumer_contract)
                break

    provider_contract = collections.OrderedDict(
        [
            (
                "fvRsProv",
                collections.OrderedDict(
                    [
                        (
                            "attributes",
                            collections.OrderedDict(
                                [
                                    (
                                        "tnVzBrCPName",
                                        "%sprometheus-opflex-agent" % contract_prefix,
                                    )
                                ]
                            ),
                        )
                    ]
                ),
            )
        ]
    )
    for epg in ["%snodes" % epg_prefix]:
        for i, child in enumerate(data['fvTenant']['children'][0]['fvAp']['children']):
            if data['fvTenant']['children'][0]['fvAp']['children'][i]['fvAEPg']['attributes']['name'] == epg:
                data['fvTenant']['children'][0]['fvAp']['children'][i]['fvAEPg']['children'].append(provider_contract)
                break

    filters = collections.OrderedDict(
        [
            (
                "vzFilter",
                collections.OrderedDict(
                    [
                        (
                            "attributes",
                            collections.OrderedDict(
                                [
                                    (
                                        "name",
                                        "%sprometheus-opflex-agent-filter" % filter_prefix,
                                    )
                                ]
                            ),
                        ),
                        (
                            "children",
                            [
                                collections.OrderedDict(
                                    [
                                        (
                                            "vzEntry",
                                            collections.OrderedDict(
                                                [
                                                    (
                                                        "attributes",
                                                        collections.OrderedDict(
                                                            [
                                                                (
                                                                    "name",
                                                                    "prometheus-opflex-agent",
                                                                ),
                                                                (
                                                                    "etherT",
                                                                    "ip",
                                                                ),
                                                                (
                                                                    "prot",
                                                                    "tcp",
                                                                ),
                                                                (
                                                                    "dFromPort",
                                                                    "9612",
                                                                ),
                                                                (
                                                                    "dToPort",
                                                                    "9612",
                                                                ),
                                                                (
                                                                    "stateful",
                                                                    "no",
                                                                ),
                                                                (
                                                                    "tcpRules",
                                                                    "",
                                                                ),
                                                            ]
                                                        ),
                                                    )
                                                ]
                                            ),
                                        )
                                    ]
                                )
                            ],
                        ),
                    ]
                ),
            )
        ]
    )
    data['fvTenant']['children'].append(filters)

    contract = collections.OrderedDict(
        [
            (
                "vzBrCP",
                collections.OrderedDict(
                    [
                        (
                            "attributes",
                            collections.OrderedDict(
                                [("name", "%sprometheus-opflex-agent" % contract_prefix)]
                            ),
                        ),
                        (
                            "children",
                            [
                                collections.OrderedDict(
                                    [
                                        (
                                            "vzSubj",
                                            collections.OrderedDict(
                                                [
                                                    (
                                                        "attributes",
                                                        collections.OrderedDict(
                                                            [
                                                                (
                                                                    "name",
                                                                    "prometheus-opflex-agent-subj",
                                                                ),
                                                                (
                                                                    "consMatchT",
                                                                    "AtleastOne",
                                                                ),
                                                                (
                                                                    "provMatchT",
                                                                    "AtleastOne",
                                                                ),
                                                            ]
                                                        ),
                                                    ),
                                                    (
                                                        "children",
                                                        [
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "vzRsSubjFiltAtt",
                                                                        collections.OrderedDict(
                                                                            [
                                                                                (
                                                                                    "attributes",
                                                                                    collections.OrderedDict(
                                                                                        [
                                                                                            (
                                                                                                "tnVzFilterName",
                                                                                                "%sprometheus-opflex-agent-filter" % filter_prefix,
                                                                                            )
                                                                                        ]
                                                                                    ),
                                                                                )
                                                                            ]
                                                                        ),
                                                                    )
                                                                ]
                                                            )
                                                        ],
                                                    ),
                                                ]
                                            ),
                                        )
                                    ]
                                )
                            ],
                        ),
                    ]
                ),
            )
        ]
    )
    data['fvTenant']['children'].append(contract)


def openshift_flavor_specific_handling(data, items, system_id, old_naming, aci_prefix, default_provide_api,
                                       kube_api_entries, api_filter_prefix, dns_entries, dns_filter_prefix):
    if items is None or len(items) == 0:
        err("Error in getting items for flavor")

    if old_naming:
        api_contract_name = "kube-api"
        dns_contract_name = "dns"
    else:
        api_contract_name = "%s%s-api" % (aci_prefix, system_id)
        dns_contract_name = '%s%s-dns' % (aci_prefix, system_id)

    # kube-systems needs to provide kube-api contract
    provide_kube_api_contract_os = collections.OrderedDict(
        [
            (
                "fvRsProv",
                collections.OrderedDict(
                    [
                        (
                            "attributes",
                            collections.OrderedDict(
                                [
                                    (
                                        "tnVzBrCPName",
                                        api_contract_name,
                                    )
                                ]
                            ),
                        )
                    ]
                ),
            )
        ]
    )
    data['fvTenant']['children'][0]['fvAp']['children'][1]['fvAEPg']['children'].append(provide_kube_api_contract_os)

    if default_provide_api:
        data['fvTenant']['children'][0]['fvAp']['children'][0]['fvAEPg']['children'].append(provide_kube_api_contract_os)

    # special case for dns contract
    consume_dns_contract_os = collections.OrderedDict(
        [
            (
                "fvRsCons",
                collections.OrderedDict(
                    [
                        (
                            "attributes",
                            collections.OrderedDict(
                                [
                                    (
                                        "tnVzBrCPName",
                                        dns_contract_name,
                                    )
                                ]
                            ),
                        )
                    ]
                ),
            )
        ]
    )
    data['fvTenant']['children'][0]['fvAp']['children'][1]['fvAEPg']['children'].append(consume_dns_contract_os)

    # add new contract
    for item in items:
        provide_os_contract = collections.OrderedDict(
            [
                (
                    "fvRsProv",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        (
                                            "tnVzBrCPName",
                                            item['name'],
                                        )
                                    ]
                                ),
                            )
                        ]
                    ),
                )
            ]
        )

        consume_os_contract = collections.OrderedDict(
            [
                (
                    "fvRsCons",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        (
                                            "tnVzBrCPName",
                                            item['name'],
                                        )
                                    ]
                                ),
                            )
                        ]
                    ),
                )
            ]
        )

        if old_naming:
            # 0 = kube-default, 1 = kube-system, 2 = kube-nodes
            if 'kube-default' in item['consumed']:
                data['fvTenant']['children'][0]['fvAp']['children'][0]['fvAEPg']['children'].append(consume_os_contract)
            if 'kube-system' in item['consumed']:
                data['fvTenant']['children'][0]['fvAp']['children'][1]['fvAEPg']['children'].append(consume_os_contract)
            if 'kube-nodes' in item['consumed']:
                data['fvTenant']['children'][0]['fvAp']['children'][2]['fvAEPg']['children'].append(consume_os_contract)

            if 'kube-default' in item['provided']:
                data['fvTenant']['children'][0]['fvAp']['children'][0]['fvAEPg']['children'].append(provide_os_contract)
            if 'kube-system' in item['provided']:
                data['fvTenant']['children'][0]['fvAp']['children'][1]['fvAEPg']['children'].append(provide_os_contract)
            if 'kube-nodes' in item['provided']:
                data['fvTenant']['children'][0]['fvAp']['children'][2]['fvAEPg']['children'].append(provide_os_contract)

        else:
            # 0 = kube-default, 1 = kube-system, 2 = kube-nodes
            if ('%sdefault' % aci_prefix) in item['consumed']:
                data['fvTenant']['children'][0]['fvAp']['children'][0]['fvAEPg']['children'].append(consume_os_contract)
            if ('%ssystem' % aci_prefix) in item['consumed']:
                data['fvTenant']['children'][0]['fvAp']['children'][1]['fvAEPg']['children'].append(consume_os_contract)
            if ('%snodes' % aci_prefix) in item['consumed']:
                data['fvTenant']['children'][0]['fvAp']['children'][2]['fvAEPg']['children'].append(consume_os_contract)

            if ('%sdefault' % aci_prefix) in item['provided']:
                data['fvTenant']['children'][0]['fvAp']['children'][0]['fvAEPg']['children'].append(provide_os_contract)
            if ('%ssystem' % aci_prefix) in item['provided']:
                data['fvTenant']['children'][0]['fvAp']['children'][1]['fvAEPg']['children'].append(provide_os_contract)
            if ('%snodes' % aci_prefix) in item['provided']:
                data['fvTenant']['children'][0]['fvAp']['children'][2]['fvAEPg']['children'].append(provide_os_contract)

    # add new contract and subject
    for item in items:
        os_contract = collections.OrderedDict(
            [
                (
                    "vzBrCP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [("name", item['name'])]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                "vzSubj",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "name",
                                                                        item['name'] + "-subj",
                                                                    ),
                                                                    (
                                                                        "consMatchT",
                                                                        "AtleastOne",
                                                                    ),
                                                                    (
                                                                        "provMatchT",
                                                                        "AtleastOne",
                                                                    ),
                                                                ]
                                                            ),
                                                        ),
                                                        (
                                                            "children",
                                                            [
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "vzRsSubjFiltAtt",
                                                                            collections.OrderedDict(
                                                                                [
                                                                                    (
                                                                                        "attributes",
                                                                                        collections.OrderedDict(
                                                                                            [
                                                                                                (
                                                                                                    "tnVzFilterName",
                                                                                                    item['name'] + "-filter",
                                                                                                )
                                                                                            ]
                                                                                        ),
                                                                                    )
                                                                                ]
                                                                            ),
                                                                        )
                                                                    ]
                                                                )
                                                            ],
                                                        ),
                                                    ]
                                                ),
                                            )
                                        ]
                                    )
                                ],
                            ),
                        ]
                    ),
                )
            ]
        )
        data['fvTenant']['children'].append(os_contract)

    # add filter and entries to that subject
    for item in items:
        os_filter = collections.OrderedDict(
            [
                (
                    "vzFilter",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        (
                                            "name",
                                            item['name'] + "-filter",
                                        )
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [],
                            ),
                        ]
                    ),
                )
            ]
        )

        for port in item['range']:
            child = collections.OrderedDict(
                [
                    (
                        "vzEntry",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [
                                            (
                                                "name",
                                                item["name"] + '-' + str(port[0]),
                                            ),
                                            (
                                                "etherT",
                                                item["etherT"],
                                            ),
                                            (
                                                "prot",
                                                item["prot"],
                                            ),
                                            (
                                                "dFromPort",
                                                str(port[0]),
                                            ),
                                            (
                                                "dToPort",
                                                str(port[1]),
                                            ),
                                            (
                                                "stateful",
                                                str(item["stateful"]),
                                            ),
                                            (
                                                "tcpRules",
                                                "",
                                            ),
                                        ]
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            )
            os_filter['vzFilter']['children'].append(child)

        data['fvTenant']['children'].append(os_filter)

    # Add http, https, etcd entries to kube-api filter for OpenShift 4.3
    if kube_api_entries:
        tenant_children = data['fvTenant']['children']
        api_filter_name = "%sapi-filter" % api_filter_prefix
        filter_entries = []
        for child in tenant_children:
            if 'vzFilter' in child.keys() and child['vzFilter']['attributes']['name'] == api_filter_name:
                for entry in kube_api_entries:
                    apic_entry = collections.OrderedDict(
                        [
                            (
                                "vzEntry",
                                collections.OrderedDict(
                                    [
                                        (
                                            "attributes",
                                            collections.OrderedDict(
                                                [
                                                    (
                                                        "name",
                                                        "openshift-%s" % entry['name'],
                                                    ),
                                                    (
                                                        "etherT",
                                                        entry["etherT"],
                                                    ),
                                                    (
                                                        "prot",
                                                        entry["prot"],
                                                    ),
                                                    (
                                                        "dFromPort",
                                                        str(entry["range"][0]),
                                                    ),
                                                    (
                                                        "dToPort",
                                                        str(entry["range"][1]),
                                                    ),
                                                    (
                                                        "stateful",
                                                        entry["stateful"],
                                                    ),
                                                    (
                                                        "tcpRules",
                                                        "",
                                                    ),
                                                ]
                                            ),
                                        )
                                    ]
                                ),
                            )
                        ]
                    )
                    filter_entries.append(apic_entry)
                child['vzFilter']['children'] = child['vzFilter']['children'] + filter_entries
                break

    if dns_entries:
        dns_filter_name = "%sdns-filter" % dns_filter_prefix
        tenant_children = data['fvTenant']['children']
        filter_entries = []
        for child in tenant_children:
            if 'vzFilter' in child.keys() and child['vzFilter']['attributes']['name'] == dns_filter_name:
                for entry in dns_entries:
                    apic_entry = collections.OrderedDict(
                        [
                            (
                                "vzEntry",
                                collections.OrderedDict(
                                    [
                                        (
                                            "attributes",
                                            collections.OrderedDict(
                                                [
                                                    (
                                                        "name",
                                                        entry['name'],
                                                    ),
                                                    (
                                                        "etherT",
                                                        entry["etherT"],
                                                    ),
                                                    (
                                                        "prot",
                                                        entry["prot"],
                                                    ),
                                                    (
                                                        "dFromPort",
                                                        str(entry["range"][0]),
                                                    ),
                                                    (
                                                        "dToPort",
                                                        str(entry["range"][1]),
                                                    ),
                                                    (
                                                        "stateful",
                                                        entry["stateful"],
                                                    ),
                                                    (
                                                        "tcpRules",
                                                        "",
                                                    ),
                                                ]
                                            ),
                                        )
                                    ]
                                ),
                            )
                        ]
                    )
                    filter_entries.append(apic_entry)
                child['vzFilter']['children'] = child['vzFilter']['children'] + filter_entries
                break


def dockerucp_flavor_specific_handling(data, ports, api_filter_prefix):

    if ports is None or len(ports) == 0:
        err("Error in getting ports for flavor")
    else:
        tenant_children = data['fvTenant']['children']
        api_filter_name = "%sapi-filter" % api_filter_prefix
        for child in tenant_children:
            if 'vzFilter' in child.keys() and child['vzFilter']['attributes']['name'] == api_filter_name:
                filter_entries = []
                for port in ports:
                    extra_port = collections.OrderedDict(
                        [
                            (
                                "vzEntry",
                                collections.OrderedDict(
                                    [
                                        (
                                            "attributes",
                                            collections.OrderedDict(
                                                [
                                                    (
                                                        "name",
                                                        port["name"],
                                                    ),
                                                    (
                                                        "etherT",
                                                        port["etherT"],
                                                    ),
                                                    (
                                                        "prot",
                                                        port["prot"],
                                                    ),
                                                    (
                                                        "dFromPort",
                                                        str(port["range"][0]),
                                                    ),
                                                    (
                                                        "dToPort",
                                                        str(port["range"][1]),
                                                    ),
                                                    (
                                                        "stateful",
                                                        str(port["stateful"]),
                                                    ),
                                                    (
                                                        "tcpRules",
                                                        "",
                                                    ),
                                                ]
                                            ),
                                        )
                                    ]
                                ),
                            )
                        ]
                    )
                    filter_entries.append(extra_port)
                child['vzFilter']['children'] = child['vzFilter']['children'] + filter_entries
                break


def rke_flavor_specific_handling(aci_prefix, data, ports, api_filter_prefix, rke_config):

    if ports is None or len(ports) == 0:
        err("Error in getting ports for flavor")
    else:
        tenant_children = data['fvTenant']['children']
        api_filter_name = "%sapi-filter" % api_filter_prefix
        for child in tenant_children:
            if 'vzFilter' in child.keys() and child['vzFilter']['attributes']['name'] == api_filter_name:
                filter_entries = []
                for port in ports:
                    extra_port = collections.OrderedDict(
                        [
                            (
                                "vzEntry",
                                collections.OrderedDict(
                                    [
                                        (
                                            "attributes",
                                            collections.OrderedDict(
                                                [
                                                    (
                                                        "name",
                                                        port["name"],
                                                    ),
                                                    (
                                                        "etherT",
                                                        port["etherT"],
                                                    ),
                                                    (
                                                        "prot",
                                                        port["prot"],
                                                    ),
                                                    (
                                                        "dFromPort",
                                                        str(port["range"][0]),
                                                    ),
                                                    (
                                                        "dToPort",
                                                        str(port["range"][1]),
                                                    ),
                                                    (
                                                        "stateful",
                                                        str(port["stateful"]),
                                                    ),
                                                    (
                                                        "tcpRules",
                                                        "",
                                                    ),
                                                ]
                                            ),
                                        )
                                    ]
                                ),
                            )
                        ]
                    )
                    filter_entries.append(extra_port)
                child['vzFilter']['children'] = child['vzFilter']['children'] + filter_entries
                break

    if rke_config is not None:
        for ctrct in rke_config["contracts"]:
            contract_name = aci_prefix + ctrct["name"]
            contract = collections.OrderedDict(
                [
                    (
                        "vzBrCP",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [("name", contract_name)]
                                    ),
                                ),
                                (
                                    "children",
                                    [
                                        collections.OrderedDict(
                                            [
                                                (
                                                    "vzSubj",
                                                    collections.OrderedDict(
                                                        [
                                                            (
                                                                "attributes",
                                                                collections.OrderedDict(
                                                                    [
                                                                        (
                                                                            "name",
                                                                            contract_name + "-subj",
                                                                        ),
                                                                        (
                                                                            "consMatchT",
                                                                            "AtleastOne",
                                                                        ),
                                                                        (
                                                                            "provMatchT",
                                                                            "AtleastOne",
                                                                        ),
                                                                    ]
                                                                ),
                                                            ),
                                                            (
                                                                "children",
                                                                [
                                                                    collections.OrderedDict(
                                                                        [
                                                                            (
                                                                                "vzRsSubjFiltAtt",
                                                                                collections.OrderedDict(
                                                                                    [
                                                                                        (
                                                                                            "attributes",
                                                                                            collections.OrderedDict(
                                                                                                [
                                                                                                    (
                                                                                                        "tnVzFilterName",
                                                                                                        aci_prefix + ctrct["filter"],
                                                                                                    )
                                                                                                ]
                                                                                            ),
                                                                                        )
                                                                                    ]
                                                                                ),
                                                                            )
                                                                        ]
                                                                    )
                                                                ],
                                                            ),
                                                        ]
                                                    ),
                                                )
                                            ]
                                        )
                                    ],
                                ),
                            ]
                        ),
                    )
                ]
            )
            data['fvTenant']['children'].append(contract)
            provide_rke_contract = collections.OrderedDict(
                [
                    (
                        "fvRsProv",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [
                                            (
                                                "tnVzBrCPName",
                                                contract_name,
                                            )
                                        ]
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            )
            consume_rke_contract = collections.OrderedDict(
                [
                    (
                        "fvRsCons",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [
                                            (
                                                "tnVzBrCPName",
                                                contract_name,
                                            )
                                        ]
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            )
            for provider in ctrct['provided']:
                for i, child in enumerate(data['fvTenant']['children'][0]['fvAp']['children']):
                    if data['fvTenant']['children'][0]['fvAp']['children'][i]['fvAEPg']['attributes']['name'] == provider:
                        data['fvTenant']['children'][0]['fvAp']['children'][i]['fvAEPg']['children'].append(provide_rke_contract)
                        break
            for consumer in ctrct['consumed']:
                for i, child in enumerate(data['fvTenant']['children'][0]['fvAp']['children']):
                    if data['fvTenant']['children'][0]['fvAp']['children'][i]['fvAEPg']['attributes']['name'] == consumer:
                        data['fvTenant']['children'][0]['fvAp']['children'][i]['fvAEPg']['children'].append(consume_rke_contract)
                        break

        for i, filter in enumerate(rke_config["filters"]):
            filt_entry = collections.OrderedDict(
                [
                    (
                        "vzFilter",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [
                                            (
                                                "name",
                                                aci_prefix + filter["name"],
                                            )
                                        ]
                                    ),
                                ),
                                (
                                    "children",
                                    []
                                ),
                            ]
                        ),
                    )
                ]
            )
        for port in rke_config["filters"][i]["items"]:
            filt_child = collections.OrderedDict(
                [
                    (
                        "vzEntry",
                        collections.OrderedDict(
                            [
                                (
                                    "attributes",
                                    collections.OrderedDict(
                                        [
                                            (
                                                "name",
                                                port["name"],
                                            ),
                                            (
                                                "etherT",
                                                port["etherT"],
                                            ),
                                            (
                                                "prot",
                                                port["prot"],
                                            ),
                                            (
                                                "dFromPort",
                                                str(port["range"][0]),
                                            ),
                                            (
                                                "dToPort",
                                                str(port["range"][1]),
                                            ),
                                            (
                                                "stateful",
                                                str(port["stateful"]),
                                            ),
                                            (
                                                "tcpRules",
                                                "",
                                            ),
                                        ]
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            )
            filt_entry['vzFilter']['children'].append(filt_child)
            data['fvTenant']['children'].append(filt_entry)


if __name__ == "__main__":
    pass
