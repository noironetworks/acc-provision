from __future__ import print_function, unicode_literals
import collections
import json
import sys
import re
import requests
import urllib3
import ipaddress
import time
from distutils.version import StrictVersion

import yaml

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
aci_chained_prefix = "netop-"


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


def is_chained_mode(config):
    return True if config.get("chained_cni_config") and (
        config["chained_cni_config"]["secondary_interface_chaining"] or config[
            "chained_cni_config"]["primary_interface_chaining"]) else False


class Apic(object):

    TENANT_OBJECTS = ["ap-kubernetes", "BD-kube-node-bd", "BD-kube-pod-bd", "brc-kube-api", "brc-health-check", "brc-dns", "brc-icmp", "flt-kube-api-filter", "flt-dns-filter", "flt-health-check-filter-out", "flt-icmp-filter", "flt-health-check-filter-in"]
    ACI_PREFIX = aci_prefix
    ACI_CHAINED_PREFIX = aci_chained_prefix

    def __init__(
        self,
        addr,
        username,
        password,
        ssl=True,
        verify=False,
        timeout=None,
        debug=False
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
        return resp

    def post(self, path, data):
        # APIC seems to accept request body as form-encoded
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        args.update(timeout=self.timeout)
        dbg("posting {}".format(json.dumps(args)))
        return requests.post(self.url(path), **args)

    def post_with_exponential_backoff(self, path, data, max_retries=5):
        retries = 0
        while True:
            try:
                resp = self.post(path, data)
                self.check_resp(resp)
                return resp
            except Exception as e:
                dbg("POST request failed %s: %s" % (path, str(e)))

            if retries == max_retries:
                break

            delay = 2 ** retries
            dbg("Retrying in %d time..(Attempt %d of %d)" % (delay, retries + 1, max_retries))
            time.sleep(delay)
            retries += 1

        err("Max retries reached for POST request to %s. Giving up." % path)
        return resp
    
    def is_system_id_matching(self, system_id, resource_name):
        contains_match_pattern = rf".*-\b{system_id}\b-.*"
        ends_with_pattern = rf".*-\b{system_id}\b$"
        if(re.match(contains_match_pattern, resource_name) or re.match(ends_with_pattern, resource_name)):
            return True
        return False

    def delete(self, path, data=None):
        args = dict(data=data, cookies=self.cookies, verify=self.verify)
        args.update(timeout=self.timeout)
        dbg("Deleting: {}".format(path))
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

    def get_local_asn(self):
        asn = None
        path = ("/api/node/mo/uni/fabric/bgpInstP-default/as.json")
        data = self.get_path(path)
        if data:
            asn = data["bgpAsP"]["attributes"]["asn"]
        return asn

    def get_aep(self, aep_name):
        path = "/api/mo/uni/infra/attentp-%s.json" % aep_name
        return self.get_path(path)

    def get_l3_domain(self, dom_name):
        path = "/api/mo/uni/l3dom-%s.json" % dom_name
        return self.get_path(path)

    def get_vrf(self, dn):
        path = "/api/mo/%s.json" % dn
        return self.get_path(path)

    def get_tenant(self, vrf_tn):
        path = "/api/mo/uni/tn-%s.json" % vrf_tn
        return self.get_path(path)

    def get_tenant_vrf(self, tn_name, vrf_name):
        path = "/api/mo/uni/tn-%s/ctx-%s.json" % (tn_name, vrf_name)
        return self.get_path(path)

    def get_l3out(self, tenant, name):
        path = "/api/mo/uni/tn-%s/out-%s.json" % (tenant, name)
        return self.get_path(path)

    def get_vmm_dom(self, vmm_type, vmm_domain):
        path = "/api/mo/uni/vmmp-%s/dom-%s.json" % (vmm_type, vmm_domain)
        return self.get_path(path)

    def get_vmmdom_vlanpool_tDn(self, vmmdom):
        path = "/api/node/mo/uni/vmmp-VMware/dom-%s.json?query-target=children&target-subtree-class=infraRsVlanNs" % (vmmdom)
        return self.get_path(path)["infraRsVlanNs"]["attributes"]["tDn"]

    def get_phys_dom(self, domain):
        path = "/api/mo/uni/phys-%s.json" % domain
        return self.get_path(path)

    def check_vlan_pool_l3_domain(self, l3_dom):
        path = "api/mo/uni/l3dom-%s.json?query-target=children&target-subtree-class=infraRsVlanNs" % l3_dom
        return self.get_path(path)["infraRsVlanNs"]["attributes"]["tDn"]

    def check_l3out_vrf(self, tenant, name, vrf_name, vrf_dn):
        path = "/api/mo/uni/tn-%s/out-%s/rsectx.json?query-target=self" % (tenant, name)
        res = False
        try:
            tDn = self.get_path(path)["l3extRsEctx"]["attributes"]["tDn"]
            res = (tDn == vrf_dn)
        except Exception as e:
            err("Error in getting configured l3out vrf for %s/%s: %s" % (tenant, name, str(e)))
        return res

    def check_ext_l3out_epg(self, tenant, ext_l3out_name):
        path = "/api/mo/uni/tn-%s/out-%s.json?query-target=children&target-subtree-class=l3extInstP" % (tenant, ext_l3out_name)
        return self.get_path(path)

    def get_user(self, name):
        path = "/api/node/mo/uni/userext/user-%s.json" % name
        return self.get_path(path)

    def get_ap(self, tenant, ap):
        path = "/api/mo/uni/tn-%s/ap-%s.json" % (tenant, ap)
        return self.get_path(path)

    def get_ext_l3out_lnodep(self, tenant, l3out_name):
        path = "/api/node/mo/uni/tn-%s/out-%s.json?query-target=children&target-subtree-class=l3extLNodeP" % (tenant, l3out_name)
        return self.get_path(path)["l3extLNodeP"]["attributes"]["name"]

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

    def get_extl3out_configured_nodes_router_id(self, tenant, l3out, node_prof):
        path = "/api/node/mo/uni/tn-%s/out-%s/lnodep-%s.json?query-target=children&target-subtree-class=l3extRsNodeL3OutAtt" % (tenant, l3out, node_prof)
        nodeid_dict = {}
        node_ids = self.get_path(path, multi=True)
        if node_ids is None:
            return nodeid_dict
        if type(node_ids) is list:
            for node_id in node_ids:
                nodeid_dict[node_id["l3extRsNodeL3OutAtt"]["attributes"]["tDn"]] = node_id["l3extRsNodeL3OutAtt"]["attributes"]["rtrId"]
        else:
            nodeid_dict[node_ids["l3extRsNodeL3OutAtt"]["attributes"]["tDn"]] = node_ids["l3extRsNodeL3OutAtt"]["attributes"]["rtrId"]
        return nodeid_dict

    def provision(self, data, sync_login, retries):
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
                    resp = self.post_with_exponential_backoff(path, config, retries)
                    self.check_resp(resp)
                    dbg("%s: %s" % (path, resp.text))
            except Exception as e:
                # log it, otherwise ignore it
                self.errors += 1
                err("Error in provisioning %s: %s" % (path, str(e)))

    def unprovision(self, data, system_id, cluster_l3out_tenant, vrf_tenant, cluster_tenant, old_naming, cfg, pre_existing_tenant=False, l3out_name=None, cluster_l3out_vrf_details=None):
        cluster_tenant_path = "/api/mo/uni/tn-%s.json" % cluster_tenant
        shared_resources = ["/api/mo/uni/infra.json", "/api/mo/uni/tn-common.json", cluster_tenant_path]

        if is_chained_mode(cfg):
            if cfg["user_config"]["aci_config"].get("physical_domain", {}).get("domain", False):
                pysdom_path = "/api/mo/uni/phys-%s.json" % cfg["user_config"]["aci_config"]["physical_domain"]["domain"]
                shared_resources.append(pysdom_path)

        if vrf_tenant not in ["common", system_id]:
            shared_resources.append("/api/mo/uni/tn-%s.json" % vrf_tenant)

        try:
            if "calico" in cfg['flavor']:
                cluster_l3out_path = "/api/node/mo/uni/tn-%s/out-%s.json?query-target=self" % (cluster_l3out_tenant, l3out_name)
                resp = self.delete(cluster_l3out_path)
                self.check_resp(resp)
                dbg("%s: %s" % (cluster_l3out_path, resp.text))
                l3_dom_path = "/api/node/mo/uni/l3dom-%s.json?query-target=self" % (l3out_name + "-L3-dom")
                resp = self.delete(l3_dom_path)
                self.check_resp(resp)
                dbg("%s: %s" % (l3_dom_path, resp.text))
                phys_dom_path = "/api/node/mo/uni/phys-%s.json?query-target=self" % (l3out_name + "-phys-dom")
                resp = self.delete(phys_dom_path)
                self.check_resp(resp)
                dbg("%s: %s" % (phys_dom_path, resp.text))
                vlan_pool_path = "/api/mo/uni/infra/vlanns-[%s]-static.json?query-target=self" % (l3out_name + "-pool")
                resp = self.delete(vlan_pool_path)
                self.check_resp(resp)
                dbg("%s: %s" % (vlan_pool_path, resp.text))
                bgp_res_path = "/api/node/mo/uni/tn-%s.json" % cluster_l3out_tenant
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
                                            if is_chained_mode(cfg) and "ap-" in val['attributes']['dn']:
                                                continue
                                            if 'annotation' in val['attributes']:
                                                annotation = val['attributes']['annotation']
                                                class_name = list(resp.keys())[0]
                                                if annotation == aciContainersOwnerAnnotation and self.is_system_id_matching(system_id, name):
                                                    if class_name == "fvAp":
                                                        ap_path = "/api/mo/%s.json?query-target=children" % val['attributes']['dn']
                                                        resp = self.get(ap_path)
                                                        self.check_resp(resp)
                                                        resp_json = json.loads(resp.text)
                                                        resp_json = resp_json["imdata"]
                                                        delete_ap = True
                                                        for resp in resp_json:
                                                            for val in resp.values():
                                                                 if 'annotation' in val['attributes']:
                                                                     annotation = val['attributes']['annotation']
                                                                     if annotation != aciContainersOwnerAnnotation:
                                                                       delete_ap = False
                                                                     else:
                                                                        epg_path = "/api/mo/%s.json" % val['attributes']['dn']
                                                                        resp = self.delete(epg_path)
                                                                        self.check_resp(resp)
                                                                 else:
                                                                     delete_ap = False
                                                        if (delete_ap) and (not old_naming):
                                                            dbg("Deleting resource: %s" % name)
                                                            resp = self.delete(del_path)
                                                            self.check_resp(resp)
                                                    elif (not old_naming):
                                                        dbg("Deleting resource: %s" % name)
                                                        resp = self.delete(del_path)
                                                        self.check_resp(resp)
                                                        dbg("%s: %s" % (del_path, resp.text))
                                            elif is_chained_mode(cfg) and (name == self.ACI_CHAINED_PREFIX + "nodes"):
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

        if "calico" in cfg['flavor']:
            tenant_name = cluster_l3out_vrf_details["tenant"]
            # Delete cluster_l3out vrf
            if cluster_l3out_vrf_details["create_vrf"]:
                vrf_name = cluster_l3out_vrf_details["name"]
                cluster_l3out_vrf_path = "/api/mo/uni/tn-%s/ctx-%s.json" % (tenant_name, vrf_name)
                if self.check_valid_vrf_annotation(cluster_l3out_vrf_path):
                    self.delete(cluster_l3out_vrf_path)

                # Delete global scope contract
                global_contract_path = "/api/mo/uni/tn-%s/brc-%s-l3out-allow-all.json" % (vrf_tenant, system_id)
                self.delete(global_contract_path)

                # Delete external l3out epg provided global scope contract
                for l3out_instp in cfg["aci_config"]["l3out"]["external_networks"]:
                    l3out = cfg["aci_config"]["l3out"]["name"]
                    l3out_rsprov_name = "%s-l3out-allow-all" % system_id
                    rsprov = "/api/mo/uni/tn-%s/out-%s/instP-%s/rsprov-%s.json" % (vrf_tenant, l3out, l3out_instp, l3out_rsprov_name)
                    self.delete(rsprov)

            # Delete cluster_l3out tenant
            if cluster_l3out_vrf_details["create_tenant"]:
                cluster_l3out_tenant_path = "/api/mo/uni/tn-%s.json" % tenant_name
                if self.check_valid_annotation(cluster_l3out_tenant_path):
                    self.delete(cluster_l3out_tenant_path)

        if is_chained_mode(cfg):
            ap_path = "/api/mo/uni/tn-%s/ap-%s.json" % (cluster_tenant, self.ACI_CHAINED_PREFIX + system_id)
            ap_query_path = ap_path + "?query-target=children"
            resp = self.get(ap_query_path)
            self.check_resp(resp)
            respj = json.loads(resp.text)
            respj = respj["imdata"]
            for resp in respj:
                for val in resp.values():
                    if 'rsTenantMonPol' not in val['attributes']['dn'] and 'svcCont' not in val['attributes']['dn']:
                        del_path = "/api/node/mo/" + val['attributes']['dn'] + ".json"
                        if 'name' in val['attributes']:
                            name = val['attributes']['name']
                            if self.check_valid_annotation(del_path, 'fvAEPg'):
                                resp = self.delete(del_path)
                                self.check_resp(resp)
                                dbg("%s: %s" % (del_path, resp.text))
            if self.check_valid_annotation(ap_path, 'fvAp'):
                resp = self.delete(ap_path)
                self.check_resp(resp)
                dbg("%s: %s" % (ap_path, resp.text))

        # Clean the cluster tenant iff it has our annotation and does
        # not have any application profiles when --skip-app-profile-check flag is not provided,
        # considering it's not a pre_existing_tenant which is manually created on the APIC
        if not pre_existing_tenant:
            if self.check_valid_annotation(cluster_tenant_path):
                if cfg["unprovision"]["skip_app_profile_check"] or self.check_no_ap(cluster_tenant_path):
                    self.delete(cluster_tenant_path)

        # Finally clean any stray resources in common
        self.clean_tagged_resources(system_id, vrf_tenant)

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

    def check_valid_annotation(self, path, mo=''):
        try:
            mo = mo if mo else 'fvTenant'
            data = self.get_path(path)
            if data[mo]['attributes']['annotation'] == aciContainersOwnerAnnotation:
                return True
        except Exception as e:
            dbg("Unable to find APIC object %s: %s" % (path, str(e)))
        return False

    def check_valid_vrf_annotation(self, path):
        try:
            data = self.get_path(path)
            if data['fvCtx']['attributes']['annotation'] == aciContainersOwnerAnnotation:
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
    ACI_CHAINED_PREFIX = aci_chained_prefix

    def __init__(self, config, apic):
        self.config = config
        self.apic = apic if apic else None
        self.use_kubeapi_vlan = True
        self.tenant_generator = "kube_tn"
        self.tenant_generator_chained_mode = "chained_mode_kube_tn"
        self.associate_aep_to_nested_inside_domain = False

    def get_nested_domain_type(self):
        inside = self.config["aci_config"]["vmm_domain"].get("nested_inside")
        if not inside:
            return None
        t = inside.get("type")
        if t and t.lower() == "vmware":
            return "VMware"
        return t

    def get_vlan_range(self, vlan):
        start_vlan = None
        end_vlan = None
        if type(vlan) is int:
            start_vlan = vlan
            end_vlan = vlan
        elif '-' in vlan:
            start_vlan = int(vlan.split('-')[0])
            end_vlan = int(vlan.split('-')[1])
        return start_vlan, end_vlan

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
        if is_chained_mode(self.config):
            if not self.config["chained_cni_config"]["skip_node_network_provisioning"]:
                pool_name = self.config["aci_config"]["physical_domain"]["vlan_pool"]
                kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
                phys_name = self.config["aci_config"]["physical_domain"]["domain"]
                if phys_name != self.config["user_config"]["aci_config"].get("physical_domain", {}).get("domain", False):
                    update(data, self.pdom_pool_chained(pool_name, [kubeapi_vlan]))
                    update(data, self.chained_phys_dom(phys_name, pool_name))
                update(data, self.chained_mode_associate_aep())

            # if self.config["user_config"]["aci_config"].get("vmm_domain") == None:
            #     update(data, self.chained_kube_dom(apic_version))

            update(data, getattr(self, self.tenant_generator_chained_mode)())
            if self.config["aci_config"].get("l3out", None).get("external_networks", False):
                update(data, self.l3out_tn())
                for l3out_instp in self.config["aci_config"]["l3out"]["external_networks"]:
                    update(data, self.l3out_contract(l3out_instp))
            update(data, self.kube_user())
            update(data, self.kube_cert())
            update(data, self.chained_mode_common_ap())
            return data
        elif "calico" not in self.config['flavor']:
            update(data, self.pdom_pool())
            update(data, self.vdom_pool())
            update(data, self.mcast_pool())
            phys_name = self.config["aci_config"]["physical_domain"]["domain"]
            pool_name = self.config["aci_config"]["physical_domain"]["vlan_pool"]
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
            update(data, self.phys_dom(phys_name, pool_name))

        else:
            cluster_l3out_vrf_details = self.get_cluster_l3out_vrf_details()
            cluster_l3out_tn = cluster_l3out_vrf_details["tenant"]
            cluster_l3out_vrf = cluster_l3out_vrf_details["name"]
            print("INFO: cluster_l3out is under tenant: %s, vrf: %s " % (cluster_l3out_tn, cluster_l3out_vrf))
            if cluster_l3out_vrf_details["create_tenant"]:
                if self.apic and not self.apic.get_tenant(cluster_l3out_tn):
                    update(data, self.cluster_l3out_tenant(cluster_l3out_vrf_details))
                else:
                    # TODO: temp UT fix, use mock
                    update(data, self.cluster_l3out_tenant(cluster_l3out_vrf_details))
            if cluster_l3out_vrf_details["create_vrf"]:
                if self.apic and not self.apic.get_tenant_vrf(cluster_l3out_tn, cluster_l3out_vrf):
                    update(data, self.cluster_l3out_vrf(cluster_l3out_vrf_details))
                else:
                    # TODO: temp UT fix, use mock
                    update(data, self.cluster_l3out_vrf(cluster_l3out_vrf_details))
            update(data, self.create_cluster_l3out(cluster_l3out_vrf_details))
            update(data, self.l3_dom_calico())
            update(data, self.pdom_pool_calico())
            update(data, self.phys_dom_calico())
            update(data, self.associate_aep_to_phys_dom_and_l3_dom_calico())
            # update(data, self.logical_node_profile())
            node_ids = None
            node_map = {}
            tenant = cluster_l3out_vrf_details["tenant"]
            if self.apic is not None:
                ext_l3out_lnodep = self.apic.get_ext_l3out_lnodep(self.config["aci_config"]["vrf"]["tenant"], self.config["aci_config"]["l3out"]["name"])
                node_ids = self.apic.get_configured_node_dns(tenant, self.config["aci_config"]["cluster_l3out"]["name"], self.config["aci_config"]["cluster_l3out"]["svi"]["node_profile_name"])
                node_map = self.apic.get_extl3out_configured_nodes_router_id(self.config["aci_config"]["vrf"]["tenant"], self.config["aci_config"]["l3out"]["name"], ext_l3out_lnodep)

            else:
                # For "calico" flavor based UT
                node_ids = ["topology/pod-1/node-101"]
                node_map = {"topology/pod-1/node-102": "2.2.2.2"}
            for rack in self.config["topology"]["rack"]:
                for leaf in rack["leaf"]:
                    if "local_ip" in leaf and "id" in leaf:
                        update(data, self.calico_floating_svi(rack["aci_pod_id"], leaf["id"], leaf["local_ip"], tenant))
                        if len(node_map) == 0 and ("topology/pod-%s/node-%s" % (rack["aci_pod_id"], leaf["id"])) not in node_ids:
                            update(data, self.add_configured_nodes(rack["aci_pod_id"], leaf["id"], tenant))
            # If the node already has a router_id in external l3out, then use the same router_id
            if len(node_map) != 0:
                for node_dn, router_id in node_map.items():
                    update(data, self.add_configured_nodes_with_routerid(rack["aci_pod_id"], node_dn, router_id, tenant))
                    if node_dn not in node_ids:
                        node_ids.append(node_dn)
                # Finally add all other nodes which arent added.
                for rack in self.config["topology"]["rack"]:
                    for leaf in rack["leaf"]:
                        if ("topology/pod-%s/node-%s" % (rack["aci_pod_id"], leaf["id"])) not in node_ids:
                            update(data, self.add_configured_nodes(rack["aci_pod_id"], leaf["id"], tenant))

            update(data, self.l3out_filter())

            external_l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
            external_l3out_vrf = self.config["aci_config"]["vrf"]["name"]

            if cluster_l3out_tn != external_l3out_tn and cluster_l3out_vrf != external_l3out_vrf:
                # different tenant, different vrf
                if external_l3out_tn != "common":
                    """
                    1. Create global scope contract under provider (vrf) tenant
                    2. Export global scope contract under consumer(cluster_l3out) tenant
                    3. Consumer tenant has the floating svi l3 out. The ext epgs under floating
                       l3out consume the exported contract
                    """
                    update(data, self.l3out_brcp_global())
                    update(data, self.cluster_l3out_cif_global())
                    update(data, self.ext_epg_svc_contract_interface())
                    update(data, self.ext_epg_int_contract_interface())
                else:
                    """
                    1. Create global scope contract under provider(vrf) tenant
                    2. The ext epgs under floating l3out consume this global scope contract
                    """
                    update(data, self.l3out_brcp_global())
                    update(data, self.ext_epg_svc_global_scope_contract())
                    update(data, self.ext_epg_int_global_scope_contract())
            elif cluster_l3out_tn == external_l3out_tn and cluster_l3out_vrf != external_l3out_vrf:
                """
                same tenant, different vrf
                1. Create global scope contract under provider(vrf) tenant
                2. The ext epgs under floating l3out consume this global scope contract
                """
                update(data, self.l3out_brcp_global())
                update(data, self.ext_epg_svc_global_scope_contract())
                update(data, self.ext_epg_int_global_scope_contract())
            else:
                """
                # same tenant, same vrf
                1. Create local vrf scope contract
                2. The ext epgs under floating l3out consume this local scope contract
                """
                update(data, self.l3out_brcp())
                update(data, self.ext_epg_svc())
                update(data, self.ext_epg_int())

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
        for l3out_instp in self.config["aci_config"]["l3out"]["external_networks"]:
            update(data, self.l3out_contract(l3out_instp))
        update(data, self.kube_user())
        update(data, self.kube_cert())
        return data

    def annotateApicObjects(self, data, pre_existing_tenant=False, ann=aciContainersOwnerAnnotation):
        # apic objects are dicts of length 1
        assert (len(data) <= 1)
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

        if is_chained_mode(self.config) and key == "fvAp":
            tenant_name = self.config["aci_config"].get("tenant", None).get("name", None)
            if self.apic and tenant_name:
                app_profile = self.ACI_CHAINED_PREFIX + self.config["aci_config"]["system_id"]
                if self.apic.get_ap(tenant_name, app_profile):
                    data[key]["attributes"]["annotation"] = ""

    def cluster_info(self):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vmm_type = self.config["aci_config"]["vmm_domain"]["type"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        vmm_inj_cluster_type = self.config["aci_config"]["vmm_domain"]["injected_cluster_type"]
        vmm_inj_cluster_provider = self.config["aci_config"]["vmm_domain"]["injected_cluster_provider"]
        input_yaml = yaml.safe_load(self.config["user_input"])
        accProvisionInput = yaml.safe_dump(input_yaml, sort_keys=False)
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

    def pdom_pool_chained(self, pool_name, vlan_list):
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
                                [],
                            ),
                        ]
                    ),
                )
            ]
        )
        for vlan in vlan_list:
            start_vlan, end_vlan = self.get_vlan_range(vlan)
            vlan_encap_blk_obj = collections.OrderedDict(
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
                                                % start_vlan,
                                            ),
                                            (
                                                "to",
                                                "vlan-%s"
                                                % end_vlan,
                                            ),
                                        ]
                                    ),
                                )
                            ]
                        ),
                    )
                ]
            )
            data["fvnsVlanInstP"]["children"].append(vlan_encap_blk_obj)
        self.annotateApicObjects(data)
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

    def chained_phys_dom(self, phys_name, pool_name):
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
                                [],
                            ),
                        ]
                    ),
                )
            ]
        )
        if pool_name:
            vlan_pool_obj = collections.OrderedDict(
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
            data["physDomP"]["children"].append(vlan_pool_obj)
        self.annotateApicObjects(data)
        return path, data

    def phys_dom(self, phys_name, pool_name):
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

    def chained_kube_dom(self, apic_version):
        vmm_type = self.config["aci_config"]["vmm_domain"]["type"]
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        encap_type = self.config["aci_config"]["vmm_domain"]["encap_type"]
        mcast_fabric = self.config["aci_config"]["vmm_domain"]["mcast_fabric"]
        cluster_provider = self.config["aci_config"]["vmm_domain"]["injected_cluster_provider"]

        mode = "k8s"
        if vmm_type == "OpenShift":
            mode = "openshift"
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

    def cluster_l3out_vrf(self, cluster_l3out_vrf_details):
        vrf_name = cluster_l3out_vrf_details["name"]
        tn_name = cluster_l3out_vrf_details["tenant"]
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
        self.annotateApicObjects(data)
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
        vpath = ""
        if 'vlan_pool' in self.config['aci_config']['vmm_domain']['nested_inside']:
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

        nvmm_elag_name = self.config["aci_config"]["vmm_domain"]["nested_inside"]["elag_name"]
        if nvmm_elag_name:
            nvmm_elag_dn = "uni/vmmp-VMware/dom-%s/vswitchpolcont/enlacplagp-%s" % (nvmm_name, nvmm_elag_name)
            data["fvRsDomAtt"]["children"].append(
                collections.OrderedDict(
                    [
                        (
                            "fvAEPgLagPolAtt",
                            collections.OrderedDict(
                                [
                                    (
                                        "attributes",
                                        collections.OrderedDict(
                                            [
                                                ("annotation", ""),
                                                ("userdom", ":all:")
                                            ]
                                        )
                                    ),
                                    (
                                        "children",
                                        [
                                            collections.OrderedDict(
                                                [
                                                    (
                                                        "fvRsVmmVSwitchEnhancedLagPol",
                                                        collections.OrderedDict(
                                                            [
                                                                (
                                                                    "attributes",
                                                                    collections.OrderedDict(
                                                                        [
                                                                            ("annotation", ""),
                                                                            ("tDn", nvmm_elag_dn),
                                                                            ("userdom", ":all:")
                                                                        ]
                                                                    )
                                                                )
                                                            ]
                                                        )
                                                    )
                                                ]
                                            )
                                        ]
                                    )
                                ]
                            )
                        )
                    ]
                )
            )

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

    def chained_mode_associate_aep(self):
        aep_name = self.config["aci_config"]["aep"]
        phys_name = self.config["aci_config"]["physical_domain"]["domain"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        system_id = self.config["aci_config"]["system_id"]
        aci_system_id = self.ACI_CHAINED_PREFIX + system_id

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
                                                                                        self.ACI_CHAINED_PREFIX,
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
        rsphy = base + "/rsdomP-[uni/phys-%s].json" % phys_name

        if self.config["aci_config"]["use_legacy_kube_naming_convention"]:
            rsfun = (
                base + "/gen-default/rsfuncToEpg-"
                "[uni/tn-%s/ap-kubernetes/epg-kube-nodes].json" % (tn_name)
            )
        else:
            rsfun = (
                base + "/gen-default/rsfuncToEpg-"
                "[uni/tn-%s/ap-%s/epg-%snodes].json" % (tn_name, aci_system_id, self.ACI_CHAINED_PREFIX)
            )
        self.annotateApicObjects(data)
        return path, data, rsphy, rsfun

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

    def cluster_l3out_tenant(self, cluster_l3out_vrf_details):
        tenant = cluster_l3out_vrf_details["tenant"]
        path = "/api/mo/uni/tn-%s.json" % tenant
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
                                        ("name", "%s" % tenant),
                                        ("dn", "uni/tn-%s" % tenant),
                                    ]
                                ),
                            ),
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

    def l3out_filter(self):
        system_id = self.config["aci_config"]["system_id"]
        vrf_tenant = self.config["aci_config"]["vrf"]["tenant"]

        path = "/api/mo/uni/tn-%s/flt-%s-allow-all-filter.json" % (vrf_tenant, system_id)
        data = collections.OrderedDict(
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
        )
        self.annotateApicObjects(data)
        return path, data

    def cluster_l3out_cif_global(self):
        system_id = self.config["aci_config"]["system_id"]
        tenant = self.config["aci_config"]["cluster_l3out"]["vrf"]["tenant"]
        vrf_tenant = self.config["aci_config"]["vrf"]["tenant"]

        path = "/api/mo/uni/tn-%s/cif-%s-l3out-allow-all-export.json" % (tenant, system_id)
        data = collections.OrderedDict(
            [
                (
                    "vzCPIf",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        (
                                            "name",
                                            "%s-l3out-allow-all-export"
                                            % system_id,
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
                                                "vzRsIf",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "intent",
                                                                        "install",
                                                                    ),
                                                                    (
                                                                        "tDn",
                                                                        "uni/tn-%s/brc-%s-l3out-allow-all"
                                                                        % (vrf_tenant, system_id),
                                                                    ),
                                                                ]
                                                            ),
                                                        ),
                                                    ],
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

    def l3out_brcp_global(self):
        system_id = self.config["aci_config"]["system_id"]
        vrf_tenant = self.config["aci_config"]["vrf"]["tenant"]

        path = "/api/mo/uni/tn-%s/brc-%s-l3out-allow-all.json" % (vrf_tenant, system_id)
        data = collections.OrderedDict(
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
                                        ),
                                        (
                                            "scope",
                                            "global",
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
        )
        self.annotateApicObjects(data)
        return path, data

    def l3out_brcp(self):
        system_id = self.config["aci_config"]["system_id"]
        vrf_tenant = self.config["aci_config"]["vrf"]["tenant"]

        path = "/api/mo/uni/tn-%s/brc-%s-l3out-allow-all.json" % (vrf_tenant, system_id)
        data = collections.OrderedDict(
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
        )
        self.annotateApicObjects(data)
        return path, data

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

    def hasV6(self):
        subnet_fields = ["node_subnet", "pod_subnet"]
        for subnet_field in subnet_fields:
            subnets = self.config["net_config"].get(subnet_field, [])
            if not isinstance(subnets, list):
                subnets = [subnets]
        for subnet in subnets:
            rtr, mask = subnet.split("/")
            ip = ipaddress.ip_address(rtr)
            if ip.version == 6:
                return True
        return False

    def isV6(self, cidr):
        rtr, mask = cidr.split("/")
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

    def chained_mode_common_ap(self):
        ap_name = 'netop-common'
        path = "/api/mo/uni/tn-common/ap-%s.json" % ap_name
        data = collections.OrderedDict(
            [
                (
                    "fvAp",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [("name", ap_name), ("dn", "uni/tn-common/ap-%s" % ap_name)]
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
        self.annotateApicObjects(data)
        return path, data

    def chained_mode_kube_tn(self):
        system_id = self.config["aci_config"]["system_id"]
        app_profile = self.config["aci_config"]["app_profile"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        pre_existing_tenant = self.config["aci_config"]["use_pre_existing_tenant"]
        phys_name = self.config["aci_config"]["physical_domain"]["domain"]
        kubeapi_vlan = self.config["net_config"]["kubeapi_vlan"]
        kube_vrf = self.config["aci_config"]["vrf"]["name"]
        kube_l3out = self.config["aci_config"].get("l3out", None).get("name", None)
        node_subnets = self.config["net_config"].get("node_subnet", [])
        if not isinstance(node_subnets, list):
            node_subnets = [node_subnets]

        bd_prefix = self.ACI_CHAINED_PREFIX
        epg_prefix = self.ACI_CHAINED_PREFIX

        node_bd_name = "%snodes" % bd_prefix
        node_epg_name = "%snodes" % epg_prefix
        kube_default_children = []
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
                                                            [],
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

        if self.config["aci_config"]["vmm_domain"]:
            vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
            vmm_type = self.config["aci_config"]["vmm_domain"]["type"]
            vmm_epg_rs_obj = collections.OrderedDict(
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
            )
            kube_default_children.append(vmm_epg_rs_obj)

        if not self.config["chained_cni_config"]["skip_node_network_provisioning"]:
            l3out_contract_obj = collections.OrderedDict(
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
            )

            node_epg_obj = collections.OrderedDict(
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
            )

            if kube_l3out:
                node_epg_obj["fvAEPg"]["children"].append(l3out_contract_obj)

            node_bd_obj = collections.OrderedDict(
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
                                                node_bd_name,
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

            # If dhcp_relay_label is present, attach the label to the kube-node-bd
            if "dhcp_relay_label" in self.config["aci_config"]:
                dbg("Handle DHCP Relay Label")
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
            tenant_obj = data["fvTenant"]["children"]
            tenant_obj.append(node_bd_obj)
            for i, child in enumerate(data["fvTenant"]["children"]):
                if "fvAp" in child.keys() and child["fvAp"]["attributes"]["name"] == app_profile:
                    ap_object = child["fvAp"]["children"]
                    ap_object.append(node_epg_obj)

                    if self.config["aci_config"]["vmm_domain"]:
                        for j, ap_child in enumerate(child["fvAp"]["children"]):
                            if "fvAEPg" in ap_child.keys() and ap_child["fvAEPg"]["attributes"]["name"] == node_epg_name:
                                epg_object = ap_child["fvAEPg"]["children"]
                                epg_object.append(vmm_epg_rs_obj)

                    if not self.config["aci_config"]["no_physdom_for_node_epg"]:
                        if not self.config["aci_config"]["vmm_domain"]:
                            for j, ap_child in enumerate(child["fvAp"]["children"]):
                                if "fvAEPg" in ap_child.keys() and ap_child["fvAEPg"]["attributes"]["name"] == node_epg_name:
                                    epg_object = ap_child["fvAEPg"]["children"]
                        epg_object.append(kubeapi_dom_obj)

                if "fvBD" in child.keys() and child["fvBD"]["attributes"]["name"] == node_bd_name:
                    bd_object = child["fvBD"]["children"]
                    for node_subnet in node_subnets:
                        node_subnet_obj = collections.OrderedDict(
                            [("attributes", collections.OrderedDict([("ip", node_subnet)]))]
                        )
                        bd_object.append(
                            collections.OrderedDict(
                                [
                                    (
                                        "fvSubnet",
                                        node_subnet_obj
                                    )
                                ]
                            )
                        )
                    if kube_l3out:
                        l3out_object = collections.OrderedDict(
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
                        )
                        bd_object.append(l3out_object)

                    # If dhcp_relay_label is present, attach the label to the kube-node-bd
                    if "dhcp_relay_label" in self.config["aci_config"]:
                        bd_object.append(attr)
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

        self.annotateApicObjects(data, pre_existing_tenant)
        return path, data

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
        node_subnets = self.config["net_config"].get("node_subnet", [])
        if not isinstance(node_subnets, list):
            node_subnets = [node_subnets]
        pod_subnets = self.config["net_config"].get("pod_subnet", [])
        if not isinstance(pod_subnets, list):
            pod_subnets = [pod_subnets]

        kade = self.config["kube_config"].get("allow_kube_api_default_epg") or \
            self.config["kube_config"].get("allow_pods_kube_api_access")
        eade = self.config["kube_config"].get("allow_pods_external_access")
        vmm_type = self.config["aci_config"]["vmm_domain"]["type"]
        v6subnet = self.hasV6()
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
        pod_bd_name = "%spod-bd" % bd_prefix

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
        ipv6_nd_policy_rs = []
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

        # if self.isV6(self.config["net_config"]["node_subnet"]):
        #     node_subnet_obj["attributes"]["ctrl"] = "nd"
        #     node_subnet_obj["children"] = ipv6_nd_policy_rs

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
        for i, child in enumerate(data["fvTenant"]["children"]):
            if "fvBD" in child.keys() and child["fvBD"]["attributes"]["name"] == node_bd_name:
                bd_object = child["fvBD"]["children"]
                for node_subnet in node_subnets:
                    node_subnet_obj = collections.OrderedDict(
                        [("attributes", collections.OrderedDict([("ip", node_subnet)]))]
                    )
                    if eade is True:
                        node_subnet_obj["attributes"]["scope"] = "public"
                    if self.isV6(node_subnet):
                        node_subnet_obj["attributes"]["ctrl"] = "nd"
                        node_subnet_obj["children"] = ipv6_nd_policy_rs
                    bd_object.append(
                        collections.OrderedDict(
                            [
                                (
                                    "fvSubnet",
                                    node_subnet_obj
                                )
                            ]
                        )
                    )
            if "fvBD" in child.keys() and child["fvBD"]["attributes"]["name"] == pod_bd_name:
                bd_object = child["fvBD"]["children"]
                for pod_subnet in pod_subnets:
                    pod_subnet_obj = collections.OrderedDict(
                        [("attributes", collections.OrderedDict([("ip", pod_subnet)]))]
                    )
                    if eade is True:
                        pod_subnet_obj["attributes"]["scope"] = "public"
                    if self.isV6(pod_subnet):
                        pod_subnet_obj["attributes"]["ctrl"] = "nd"
                        pod_subnet_obj["children"] = ipv6_nd_policy_rs
                    bd_object.append(
                        collections.OrderedDict(
                            [
                                (
                                    "fvSubnet",
                                    pod_subnet_obj
                                )
                            ]
                        )
                    )

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
            del data["fvTenant"]["children"][2]["fvBD"]["children"][1]

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
                if flavor.startswith("openshift") and self.is_ocp_version_4_8_and_above(flavor):
                    add_l3out_allow_all_for_istio_epg(data, system_id, epg_prefix)
            elif flavor == "docker-ucp-3.0":
                dockerucp_flavor_specific_handling(data, items, api_filter_prefix)
            elif flavor.startswith("RKE"):
                rke_flavor_specific_handling(aci_prefix, data, items, api_filter_prefix, self.config["rke_config"])
            elif flavor == "k8s-aci-cilium":
                k8s_cilium_aci_specific_handling(self.ACI_PREFIX, old_naming, data, items)

        # Adding prometheus opflex-agent contract for all flavors
        add_prometheus_opflex_agent_contract(data, epg_prefix, contract_prefix, filter_prefix)

        if self.config.get("cilium_chaining"):
            if self.config["cilium_chaining"].get("enable"):
                if self.config["cilium_chaining"]["enable"]:
                    # Adding hubble-peer contract for all flavors
                    add_hubble_4244_allow(data, epg_prefix, contract_prefix, filter_prefix)

        self.annotateApicObjects(data, pre_existing_tenant)
        return path, data

    def is_ocp_version_4_8_and_above(self, flavor):
        flavor_version = flavor.split('-')
        major_version = int(flavor_version[1].split('.')[0])
        minor_version = int(flavor_version[1].split('.')[1])
        if (major_version >= 4 and minor_version >= 8):
            return True
        return False

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

    def l3_dom_calico(self):
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        l3_dom_name = l3out_name + "-L3-dom"
        pool_name = l3out_name + "-pool"

        path = "/api/mo/uni/l3dom-%s.json" % l3_dom_name
        data = collections.OrderedDict(
            [
                (
                    "l3extDomP",
                    collections.OrderedDict(
                        [
                            (
                                "attributes",
                                collections.OrderedDict(
                                    [
                                        ("dn", "uni/l3dom-%s" % l3_dom_name),
                                        ("name", l3_dom_name),
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

    def pdom_pool_calico(self):
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        pool_name = l3out_name + "-pool"
        vlan = self.config["aci_config"]["cluster_l3out"]["svi"]["vlan_id"]

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
                                                                        % vlan,
                                                                    ),
                                                                    (
                                                                        "to",
                                                                        "vlan-%s"
                                                                        % vlan,
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

    def phys_dom_calico(self):
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        phys_name = l3out_name + "-phys-dom"
        pool_name = l3out_name + "-pool"

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

    def create_cluster_l3out(self, cluster_l3out_vrf_details):
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        l3out_tn = cluster_l3out_vrf_details["tenant"]
        vrf_name = cluster_l3out_vrf_details["name"]
        l3_dom_name = l3out_name + "-L3-dom"
        lnodep = self.config["aci_config"]["cluster_l3out"]["svi"]["node_profile_name"]
        lifp = self.config["aci_config"]["cluster_l3out"]["svi"]["int_prof_name"]
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
                                        ("name", l3out_name),
                                        ("enforceRtctrl", "export,import"),
                                    ]
                                ),
                            ),
                            (
                                "children",
                                [
                                    collections.OrderedDict(
                                        [
                                            (
                                                # Map VRF
                                                "l3extRsEctx",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("tnFvCtxName", vrf_name),
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
                                                # Map l3_domain
                                                "l3extRsL3DomAtt",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("tDn", "uni/l3dom-%s" % l3_dom_name),
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
                                ],
                            )

                        ],
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def associate_aep_to_phys_dom_and_l3_dom_calico(self):
        aep_name = self.config["aci_config"]["cluster_l3out"]["aep"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        phys_name = l3out_name + "-phys-dom"
        l3dom_name = l3out_name + "-L3-dom"

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
                                                "infraRsDomP",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    (
                                                                        "tDn",
                                                                        "uni/l3dom-%s"
                                                                        % l3dom_name,
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
                    )
                )
            ]
        )
        self.annotateApicObjects(data)
        return path, data

    def add_configured_nodes(self, pod_id, node_id, l3out_tn):
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        lnodep = self.config["aci_config"]["cluster_l3out"]["svi"]["node_profile_name"]
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
                                        ("rtrIdLoopBack", "no"),
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

    def add_configured_nodes_with_routerid(self, pod_id, node_dn, router_id, l3out_tn):
        cluster_l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        lnodep = self.config["aci_config"]["cluster_l3out"]["svi"]["node_profile_name"]
        path = "/api/mo/uni/tn-%s/out-%s/lnodep-%s/rsnodeL3OutAtt-[%s].json" % (l3out_tn, cluster_l3out_name, lnodep, node_dn)
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
                                        ("rtrIdLoopBack", "no"),
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

    def get_cluster_l3out_vrf_details(self):
        cluster_l3out_vrf = {
            "name": self.config["aci_config"]["vrf"]["name"],
            "tenant": self.config["aci_config"]["vrf"]["tenant"],
            "create_tenant": False,
            "create_vrf": False,
        }
        if self.config["aci_config"]["cluster_l3out"].get("vrf"):
            if self.config["aci_config"]["cluster_l3out"]["vrf"].get("tenant"):
                cluster_l3out_vrf["tenant"] = self.config["aci_config"]["cluster_l3out"]["vrf"]["tenant"]
                cluster_l3out_vrf["create_tenant"] = True

            cluster_l3out_vrf["create_vrf"] = True
            if self.config["aci_config"]["cluster_l3out"]["vrf"].get("name"):
                cluster_l3out_vrf["name"] = self.config["aci_config"]["cluster_l3out"]["vrf"]["name"]
            else:
                cluster_l3out_vrf["name"] = cluster_l3out_vrf["tenant"] + "_vrf"
        return cluster_l3out_vrf

    def calico_floating_svi(self, pod_id, node_id, primary_ip, l3out_tn):
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        node_dn = "topology/pod-%s/node-%s" % (pod_id, node_id)
        vlan_id = self.config["aci_config"]["cluster_l3out"]["svi"]["vlan_id"]
        mtu = self.config["aci_config"]["cluster_l3out"]["svi"]["mtu"]
        node_subnet = self.config["net_config"]["node_subnet"]
        primary_addr = primary_ip + "/" + node_subnet.split("/")[-1]
        floating_ip = self.config["aci_config"]["cluster_l3out"]["svi"]["floating_ip"]
        secondary_ip = self.config["aci_config"]["cluster_l3out"]["svi"]["secondary_ip"]
        physical_domain_name = l3out_name + "-phys-dom"
        remote_asn = self.config["aci_config"]["cluster_l3out"]["bgp"]["peering"]["remote_as_number"]
        if "secret" in self.config["aci_config"]["cluster_l3out"]["bgp"]:
            password = self.config["aci_config"]["cluster_l3out"]["bgp"]["secret"]
        else:
            password = None
        logical_node_profile = self.config["aci_config"]["cluster_l3out"]["svi"]["node_profile_name"]
        int_prof = self.config["aci_config"]["cluster_l3out"]["svi"]["int_prof_name"]
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
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        l3out_tn = self.get_cluster_l3out_vrf_details()["tenant"]
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

    def ext_epg_svc_contract_interface(self):
        system_id = self.config["aci_config"]["system_id"]
        l3out_tn = self.config["aci_config"]["cluster_l3out"]["vrf"]["tenant"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        external_svc_subnet = self.config["net_config"]["extern_dynamic"]
        ext_epg = self.config["aci_config"]["cluster_l3out"]["svi"]["external_network_svc"]
        l3out_rsprov_name = "%s-l3out-allow-all-export" % system_id
        path = "/api/mo/uni/tn-%s/out-%s/instP-%s.json" % (l3out_tn, l3out_name, ext_epg)
        scope = "export-rtctrl,import-rtctrl,import-security,shared-security,shared-rtctrl"
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
                                                # consume l3out-allow-all-export contract
                                                "fvRsConsIf",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("tnVzCPIfName", l3out_rsprov_name),
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
                                                                    ("scope", scope),
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

    def ext_epg_svc_global_scope_contract(self):
        system_id = self.config["aci_config"]["system_id"]
        l3out_tn = self.config["aci_config"]["cluster_l3out"]["vrf"].get("tenant")
        if not l3out_tn:
            l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        external_svc_subnet = self.config["net_config"]["extern_dynamic"]
        ext_epg = self.config["aci_config"]["cluster_l3out"]["svi"]["external_network_svc"]
        l3out_rsprov_name = "%s-l3out-allow-all" % system_id
        path = "/api/mo/uni/tn-%s/out-%s/instP-%s.json" % (l3out_tn, l3out_name, ext_epg)
        scope = "export-rtctrl,import-rtctrl,import-security,shared-security,shared-rtctrl"
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
                                                "fvRsCons",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("tnVzBrCPName", l3out_rsprov_name),
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
                                                                    ("scope", scope),
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

    def ext_epg_svc(self):
        system_id = self.config["aci_config"]["system_id"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        external_svc_subnet = self.config["net_config"]["extern_dynamic"]
        ext_epg = self.config["aci_config"]["cluster_l3out"]["svi"]["external_network_svc"]
        l3out_rsprov_name = "%s-l3out-allow-all" % system_id
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
                                                "fvRsCons",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("tnVzBrCPName", l3out_rsprov_name),
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

    def ext_epg_int_contract_interface(self):
        system_id = self.config["aci_config"]["system_id"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        l3out_tn = self.config["aci_config"]["cluster_l3out"]["vrf"]["tenant"]
        pod_subnet = self.config["net_config"]["pod_subnet"]
        node_subnet = self.config["net_config"]["node_subnet"]
        cluster_svc_subnet = self.config["net_config"]["cluster_svc_subnet"]
        ext_epg = self.config["aci_config"]["cluster_l3out"]["svi"]["external_network"]
        l3out_rsprov_name = "%s-l3out-allow-all-export" % system_id
        path = "/api/mo/uni/tn-%s/out-%s/instP-%s.json" % (l3out_tn, l3out_name, ext_epg)
        scope = "export-rtctrl,import-rtctrl,import-security,shared-security,shared-rtctrl"
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
                                                # consume l3out-allow-all-export contract
                                                "fvRsConsIf",
                                                collections.OrderedDict(
                                                    [
                                                        (
                                                            "attributes",
                                                            collections.OrderedDict(
                                                                [
                                                                    ("tnVzCPIfName", l3out_rsprov_name),
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
                                                                    ("scope", scope),
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
                                                                    ("aggregate", "shared-rtctrl"),
                                                                    ("scope", scope),
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
                                                                    ("scope", scope),
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

    def ext_epg_int_global_scope_contract(self):
        system_id = self.config["aci_config"]["system_id"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        l3out_tn = self.config["aci_config"]["cluster_l3out"]["vrf"].get("tenant")
        if not l3out_tn:
            l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        pod_subnet = self.config["net_config"]["pod_subnet"]
        node_subnet = self.config["net_config"]["node_subnet"]
        cluster_svc_subnet = self.config["net_config"]["cluster_svc_subnet"]
        ext_epg = self.config["aci_config"]["cluster_l3out"]["svi"]["external_network"]
        l3out_rsprov_name = "%s-l3out-allow-all" % system_id
        path = "/api/mo/uni/tn-%s/out-%s/instP-%s.json" % (l3out_tn, l3out_name, ext_epg)
        scope = "export-rtctrl,import-rtctrl,import-security,shared-security,shared-rtctrl"
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
                                                                    ("tnVzBrCPName", l3out_rsprov_name),
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
                                                                    ("scope", scope),
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
                                                                    ("aggregate", "shared-rtctrl"),
                                                                    ("scope", scope),
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
                                                                    ("scope", scope),
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
    def ext_epg_int(self):
        system_id = self.config["aci_config"]["system_id"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        l3out_tn = self.config["aci_config"]["vrf"]["tenant"]
        pod_subnet = self.config["net_config"]["pod_subnet"]
        node_subnet = self.config["net_config"]["node_subnet"]
        cluster_svc_subnet = self.config["net_config"]["cluster_svc_subnet"]
        ext_epg = self.config["aci_config"]["cluster_l3out"]["svi"]["external_network"]
        l3out_rsprov_name = "%s-l3out-allow-all" % system_id
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
                                                                    ("tnVzBrCPName", l3out_rsprov_name),
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
        if not self.config["net_config"]["advertise_cluster_svc_subnet"]:
            del data["l3extInstP"]["children"][3]
        self.annotateApicObjects(data)
        return path, data

    def enable_bgp(self):
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        l3out_tn = self.get_cluster_l3out_vrf_details()["tenant"]
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
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        l3out_tn = self.get_cluster_l3out_vrf_details()["tenant"]
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
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        l3out_tn = self.get_cluster_l3out_vrf_details()["tenant"]
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
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        l3out_tn = self.get_cluster_l3out_vrf_details()["tenant"]
        logical_node_profile = self.config["aci_config"]["cluster_l3out"]["svi"]["node_profile_name"]
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
        l3out_tn = self.get_cluster_l3out_vrf_details()["tenant"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
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
        cluster_l3out_vrf_details = self.get_cluster_l3out_vrf_details()
        l3out_tn = cluster_l3out_vrf_details["tenant"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        l3out_vrf = cluster_l3out_vrf_details["name"]
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
        cluster_l3out_vrf_details = self.get_cluster_l3out_vrf_details()
        l3out_tn = cluster_l3out_vrf_details["tenant"]
        l3out_vrf = cluster_l3out_vrf_details["name"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
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
        l3out_tn = self.get_cluster_l3out_vrf_details()["tenant"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
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
        l3out_tn = self.get_cluster_l3out_vrf_details()["tenant"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
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
        l3out_tn = self.get_cluster_l3out_vrf_details()["tenant"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
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
        if not self.config["net_config"]["advertise_cluster_svc_subnet"]:
            del data["rtctrlSubjP"]["children"][2]
        self.annotateApicObjects(data)
        return path, data

    def attach_rule_to_default_import_pol(self):
        l3out_tn = self.get_cluster_l3out_vrf_details()["tenant"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
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
        l3out_tn = self.get_cluster_l3out_vrf_details()["tenant"]
        l3out_name = self.config["aci_config"]["cluster_l3out"]["name"]
        prefixes = self.config["aci_config"]["cluster_l3out"]["bgp"]["peering"]["prefixes"]
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
                                        ("maxPfx", str(prefixes)),
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


def add_hubble_4244_allow(data, epg_prefix, contract_prefix, filter_prefix):
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
                                        "%shubble-peer" % contract_prefix
                                    )
                                ]
                            ),
                        )
                    ]
                ),
            )
        ]
    )
    for epg in ["%ssystem" % epg_prefix]:
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
                                        "%shubble-peer" % contract_prefix,
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
                                        "%shubble-peer-filter" % filter_prefix,
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
                                                                    "hubble-peer",
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
                                                                    "4244",
                                                                ),
                                                                (
                                                                    "dToPort",
                                                                    "4244",
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
                                [("name", "%shubble-peer" % contract_prefix)]
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
                                                                    "hubble-peer-subj",
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
                                                                                                "%shubble-peer-filter" % filter_prefix,
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


def add_l3out_allow_all_for_istio_epg(data, system_id, epg_prefix):
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
                                        "%s-l3out-allow-all" % system_id,
                                    )
                                ]
                            ),
                        )
                    ]
                ),
            )
        ]
    )
    for epg in ["%sistio" % epg_prefix]:
        for i, child in enumerate(data['fvTenant']['children'][0]['fvAp']['children']):
            if data['fvTenant']['children'][0]['fvAp']['children'][i]['fvAEPg']['attributes']['name'] == epg:
                data['fvTenant']['children'][0]['fvAp']['children'][i]['fvAEPg']['children'].append(consumer_contract)
                break


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
    data['fvTenant']['children'][0]['fvAp']['children'][2]['fvAEPg']['children'].append(consume_dns_contract_os)

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


def k8s_cilium_aci_specific_handling(aci_prefix, old_naming, data, items):
    if items is None or len(items) == 0:
        err("Error in getting items for flavor")
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
            if ('%sdefault' % "aci_prefix") in item['consumed']:
                data['fvTenant']['children'][0]['fvAp']['children'][0]['fvAEPg']['children'].append(consume_os_contract)
            if ('%ssystem' % aci_prefix) in item['consumed']:
                print("Here in consume contract")
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
                                                                                                    item[
                                                                                                        'name'] + "-filter",
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


if __name__ == "__main__":
    pass
