from __future__ import print_function, unicode_literals

import ipaddress
import json
import os
import os.path
import sys

import tempfile
if __package__ is None or __package__ == '':
    import kafka_cert
    from apic_provision import ApicKubeConfig
else:
    from . import kafka_cert
    from .apic_provision import ApicKubeConfig


def gwToSubnet(gw):
    u_gw = '{}'.format(str(gw))
    return str(ipaddress.ip_network(u_gw, strict=False))


def err(msg):
    print("ERR:  " + msg, file=sys.stderr)


class MoCleaner(object):
    def __init__(self, apic, config, debug=False):
        vmm_name = config["aci_config"]["vmm_domain"]["domain"]
        tn_name = config["aci_config"]["cluster_tenant"]
        annStr = "orchestrator:acc-provision-{}-{}".format(tn_name, vmm_name)
        self.apic = apic
        self.annStr = annStr
        self.debug = debug
        self.paths = []
        self.classes = []
        self.vmm_name = vmm_name

    def getAnnStr(self):
        return self.annStr

    def record(self, path, data):
        if path in self.paths:
            if self.debug:
                print("MoCleaner.record: path: {} already added".format(path))
            return
        self.paths.append(path)
        for klass in data.keys():
            self.classes.append(klass)
            if self.debug:
                print("MoCleaner.record: path: {} class: {}".format(path, klass))

    def deleteCandidate(self, p):
        resp = self.apic.get(path=p)
        resJson = json.loads(resp.content)
        if len(resJson["imdata"]) == 0:
            return False
        for key, value in resJson["imdata"][0].items():
            if "attributes" in value.keys():
                att = value["attributes"]
                if "annotation" in att.keys():
                    if att["annotation"] == self.annStr:
                        return True
        return False

    def doIt(self):
        print("Processing {} objects to delete".format(len(self.paths)))
        for p in reversed(self.paths):
            to_del = self.deleteCandidate(p)
            if not to_del:
                if self.debug:
                    print("MoCleaner: skipping {}".format(p))
                continue
            resp = self.apic.delete(p)
            if self.debug:
                print("MoCleaner.doIt: path: {} resp: {}".format(p, resp.text))
        inj_path = "/api/node/mo/comp/prov-Kubernetes/ctrlr-[{}]-{}/injcont.json".format(self.vmm_name, self.vmm_name)
        query = "{}?query-target=children&rsp-prop-include=naming-only".format(inj_path)
        resp = self.apic.get(path=query)
        resJson = json.loads(resp.content)
        if len(resJson["imdata"]) == 0:
            print("Nothing left to delete")
            return
        print("Deleting {} injected objects".format(len(resJson["imdata"])))
        for child in resJson["imdata"]:
            for key, value in child.items():
                if "attributes" in value.keys():
                    att = value["attributes"]
                    if "dn" in att.keys():
                        child_dn = att["dn"]
                        c_path = "/api/node/mo/{}.json".format(child_dn)
                        resp = self.apic.delete(c_path)
                        if self.debug:
                            print("MoCleaner.doIt: path: {} resp: {}".format(c_path, resp.text))


class CloudProvision(object):
    def __init__(self, apic, config, user_args):
        self.apic = apic
        self.config = config
        self.args = user_args

    def Run(self, flavor_opts, kube_yaml_gen_func):
        self.adjust_cidrs()
        self.configurator = ApicKubeConfig(self.config)
        self.deleter = MoCleaner(self.apic, self.config, self.args.debug)
        underlay_posts = []
        # if the cert_file was created or the sync user does not exist
        # create it
        sync_user = self.config["aci_config"]["sync_login"]["username"]
        post_user = not self.config["aci_config"]["sync_login"]["cert_reused"]
        post_user = post_user or not self.apic.get_user(sync_user)
        post_user = post_user or self.args.delete
        if post_user:
            underlay_posts.append(self.configurator.kube_user)
            underlay_posts.append(self.configurator.kube_cert)

        # update zone information as necessary
        self.setupZoneInfo()
        # if underlay ccp doesn't exist, create one
        u_ccp = self.getUnderlayCCP()
        if not u_ccp or self.args.delete:
            if not self.args.delete:
                print("Creating underlay\n")
            underlay_posts += [self.configurator.capic_underlay_vrf, self.configurator.capic_underlay_cloudApp, self.configurator.capic_underlay_ccp]
        else:
            # if existing vpc, cidr and subnet should be created as well
            underlay_posts += [self.configurator.capic_underlay_cloudApp]

        underlay_posts.append(self.setupCapicContractsInline)

        postGens = underlay_posts + [self.configurator.capic_kube_dom, self.configurator.capic_overlay_vrf, self.overlayCtx, self.configurator.capic_overlay_cloudApp, self.clusterInfo, self.configurator.capic_kafka_topic, self.prodAcl, self.consAcl]
        for pGen in postGens:
            path, data = pGen()
            if not path:  # posted inline
                continue

            self.postIt(path, data)
        if self.args.delete:
            self.deleter.doIt()
            self.apic.save()
            return True

        self.addKafkaConfig()
        self.addMiscConfig()

        if self.args.debug:
            print("Config is: {}".format(self.config["kube_config"]))
        gen = flavor_opts.get("template_generator", kube_yaml_gen_func)
        output_file = self.args.output
        output_tar = self.args.output_tar
        operator_cr_output_file = self.args.aci_operator_cr
        gen(self.config, output_file, output_tar, operator_cr_output_file)
        m_cidr = self.config["net_config"]["machine_cidr"]
        b_subnet = self.config["net_config"]["bootstrap_subnet"]
        n_subnet = self.config["net_config"]["node_subnet"]
        p_subnet = self.config["net_config"]["pod_subnet"].replace(".1/", ".0/")
        region = self.config["aci_config"]["vrf"]["region"]
        boot_subnetID = self.getSubnetID(b_subnet)
        node_subnetID = self.getSubnetID(n_subnet)
        print("\nOpenshift Info")
        print("----------------")
        print("networking:\n  clusterNetwork:\n  - cidr: {}\n    hostPrefix: 23\n  machineCIDR: {}\n  networkType: CiscoACI\n  serviceNetwork:\n  - 172.30.0.0/16\nplatform:\n  aws:\n    region: {}\n    subnets:\n    - {}\n    - {}".format(p_subnet, m_cidr, region, boot_subnetID, node_subnetID))
        self.apic.save()
        return True

    def adjust_cidrs(self):
        cidr = gwToSubnet(self.config["net_config"]["machine_cidr"])
        b_subnet = gwToSubnet(self.config["net_config"]["bootstrap_subnet"])
        n_subnet = gwToSubnet(self.config["net_config"]["node_subnet"])
        self.config["net_config"]["machine_cidr"] = cidr
        self.config["net_config"]["bootstrap_subnet"] = b_subnet
        self.config["net_config"]["node_subnet"] = n_subnet

    def getSubnetID(self, subnet):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        ccp_name = self.getUnderlayCCPName()
        cidr = self.config["net_config"]["machine_cidr"]
        subnetDN = "uni/tn-{}/ctxprofile-{}/cidr-[{}]/subnet-[{}]".format(tn_name, ccp_name, cidr, subnet)
        filter = "eq(hcloudSubnetOper.delegateDn, \"{}\")".format(subnetDN)
        query = '/api/node/class/hcloudSubnetOper.json?query-target=self&query-target-filter={}'.format(filter)
        resp = self.apic.get(path=query)
        resJson = json.loads(resp.content)
        if self.args.debug:
            print("query: {}".format(query))
            print("resp: {}".format(resJson))
        subnetID = resJson["imdata"][0]["hcloudSubnetOper"]["attributes"]["cloudProviderId"]
        return subnetID

    def getOverlayDn(self):
        query = self.configurator.capic_overlay_dn_query()
        resp = self.apic.get(path=query)
        resJson = json.loads(resp.content)
        if len(resJson["imdata"]) == 0:
            return ""
        overlayDn = resJson["imdata"][0]["hcloudCtx"]["attributes"]["dn"]
        return overlayDn

    def prodAcl(self):
        return self.configurator.capic_kafka_acl(self.config["aci_config"]["system_id"])

    def consAcl(self):
        # query to obtain the consumer common name
        resp = self.apic.get(path='/api/node/class/topSystem.json?query-target-filter=and(eq(topSystem.role,"controller"))')
        resJson = json.loads(resp.content)
        consCN = resJson["imdata"][0]["topSystem"]["attributes"]["serial"]
        if self.args.debug:
            print("Consumer CN: {}".format(consCN))
        return self.configurator.capic_kafka_acl(consCN)

    def clusterInfo(self):
        overlayDn = self.getOverlayDn()
        assert(overlayDn or self.args.delete), "Need an overlayDn"
        if self.args.debug:
            print("overlayDn: {}".format(overlayDn))
        return self.configurator.capic_cluster_info(overlayDn)

    def addMiscConfig(self):
        query = self.configurator.capic_subnet_dn_query()
        resp = self.apic.get(path=query)
        resJson = json.loads(resp.content)
        subnet_dn = resJson["imdata"][0]["hcloudSubnet"]["attributes"]["dn"]
        if self.args.debug:
            print("subnet_dn is {}".format(subnet_dn))
        self.config["aci_config"]["subnet_dn"] = subnet_dn
        vrf_dn = self.getOverlayDn()
        self.config["aci_config"]["vrf_dn"] = vrf_dn
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        self.config["aci_config"]["overlay_vrf"] = vmm_name + "_overlay"

    def getUnderlayCCP(self):
        vrfName = self.config["aci_config"]["vrf"]["name"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vrf_path = "/api/mo/uni/tn-%s/ctx-%s.json?query-target=subtree&target-subtree-class=fvRtToCtx" % (tn_name, vrfName)
        resp = self.apic.get(path=vrf_path)
        resJson = json.loads(resp.content)
        if self.args.debug:
            print(resJson)
        if len(resJson["imdata"]) == 0:
            return ""

        underlay_ccp = resJson["imdata"][0]["fvRtToCtx"]["attributes"]["tDn"]
        return underlay_ccp

    def overlayCtx(self):
        underlay_ccp = self.getUnderlayCCP()
        # cannot proceed without an underlay ccp
        assert(underlay_ccp or self.args.delete), "Need an underlay ccp"
        return self.configurator.capic_overlay(underlay_ccp)

    def getUnderlayCCPName(self):
        u_ccp = self.getUnderlayCCP()
        assert(u_ccp), "Need an underlay ccp"
        split_ccp = u_ccp.split("/")
        ccp_name = split_ccp[-1].replace("ctxprofile-", "")
        if self.args.debug:
            print("UnderlayCCPName: {}".format(ccp_name))
        return ccp_name

    def underlayCidr(self):
        ccp_name = self.getUnderlayCCPName()
        cidr = self.config["net_config"]["machine_cidr"]
        b_subnet = self.config["net_config"]["bootstrap_subnet"]
        n_subnet = self.config["net_config"]["node_subnet"]
        return self.configurator.cloudCidr(ccp_name, cidr, [b_subnet, n_subnet], "no")

    def setupCapicContractsInline(self):
        # setup filters
        for f in self.config["aci_config"]["filters"]:
            path, data = self.configurator.make_filter(f)
            self.postIt(path, data)

        # setup contracts
        for f in self.config["aci_config"]["contracts"]:
            path, data = self.configurator.make_contract(f)
            self.postIt(path, data)

        return "", None

    def postIt(self, path, data):
        if self.args.delete:
            self.deleter.record(path, data)
            return

        # annotate before posting
        annStr = self.deleter.getAnnStr()
        self.configurator.annotateApicObjects(data, ann=annStr)
        if self.args.debug:
            print("Path: {}".format(path))
            print("data: {}".format(data))
        try:
            resp = self.apic.post(path, data)
            if self.args.debug:
                print("Resp: {}".format(resp.text))
        except Exception as e:
            err("Error in provisioning {}: {}".format(path, str(e)))

    def setupZoneInfo(self):
        if "zone" in self.config["cloud"]:
            return  # user specified zone
        region = self.config["aci_config"]["vrf"]["region"]
        provider = self.config["cloud"]["provider"]
        regionDn = "/api/mo/uni/clouddomp/provp-{}/region-{}.json".format(provider, region)
        query = "{}?query-target=children&target-subtree-class=cloudZone&rsp-prop-include=naming-only".format(regionDn)
        resp = self.apic.get(path=query)
        resJson = json.loads(resp.content)
        zone = resJson["imdata"][0]["cloudZone"]["attributes"]["name"]
        print("Using zone {}".format(zone))
        self.config["cloud"]["zone"] = zone

    def getTenantAccount(self):
        tn_name = self.config["aci_config"]["cluster_tenant"]
        tn_path = "/api/mo/uni/tn-%s.json?query-target=subtree&target-subtree-class=cloudAwsProvider" % (tn_name)
        resp = self.apic.get(path=tn_path)
        resJson = json.loads(resp.content)
        accountId = resJson["imdata"][0]["cloudAwsProvider"]["attributes"]["accountId"]
        print(accountId)

    def addKafkaConfig(self):
        cKey, cCert, caCert = self.getKafkaCerts(self.config)
        self.config["aci_config"]["kafka"]["key"] = cKey.encode()
        self.config["aci_config"]["kafka"]["cert"] = cCert.encode()
        self.config["aci_config"]["kafka"]["cacert"] = caCert.encode()
        brokers = []
        for host in self.config["aci_config"]["apic_hosts"]:
            host = host.split(":")[0]
            brokers.append(host + ":9095")

        self.config["aci_config"]["kafka"]["brokers"] = brokers

    def getKafkaCerts(self, config):
        if self.config["provision"]["skip-kafka-certs"]:
            return "none", "none", "none"
        wdir = tempfile.mkdtemp()
        apic_host = self.config["aci_config"]["apic_hosts"][0]
        user = self.config["aci_config"]["apic_login"]["username"]
        pwd = self.config["aci_config"]["apic_login"]["password"]
        cn = self.config["aci_config"]["system_id"]
        kafka_cert.logger = kafka_cert.set_logger(wdir, "kc.log")
        res = kafka_cert.generate(wdir, apic_host, cn, user, pwd)
        if not res:
            raise(Exception("Failed to get kafka certs"))

        readDict = {
            "server.key": "",
            "server.crt": "",
            "cacert.crt": "",
        }

        dir = wdir + "/"
        for fname in readDict:
            f = open(dir + fname, "r")
            readDict[fname] = f.read()
            f.close()

        os.system('rm -rf ' + wdir)
        return readDict["server.key"], readDict["server.crt"], readDict["cacert.crt"]
