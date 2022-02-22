from __future__ import print_function, unicode_literals

import ipaddress
import json
import os
import os.path
import sys
import boto3
import time

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
        self.delete_injected()

    def delete_injected(self):
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
        self.cfg_validate()
        self.cfg_init()

    def Run(self, flavor_opts, kube_yaml_gen_func):
        self.adjust_cidrs()
        self.configurator = ApicKubeConfig(self.config, self.apic)
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

        # query cloudGatewayRouterP
        if "transit_subnet" in self.config["net_config"]:
            router_p = self.getRouterP()
            assert router_p, "Need hub for transit, none found"
            self.config["oper"]["routerP"] = router_p

        # update zone information as necessary
        self.setupZoneInfo()
        self.setupSubnetInfo()
        # if underlay ccp doesn't exist, create one
        u_ccp = self.getUnderlayCCP()
        if not u_ccp or self.args.delete:
            if not self.args.delete:
                print("Creating underlay\n")
            underlay_posts += [self.configurator.capic_underlay_vrf, self.capic_underlay_ccp, self.underlayCloudApp]
        else:
            # if existing vpc, cidr and subnet should be created as well
            underlay_posts += [self.underlayCloudApp]

        underlay_posts.append(self.setupCapicContractsInline)

        postGens = underlay_posts + [self.configurator.capic_kube_dom, self.configurator.capic_overlay_vrf, self.overlayCtx, self.configurator.capic_overlay_cloudApp, self.clusterInfo, self.configurator.capic_kafka_topic, self.prodAcl, self.consAcl]
        for pGen in postGens:
            path, data = pGen()
            if not path:  # posted inline
                continue

            self.postIt(path, data)
        if self.args.delete:
            if self.args.flavor != "aks":
                self.cleanup_natgw()
            self.deleter.doIt()
            self.apic.save()
            return True

        self.addKafkaConfig()
        self.addMiscConfig()
        self.fetchOperInfo()

        if self.args.debug:
            print("Config is: {}".format(self.config["kube_config"]))
        gen = flavor_opts.get("template_generator", kube_yaml_gen_func)
        output_file = self.args.output
        output_tar = self.args.output_tar
        operator_cr_output_file = self.args.aci_operator_cr
        gen(self.config, output_file, output_tar, operator_cr_output_file)
        try:
            if "test_run" not in vars(self.args):
                if self.args.flavor == "aks":
                    self.print_aks_setup()
                elif self.args.flavor == "eks":
                    self.print_eks_setup()
                else:
                    self.print_openshift_setup()
        except TypeError:
            pass
        self.apic.save()
        return True

    def capic_underlay_ccp(self):
        return self.configurator.capic_underlay_ccp(self.cloud_subnets)

    def print_openshift_setup(self):
        m_cidr = self.config["net_config"]["machine_cidr"]
        b_subnet = self.config["net_config"]["bootstrap_subnet"]
        n_subnet = self.config["net_config"]["node_subnet"]
        p_subnet = self.config["net_config"]["pod_subnet"].replace(".1/", ".0/")
        region = self.config["aci_config"]["vrf"]["region"]
        boot_subnetID = self.getSubnetID(b_subnet)
        node_subnetID = self.getSubnetID(n_subnet)
        self.setupNatGw(boot_subnetID, [node_subnetID])
        print("\nOpenshift Info")
        print("----------------")
        print("networking:\n  clusterNetwork:\n  - cidr: {}\n    hostPrefix: 23\n  machineCIDR: {}\n  networkType: CiscoACI\n  serviceNetwork:\n  - 172.30.0.0/16\nplatform:\n  aws:\n    region: {}\n    subnets:\n    - {}\n    - {}".format(p_subnet, m_cidr, region, boot_subnetID, node_subnetID))

    def print_aks_setup(self):
        with open(".acirc", "w") as rcfile:
            n_subnet = self.config["net_config"]["node_subnet"]
            node_subnetID = self.getSubnetID(n_subnet)
            region = self.config["aci_config"]["vrf"]["region"]
            vnet_name = self.config["aci_config"]["vrf"]["name"]
            infoStr = 'export AZ_VIRTUAL_NETWORK="{}"\nexport AZ_CAPIC_SUBNET_ID="{}"\nexport AZ_CAPIC_REGION="{}"'.format(vnet_name, node_subnetID, region)
            rcfile.write(infoStr)
            displayStr = 'AZ_VIRTUAL_NETWORK="{}"\nAZ_CAPIC_SUBNET_ID="{}"\nAZ_CAPIC_REGION="{}"'.format(vnet_name, node_subnetID, region)
            print(displayStr)

    def print_eks_setup(self):
        def get_eks_subnets(sk):
            res = []
            for sinfo in self.config["net_config"]["subnets"][sk]:
                subnetID = self.getSubnetID(sinfo["cidr"])
                res.append(subnetID)
            return res

        pub_snets = get_eks_subnets("public")
        pvt_snets = get_eks_subnets("private")
        self.setupNatGw(pub_snets[0], pvt_snets)
        with open(".acirc", "w") as rcfile:
            infoStr = "|public subnets|: {}\n|private subnets|: {}\n".format(pub_snets, pvt_snets)
            rcfile.write(infoStr)
            print(infoStr)

    def cfg_init(self):
        self.config["oper"] = {"vrf_encap_id": 1}
        node_snet = self.config["net_config"]["node_subnet"]
        if self.args.flavor == "cloud":
            self.config["private_subnets"] = [node_snet]
        else:
            self.config["private_subnets"] = []

    def setupSubnetInfo(self):
        # each cloud subnet has a cidr and a zone
        self.cloud_subnets = []
        self.ul_epg_info = {}
        if self.args.flavor == "eks":
            netKeys = ["public", "private"]
            for k in netKeys:
                snets = self.config["net_config"]["subnets"][k]
                self.cloud_subnets += snets
                epg_name = "ul_" + k
                sel = []
                for s in snets:
                    sel.append(s["cidr"])
                self.ul_epg_info[epg_name] = sel
        if self.args.flavor == "aks":
            snet = {"cidr": self.config["net_config"]["node_subnet"],
                    "zone": self.config["cloud"]["zone"]}
            self.cloud_subnets.append(snet)
        if self.args.flavor == "cloud":
            n_snet = {"cidr": self.config["net_config"]["node_subnet"],
                      "zone": self.config["cloud"]["zone"]}
            self.cloud_subnets.append(n_snet)
            b_snet = {"cidr": self.config["net_config"]["bootstrap_subnet"],
                      "zone": self.config["cloud"]["zone"]}
            self.cloud_subnets.append(b_snet)

    def cfg_validate(self):
        required = []
        if self.args.flavor == "eks":
            required = [
                "net_config/machine_cidr",
                "net_config/subnets/public",
                "net_config/subnets/private",
                "cloud/provider"
            ]
        elif self.args.flavor == "cloud":
            required = [
                "net_config/machine_cidr",
                "net_config/bootstrap_subnet",
                "net_config/node_subnet",
                "cloud/provider"
            ]
        else:
            required = [
                "net_config/machine_cidr",
                "net_config/node_subnet",
                "cloud/provider"
            ]
        for req in required:
            if self.cfg_get(req) is None:
                raise(Exception("{} is required".format(req)))

    def cfg_get(self, key):
        keys = key.split("/")
        c = self.config
        for k in keys:
            if k in c:
                c = c[k]
            else:
                return None
        return c

    def adjust_cidrs(self):
        adj_list = ["machine_cidr", "bootstrap_subnet", "node_subnet", "transit_subnet"]
        for nwKey in adj_list:
            if nwKey in self.config["net_config"]:
                adjNw = gwToSubnet(self.config["net_config"][nwKey])
                self.config["net_config"][nwKey] = adjNw
        if self.config["net_config"]["max_csr_tunnels"] == 0:
            return
        if "transit_subnet" not in self.config["net_config"]:
            # allocate a subnet from cidr
            m_cidr = self.config["net_config"]["machine_cidr"]
            b_addr = ipaddress.ip_network(unicode(m_cidr)).broadcast_address
            tgw_net = ipaddress.ip_network(b_addr).supernet(new_prefix=28)
            self.config["net_config"]["transit_subnet"] = tgw_net.exploded
            if self.args.debug:
                print("Using {} as transit_subnet".format(tgw_net))

    def getRouterP(self):
        query = '/api/node/class/cloudGatewayRouterP.json?query-target=self&rsp-prop-include=naming-only'
        resp = self.apic.get(path=query)
        resJson = json.loads(resp.content)
        print(resJson)
        if len(resJson["imdata"]) == 0:
            return None
        routerDn = resJson["imdata"][0]["cloudGatewayRouterP"]["attributes"]["dn"]
        return routerDn

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

    def underlayCloudApp(self):
        if self.args.flavor == "cloud":
            return self.configurator.capic_underlay_cloudApp()

        appName = self.configurator.vmm_scoped_name("ul_ap")
        path, data = self.configurator.capic_cloudApp(appName)

        if self.args.flavor == "aks":
            node_epg_obj = self.configurator.capic_underlay_epg("ul-nodes", [self.config["net_config"]["node_subnet"]])
            data["cloudApp"]["children"].append(node_epg_obj)
            inet_epg_obj = self.configurator.capic_ext_epg("inet-ext", "0.0.0.0/0")
            data["cloudApp"]["children"].append(inet_epg_obj)
        elif self.args.flavor == "eks":
            # add a cloud epg based on subnets
            for name, sel in self.ul_epg_info.items():
                node_epg_obj = self.configurator.capic_underlay_epg(name, sel)
                data["cloudApp"]["children"].append(node_epg_obj)
            # add an external epg
            inet_epg_obj = self.configurator.capic_ext_epg("inet-ext", "0.0.0.0/0")
            data["cloudApp"]["children"].append(inet_epg_obj)
        return path, data

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

    def fetchOperInfo(self):
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        vrfName = vmm_name + "_overlay"
        tn_name = self.config["aci_config"]["cluster_tenant"]
        vrf_path = "/api/mo/uni/tn-%s/ctx-%s.json" % (tn_name, vrfName)
        resp = self.apic.get(path=vrf_path)
        resJson = json.loads(resp.content)
        encap_id = resJson["imdata"][0]["fvCtx"]["attributes"]["seg"]
        self.config["oper"]["vrf_encap_id"] = int(encap_id)

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
        t_subnet = self.config["net_config"]["transit_subnet"]
        return self.configurator.cloudCidr(ccp_name, cidr, [b_subnet, n_subnet, t_subnet], "no")

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
        resp = self.apic.post(path, data)
        if self.args.debug:
            print("Resp: {}".format(resp.text))
        resJson = json.loads(resp.content)
        if "imdata" in resJson:
            for r_data in resJson["imdata"]:
                assert "error" not in r_data

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
        return accountId

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

    def wait_for_natgw(self, gwId, state, timeout=60):
        region = self.config["aci_config"]["vrf"]["region"]
        ec2_c = boto3.client('ec2', region_name=region)
        count = timeout / 5 + 1
        for x in range(count):
            resp = ec2_c.describe_nat_gateways(NatGatewayIds=[gwId])
            if 'NatGateways' in resp:
                if resp['NatGateways'][0]['State'] == state:
                    return True
                print("Waiting for nat-gateway to be {}...".format(state))
                time.sleep(5)
        return False

    def lookup_natgw(self, tag):
        region = self.config["aci_config"]["vrf"]["region"]
        ec2_c = boto3.client('ec2', region_name=region)
        filters = [
            {'Name': 'tag:orchestrator', 'Values': [tag]}
        ]
        resp = ec2_c.describe_nat_gateways(Filters=filters)
        print(resp)
        if "NatGateways" in resp:
            for ngw in resp["NatGateways"]:
                gw_state = ngw['State']
                if gw_state not in ["deleted", "deleting"]:
                    return ngw["NatGatewayId"]
        return None

    def provision_natgw(self, subnet, tag):
        gw = self.lookup_natgw(tag)
        if gw is not None:
            if self.args.debug:
                print("Existing NatGatewayId {} found".format(gw))
            return gw

        region = self.config["aci_config"]["vrf"]["region"]
        ec2_c = boto3.client('ec2', region_name=region)
        tagSpec = [
            {
                'ResourceType': 'natgateway',
                'Tags': [
                    {
                        'Key': 'orchestrator',
                        'Value': tag
                    },
                ]
            },
        ]
        eip = self.getElasticIP(ec2_c)
        resp = ec2_c.create_nat_gateway(SubnetId=subnet, AllocationId=eip, TagSpecifications=tagSpec)
        return resp['NatGateway']['NatGatewayId']

    def provision_natgw_route(self, subnets, gwId, tag):
        region = self.config["aci_config"]["vrf"]["region"]
        ec2_c = boto3.client('ec2', region_name=region)
        filters = [
            {'Name': 'tag:orchestrator', 'Values': [tag]}
        ]
        resp = ec2_c.describe_route_tables(Filters=filters)
        if "RouteTables" in resp:
            if len(resp["RouteTables"]) > 0:
                if self.args.debug:
                    print("Existing RouteTable found")
                return

        vpc_id = self.getVpcId(subnets[0])
        ec2_r = boto3.resource('ec2', region_name=region)
        r_tags = [{"Key": "orchestrator", "Value": tag}]
        vpc = ec2_r.Vpc(id=vpc_id)
        route_table = vpc.create_route_table()
        route_table.create_tags(Tags=r_tags)
        route_table.create_route(DestinationCidrBlock='0.0.0.0/0',
                                 GatewayId=gwId)
        for subnet in subnets:
            self.remove_rt_association(subnet)
            route_table.associate_with_subnet(SubnetId=subnet)

    def getVpcId(self, subnet):
        region = self.config["aci_config"]["vrf"]["region"]
        ec2_c = boto3.client('ec2', region_name=region)
        subnet_ids = [subnet]
        resp = ec2_c.describe_subnets(SubnetIds=subnet_ids)
        return resp['Subnets'][0]['VpcId']

    def getElasticIP(self, ec2):
        filters = [
            {'Name': 'domain', 'Values': ['vpc']}
        ]
        addr_resp = ec2.describe_addresses(Filters=filters)
        for addr in addr_resp['Addresses']:
            if "AssociationId" not in addr:
                if "PublicIp" in addr:
                    return addr["AllocationId"]
        try:
            allocation = ec2.allocate_address(Domain='vpc')
            return allocation["AllocationId"]
        except ec2.ClientError as e:
            print(e)

    def getTag(self):
        vmm_name = self.config["aci_config"]["vmm_domain"]["domain"]
        tn_name = self.config["aci_config"]["cluster_tenant"]
        annStr = "acc-provision-{}-{}".format(tn_name, vmm_name)
        return annStr

    def setupNatGw(self, pubSubnet, pvtSubnets):
        if "skip-nat-gw" in self.config["cloud"]:
            if self.config["cloud"]["skip-nat-gw"]:
                print("Skipping NAT Gateway setup")
                return
        tag = self.getTag()
        natGw = self.provision_natgw(pubSubnet, tag)
        available = self.wait_for_natgw(natGw, 'available', timeout=120)
        assert available
        self.provision_natgw_route(pvtSubnets, natGw, tag)

    def cleanup_natgw(self):
        if "skip-nat-gw" in self.config["cloud"]:
            if self.config["cloud"]["skip-nat-gw"]:
                print("Skipping NAT Gateway cleanup")
                return
        tag = self.getTag()
        gwId = self.lookup_natgw(tag)
        if gwId is None:
            self.remove_rt(tag)
            return
        region = self.config["aci_config"]["vrf"]["region"]
        ec2_c = boto3.client('ec2', region_name=region)
        ec2_c.delete_nat_gateway(NatGatewayId=gwId)
        self.wait_for_natgw(gwId, 'deleted')
        self.remove_rt(tag)

    def remove_rt(self, tag):
        region = self.config["aci_config"]["vrf"]["region"]
        ec2_c = boto3.client('ec2', region_name=region)
        ec2_r = boto3.resource('ec2', region_name=region)
        filters = [
            {'Name': 'tag:orchestrator', 'Values': [tag]}
        ]
        resp = ec2_c.describe_route_tables(Filters=filters)
        for rt in resp['RouteTables']:
            for entry in rt['Associations']:
                ra_id = entry['RouteTableAssociationId']
                ra = ec2_r.RouteTableAssociation(ra_id)
                ra.delete()

            rt_id = rt['RouteTableId']
            r_table = ec2_r.RouteTable(rt_id)
            r_table.delete()

    def remove_rt_association(self, subnet):
        region = self.config["aci_config"]["vrf"]["region"]
        ec2_c = boto3.client('ec2', region_name=region)
        ec2_r = boto3.resource('ec2', region_name=region)
        filter = [{'Values': [subnet], 'Name': 'association.subnet-id'}]
        resp = ec2_c.describe_route_tables(Filters=filter)
        for rt in resp['RouteTables']:
            for entry in rt['Associations']:
                if entry['SubnetId'] == subnet:
                    ra_id = entry['RouteTableAssociationId']
                    ra = ec2_r.RouteTableAssociation(ra_id)
                    ra.delete()
                    return
