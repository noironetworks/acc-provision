#!/usr/bin/env python

from __future__ import print_function, unicode_literals

import argparse
import base64
import copy
import functools
import ipaddr
import ipaddress
import requests
import json
import os
import os.path
import random
import re
import string
import sys
import uuid

import pkg_resources
import pkgutil
import tarfile
import yaml
from yaml import SafeLoader

from itertools import combinations
from OpenSSL import crypto
from jinja2 import Environment, PackageLoader
from os.path import exists
import tempfile
if __package__ is None or __package__ == '':
    import kafka_cert
    from apic_provision import Apic, ApicKubeConfig
else:
    from . import kafka_cert
    from .apic_provision import Apic, ApicKubeConfig


# This black magic forces pyyaml to load YAML strings as unicode rather
# than byte strings in Python 2, thus ensuring that the type of strings
# is consistent across versions.  From
# https://stackoverflow.com/a/2967461/3857947.
def construct_yaml_str(self, node):
    return self.construct_scalar(node)


SafeLoader.add_constructor(u'tag:yaml.org,2002:str', construct_yaml_str)

VERSION_FIELDS = [
    "cnideploy_version",
    "aci_containers_host_version",
    "opflex_agent_version",
    "aci_containers_controller_version",
    "aci_containers_operator_version",
    "openvswitch_version",
]


FLAVORS_PATH = os.path.dirname(os.path.realpath(__file__)) + "/flavors.yaml"
VERSIONS_PATH = os.path.dirname(os.path.realpath(__file__)) + "/versions.yaml"


with open(VERSIONS_PATH, 'r') as stream:
    try:
        doc = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(exc)
    VERSIONS = doc['versions']

with open(FLAVORS_PATH, 'r') as stream:
    try:
        doc = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(exc)
    DEFAULT_FLAVOR_OPTIONS = doc['kubeFlavorOptions']
    CfFlavorOptions = doc['cfFlavorOptions']
    FLAVORS = doc['flavors']


def info(msg):
    print("INFO: " + msg, file=sys.stderr)


def warn(msg):
    print("WARN: " + msg, file=sys.stderr)


def err(msg):
    print("ERR:  " + msg, file=sys.stderr)


def json_indent(s):
    return json.dumps(s, indent=4, separators=(',', ': '), sort_keys=True)


def yaml_quote(s):
    return "'%s'" % str(s).replace("'", "''")


def yaml_indent(s, **kwargs):
    return yaml.dump(s, **kwargs)


def yaml_list_dict(l):
    out = "\n"
    for d in l:
        keys = sorted(d.keys())
        prefix = "  - "
        for k in keys:
            out += "%s%s: %s\n" % (prefix, k, d[k])
            prefix = "    "
    return out


class SafeDict(dict):
    'Provide a default value for missing keys'
    def __missing__(self, key):
        return None


def list_unicode_strings(l):
    return "['" + "', '".join(l) + "']"


def deep_merge(user, default):
    if isinstance(user, dict) and isinstance(default, dict):
        for k, v in default.items():
            if k not in user:
                user[k] = v
            else:
                user[k] = deep_merge(user[k], v)
    return copy.deepcopy(user)


def config_default():
    # Default values for configuration
    default_config = {
        "aci_config": {
            "apic_version": 1.0,
            "system_id": None,
            "tenant": {
                "name": None,
            },
            "use_pre_existing_tenant": False,
            "use_legacy_kube_naming_convention": False,
            "vrf": {
                "name": None,
                "tenant": None,
            },
            "l3out": {
                "name": None,
                "external_networks": None,
            },
            "vmm_domain": {
                "type": "Kubernetes",
                "encap_type": "vxlan",
                "mcast_fabric": "225.1.2.3",
                "mcast_range": {
                    "start": "225.20.1.1",
                    "end": "225.20.255.255",
                },
                "nested_inside": {
                    "portgroup": None,
                    "elag_name": None,
                },
            },
            "client_cert": False,
            "client_ssl": True,
            "use_inst_tag": True,
            "netflow_exporter": {
                "enable": False,
                "name": None,
                "ver": "v5",
                "dstPort": None,
                "dstAddr": None,
                "srcAddr": None,
                "activeFlowTimeOut": None,
            },
            "kube_default_provide_kube_api": False,
        },
        "net_config": {
            "node_subnet": None,
            "pod_subnet": None,
            "pod_subnet_chunk_size": 32,
            "extern_dynamic": None,
            "extern_static": None,
            "node_svc_subnet": None,
            "kubeapi_vlan": None,
            "service_vlan": None,
            "service_monitor_interval": 5,
            "pbr_tracking_non_snat": False,
            "interface_mtu": None,
            "second_kubeapi_portgroup": False,
        },
        "kube_config": {
            "controller": "1.1.1.1",
            "use_rbac_api": "rbac.authorization.k8s.io/v1",
            "use_apps_api": "apps/v1",
            "use_apps_apigroup": "apps",
            "host_agent_openshift_resource": False,
            "use_netpol_apigroup": "networking.k8s.io",
            "use_netpol_annotation": False,
            "use_cluster_role": True,
            "image_pull_policy": "Always",
            "kubectl": "kubectl",
            "system_namespace": "aci-containers-system",
            "ovs_memory_limit": "1Gi",
            "reboot_opflex_with_ovs": "true",
            "snat_operator": {
                "name": "snat-operator",
                "watch_namespace": "",
                "globalinfo_name": "snatglobalinfo",
                "rdconfig_name": "routingdomain-config",
                "port_range": {
                    "start": 5000,
                    "end": 65000,
                    "ports_per_node": 3000,
                },
                "snat_namespace": "aci-containers-system",
                "contract_scope": "global",
            },
            "max_nodes_svc_graph": 32,
            "ep_registry": None,
            "opflex_mode": None,
            "host_agent_cni_bin_path": "/opt",
            "host_agent_cni_conf_path": "/etc",
            "generate_installer_files": False,
            "generate_cnet_file": False,
            "generate_apic_file": False
        },
        "istio_config": {
            "install_istio": True,
            "install_profile": "demo",
            "istio_ns": "istio-system",
            "istio_operator_ns": "istio-operator"
        },
        "registry": {
            "image_prefix": "noiro",
        },
        "logging": {
            "controller_log_level": "info",
            "hostagent_log_level": "info",
            "opflexagent_log_level": "info",
        },
        "drop_log_config": {
            "enable": True
        },
    }
    return default_config


def config_user(config_file):
    config = {}
    if config_file:
        if config_file == "-":
            info("Loading configuration from \"STDIN\"")
            data = sys.stdin.read()
            config = yaml.safe_load(data)
        else:
            info("Loading configuration from \"%s\"" % config_file)
            with open(config_file, 'r') as file:
                config = yaml.safe_load(file)
            with open(config_file, 'r') as file:
                data = file.read()
        user_input = re.sub('password:.*', '', data)
        config["user_input"] = user_input
    if config is None:
        config = {}
    return config


def config_discover(config, prov_apic):
    apic = None
    if prov_apic is not None:
        apic = get_apic(config)

    orig_infra_vlan = config["net_config"].get("infra_vlan")
    ret = {
        "net_config": {
            "infra_vlan": orig_infra_vlan,
        }
    }

    infra_vlan = config["discovered"]["infra_vlan"]
    if apic is not None:
        infra_vlan = apic.get_infravlan()

    if infra_vlan is not None:
        if orig_infra_vlan is not None and orig_infra_vlan != infra_vlan:
            warn("ACI infra_vlan (%s) is different from input file (%s)" %
                 (infra_vlan, orig_infra_vlan))
        if orig_infra_vlan is None or orig_infra_vlan != infra_vlan:
            info("Using infra_vlan from ACI: %s" %
                 (infra_vlan,))
        ret["net_config"]["infra_vlan"] = infra_vlan

    return ret


def config_set_dst(pod_cidr):
    rtr, mask = pod_cidr.split('/')
    ip = ipaddress.ip_address(rtr)
    if ip.version == 4:
        return "0.0.0.0/0"
    else:
        return "::/0"


def cidr_split(cidr):
    rtr, mask = cidr.split('/')
    ip = ipaddress.ip_address(rtr)
    if ip.version == 4:
        n = ipaddress.IPv4Network(cidr, strict=False)
    else:
        n = ipaddress.IPv6Network(cidr, strict=False)
    first, last = n[2], n[-2]
    return str(first), str(last), str(n[1]), str(n.network_address), mask


def config_adjust(args, config, prov_apic, no_random):
    system_id = config["aci_config"]["system_id"]
    infra_vlan = config["net_config"]["infra_vlan"]
    node_subnet = config["net_config"]["node_subnet"]
    pod_subnet = config["net_config"]["pod_subnet"]
    extern_dynamic = config["net_config"]["extern_dynamic"]
    extern_static = config["net_config"]["extern_static"]
    node_svc_subnet = config["net_config"]["node_svc_subnet"]
    encap_type = config["aci_config"]["vmm_domain"]["encap_type"]
    ep_registry = config["kube_config"]["ep_registry"]
    opflex_mode = config["kube_config"]["opflex_mode"]
    istio_profile = config["istio_config"]["install_profile"]
    istio_namespace = config["istio_config"]["istio_ns"]
    istio_operator_ns = config["istio_config"]["istio_operator_ns"]
    token = str(uuid.uuid4())
    if (config["aci_config"]["tenant"]["name"]):
        config["aci_config"]["use_pre_existing_tenant"] = True
        tenant = config["aci_config"]["tenant"]["name"]
    else:
        tenant = system_id
    if not config["aci_config"]["use_legacy_kube_naming_convention"]:
        app_profile = Apic.ACI_PREFIX + system_id
        default_endpoint_group = Apic.ACI_PREFIX + "default"
        namespace_endpoint_group = Apic.ACI_PREFIX + "system"
        config["aci_config"]["nodes_epg"] = Apic.ACI_PREFIX + "nodes"
        bd_dn_prefix = "uni/tn-%s/BD-%s%s-" % (tenant, Apic.ACI_PREFIX, system_id)
        istio_epg = Apic.ACI_PREFIX + "istio"
    else:
        app_profile = "kubernetes"
        default_endpoint_group = "kube-default"
        namespace_endpoint_group = "kube-system"
        if config["aci_config"]["vmm_domain"]["type"] == "OpenShift":
            config["kube_config"]["system_namespace"] = "aci-containers-system"
        else:
            config["kube_config"]["system_namespace"] = "kube-system"
        config["aci_config"]["nodes_epg"] = "kube-nodes"
        bd_dn_prefix = "uni/tn-%s/BD-kube-" % tenant
        istio_epg = "kube-istio"

    config["aci_config"]["app_profile"] = app_profile
    system_namespace = config["kube_config"]["system_namespace"]
    if args.version_token:
        token = args.version_token

    if extern_static:
        static_service_ip_pool = [{"start": cidr_split(extern_static)[0], "end": cidr_split(extern_static)[1]}]
    else:
        static_service_ip_pool = []

    adj_config = {
        "aci_config": {
            "cluster_tenant": tenant,
            "physical_domain": {
                "domain": system_id + "-pdom",
                "vlan_pool": system_id + "-pool",
            },
            "vmm_domain": {
                "domain": system_id,
                "controller": system_id,
                "mcast_pool": system_id + "-mpool",
                "vlan_pool": system_id + "-vpool",
                "vlan_range": {
                    "start": None,
                    "end": None,
                }
            },
            "sync_login": {
                "username": system_id,
                "password": generate_password(no_random),
                "certfile": "user-%s.crt" % system_id,
                "keyfile": "user-%s.key" % system_id,
                "cert_reused": False,
            },
            "node_bd_dn": bd_dn_prefix + "node-bd",
            "pod_bd_dn": bd_dn_prefix + "pod-bd",
            "kafka": {
            },
            "subnet_dn": {
            },
            "vrf_dn": {
            },
            "overlay_vrf": {
            },
        },
        "net_config": {
            "infra_vlan": infra_vlan,
            "gbp_pod_subnet": "%s/%s" % (cidr_split(pod_subnet)[2], cidr_split(pod_subnet)[4]),
            "gbp_node_subnet": "%s/%s" % (cidr_split(node_subnet)[2], cidr_split(node_subnet)[4]),
            "node_network_gateway": cidr_split(node_subnet)[2],
        },
        "node_config": {
            "encap_type": encap_type,
        },
        "istio_config": {
            "install_profile": istio_profile,
        },
        "kube_config": {
            "default_endpoint_group": {
                "tenant": tenant,
                "app_profile": app_profile,
                "group": default_endpoint_group,
            },
            "namespace_default_endpoint_group": {
                system_namespace: {
                    "tenant": tenant,
                    "app_profile": app_profile,
                    "group": namespace_endpoint_group,
                },
                istio_namespace: {
                    "tenant": tenant,
                    "app_profile": app_profile,
                    "group": istio_epg,
                },
                istio_operator_ns: {
                    "tenant": tenant,
                    "app_profile": app_profile,
                    "group": istio_epg,
                },
            },
            "pod_ip_pool": [
                {
                    "start": cidr_split(pod_subnet)[0],
                    "end": cidr_split(pod_subnet)[1],
                }
            ],
            "pod_network": [
                {
                    "subnet": "%s/%s" % cidr_split(pod_subnet)[3:],
                    "gateway": cidr_split(pod_subnet)[2],
                    "routes": [
                        {
                            "dst": config_set_dst(pod_subnet),
                            "gw": cidr_split(pod_subnet)[2],
                        }
                    ],
                },
            ],
            "service_ip_pool": [
                {
                    "start": cidr_split(extern_dynamic)[0],
                    "end": cidr_split(extern_dynamic)[1],
                },
            ],
            "static_service_ip_pool": static_service_ip_pool,
            "node_service_ip_pool": [
                {
                    "start": cidr_split(node_svc_subnet)[0],
                    "end": cidr_split(node_svc_subnet)[1],
                },
            ],
            "node_service_gw_subnets": [
                node_svc_subnet,
            ],
            "ep_registry": ep_registry,
            "opflex_mode": opflex_mode,
        },
        "cf_config": {
            "default_endpoint_group": {
                "tenant": tenant,
                "app_profile": "cloudfoundry",
                "group": "cf-app-default",
            },
            "node_subnet_cidr": "%s/%s" % cidr_split(node_subnet)[3:],
            "node_epg": "cf-node",
            "app_ip_pool": [
                {
                    "start": cidr_split(pod_subnet)[0],
                    "end": cidr_split(pod_subnet)[1],
                }
            ],
            "app_subnet": "%s/%s" % cidr_split(pod_subnet)[2::2],
            "dynamic_ext_ip_pool": [
                {
                    "start": cidr_split(extern_dynamic)[0],
                    "end": cidr_split(extern_dynamic)[1],
                },
            ],
            "static_ext_ip_pool": static_service_ip_pool,
            "node_service_ip_pool": [
                {
                    "start": cidr_split(node_svc_subnet)[0],
                    "end": cidr_split(node_svc_subnet)[1],
                },
            ],
            "node_service_gw_subnets": [
                node_svc_subnet,
            ],
            "api_port": 9900,
            "key_value_port": 9902,
        },
        "registry": {
            "configuration_version": token,
        }
    }
    if config["aci_config"].get("apic_refreshtime"):  # APIC Subscription refresh timeout value
        apic_refreshtime = config["aci_config"]["apic_refreshtime"]
        adj_config["aci_config"]["apic_refreshtime"] = apic_refreshtime

    if config["kube_config"].get("ovs_memory_limit"):  # OVS memory limit to be set in K8S Spec
        adj_config["kube_config"]["ovs_memory_limit"] = config["kube_config"]["ovs_memory_limit"]

    if config["kube_config"].get("image_pull_policy"):  # imagePullPolicy to be set for ACI CNI pods in K8S Spec
        adj_config["kube_config"]["image_pull_policy"] = config["kube_config"]["image_pull_policy"]

    if config["istio_config"].get("install_istio"):  # Install istio control-plane by default?
        adj_config["istio_config"]["install_istio"] = config["istio_config"]["install_istio"]

    if config["istio_config"].get("install_profile"):  # Which istio profile to bring-up
        adj_config["istio_config"]["install_profile"] = config["istio_config"]["install_profile"]

    if config["net_config"].get("pbr_tracking_non_snat"):
        adj_config["net_config"]["pbr_tracking_non_snat"] = config["net_config"]["pbr_tracking_non_snat"]

    if config["net_config"].get("service_monitor_interval"):
        adj_config["net_config"]["service_monitor_interval"] = config["net_config"]["service_monitor_interval"]

    if config["net_config"].get("vip_subnet"):
        vip_subnet = cidr_split(config["net_config"]["vip_subnet"])
        adj_config["cf_config"]["app_vip_pool"] = [
            {
                "start": vip_subnet[0],
                "end": vip_subnet[1],
            }
        ]
        adj_config["cf_config"]["app_vip_subnet"] = [
            "%s/%s" % vip_subnet[2::2]]

    adj_config["cf_config"]["node_network"] = (
        "%s|%s|%s" % (
            tenant,
            adj_config['cf_config']['default_endpoint_group']['app_profile'],
            adj_config['cf_config']['node_epg']))

    ns_value = {"tenant": tenant, "app_profile": app_profile, "group": namespace_endpoint_group}

    # To add kube-system namespace to ACI system EPG
    adj_config["kube_config"]["namespace_default_endpoint_group"]["kube-system"] = ns_value

    # Add openshift system namespaces to ACI system EPG
    if config["aci_config"]["vmm_domain"]["type"] == "OpenShift":
        ns_list = ["kube-service-catalog", "openshift-console", "openshift-dns", "openshift-authentication",
                   "openshift-authentication-operator", "openshift-monitoring", "openshift-web-console"]
        for ns in ns_list:
            adj_config["kube_config"]["namespace_default_endpoint_group"][ns] = ns_value

    return adj_config


def is_valid_mtu(xval):
    if xval is None:
        # use default configured on this host
        return True

    xmin = 1280   # for IPv6
    xmax = 8900   # leave 100 byte header for VxLAN
    try:
        x = int(xval)
        if xmin <= x <= xmax:
            return True
    except ValueError:
        pass
    raise(Exception("Must be integer between %d and %d" % (xmin, xmax)))


def is_valid_ipsla_interval(xval):
    if xval is None:
        # use default configured on this host
        return True

    xmin = 0
    xmax = 65535
    try:
        x = int(xval)
        if xmin <= x <= xmax:
            return True
    except ValueError:
        pass
    raise(Exception("Must be integer between %d and %d" % (xmin, xmax)))


def is_valid_refreshtime(xval):
    if xval is None:
        # Not a required field.
        return True
    xmin = 0
    xmax = (12 * 60 * 60)  # 12Hrs is the max suggested subscription refresh time for APIC
    try:
        x = int(xval)
        if xmin <= x <= xmax:
            return True
    except ValueError:
        pass
    raise(Exception("Must be integer between %d and %d" % (xmin, xmax)))


def is_valid_max_nodes_svc_graph(xval):
    if xval is None:
        return True
    xmin = 1
    xmax = 64
    try:
        x = int(xval)
        if xmin <= x <= xmax:
            return True
    except ValueError:
        pass
    raise(Exception("Must be integer between %d and %d" % (xmin, xmax)))


def is_valid_istio_install_profile(xval):
    if xval is None:
        # Not a required field - default will be set to demo
        return True
    validProfiles = ['demo', 'default', 'minimal', 'sds', 'remote']
    try:
        if xval in validProfiles:
            return True
    except ValueError:
        pass
    raise(Exception("Must be one of the profile in this List: ", validProfiles))


def is_valid_image_pull_policy(xval):
    if xval is None:
        # Not a required field - default will be set to Always
        return True
    validPullPolicies = ['Always', 'IfNotPresent', 'Never']
    try:
        if xval in validPullPolicies:
            return True
    except ValueError:
        pass
    raise(Exception("Must be one of the values in this List: ", validPullPolicies))


def is_valid_netflow_version(xval):
    if xval is None:
        # Not a required field - default will be set to demo
        return True
    validVersions = ['v5', 'v9']
    try:
        if xval in validVersions:
            return True
    except ValueError:
        pass
    raise(Exception("Must be one of the versions in this List: ", validVersions))


def is_valid_contract_scope(xval):
    if xval is None:
        # Not a required field - default will be set to demo
        return True
    validVersions = ['global', 'tenant', 'context']
    try:
        if xval in validVersions:
            return True
    except ValueError:
        pass
    raise(Exception("Must be one of the contract scopes in this List: ", validVersions))


def isOverlay(flavor):
    flav = SafeDict(FLAVORS[flavor])
    ovl = flav["overlay"]
    if ovl is True:
        return True

    return False


def config_validate(flavor_opts, config):
    def Raise(exception):
        raise exception

    required = lambda x: True if x else Raise(Exception("Missing option"))
    lower_in = lambda y: (
        lambda x: (
            (True if str(x).lower() in y
             else Raise(Exception("Invalid value: %s; "
                                  "Expected one of: {%s}" %
                                  (x, ','.join(y)))))))
    isname = lambda x, l: (1 < len(x) < l) and \
        x[0].isalpha() and x.replace('_', '').isalnum() \
        if x else Raise(Exception("Invalid name"))
    get = lambda t: functools.reduce(lambda x, y: x and x.get(y), t, config)

    checks = {
        # ACI config
        "aci_config/system_id": (get(("aci_config", "system_id")),
                                 lambda x: required(x) and isname(x, 32)),
        "aci_config/apic_refreshtime": (get(("aci_config", "apic_refreshtime")),
                                        is_valid_refreshtime),
        "aci_config/apic_host": (get(("aci_config", "apic_hosts")), required),
        "aci_config/vrf/name": (get(("aci_config", "vrf", "name")), required),
        "aci_config/vrf/tenant": (get(("aci_config", "vrf", "tenant")),
                                  required),
        # Istio config
        "istio_config/install_profile": (get(("istio_config", "install_profile")),
                                         is_valid_istio_install_profile),
        "kube_config/image_pull_policy": (get(("kube_config", "image_pull_policy")),
                                          is_valid_image_pull_policy),
        # Network Config
        "net_config/pod_subnet": (get(("net_config", "pod_subnet")),
                                  required),
    }

    if isOverlay(config["flavor"]):
        print("Using overlay")
        extra_checks = {
            "aci_config/vrf/region": (get(("aci_config", "vrf", "region")), required),
            "net_config/machine_cidr": (get(("net_config", "machine_cidr")), required),
            "net_config/bootstrap_subnet": (get(("net_config", "bootstrap_subnet")), required),
        }
    else:
        extra_checks = {
            "aci_config/aep": (get(("aci_config", "aep")), required),
            "aci_config/l3out/name": (get(("aci_config", "l3out", "name")),
                                      required),
            "aci_config/l3out/external-networks":
            (get(("aci_config", "l3out", "external_networks")), required),

            # Kubernetes config
            "kube_config/max_nodes_svc_graph": (get(("kube_config", "max_nodes_svc_graph")),
                                                is_valid_max_nodes_svc_graph),

            "kube_config/snat_operator/contract_scope": (get(("kube_config", "snat_operator", "contract_scope")),
                                                         is_valid_contract_scope),

            # Network Config
            "net_config/infra_vlan": (get(("net_config", "infra_vlan")),
                                      required),
            "net_config/service_vlan": (get(("net_config", "service_vlan")),
                                        required),
            "net_config/node_subnet": (get(("net_config", "node_subnet")),
                                       required),
            "net_config/extern_dynamic": (get(("net_config", "extern_dynamic")),
                                          required),
            "net_config/extern_static": (get(("net_config", "extern_static")),
                                         required),
            "net_config/node_svc_subnet": (get(("net_config", "node_svc_subnet")),
                                           required),
            "net_config/interface_mtu": (get(("net_config", "interface_mtu")),
                                         is_valid_mtu),
            "net_config/service_monitor_interval": (get(("net_config", "service_monitor_interval")),
                                                    is_valid_ipsla_interval)
        }

        if (config["aci_config"]["vmm_domain"]["type"] == "OpenShift"):
            del extra_checks["net_config/extern_static"]

        if flavor_opts.get("apic", {}).get("use_kubeapi_vlan", True):
            checks["net_config/kubeapi_vlan"] = (
                get(("net_config", "kubeapi_vlan")), required)
        if (config["aci_config"]["netflow_exporter"]["enable"]):
            checks["aci_config/netflow_exporter/dstAddr"] = (
                get(("aci_config", "netflow_exporter", "dstAddr")), required)
            checks["aci_config/netflow_exporter/dstPort"] = (
                get(("aci_config", "netflow_exporter", "dstPort")), required)
            checks["aci_config/netflow_exporter/name"] = (
                get(("aci_config", "netflow_exporter", "name")), required)
            checks["aci_config/netflow_exporter/ver"] = (
                get(("aci_config", "netflow_exporter", "ver")), is_valid_netflow_version)

    # Allow deletion of resources without isname check
    if get(("provision", "prov_apic")) is False:
        checks["aci_config/system_id"] = \
            (get(("aci_config", "system_id")), required)

    # Versions
    for field in flavor_opts.get('version_fields', VERSION_FIELDS):
        checks[field] = (get(("registry", field)), required)

    if flavor_opts.get("apic", {}).get("associate_aep_to_nested_inside_domain",
                                       False):
        checks["aci_config/vmm_domain/nested_inside/type"] = (
            get(("aci_config", "vmm_domain", "nested_inside", "type")),
            required)

    if get(("aci_config", "vmm_domain", "encap_type")) == "vlan":
        checks["aci_config/vmm_domain/vlan_range/start"] = \
            (get(("aci_config", "vmm_domain", "vlan_range", "start")),
             required)
        checks["aci_config/vmm_domain/vlan_range/end"] = \
            (get(("aci_config", "vmm_domain", "vlan_range", "end")),
             required)

    if get(("aci_config", "vmm_domain", "nested_inside", "type")):
        checks["aci_config/vmm_domain/nested_inside/type"] = \
            (get(("aci_config", "vmm_domain", "nested_inside", "type")),
             lower_in({"vmware"}))
        checks["aci_config/vmm_domain/nested_inside/name"] = \
            (get(("aci_config", "vmm_domain", "nested_inside", "name")),
             required)

    if get(("provision", "prov_apic")) is not None:
        checks.update({
            # auth for API access
            "aci_config/apic_login/username":
            (get(("aci_config", "apic_login", "username")), required),
            "aci_config/apic_login/password":
            (get(("aci_config", "apic_login", "password")), required),
        })

    if flavor_opts.get('vip_pool_required', False):
        checks["net_config/vip_subnet"] = (
            get(("net_config", "vip_subnet")), required)

    iso_seg_check = (
        lambda x: True
        if all(('name' in iso and 'subnet' in iso) for iso in x)
        else Raise(
            Exception("'name' and 'subnet' required for "
                      "each isolation segment")))
    iso_seg = get(("aci_config", "isolation_segments"))
    if iso_seg:
        checks["aci_config/isolation_segments"] = (iso_seg, iso_seg_check)

    checks = deep_merge(checks, extra_checks)
    ret = True
    for k in sorted(checks.keys()):
        value, validator = checks[k]
        try:
            if not validator(value):
                raise Exception(k)
        except Exception as e:
            err("Invalid configuration for %s: %s" % (k, e))
            ret = False
    return ret


def config_validate_preexisting(config, prov_apic):
    try:
        if isOverlay(config["flavor"]):
            return True

        if prov_apic is not None:
            apic = get_apic(config)
            if apic is None:
                return False

            aep_name = config["aci_config"]["aep"]
            aep = apic.get_aep(aep_name)
            if aep is None:
                warn("AEP not defined in the APIC: %s" % aep_name)

            vrf_tenant = config["aci_config"]["vrf"]["tenant"]
            vrf_name = config["aci_config"]["vrf"]["name"]
            l3out_name = config["aci_config"]["l3out"]["name"]
            vrf = apic.get_vrf(vrf_tenant, vrf_name)
            if vrf is None:
                warn("VRF not defined in the APIC: %s/%s" %
                     (vrf_tenant, vrf_name))
            l3out = apic.get_l3out(vrf_tenant, l3out_name)
            if l3out is None:
                warn("L3out not defined in the APIC: %s/%s" %
                     (vrf_tenant, l3out_name))
            else:
                # get l3out context and check if it's the same as vrf in
                # input config
                result = apic.check_l3out_vrf(vrf_tenant, l3out_name, vrf_name)
                if not result:
                    warn("L3out %s/%s not configured in the correct VRF %s/%s" %
                         (vrf_tenant, l3out_name, vrf_tenant, vrf_name))

            # Following code is to detect a legacy cluster
            # kube_ap = apic.get_ap(config["aci_config"]["system_id"])
            # if an app profile with the name "kubernetes" exists under system
            # tenant, this means the cluster was provisioned with older
            # naming convention. This is a fallback in case the user
            # forgets to add the field to indicate an existing legacy
            # cluster.
            # if kube_ap:
            #     config["aci_config"]["use_legacy_kube_naming_convention"] = True
            #     if config["aci_config"]["vmm_domain"]["type"] == "OpenShift":
            #         config["kube_config"]["system_namespace"] = "aci-containers-system"
            #     else:
            #         config["kube_config"]["system_namespace"] = "kube-system"

    except Exception as e:
        warn("Unable to validate resources on APIC: {}".format(e))
    return True


def generate_sample(filep, flavor):
    if flavor == "cloud":
        data = pkgutil.get_data('acc_provision', 'templates/overlay-provision-config.yaml')
    else:
        data = pkgutil.get_data('acc_provision', 'templates/provision-config.yaml')
    try:
        filep.write(data)
    except TypeError:
        filep.write(data.decode(filep.encoding))
    finally:
        filep.flush()
    return filep


def generate_password(no_random):
    chars = string.ascii_letters + string.digits + ("_-+=!" * 3)
    ret = ''.join(random.SystemRandom().sample(chars, 20))
    if no_random:
        ret = "NotRandom!"
    return ret


def generate_cert(username, cert_file, key_file):
    reused = False
    if not exists(cert_file) or not exists(key_file):
        info("Generating certs for kubernetes controller")
        info("  Private key file: \"%s\"" % key_file)
        info("  Certificate file: \"%s\"" % cert_file)

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().O = "Cisco Systems"
        cert.get_subject().CN = "User %s" % username
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(-12 * 60 * 60)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        # Work around this bug:
        # https://github.com/pyca/pyopenssl/issues/741

        # This should be b'sha1' on both 2 and 3, but the bug requires
        # passing a string on Python 3.
        if sys.version_info[0] >= 3:
            hash_algorithm = 'sha1'
        else:
            hash_algorithm = b'sha1'
        cert.sign(k, hash_algorithm)

        cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
        with open(cert_file, "wb") as certp:
            certp.write(cert_data)
        with open(key_file, "wb") as keyp:
            keyp.write(key_data)
    else:
        # Do not overwrite previously generated data if it exists
        reused = True
        info("Reusing existing certs for kubernetes controller")
        info("  Private key file: \"%s\"" % key_file)
        info("  Certificate file: \"%s\"" % cert_file)
        with open(cert_file, "rb") as certp:
            cert_data = certp.read()
        with open(key_file, "rb") as keyp:
            key_data = keyp.read()
    return key_data, cert_data, reused


def get_jinja_template(file):
    env = Environment(
        loader=PackageLoader('acc_provision', 'templates'),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True
    )
    env.filters['base64enc'] = lambda s: base64.b64encode(s).decode("ascii")
    env.filters['cf_secret'] = lambda s: yaml.safe_dump(s.decode("ascii"), default_style='|')
    env.filters['json'] = json_indent
    env.filters['yaml'] = yaml_indent
    env.filters['yaml_quote'] = yaml_quote
    env.filters['yaml_list_dict'] = yaml_list_dict
    env.filters['list_unicode_strings'] = list_unicode_strings
    template = env.get_template(file)
    return template


def generate_operator_tar(tar_path, cont_docs, config):

    # YAML file numbers generated start from 4 as first three are
    # reserved for OpenShift specific files
    file_start = 4
    filenames = []

    # Function to construct filenames for each yaml
    def gen_file_list(docs, counter, filenames):
        for doc in docs:
            filename = "cluster-network-" + str(counter).zfill(2) + "-" + doc['kind'] + "-" + doc['metadata']['name'] + ".yaml"
            filenames.append(os.path.basename(filename))
            with open(filename, 'w') as outfile:
                yaml.safe_dump(doc, outfile, default_flow_style=False, encoding="utf-8")
            counter += 1
        return counter

    gen_file_list(cont_docs, file_start, filenames)

    # Create three extra files needed for Openshift 4.3 installer
    extra_files = []
    gen_inst_files = config["kube_config"]["generate_installer_files"]
    gen_cnet_file = config["kube_config"]["generate_cnet_file"]
    gen_apic_file = config["kube_config"]["generate_apic_file"]
    if gen_inst_files or gen_cnet_file:
        cnetfile_name = 'cluster-network-03-config.yaml'
        extra_files.append(cnetfile_name)

    if gen_inst_files:
        masterfile_name = '99-master-kubelet-node-ip.yaml'
        workerfile_name = '99-worker-kubelet-node-port.yaml'
        extra_files.append(masterfile_name)
        extra_files.append(workerfile_name)

    if gen_apic_file:
        apic_name = 'apic.json'
        extra_files.append(apic_name)

    for x_file in extra_files:
        x_template = get_jinja_template(x_file)
        x_template.stream(config=config).dump(x_file)
        filenames.append(x_file)

    # Create tar for the parsed files and delete the files too
    tar = tarfile.open(tar_path, "w:gz", encoding="utf-8")
    for name in filenames:
        tar.add(name)
        os.remove(name)
    tar.close()


def generate_kube_yaml(config, operator_output, operator_tar, operator_cr_output):
    kube_objects = [
        "configmap", "secret", "serviceaccount",
        "daemonset", "deployment",
    ]
    if config["kube_config"].get("use_openshift_security_context_constraints",
                                 False):
        kube_objects.append("securitycontextconstraints")
    if config["kube_config"].get("use_cluster_role", False):
        kube_objects.extend(["clusterrolebinding", "clusterrole"])

    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-containers.yaml')
        outname = operator_output
        applyname = operator_output
        tar_path = operator_tar

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file and tar with the same name.
        if operator_output == "-":
            outname = "<stdout>"
            applyname = "<filename>"
            operator_output = sys.stdout
        else:
            applyname = os.path.basename(operator_output)
            if not tar_path or tar_path == "-":
                tar_path = operator_output + ".tar.gz"

        temp = ''.join(template.stream(config=config))
        parsed_temp = temp.split("---")

        # Find the place where to put the acioperators configmap
        for cmap_idx in range(len(parsed_temp)):
            current_yaml = yaml.safe_load(parsed_temp[cmap_idx])
            if current_yaml['kind'] == 'ConfigMap':
                break

        # Generate and convert containers deployment to base64 and add
        # as configMap entry to the operator deployment.
        config["kube_config"]["deployment_base64"] = base64.b64encode(temp.encode('ascii')).decode('ascii')
        oper_cmap_template = get_jinja_template('aci-operators-configmap.yaml')
        cmap_temp = ''.join(oper_cmap_template.stream(config=config))

        op_template = get_jinja_template('aci-operators.yaml')
        output_from_parsed_template = op_template.render(config=config)

        # Generate acioperator CRD from template and add it to top
        op_crd_template = get_jinja_template('aci-operators-crd.yaml')
        op_crd_output = op_crd_template.render(config=config)

        new_parsed_yaml = [op_crd_output] + parsed_temp[:cmap_idx] + [cmap_temp] + parsed_temp[cmap_idx:] + [output_from_parsed_template]
        new_deployment_file = '---'.join(new_parsed_yaml)

        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(new_deployment_file)
        else:
            op_template.stream(config=config).dump(operator_output)

        # The next few files are to generate tar file with each
        # containers and operator yaml in separate file. This is needed
        # by OpenShift >= 4.3. If tar_path is provided(-z), we save the tar
        # with that filename, else we use the provided containers
        # deployment filepath. If neither is provided, we don't generate
        # the tar.
        if tar_path == "-":
            tar_path = "/dev/null"
        else:
            deployment_docs = yaml.load_all(new_deployment_file, Loader=yaml.SafeLoader)
            generate_operator_tar(tar_path, deployment_docs, config)

        op_cr_template = get_jinja_template('aci-operators-cr.yaml')
        if operator_cr_output and operator_cr_output != "/dev/null":
            if operator_cr_output == "-":
                operator_cr_output = "/dev/null"
            else:
                info("Writing kubernetes ACI operator CR to %s" % operator_cr_output)
        op_cr_template.stream(config=config).dump(operator_cr_output)

        info("Writing kubernetes infrastructure YAML to %s" % outname)
        info("Writing ACI CNI operator tar to %s" % tar_path)
        info("Apply infrastructure YAML using:")
        info("  %s apply -f %s" %
             (config["kube_config"]["kubectl"], applyname))
        info("Delete stale objects from older deployments using:")
        info("  %s -n %s delete %s -l "
             " 'aci-containers-config-version,"
             "aci-containers-config-version notin (%s)'" %
             (config["kube_config"]["kubectl"],
              config["kube_config"]["system_namespace"],
              ",".join(kube_objects),
              str(config["registry"]["configuration_version"])))
    return config


def generate_cf_yaml(config, output, operator_output=None, operator_cr_output=None):
    template = get_jinja_template('aci-cf-containers.yaml')

    if output and output != "/dev/null":
        outname = output
        applyname = output
        if output == "-":
            outname = "<stdout>"
            applyname = "<filename>"
            output = sys.stdout
        else:
            applyname = os.path.basename(output)

        info("Writing deployment vars for ACI add-ons to %s" % outname)
        template.stream(config=config).dump(output)
        pg = ("%s/%s" %
              (config['aci_config']['vmm_domain']['nested_inside']['name'],
               config['cf_config']['node_network']))
        node_subnet = config["net_config"]["node_subnet"]
        node_subnet_cidr = "%s/%s" % cidr_split(node_subnet)[3:]
        node_subnet_gw = cidr_split(node_subnet)[2]
        info("Steps to deploy ACI add-ons:")
        # TODO Merge steps 1 & 2 into a single cloud-config update
        info("1. Manually update your cloud config to use vCenter Portgroup " +
             "'" + pg + "' in 'cloud_properties' of subnet " +
             node_subnet_cidr + " in the network named " +
             "'default'. E.g." + '''

networks:
- name: default
  type: manual
  subnets:
  - range: %s
    gateway: %s
    [...]
    cloud_properties:
      name: %s
''' % (node_subnet_cidr, node_subnet_gw, pg))
        info("2. Update cloud config using:")
        info("  bosh update-cloud-config <your current cloud config file> " +
             "-o <aci-containers-release>/manifest-generation/" +
             "cloud_config_ops.yml -l %s" % applyname)
        info("3. Deploy ACI add-ons using:")
        info("  bosh deploy <your current arguments> -o " +
             "<aci-containers-release>/manifest-generation/" +
             "cf_ops.yml -l %s" % applyname)

    return config


CfFlavorOptions['template_generator'] = generate_cf_yaml


def generate_apic_config(flavor_opts, config, prov_apic, apic_file):
    configurator = ApicKubeConfig(config)
    for k, v in flavor_opts.get("apic", {}).items():
        setattr(configurator, k, v)
    apic_config = configurator.get_config(config["aci_config"]["apic_version"])
    if apic_file:
        if apic_file == "-":
            info("Writing apic configuration to \"STDOUT\"")
            ApicKubeConfig.save_config(apic_config, sys.stdout)
        else:
            info("Writing apic configuration to \"%s\"" % apic_file)
            with open(apic_file, 'w') as outfile:
                ApicKubeConfig.save_config(apic_config, outfile)

    ret = True
    sync_login = config["aci_config"]["sync_login"]["username"]
    if prov_apic is not None:
        apic = get_apic(config)
        if apic is not None:
            if prov_apic is True:
                info("Provisioning configuration in APIC")
                apic.provision(apic_config, sync_login)
            if prov_apic is False:
                info("Unprovisioning configuration in APIC")
                system_id = config["aci_config"]["system_id"]
                tenant = config["aci_config"]["vrf"]["tenant"]
                vrf_tenant = config["aci_config"]["vrf"]["tenant"]
                cluster_tenant = config["aci_config"]["cluster_tenant"]
                old_naming = config["aci_config"]["use_legacy_kube_naming_convention"]
                apic.unprovision(apic_config, system_id, tenant, vrf_tenant, cluster_tenant, old_naming)
            ret = False if apic.errors > 0 else True
    return ret


def get_apic(config):
    apic_host = config["aci_config"]["apic_hosts"][0]
    apic_username = config["aci_config"]["apic_login"]["username"]
    apic_password = config["aci_config"]["apic_login"]["password"]
    timeout = config["aci_config"]["apic_login"]["timeout"]
    debug = config["provision"]["debug_apic"]
    save_to = config["provision"]["save_to"]
    capic = config["aci_config"]["capic"]

    if config["aci_config"]["apic_proxy"]:
        apic_host = config["aci_config"]["apic_proxy"]
    apic = Apic(
        apic_host, apic_username, apic_password,
        timeout=timeout, debug=debug, capic=capic, save_to=save_to)
    if apic.cookies is None:
        return None
    return apic


class CustomFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        ret = super(CustomFormatter, self)._format_action_invocation(action)
        ret = ret.replace(' ,', ',')
        ret = ret.replace(' file,', ',')
        ret = ret.replace(' name,', ',')
        ret = ret.replace(' pass,', ',')
        return ret


def parse_args(show_help):
    version = 'Unknown'
    try:
        version = pkg_resources.require("acc_provision")[0].version
    except pkg_resources.DistributionNotFound:
        # ignore, expected in case running from source
        pass

    parser = argparse.ArgumentParser(
        description='Provision an ACI/Kubernetes installation',
        formatter_class=CustomFormatter,
    )
    parser.add_argument(
        '-v', '--version', action='version', version=version)
    parser.add_argument(
        '--release', action='store_true', default=False, help='print git release info')
    parser.add_argument(
        '--debug', action='store_true', default=False,
        help='enable debug')
    parser.add_argument(
        '--sample', action='store_true', default=False,
        help='print a sample input file with fabric configuration')
    parser.add_argument(
        '-c', '--config', default="-", metavar='file',
        help='input file with your fabric configuration')
    parser.add_argument(
        '-o', '--output', default="-", metavar='file',
        help='output file for your kubernetes deployment')
    parser.add_argument(
        '-z', '--output_tar', default="-", metavar='file',
        help='output zipped tar file for your kubernetes deployment')
    parser.add_argument(
        '-r', '--aci_operator_cr', default="-", metavar='file',
        help='output file for your aci-operator deployment custom resource')
    parser.add_argument(
        '-a', '--apic', action='store_true', default=False,
        help='create/validate the required APIC resources')
    parser.add_argument(
        '-d', '--delete', action='store_true', default=False,
        help='delete the APIC resources that would have been created')
    parser.add_argument(
        '-u', '--username', default=None, metavar='name',
        help='apic-admin username to use for APIC API access')
    parser.add_argument(
        '-p', '--password', default=None, metavar='pass',
        help='apic-admin password to use for APIC API access')
    parser.add_argument(
        '-w', '--timeout', default=None, metavar='timeout',
        help='wait/timeout to use for APIC API access')
    parser.add_argument(
        '--list-flavors', action='store_true', default=False,
        help='list available configuration flavors')
    parser.add_argument(
        '-f', '--flavor', default=None, metavar='flavor',
        help='set configuration flavor.  Example: openshift-3.6')
    parser.add_argument(
        '-t', '--version-token', default=None, metavar='token',
        help='set a configuration version token. Default is UUID.')
    parser.add_argument(
        '--apic-proxy', default=None, metavar='addr',
        help=argparse.SUPPRESS)
    parser.add_argument(
        '--test-data-out', default=None, metavar='file',
        help='capture apic responses for test replay. E.g. ../testdata/apic_xx.json')
    parser.add_argument(
        '--skip-kafka-certs', action='store_true', default=False,
        help='skip kafka certificate generation')

    # If the input has no arguments, show help output and exit
    if show_help:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()


def get_versions(versions_url):
    global VERSIONS
    try:
        # try as a URL
        res = requests.get(versions_url)
        versions_yaml = yaml.safe_load(res)
        info("Loading versions from URL: " + versions_url)
        VERSIONS = versions_yaml['versions']

    except Exception:
        try:
            # try as a local file
            with open(versions_url, 'r') as res:
                versions_yaml = yaml.safe_load(res)
                info("Loading versions from local file: " + versions_url)
                VERSIONS = versions_yaml['versions']
        except Exception:
            info("Unable to load versions from path: " + versions_url)


def check_overlapping_subnets(config):
    """check if subnets are overlapping."""
    subnet_info = {
        "node_subnet": config["net_config"]["node_subnet"],
        "pod_subnet": config["net_config"]["pod_subnet"],
        "extern_dynamic": config["net_config"]["extern_dynamic"],
        "node_svc_subnet": config["net_config"]["node_svc_subnet"]
    }
    # Don't have extern_static field set for OpenShift flavors
    if config["net_config"]["extern_static"]:
        subnet_info["extern_static"] = config["net_config"]["extern_static"]

    for sub1, sub2 in combinations(subnet_info.values(), r=2):
        net1, net2 = ipaddr.IPNetwork(sub1), ipaddr.IPNetwork(sub2)
        out = net1.overlaps(net2)
        if out:
            return False
    return True


def gwToSubnet(gw):
    u_gw = '{}'.format(str(gw))
    return str(ipaddress.ip_network(u_gw, strict=False))


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


def provision(args, apic_file, no_random):
    config_file = args.config
    output_file = args.output
    output_tar = args.output_tar
    operator_cr_output_file = args.aci_operator_cr

    prov_apic = None
    if args.apic:
        prov_apic = True
    if args.delete:
        prov_apic = False

    timeout = None
    if args.timeout:
        try:
            if int(args.timeout) >= 0:
                timeout = int(args.timeout)
        except ValueError:
            # ignore that timeout value
            warn("Invalid timeout value ignored: '%s'" % timeout)

    generate_cert_data = True
    if args.delete:
        output_file = "/dev/null"
        output_tar = "/dev/null"
        operator_cr_output_file = "/dev/null"
        generate_cert_data = False

    # Print sample, if needed
    if args.sample:
        generate_sample(sys.stdout, args.flavor)
        return True

    # command line config
    config = {
        "aci_config": {
            "apic_login": {
            },
            "capic": False,
            "apic_proxy": args.apic_proxy,
        },
        "provision": {
            "prov_apic": prov_apic,
            "debug_apic": args.debug,
            "save_to": args.test_data_out,
            "skip-kafka-certs": args.skip_kafka_certs,
        },
    }

    # infra_vlan is not part of command line input, but we do
    # pass it as a command line arg in unit tests to pass in
    # configuration which would otherwise be discovered from
    # the APIC
    config["discovered"] = {"infra_vlan": getattr(args, "infra_vlan", None)}

    flavor = args.flavor
    if args.username:
        config["aci_config"]["apic_login"]["username"] = args.username

    config["aci_config"]["apic_login"]["password"] = \
        args.password if args.password else os.environ.get('ACC_PROVISION_PASS')
    config["aci_config"]["apic_login"]["timeout"] = timeout

    # Create config
    user_config = config_user(config_file)
    if 'aci_config' in user_config and 'use_legacy_kube_naming_convention' in user_config['aci_config'] and 'tenant' in user_config['aci_config']:
        err("Not allowed to set tenant and use_legacy_kube_naming_convention fields at the same time")
        return False

    if flavor == "cloud" and 'use_legacy_kube_naming_convention' in user_config['aci_config']:
        err("use_legacy_kube_naming_convention not allowed in cloud flavor")
        return False

    if user_config:
        if 'versions_url' in user_config and 'path' in user_config['versions_url']:
            versions_url = user_config['versions_url']['path']
            get_versions(versions_url)

    deep_merge(config, user_config)
    if "netflow_exporter" in config["aci_config"]:
        config["aci_config"]["netflow_exporter"]["enable"] = True

    if flavor in FLAVORS:
        info("Using configuration flavor " + flavor)
        deep_merge(config, {"flavor": flavor})
        if "config" in FLAVORS[flavor]:
            deep_merge(config, FLAVORS[flavor]["config"])
        if "default_version" in FLAVORS[flavor]:
            deep_merge(config, {
                "registry": {
                    "version": FLAVORS[flavor]["default_version"]
                }
            })
    else:
        err("Unknown flavor %s" % flavor)
        return False
    flavor_opts = FLAVORS[flavor].get("options", DEFAULT_FLAVOR_OPTIONS)

    deep_merge(config, config_default())

    if config["registry"]["version"] in VERSIONS:
        deep_merge(config,
                   {"registry": VERSIONS[config["registry"]["version"]]})

    # Discoverd state (e.g. infra-vlan) overrides the config file data
    if isOverlay(flavor):
        config["net_config"]["infra_vlan"] = None
    else:
        config = deep_merge(config_discover(config, prov_apic), config)

    # Validate APIC access
    if prov_apic is not None:
        apic = get_apic(config)
        apic_version = apic.apic_version
        if apic is None:
            err("Not able to login to the APIC, please check username or password")
            return False
        config["aci_config"]["apic_version"] = apic_version

    # Validate config
    try:
        if not config_validate(flavor_opts, config):
            err("Please fix configuration and retry.")
            return False
    except Exception as ex:
        print("%s") % ex

    # Verify if overlapping subnet present in config input file
    if not check_overlapping_subnets(config):
        err("overlapping subnets found in configuration input file")
        return False

    # Adjust config based on convention/apic data
    adj_config = config_adjust(args, config, prov_apic, no_random)
    deep_merge(config, adj_config)

    # Advisory checks, including apic checks, ignore failures
    if not config_validate_preexisting(config, prov_apic):
        # Ignore failures, this check is just advisory for now
        pass

    # generate key and cert if needed
    username = config["aci_config"]["sync_login"]["username"]
    certfile = config["aci_config"]["sync_login"]["certfile"]
    keyfile = config["aci_config"]["sync_login"]["keyfile"]
    key_data, cert_data = None, None
    reused = True
    if generate_cert_data:
        key_data, cert_data, reused = generate_cert(username, certfile, keyfile)
    config["aci_config"]["sync_login"]["key_data"] = key_data
    config["aci_config"]["sync_login"]["cert_data"] = cert_data
    config["aci_config"]["sync_login"]["cert_reused"] = reused

    if flavor == "cloud":
        if prov_apic is None:
            return True
        print("Configuring cAPIC")
        config["aci_config"]["capic"] = True

        def adjust_cidrs():
            cidr = gwToSubnet(config["net_config"]["machine_cidr"])
            b_subnet = gwToSubnet(config["net_config"]["bootstrap_subnet"])
            n_subnet = gwToSubnet(config["net_config"]["node_subnet"])
            config["net_config"]["machine_cidr"] = cidr
            config["net_config"]["bootstrap_subnet"] = b_subnet
            config["net_config"]["node_subnet"] = n_subnet

        apic = get_apic(config)
        if apic is None:
            print("APIC login failed")
            return False

        adjust_cidrs()
        configurator = ApicKubeConfig(config)
        deleter = MoCleaner(apic, config, args.debug)

        def getSubnetID(subnet):
            tn_name = config["aci_config"]["cluster_tenant"]
            ccp_name = getUnderlayCCPName()
            cidr = config["net_config"]["machine_cidr"]
            subnetDN = "uni/tn-{}/ctxprofile-{}/cidr-[{}]/subnet-[{}]".format(tn_name, ccp_name, cidr, subnet)
            filter = "eq(hcloudSubnetOper.delegateDn, \"{}\")".format(subnetDN)
            query = '/api/node/class/hcloudSubnetOper.json?query-target=self&query-target-filter={}'.format(filter)
            resp = apic.get(path=query)
            resJson = json.loads(resp.content)
            if args.debug:
                print("query: {}".format(query))
                print("resp: {}".format(resJson))
            subnetID = resJson["imdata"][0]["hcloudSubnetOper"]["attributes"]["cloudProviderId"]
            return subnetID

        def getOverlayDn():
            query = configurator.capic_overlay_dn_query()
            resp = apic.get(path=query)
            resJson = json.loads(resp.content)
            if len(resJson["imdata"]) == 0:
                return ""
            overlayDn = resJson["imdata"][0]["hcloudCtx"]["attributes"]["dn"]
            return overlayDn

        def prodAcl():
            return configurator.capic_kafka_acl(config["aci_config"]["system_id"])

        def consAcl():
            # query to obtain the consumer common name
            resp = apic.get(path='/api/node/class/topSystem.json?query-target-filter=and(eq(topSystem.role,"controller"))')
            resJson = json.loads(resp.content)
            consCN = resJson["imdata"][0]["topSystem"]["attributes"]["serial"]
            print("Consumer CN: {}".format(consCN))
            return configurator.capic_kafka_acl(consCN)

        def clusterInfo():
            overlayDn = getOverlayDn()
            print("overlayDn: {}".format(overlayDn))
            return configurator.capic_cluster_info(overlayDn)

        def addMiscConfig(config):
            query = configurator.capic_subnet_dn_query()
            resp = apic.get(path=query)
            resJson = json.loads(resp.content)
            subnet_dn = resJson["imdata"][0]["hcloudSubnet"]["attributes"]["dn"]
            print("subnet_dn is {}".format(subnet_dn))
            config["aci_config"]["subnet_dn"] = subnet_dn
            vrf_dn = getOverlayDn()
            config["aci_config"]["vrf_dn"] = vrf_dn
            vmm_name = config["aci_config"]["vmm_domain"]["domain"]
            config["aci_config"]["overlay_vrf"] = vmm_name + "_overlay"
            return config

        def getUnderlayCCP():
            vrfName = config["aci_config"]["vrf"]["name"]
            tn_name = config["aci_config"]["cluster_tenant"]
            vrf_path = "/api/mo/uni/tn-%s/ctx-%s.json?query-target=subtree&target-subtree-class=fvRtToCtx" % (tn_name, vrfName)
            resp = apic.get(path=vrf_path)
            resJson = json.loads(resp.content)
            print(resJson)
            if len(resJson["imdata"]) == 0:
                return ""

            underlay_ccp = resJson["imdata"][0]["fvRtToCtx"]["attributes"]["tDn"]
            return underlay_ccp

        def overlayCtx():
            underlay_ccp = getUnderlayCCP()
            # cannot proceed without an underlay ccp
            assert(underlay_ccp or args.delete), "Need an underlay ccp"
            return configurator.capic_overlay(underlay_ccp)

        def getUnderlayCCPName():
            u_ccp = getUnderlayCCP()
            assert(u_ccp), "Need an underlay ccp"
            split_ccp = u_ccp.split("/")
            ccp_name = split_ccp[-1].replace("ctxprofile-", "")
            if args.debug:
                print("UnderlayCCPName: {}".format(ccp_name))
            return ccp_name

        def underlayCidr():
            ccp_name = getUnderlayCCPName()
            cidr = config["net_config"]["machine_cidr"]
            b_subnet = config["net_config"]["bootstrap_subnet"]
            n_subnet = config["net_config"]["node_subnet"]
            return configurator.cloudCidr(ccp_name, cidr, [b_subnet, n_subnet], "no")

        def setupCapicContractsInline():
            # setup filters
            for f in config["aci_config"]["filters"]:
                path, data = configurator.make_filter(f)
                postIt(path, data)

            # setup contracts
            for f in config["aci_config"]["contracts"]:
                path, data = configurator.make_contract(f)
                postIt(path, data)

            return "", None

        def postIt(path, data):
            if args.delete:
                deleter.record(path, data)
                return

            # annotate before posting
            annStr = deleter.getAnnStr()
            configurator.annotateApicObjects(data, ann=annStr)
            if args.debug:
                print("Path: {}".format(path))
                print("data: {}".format(data))
            try:
                resp = apic.post(path, data)
                print("Resp: {}".format(resp.text))
            except Exception as e:
                err("Error in provisioning {}: {}".format(path, str(e)))

        def getTenantAccount():
            tn_name = config["aci_config"]["cluster_tenant"]
            tn_path = "/api/mo/uni/tn-%s.json?query-target=subtree&target-subtree-class=cloudAwsProvider" % (tn_name)
            resp = apic.get(path=tn_path)
            resJson = json.loads(resp.content)
            accountId = resJson["imdata"][0]["cloudAwsProvider"]["attributes"]["accountId"]
            print(accountId)

        underlay_posts = []
        # if the cert_file was created or the sync user does not exist
        # create it
        sync_user = config["aci_config"]["sync_login"]["username"]
        post_user = not config["aci_config"]["sync_login"]["cert_reused"]
        post_user = post_user or not apic.get_user(sync_user)
        post_user = post_user or args.delete
        if post_user:
            underlay_posts.append(configurator.kube_user)
            underlay_posts.append(configurator.kube_cert)

        # if underlay ccp doesn't exist, create one
        u_ccp = getUnderlayCCP()
        if not u_ccp or args.delete:
            if not args.delete:
                print("Creating VPC, you will need additional settings for IPI\n")
            underlay_posts += [configurator.capic_underlay_vrf, configurator.capic_underlay_cloudApp, configurator.capic_underlay_ccp]
        else:
            # if existing vpc, cidr and subnet should be created as well
            underlay_posts += [configurator.capic_underlay_cloudApp]

        underlay_posts.append(setupCapicContractsInline)

        postGens = underlay_posts + [configurator.capic_kube_dom, configurator.capic_overlay_vrf, overlayCtx, configurator.capic_overlay_cloudApp, clusterInfo, configurator.capic_kafka_topic, prodAcl, consAcl]
        for pGen in postGens:
            path, data = pGen()
            if not path:  # posted inline
                continue

            postIt(path, data)
        if args.delete:
            deleter.doIt()
            apic.save()
            return True

        config = addKafkaConfig(config)
        config = addMiscConfig(config)

        print("Config is: {}".format(config["kube_config"]))
        gen = flavor_opts.get("template_generator", generate_kube_yaml)
        gen(config, output_file, output_tar, operator_cr_output_file)
        m_cidr = config["net_config"]["machine_cidr"]
        b_subnet = config["net_config"]["bootstrap_subnet"]
        n_subnet = config["net_config"]["node_subnet"]
        p_subnet = config["net_config"]["pod_subnet"].replace(".1/", ".0/")
        region = config["aci_config"]["vrf"]["region"]
        boot_subnetID = getSubnetID(b_subnet)
        node_subnetID = getSubnetID(n_subnet)
        print("\nOpenshift Info")
        print("----------------")
        print("networking:\n  clusterNetwork:\n  - cidr: {}\n    hostPrefix: 23\n  machineCIDR: {}\n  networkType: CiscoACI\n  serviceNetwork:\n  - 172.30.0.0/16\nplatform:\n  aws:\n    region: {}\n    subnets:\n    - {}\n    - {}".format(p_subnet, m_cidr, region, boot_subnetID, node_subnetID))
        apic.save()
        return True

    # generate output files; and program apic if needed
    gen = flavor_opts.get("template_generator", generate_kube_yaml)
    gen(config, output_file, output_tar, operator_cr_output_file)
    ret = generate_apic_config(flavor_opts, config, prov_apic, apic_file)
    return ret


def addKafkaConfig(config):
    cKey, cCert, caCert = getKafkaCerts(config)
    config["aci_config"]["kafka"]["key"] = cKey.encode()
    config["aci_config"]["kafka"]["cert"] = cCert.encode()
    config["aci_config"]["kafka"]["cacert"] = caCert.encode()
    brokers = []
    for host in config["aci_config"]["apic_hosts"]:
        host = host.split(":")[0]
        brokers.append(host + ":9095")

    config["aci_config"]["kafka"]["brokers"] = brokers

    return config


def getKafkaCerts(config):
    if config["provision"]["skip-kafka-certs"]:
        return "none", "none", "none"
    wdir = tempfile.mkdtemp()
    apic_host = config["aci_config"]["apic_hosts"][0]
    user = config["aci_config"]["apic_login"]["username"]
    pwd = config["aci_config"]["apic_login"]["password"]
    cn = config["aci_config"]["system_id"]
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


def main(args=None, apic_file=None, no_random=False):
    # apic_file and no_random are used by the test functions
    # len(sys.argv) == 1 when acc-provision is called w/o arguments
    if args is None:
        args = parse_args(len(sys.argv) == 1)

    if args.release:
        try:
            release_file_path = os.path.dirname(os.path.realpath(__file__)) + '/RELEASE-VERSION'
            release = open(release_file_path, "r").read().rstrip()
            print(release, file=sys.stderr)
        except Exception:
            info("Release info not present in this package")
        return

    if args.list_flavors:
        info("Available configuration flavors:")
        for flavor in sorted(FLAVORS, key=lambda x: int(FLAVORS[x]['order'])):
            if not FLAVORS[flavor]['hidden']:
                desc = FLAVORS[flavor]["desc"]
                if FLAVORS[flavor]["status"]:
                    desc = desc + " [" + FLAVORS[flavor]["status"] + "]"
                info(flavor + ":\t" + desc)
        return

    if args.flavor is None:
        err("Flavor not provided. Use -f to pass a flavor name, --list-flavors to see a list of supported flavors")
        sys.exit(1)

    if args.flavor is not None and args.flavor not in FLAVORS:
        err("Invalid configuration flavor: " + args.flavor)
        sys.exit(1)

    success = True
    if args.debug:
        success = provision(args, apic_file, no_random)
    else:
        try:
            success = provision(args, apic_file, no_random)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            success = False
            err("%s: %s" % (e.__class__.__name__, e))

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
