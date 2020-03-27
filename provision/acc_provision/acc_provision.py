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
            "generate_installer_files": False
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
    }
    return default_config


def config_user(config_file):
    config = {}
    if config_file:
        if config_file == "-":
            info("Loading configuration from \"STDIN\"")
            config = yaml.safe_load(sys.stdin)
        else:
            info("Loading configuration from \"%s\"" % config_file)
            with open(config_file, 'r') as file:
                config = yaml.safe_load(file)
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
            },
            "node_bd_dn": bd_dn_prefix + "node-bd",
            "pod_bd_dn": bd_dn_prefix + "pod-bd",
            "kafka": {
            },
            "subnet_dn": {
            },
            "vrf_dn": {
            },
        },
        "net_config": {
            "infra_vlan": infra_vlan,
            "gbp_pod_subnet": "%s/%s" % (cidr_split(pod_subnet)[2], cidr_split(pod_subnet)[4]),
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

        # Network Config
        "net_config/pod_subnet": (get(("net_config", "pod_subnet")),
                                  required),
    }

    if isOverlay(config["flavor"]):
        print("Using overlay")
        extra_checks = {
            "aci_config/vrf/region": (get(("aci_config", "vrf", "region")), required),
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
        warn("Unable to validate resources on APIC: '%s'" % e.message)
    return True


def generate_sample(filep, flavor):
    if flavor == "eks":
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
        info("Reusing existing certs for kubernetes controller")
        info("  Private key file: \"%s\"" % key_file)
        info("  Certificate file: \"%s\"" % cert_file)
        with open(cert_file, "rb") as certp:
            cert_data = certp.read()
        with open(key_file, "rb") as keyp:
            key_data = keyp.read()
    return key_data, cert_data


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


def generate_operator_tar(tar_path, cont_docs, oper_docs, config):

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

    file_start = gen_file_list(cont_docs, file_start, filenames)
    gen_file_list(oper_docs, file_start, filenames)

    # Create three extra files needed for Openshift 4.3 installer
    if config["kube_config"]["generate_installer_files"]:

        cnetfile_name = 'cluster-network-03-config.yaml'
        masterfile_name = '99-master-kubelet-node-ip.yaml'
        workerfile_name = '99-worker-kubelet-node-port.yaml'

        template_cnet = get_jinja_template(cnetfile_name)
        template_cnet.stream(config=config).dump(cnetfile_name)

        template_master = get_jinja_template(masterfile_name)
        template_master.stream(config=config).dump(masterfile_name)

        template_worker = get_jinja_template(workerfile_name)
        template_worker.stream(config=config).dump(workerfile_name)

        filenames.append(cnetfile_name)
        filenames.append(masterfile_name)
        filenames.append(workerfile_name)

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

        # Generate and convert containers deployment to base64 and add as configMap
        # entry to the operator deployment.
        temp = ''.join(template.stream(config=config))
        config["kube_config"]["deployment_base64"] = base64.b64encode(temp.encode('ascii')).decode('ascii')
        op_template = get_jinja_template('aci-operators.yaml')

        # Generate kubernetes deployment
        template.stream(config=config).dump(operator_output)
        # Render operator deployment
        output_from_parsed_template = op_template.render(config=config)

        # If output containers deployment file arg present, append rendered
        # operator deployment yamls to containers deployment yaml.
        # This needs to be ultimately(kubectl) applied to install the
        # ACI CNI. Else print to stdout.
        if operator_output != sys.stdout:
            with open(operator_output, "a+") as fh:
                fh.write("---\n")
                fh.write(output_from_parsed_template)
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
            # Generate yamls for containers and operator deployment
            # which are consumed by the geneate_operator_tar method
            cont_stream = template.stream(config=config)
            cont_yamls = ''.join(cont_stream)
            cont_docs = yaml.load_all(cont_yamls, Loader=yaml.SafeLoader)
            oper_stream = op_template.stream(config=config)
            oper_yamls = ''.join(oper_stream)
            oper_docs = yaml.load_all(oper_yamls, Loader=yaml.SafeLoader)
            generate_operator_tar(tar_path, cont_docs, oper_docs, config)

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
    apic_config = configurator.get_config()
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
    capic = config["aci_config"]["capic"]
    apic = Apic(
        apic_host, apic_username, apic_password,
        timeout=timeout, debug=debug, capic=capic)
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
            "capic": False
        },
        "provision": {
            "prov_apic": prov_apic,
            "debug_apic": args.debug,
        },
    }

    # infra_vlan is not part of command line input, but we do
    # pass it as a command line arg in unit tests to pass in
    # configuration which would otherwise be discovered from
    # the APIC
    config["discovered"] = {"infra_vlan": getattr(args, "infra_vlan", None)}

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

    if user_config:
        if 'versions_url' in user_config and 'path' in user_config['versions_url']:
            versions_url = user_config['versions_url']['path']
            get_versions(versions_url)

    deep_merge(config, user_config)
    if "netflow_exporter" in config["aci_config"]:
        config["aci_config"]["netflow_exporter"]["enable"] = True

    flavor = args.flavor
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
        if apic is None:
            err("Not able to login to the APIC, please check username or password")
            return False

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
    if generate_cert_data:
        key_data, cert_data = generate_cert(username, certfile, keyfile)
    config["aci_config"]["sync_login"]["key_data"] = key_data
    config["aci_config"]["sync_login"]["cert_data"] = cert_data

    if flavor == "eks":
        if prov_apic is None:
            return True
        print("Configuring cAPIC")
        config["aci_config"]["capic"] = True
        apic = get_apic(config)
        if apic is None:
            print("APIC login failed")
            return False

        configurator = ApicKubeConfig(config)

        def getOverlayDn():
            query = configurator.capic_overlay_dn_query()
            resp = apic.get(path=query)
            resJson = json.loads(resp.content)
            overlayDn = resJson["imdata"][0]["hcloudCtx"]["attributes"]["dn"]
            return overlayDn

        def prodAcl():
            return configurator.capic_kafka_acl(config["aci_config"]["system_id"])

        # This is a temporary fix until cAPIC implements its consumer ACL.
        def consAcl():
            return configurator.capic_kafka_acl("1EE9AB4924E2")

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
            return config

        postGens = [configurator.capic_kube_dom, configurator.capic_overlay, configurator.capic_cloudApp, clusterInfo, configurator.capic_kafka_topic, prodAcl, consAcl]
        for pGen in postGens:
            path, data = pGen()
            print("Path: {}".format(path))
            print("data: {}".format(data))
            try:
                resp = apic.post(path, data)
                print("Resp: {}".format(resp.text))
            except Exception as e:
                err("Error in provisioning %s: %s" % (path, str(e)))

        config = addKafkaConfig(config)
        config = addMiscConfig(config)

        gen = flavor_opts.get("template_generator", generate_kube_yaml)
        gen(config, output_file, output_tar, operator_cr_output_file)
        return True

    # generate output files; and program apic if needed
    ret = generate_apic_config(flavor_opts, config, prov_apic, apic_file)
    gen = flavor_opts.get("template_generator", generate_kube_yaml)
    gen(config, output_file, output_tar, operator_cr_output_file)
    return ret


def addKafkaConfig(config):
    cKey, cCert, caCert = getKafkaCerts(config)
    config["aci_config"]["kafka"]["key"] = cKey
    config["aci_config"]["kafka"]["cert"] = cCert
    config["aci_config"]["kafka"]["cacert"] = caCert
    brokers = []
    for host in config["aci_config"]["apic_hosts"]:
        brokers.append(host + ":9093")

    config["aci_config"]["kafka"]["brokers"] = brokers

    return config


def getKafkaCerts(config):
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
