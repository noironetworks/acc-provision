#!/usr/bin/env python3

from __future__ import print_function, unicode_literals

import argparse
import base64
import copy
import csv
import functools
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

from jinja2 import Undefined
from itertools import combinations, groupby
from OpenSSL import crypto
from jinja2 import Environment, PackageLoader
from os.path import exists
if __package__ is None or __package__ == '':
    from apic_provision import Apic, ApicKubeConfig
    from cloud_provision import CloudProvision
else:
    from .apic_provision import Apic, ApicKubeConfig
    from .cloud_provision import CloudProvision


# This black magic forces pyyaml to load YAML strings as unicode rather
# than byte strings in Python 2, thus ensuring that the type of strings
# is consistent across versions.  From
# https://stackoverflow.com/a/2967461/3857947. Revisit for Python 3.
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


def get_csv_contents(file_path):
    csv_data = []
    try:
        with open(file_path, 'r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                csv_data.append(row)
    except Exception as ex:
        print("Error while getting CSV %s file contents. Error: %s") % (file_path, ex)
    return csv_data


def prepare_nadvlanmap(file_path):
    csv_data = get_csv_contents(file_path)
    all_resources = {}
    old_namespace = ''
    old_nad_prefix = ''
    network = ''
    vlan_id = ''
    try:
        for resource in csv_data:
            namespace = resource['Namespace']
            nad_prefix = resource['NAD Prefix']
            if (namespace and namespace != old_namespace) or (nad_prefix and nad_prefix != old_nad_prefix):
                resource_header = namespace + "/" + nad_prefix
                if resource_header not in all_resources.keys():
                    all_resources[resource_header] = []
                old_namespace = namespace
                old_nad_prefix = nad_prefix

            network = resource['Network'] if resource['Network'] else network
            vlan_id = resource['VLAN ID'] if resource['VLAN ID'] else vlan_id
            resource_item = {
                "label": network,
                "vlans": vlan_id.split('.')[0]
            }
            all_resources[resource_header].append(resource_item)
    except Exception as ex:
        print("Error while preparing yaml contents from given CSV %s file. Error: %s" % (file_path, ex))
        all_resources = {}
    return all_resources


def check_vlans_available_in_file(vlans_file_path):
    csv_data = get_csv_contents(vlans_file_path)
    vlans_from_file = []
    try:
        for resource in csv_data:
            vlan_id = resource.get('VLAN ID')
            if vlan_id:
                vlans_from_file.append(int(vlan_id.split('.')[0]))
    except Exception:
        print("ERR:  Invalid VLAN value in file: ", vlans_file_path)
        return False
    if not vlans_from_file:
        print("ERR:  VLANs not available in file: ", vlans_file_path)
        return False
    return True


def prepare_secondary_vlans(config):
    vlans_file_path = config["chained_cni_config"].get("vlans_file")
    secondary_vlans = config["chained_cni_config"][
        "secondary_vlans"] if config["chained_cni_config"].get(
        "secondary_vlans") else []
    if vlans_file_path:
        vlans_from_file = []
        csv_data = get_csv_contents(vlans_file_path)
        for resource in csv_data:
            vlan_id = resource.get('VLAN ID')
            if vlan_id:
                vlans_from_file.append(vlan_id.split('.')[0])
        secondary_vlans.extend(vlans_from_file)
    return secondary_vlans


def group_in_ranges(vlans):
    integer_vlans = [int(x) for x in vlans]
    sorted_vlans = list(sorted(set(integer_vlans)))
    ranges = []
    for _, group in groupby(enumerate(sorted_vlans), lambda i_x: i_x[1] - i_x[0]):
        group = list(group)
        if len(group) > 1:
            ranges.append(f"{group[0][1]}-{group[-1][1]}")
        else:
            ranges.append(str(group[0][1]))
    return ranges


def yaml_indent(s, **kwargs):
    return yaml.dump(s, **kwargs)


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
        "operator_managed_config": {
            "enable_updates": False,
        },
        "aci_config": {
            "apic_version": "1.0",
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
            "cluster_l3out": {
                "name": None,
                "svi": {
                    "type": "floating",
                    "mtu": 9000
                },
                "bgp": {
                    "peering": {
                        "prefixes": 500,
                        "remote_as_number": 64512,
                    },
                },
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
                    "duplicate_file_router_default_svc": False,
                },
            },
            "client_cert": False,
            "client_ssl": True,
            "kube_default_provide_kube_api": False,
            "no_physdom_for_node_epg": False,
            "disable_node_subnet_creation": False,
            "preexisting_kube_bd": None,
            "apic_subscription_delay": None,
            "apic_refreshticker_adjust": None,
            "opflex_device_delete_timeout": None,
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
            "interface_mtu_headroom": None,
            "second_kubeapi_portgroup": False,
            "disable_wait_for_network": False,
            "duration_wait_for_network": 210,
            "kubeapi_vlan_mode": "regular",
            "cluster_svc_subnet": None,
            "advertise_cluster_svc_subnet": False,
        },
        "topology": {
            "rack": {
            },
        },
        "calico_config": {
            "net_config": {
                "block_size": 26,
                "encapsulation": "None",
                "nat_outgoing": "Disabled",
                "nodeSelector": "all()",
            },
        },
        "kube_config": {
            "controller": "1.1.1.1",
            "use_rbac_api": "rbac.authorization.k8s.io/v1",
            "use_apps_api": "apps/v1",
            "use_apps_apigroup": "apps",
            "host_agent_openshift_resource": False,
            "use_netpol_apigroup": "networking.k8s.io",
            "use_cluster_role": True,
            "no_wait_for_service_ep_readiness": False,
            "add_external_subnets_to_rdconfig": False,
            "image_pull_policy": "Always",
            "kubectl": "kubectl",
            "system_namespace": "aci-containers-system",
            "ovs_memory_request": "128Mi",
            "ovs_memory_limit": "1Gi",
            "aci_containers_memory_request": "128Mi",
            "aci_containers_memory_limit": "3Gi",
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
                "disable_periodic_snat_global_info_sync": False,
                "sleep_time_snat_global_info_sync": None,
            },
            "max_nodes_svc_graph": 32,
            "opflex_mode": None,
            "opflex_agent_prometheus": "false",
            "host_agent_cni_bin_path": "/opt",
            "host_agent_cni_conf_path": "/etc",
            "generate_installer_files": False,
            "generate_cnet_file": False,
            "generate_apic_file": False,
            "use_host_netns_volume": False,
            "enable_endpointslice": False,
            "opflex_agent_opflex_asyncjson_enabled": "false",
            "opflex_agent_ovs_asyncjson_enabled": "false",
            "acicni_priority_class_value": 1000000000,
        },
        "istio_config": {
            "install_istio": False,
            "install_profile": "demo",
            "istio_ns": "istio-system",
            "istio_operator_ns": "istio-operator"
        },
        "registry": {
            "image_prefix": "noiro",
            "aci_cni_operator_version": None,
        },
        "logging": {
            "size": None,
            "controller_log_level": "info",
            "hostagent_log_level": "info",
            "opflexagent_log_level": "info",
        },
        "drop_log_config": {
            "enable": True,
        },
        "provision": {
            "upgrade_cluster": False,
        },
        "multus": {
            "disable": True,
        },
        "sriov_config": {
            "enable": False,
        },
        "dpu_config": {
            "enable": False,
        },
        "nodepodif_config": {
            "enable": False,
        },
        "lb_config": {
            "lb_type": "metallb",
        },
        "rke2_config": {
            "logging_namespace": "cattle-logging",
            "monitoring_namespace": "cattle-prometheus",
        },
        "chained_cni_config": {
            "secondary_interface_chaining": False,
            "primary_interface_chaining": False,
            "primary_cni_path": None,
            "skip_node_network_provisioning": False,
            "use_global_scope_vlan": False,
            "secondary_vlans": None,
        }
    }
    return default_config


def config_user(flavor, config_file):
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
        if not is_chained_mode(config):
            if not isinstance(config["net_config"]["pod_subnet"], list):
                config["net_config"]["pod_subnet"] = [config["net_config"]["pod_subnet"]]
            if not isinstance(config["net_config"]["extern_dynamic"], list):
                config["net_config"]["extern_dynamic"] = [config["net_config"]["extern_dynamic"]]
            if "extern_static" in config["net_config"] and not isinstance(config["net_config"]["extern_static"], list):
                config["net_config"]["extern_static"] = [config["net_config"]["extern_static"]]
        if "net_config" in config.keys() and config["net_config"].get(
                "node_subnet") and not isinstance(config["net_config"]["node_subnet"], list):
            config["net_config"]["node_subnet"] = [config["net_config"]["node_subnet"]]
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
    return str(first), str(last), str(n[1]), str(n.network_address), mask, str(ip)


def normalize_cidr(cidr):
    # To convert CIDR network ending with .1 to .0. For eg, convert 10.0.0.1/16 to 10.0.0.0/16
    rtr, _ = cidr.split('/')
    ip = ipaddress.ip_address(rtr)
    if ip.version == 4:
        n = ipaddress.IPv4Network(cidr, strict=False)
    else:
        n = ipaddress.IPv6Network(cidr, strict=False)
    return str(n)


def normalize_vlans(secondary_vlans):
    normalized_vlans = []
    if not secondary_vlans:
        return normalized_vlans
    for vlan in secondary_vlans:
        if isinstance(vlan, list):
            normalized_vlans.extend(vlan)
        elif ',' in str(vlan):
            values = [int(val) for val in vlan.split(',')]
            normalized_vlans.extend(values)
        elif '-' in str(vlan):
            start, end = map(int, vlan.split('-'))
            result_vlans = list(range(start, end + 1))
            normalized_vlans.extend(result_vlans)
        else:
            normalized_vlans.append(vlan)
    return normalized_vlans


def config_adjust_chained_mode(args, config, no_random):
    system_id = config["aci_config"]["system_id"]
    infra_vlan = config["net_config"]["infra_vlan"]
    token = str(uuid.uuid4())

    # Have tenant name in acc provision input file under aci_config section if tenant is manually created on the APIC before provisioning
    if (config["aci_config"]["tenant"]["name"]):
        config["aci_config"]["use_pre_existing_tenant"] = True
        tenant = config["aci_config"]["tenant"]["name"]
    else:
        tenant = system_id

    if config["aci_config"].get("physical_domain"):
        physical_domain = config["aci_config"]["physical_domain"]["domain"]
    else:
        physical_domain = system_id + "-physdom"

    secondary_vlans = config["chained_cni_config"]["secondary_vlans"]

    app_profile = Apic.ACI_CHAINED_PREFIX + system_id
    default_endpoint_group = Apic.ACI_CHAINED_PREFIX + "default"
    namespace_endpoint_group = Apic.ACI_CHAINED_PREFIX + "system"
    config["aci_config"]["nodes_epg"] = Apic.ACI_CHAINED_PREFIX + "nodes"
    bd_dn_prefix = "uni/tn-%s/BD-%snodes" % (tenant, Apic.ACI_CHAINED_PREFIX)

    aci_vrf_dn = "uni/tn-%s/ctx-%s" % (config["aci_config"]["vrf"]["tenant"], config["aci_config"]["vrf"]["name"])
    node_bd_dn = bd_dn_prefix

    config["aci_config"]["app_profile"] = app_profile
    system_namespace = config["kube_config"]["system_namespace"]
    if args.version_token:
        token = args.version_token

    adj_config = {
        "aci_config": {
            "cluster_tenant": tenant,
            "physical_domain": {
                "domain": physical_domain,
                "vlan_pool": system_id + "-pool",
            },
            "vrf": {
                "dn": aci_vrf_dn,
            },
            "sync_login": {
                "username": system_id,
                "password": generate_password(no_random),
                "certfile": "user-%s.crt" % system_id,
                "keyfile": "user-%s.key" % system_id,
                "cert_reused": False,
            },
            "node_bd_dn": node_bd_dn,
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
            },
        },
        "chained_cni_config": {
            "secondary_vlans": secondary_vlans,
        },
        "registry": {
            "configuration_version": token,
        }
    }

    if not config["chained_cni_config"]["skip_node_network_provisioning"]:
        node_subnet = config["net_config"]["node_subnet"][0]
        config["net_config"]["node_subnet"] = node_subnet

    if config["aci_config"].get("apic_refreshtime"):  # APIC Subscription refresh timeout value
        adj_config["aci_config"]["apic_refreshtime"] = config["aci_config"]["apic_refreshtime"]

    if config["kube_config"].get("image_pull_policy"):  # imagePullPolicy to be set for ACI CNI pods in K8S Spec
        adj_config["kube_config"]["image_pull_policy"] = config["kube_config"]["image_pull_policy"]

    if config["net_config"].get("pbr_tracking_non_snat"):
        adj_config["net_config"]["pbr_tracking_non_snat"] = config["net_config"]["pbr_tracking_non_snat"]

    ns_value = {"tenant": tenant, "app_profile": app_profile, "group": namespace_endpoint_group}

    # To add kube-system namespace to ACI system EPG
    adj_config["kube_config"]["namespace_default_endpoint_group"]["kube-system"] = ns_value

    if config["aci_config"]["vmm_domain"]:
        encap_type = config["aci_config"]["vmm_domain"]["encap_type"]
        adj_config["aci_config"]["vmm_domain"] = {
            "domain": system_id,
            "controller": system_id,
            "mcast_pool": system_id + "-mpool",
            "vlan_pool": system_id + "-vpool",
            "vlan_range": {
                "start": None,
                "end": None,
            },
        }
        adj_config["aci_config"]["node_config"] = {
            "encap_type": encap_type,
        }
        # Add openshift system namespaces to ACI system EPG
        if config["aci_config"]["vmm_domain"]["type"] == "OpenShift":
            ns_list = ["kube-service-catalog", "openshift-console", "openshift-dns", "openshift-authentication",
                       "openshift-authentication-operator", "openshift-monitoring", "openshift-web-console"]
            for ns in ns_list:
                adj_config["kube_config"]["namespace_default_endpoint_group"][ns] = ns_value

        if not config["aci_config"]["vmm_domain"].get("injected_cluster_type"):
            adj_config["aci_config"]["vmm_domain"]["injected_cluster_type"] = ""
        if not config["aci_config"]["vmm_domain"].get("injected_cluster_provider"):
            adj_config["aci_config"]["vmm_domain"]["injected_cluster_provider"] = ""

    return adj_config


def config_adjust(args, config, prov_apic, no_random):
    if is_calico_flavor(config["flavor"]):
        l3out_name = ""
        if not config["aci_config"]["cluster_l3out"].get("name"):
            vlan_id = config["aci_config"]["cluster_l3out"]["svi"]["vlan_id"]
            l3out_name = "calico-l3out-fsvi-vlan-%s" % vlan_id
            config["aci_config"]["cluster_l3out"]["name"] = l3out_name
        l3out_name = config["aci_config"]["cluster_l3out"]["name"]
        system_id = "calico-%s" % l3out_name if "calico" not in l3out_name else l3out_name
        system_id = system_id[:20]
        config["aci_config"]["system_id"] = system_id
    else:
        l3out_name = config["aci_config"]["l3out"]["name"]
        system_id = config["aci_config"]["system_id"]
    infra_vlan = config["net_config"]["infra_vlan"]
    node_subnets = []
    for node_subnet in config["net_config"]["node_subnet"]:
        node_subnets.append(node_subnet)
    pod_subnets = []
    for pod_subnet in config["net_config"]["pod_subnet"]:
        pod_subnets.append(pod_subnet)
    extern_dynamics = []
    for extern_dynamic in config["net_config"]["extern_dynamic"]:
        extern_dynamics.append(extern_dynamic)
    extern_statics = []
    extern_static = config["net_config"].get("extern_static", [])
    if extern_static is not None and not isinstance(extern_static, list):
        extern_statics = [extern_static]
    if extern_static is not None and isinstance(extern_static, list):
        for subnet in extern_static:
            extern_statics.append(subnet)

    extern_static = config["net_config"]["extern_static"]
    node_svc_subnet = config["net_config"]["node_svc_subnet"]
    disable_wait_for_network = config["net_config"]["disable_wait_for_network"]
    duration_wait_for_network = config["net_config"]["duration_wait_for_network"]
    encap_type = config["aci_config"]["vmm_domain"]["encap_type"]
    opflex_mode = config["kube_config"]["opflex_mode"]
    istio_profile = config["istio_config"]["install_profile"]
    istio_namespace = config["istio_config"]["istio_ns"]
    istio_operator_ns = config["istio_config"]["istio_operator_ns"]
    enable_endpointslice = config["kube_config"]["enable_endpointslice"]
    token = str(uuid.uuid4())
    # Have tenant name in acc provision input file under aci_config section if tenant is manually created on the APIC before provisioning
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

    aci_vrf_dn = "uni/tn-%s/ctx-%s" % (config["aci_config"]["vrf"]["tenant"], config["aci_config"]["vrf"]["name"])
    node_bd_dn = bd_dn_prefix + "node-bd"
    pod_bd_dn = bd_dn_prefix + "pod-bd"

    config["aci_config"]["app_profile"] = app_profile
    system_namespace = config["kube_config"]["system_namespace"]
    if args.version_token:
        token = args.version_token

    static_service_ip_pool = []
    if (not is_calico_flavor(config["flavor"])) and (extern_static is not None):
        for subnet in extern_statics:
            static_service_ip_pool.append({"start": cidr_split(subnet)[0], "end": cidr_split(subnet)[1]})

    node_service_ip_pool = []
    if not is_calico_flavor(config["flavor"]) and node_svc_subnet:
        node_service_ip_pool = [{"start": cidr_split(node_svc_subnet)[0], "end": cidr_split(node_svc_subnet)[1]}]

    if is_calico_flavor(config["flavor"]):
        config["aci_config"]["cluster_l3out"]["svi"]["node_profile_name"] = l3out_name + "_node_prof"
        config["aci_config"]["cluster_l3out"]["svi"]["int_prof_name"] = l3out_name + "_int_prof"
        config["aci_config"]["cluster_l3out"]["svi"]["external_network"] = l3out_name + "_int_epg"
        config["aci_config"]["cluster_l3out"]["svi"]["external_network_svc"] = l3out_name + "_svc_epg"

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
            "vrf": {
                "dn": aci_vrf_dn,
            },
            "sync_login": {
                "username": system_id,
                "password": generate_password(no_random),
                "certfile": "user-%s.crt" % system_id,
                "keyfile": "user-%s.key" % system_id,
                "cert_reused": False,
            },
            "node_bd_dn": node_bd_dn,
            "pod_bd_dn": pod_bd_dn,
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
            # TODO: For overlay mode we are currently not supporting multiple subnets, hence the assumption that there is only one subnet.
            "gbp_pod_subnet": "%s/%s" % (cidr_split(pod_subnets[0])[2], cidr_split(pod_subnets[0])[4]),
            "gbp_node_subnet": "%s/%s" % (cidr_split(node_subnets[0])[2], cidr_split(node_subnets[0])[4]),
            "node_network_gateway": cidr_split(node_subnets[0])[5],
            "disable_wait_for_network": disable_wait_for_network,
            "duration_wait_for_network": duration_wait_for_network,
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
            "static_service_ip_pool": static_service_ip_pool,
            "node_service_ip_pool": node_service_ip_pool,
            "node_service_gw_subnets": [
                node_svc_subnet,
            ],
            "opflex_mode": opflex_mode,
            "enable_endpointslice": enable_endpointslice,
        },
        "registry": {
            "configuration_version": token,
        }
    }

    if "kube_config" in adj_config.keys():
        kube_config_object = adj_config["kube_config"]
        for pod_subnet in pod_subnets:
            if "pod_ip_pool" not in kube_config_object:
                kube_config_object["pod_ip_pool"] = [
                    {
                        "start": cidr_split(pod_subnet)[0],
                        "end": cidr_split(pod_subnet)[1],
                    }
                ]
            else:
                kube_config_object["pod_ip_pool"].append(
                    {
                        "start": cidr_split(pod_subnet)[0],
                        "end": cidr_split(pod_subnet)[1],
                    }
                )
            if "pod_network" not in kube_config_object:
                kube_config_object["pod_network"] = [
                    {
                        "subnet": "%s/%s" % cidr_split(pod_subnet)[3:5],
                        "gateway": cidr_split(pod_subnet)[2],
                        "routes": [
                            {
                                "dst": config_set_dst(pod_subnet),
                                "gw": cidr_split(pod_subnet)[2],
                            }
                        ]
                    }
                ]
            else:
                kube_config_object["pod_network"].append(
                    {
                        "subnet": "%s/%s" % cidr_split(pod_subnet)[3:5],
                        "gateway": cidr_split(pod_subnet)[2],
                        "routes": [
                            {
                                "dst": config_set_dst(pod_subnet),
                                "gw": cidr_split(pod_subnet)[2],
                            }
                        ]
                    }
                )
        for extern_dynamic in extern_dynamics:
            if "service_ip_pool" not in kube_config_object:
                kube_config_object["service_ip_pool"] = [
                    {
                        "start": cidr_split(extern_dynamic)[0],
                        "end": cidr_split(extern_dynamic)[1],
                    }
                ]
            else:
                kube_config_object["service_ip_pool"].append(
                    {
                        "start": cidr_split(extern_dynamic)[0],
                        "end": cidr_split(extern_dynamic)[1],
                    }
                )

    if "net_config" in adj_config.keys():
        net_config_object = adj_config["net_config"]
        for pod_subnet in pod_subnets:
            if "pod_network" not in net_config_object:
                net_config_object["pod_network"] = normalize_cidr(pod_subnet)

        for node_subnet in node_subnets:
            if "node_network" not in net_config_object:
                net_config_object["node_network"] = normalize_cidr(node_subnet)

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

    ns_value = {"tenant": tenant, "app_profile": app_profile, "group": namespace_endpoint_group}

    # To add kube-system namespace to ACI system EPG
    adj_config["kube_config"]["namespace_default_endpoint_group"]["kube-system"] = ns_value

    # Add openshift system namespaces to ACI system EPG
    if config["aci_config"]["vmm_domain"]["type"] == "OpenShift":
        ns_list = ["kube-service-catalog", "openshift-console", "openshift-dns", "openshift-authentication",
                   "openshift-authentication-operator", "openshift-monitoring", "openshift-web-console"]
        for ns in ns_list:
            adj_config["kube_config"]["namespace_default_endpoint_group"][ns] = ns_value

    if config["flavor"] == "k8s-overlay":
        ns_list = ["kube-system"]
        adj_config["kube_config"]["namespace_default_endpoint_group"].clear()
        for ns in ns_list:
            adj_config["kube_config"]["namespace_default_endpoint_group"][ns] = ns_value

    if not config["aci_config"]["vmm_domain"].get("injected_cluster_type"):
        adj_config["aci_config"]["vmm_domain"]["injected_cluster_type"] = ""
    if not config["aci_config"]["vmm_domain"].get("injected_cluster_provider"):
        adj_config["aci_config"]["vmm_domain"]["injected_cluster_provider"] = ""

    if config["aci_config"]["vmm_domain"].get("injected_cluster_type") == "RKE2":
        ns_list = ["cattle-system"]
        ns_list.append(config["rke2_config"]["logging_namespace"])
        ns_list.append(config["rke2_config"]["monitoring_namespace"])
        for ns in ns_list:
            adj_config["kube_config"]["namespace_default_endpoint_group"][ns] = ns_value

    if config["sriov_config"].get("enable"):
        adj_config["vendors"] = "15b3"
        adj_config["drivers"] = "mlx5_core"
        adj_config["resourcePrefix"] = "mellanox.com"
        adj_config["resourceName"] = "cx5_sriov_switchdev"
        adj_config["pfNames"] = "enp193s0f0np0#2-59"
        adj_config["devices"] = ""
        adj_config["isRdma"] = "false"

        if 'device_info' in config["sriov_config"]:
            if 'devices' in config["sriov_config"]["device_info"]:
                adj_config["devices"] = str(config["sriov_config"]["device_info"].get("devices"))
            if config["sriov_config"]["device_info"].get("isRdma"):
                adj_config["isRdma"] = "true"

        if config["dpu_config"].get("enable"):
            if opflex_mode == "dpu":
                if 'ip' in config["dpu_config"] and config["dpu_config"].get("ip"):
                    adj_config["dpuIp"] = str(config["dpu_config"]["ip"])
                else:
                    adj_config["dpuIp"] = "192.168.200.2"

                if 'user' in config["dpu_config"] and config["dpu_config"].get("user"):
                    adj_config["dpuUser"] = str(config["dpu_config"]["user"])
                else:
                    adj_config["dpuUser"] = "opflex"

                if 'ovsdb_socket_port' in config["dpu_config"] and config["dpu_config"].get("ovsdb_socket_port"):
                    adj_config["dpu_ovsdb_socket"] = "tcp:" + adj_config["dpuIp"] + ":" + str(config["dpu_config"]["ovsdb_socket_port"])
                else:
                    adj_config["dpu_ovsdb_socket"] = "tcp:" + adj_config["dpuIp"] + ":6640"
            else:
                err("Opflex_mode is not set to dpu. Cannot generate dpu config")

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
    raise (Exception("Must be integer between %d and %d" % (xmin, xmax)))


def is_valid_mtu_VirtualLIfP(xval):
    if xval is None:
        # use default configured on this host
        return True

    xmin = 576
    xmax = 9216
    try:
        x = int(xval)
        if xmin <= x <= xmax:
            return True
    except ValueError:
        pass
    raise (Exception("Must be integer between %d and %d" % (xmin, xmax)))


def is_valid_headroom(xval):
    if xval is None:
        # use default configured on this host
        return True

    xmin = 50
    try:
        x = int(xval)
        if x >= xmin:
            return True
    except ValueError:
        pass
    raise (Exception("Must be integer >= %d" % (xmin)))


def is_valid_apic_sub_delay(xval):
    if xval is None:
        # use default configured on this host
        return True

    xmin = 1
    xmax = 65535
    try:
        x = int(xval)
        if xmin <= x <= xmax:
            return True
    except ValueError:
        pass
    raise (Exception("Must be integer between %d and %d" % (xmin, xmax)))


def is_valid_dev_del_timeout(xval):
    if xval is None:
        # use default configured on this host
        return True

    xmin = 1
    xmax = 65535
    try:
        x = int(xval)
        if xmin <= x <= xmax:
            return True
    except ValueError:
        pass
    raise (Exception("Must be integer between %d and %d" % (xmin, xmax)))


def is_valid_sleep_time(xval):
    if xval is None:
        # use default configured on this host
        return True

    xmin = 1
    xmax = 300
    try:
        x = int(xval)
        if xmin <= x <= xmax:
            return True
    except ValueError:
        pass
    raise (Exception("Must be integer between %d and %d" % (xmin, xmax)))


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
    raise (Exception("Must be integer between %d and %d" % (xmin, xmax)))


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
    raise (Exception("Must be integer between %d and %d" % (xmin, xmax)))


def is_valid_apic_refreshticker_adjust(xval):
    if xval is None:
        # use default configured on this host(150 seconds)
        return True

    xmin = 1
    xmax = 65535
    try:
        x = int(xval)
        if xmin <= x <= xmax:
            return True
    except ValueError:
        pass
    raise (Exception("Must be integer between %d and %d" % (xmin, xmax)))


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
    raise (Exception("Must be integer between %d and %d" % (xmin, xmax)))


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
    raise (Exception("Must be one of the profile in this List: ", validProfiles))


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
    raise (Exception("Must be one of the values in this List: ", validPullPolicies))


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
    raise (Exception("Must be one of the contract scopes in this List: ", validVersions))


def isOverlay(flavor):
    flav = SafeDict(FLAVORS[flavor])
    ovl = flav["overlay"]
    if ovl is True:
        return True

    return False


def is_valid_file(path):
    if not path or not os.path.isfile(path):
        print("ERR:  File path invalid: ", path)
        return False
    if not check_vlans_available_in_file(path):
        return False
    return True


def validate_system_id_if_openshift(system_id, flavor):
    if "openshift" in flavor.lower():
        if not system_id.isalnum() or not system_id.islower():
            raise Exception("Invalid system_id: %s, only lower case alphanumeric characters allowed" % system_id)
    return True


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


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

    if is_calico_flavor(config["flavor"]):
        checks = {
            # ACI config
            "aci_config/apic_host": (get(("aci_config", "apic_hosts")), required),
            "aci_config/vrf/name": (get(("aci_config", "vrf", "name")), required),
            "aci_config/vrf/tenant": (get(("aci_config", "vrf", "tenant")), required),
            # Network Config
            "net_config/pod_subnet": (get(("net_config", "pod_subnet")), required),
            "net_config/node_subnet": (get(("net_config", "node_subnet")), required),
        }
    elif is_chained_mode(config):
        checks = {
            # ACI config
            "aci_config/system_id": (get(("aci_config", "system_id")),
                                     lambda x: required(x) and isname(x, 32) and
                                     validate_system_id_if_openshift(x, config['flavor'])),
            "aci_config/apic_refreshtime": (get(("aci_config", "apic_refreshtime")),
                                            is_valid_refreshtime),
            "aci_config/apic_refreshticker_adjust": (get(("aci_config", "apic_refreshticker_adjust")),
                                                     is_valid_apic_refreshticker_adjust),
            "aci_config/apic_subscription_delay": (get(("aci_config", "apic_subscription_delay")),
                                                   is_valid_apic_sub_delay),
            "aci_config/apic_host": (get(("aci_config", "apic_hosts")), required),
            "kube_config/image_pull_policy": (get(("kube_config", "image_pull_policy")),
                                              is_valid_image_pull_policy),
        }
        if not config["chained_cni_config"]["skip_node_network_provisioning"]:
            # Network Config
            checks["net_config/node_subnet"] = (
                get(("net_config", "node_subnet")), required)
            checks["aci_config/vrf/name"] = (get(("aci_config", "vrf", "name")), required)
            checks["aci_config/vrf/tenant"] = (get(("aci_config", "vrf", "tenant")), required)
        if config["user_config"]["aci_config"].get("vmm_domain", False):
            # ACI Config
            checks["aci_config/vmm_domain/domain"] = (
                get(("aci_config", "vmm_domain", "domain")), required)
            checks["aci_config/vmm_domain/type"] = (
                get(("aci_config", "vmm_domain", "type")), required)
    elif not isOverlay(config["flavor"]) or config["aci_config"]["capic"]:
        checks = {
            # ACI config
            "aci_config/system_id": (get(("aci_config", "system_id")),
                                     lambda x: required(x) and isname(x, 32) and
                                     validate_system_id_if_openshift(x, config['flavor'])),
            "aci_config/apic_refreshtime": (get(("aci_config", "apic_refreshtime")),
                                            is_valid_refreshtime),
            "aci_config/apic_refreshticker_adjust": (get(("aci_config", "apic_refreshticker_adjust")),
                                                     is_valid_apic_refreshticker_adjust),
            "aci_config/apic_subscription_delay": (get(("aci_config", "apic_subscription_delay")),
                                                   is_valid_apic_sub_delay),
            "aci_config/opflex_device_delete_timeout": (get(("aci_config", "opflex_device_delete_timeout")),
                                                        is_valid_dev_del_timeout),
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
    else:
        checks = {
            "kube_config/image_pull_policy": (get(("kube_config", "image_pull_policy")),
                                              is_valid_image_pull_policy),
            # Network Config
            "net_config/pod_subnet": (get(("net_config", "pod_subnet")),
                                      required),
            "net_config/node_subnet": (get(("net_config", "node_subnet")),
                                       required),
        }
    if isOverlay(config["flavor"]):
        if (config["aci_config"]["capic"]):
            extra_checks = {
                "aci_config/vrf/region": (get(("aci_config", "vrf", "region")), required),
            }
        else:
            extra_checks = {}
    elif is_chained_mode(config):
        extra_checks = {
            "aci_config/secondary_aep": (get(("aci_config", "secondary_aep")), required),
            # Network Config
            "net_config/interface_mtu": (get(("net_config", "interface_mtu")),
                                         is_valid_mtu),
            "net_config/interface_mtu_headroom": (get(("net_config", "interface_mtu_headroom")),
                                                  is_valid_headroom),
        }
        if not config["chained_cni_config"]["skip_node_network_provisioning"]:
            extra_checks["aci_config/aep"] = (
                get(("aci_config", "aep")), required)
        if config["chained_cni_config"].get("vlans_file"):
            extra_checks["chained_cni_config/vlans_file"] = (
                get(("chained_cni_config", "vlans_file")), is_valid_file)
        else:
            extra_checks["chained_cni_config/secondary_vlans"] = (
                get(("chained_cni_config", "secondary_vlans")), required)
    elif is_calico_flavor(config["flavor"]):
        extra_checks = {
            "aci_config/cluster_l3out/aep": (get(("aci_config", "cluster_l3out", "aep")), required),
            "aci_config/cluster_l3out/svi/mtu": (get(("aci_config", "cluster_l3out", "svi", "mtu")),
                                                 is_valid_mtu_VirtualLIfP),
            "aci_config/cluster_l3out/svi/vlan_id": (get(("aci_config", "cluster_l3out", "svi", "vlan_id")),
                                                     required),
            "aci_config/cluster_l3out/svi/floating_ip": (get(("aci_config", "cluster_l3out", "svi", "floating_ip")),
                                                         required),
            "aci_config/cluster_l3out/svi/secondary_ip": (get(("aci_config", "cluster_l3out", "svi", "secondary_ip")),
                                                          required),
            "aci_config/cluster_l3out/bgp/peering/aci_as_number":
            (get(("aci_config", "cluster_l3out", "bgp", "peering", "aci_as_number")), required),
            "net_config/extern_dynamic": (get(("net_config", "extern_dynamic")),
                                          required),
            "net_config/cluster_svc_subnet": (get(("net_config", "cluster_svc_subnet")),
                                              required),
        }

    else:
        extra_checks = {
            "net_config/node_subnet": (get(("net_config", "node_subnet")),
                                       required),
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

            "kube_config/snat_operator/sleep_time_snat_global_info_sync": (get(("kube_config", "snat_operator", "sleep_time_snat_global_info_sync")),
                                                                           is_valid_sleep_time),

            # Network Config
            "net_config/infra_vlan": (get(("net_config", "infra_vlan")),
                                      required),
            "net_config/service_vlan": (get(("net_config", "service_vlan")),
                                        required),
            "net_config/extern_dynamic": (get(("net_config", "extern_dynamic")),
                                          required),
            "net_config/extern_static": (get(("net_config", "extern_static")),
                                         required),
            "net_config/node_svc_subnet": (get(("net_config", "node_svc_subnet")),
                                           required),
            "net_config/interface_mtu": (get(("net_config", "interface_mtu")),
                                         is_valid_mtu),
            "net_config/interface_mtu_headroom": (get(("net_config", "interface_mtu_headroom")),
                                                  is_valid_headroom),
            "net_config/service_monitor_interval": (get(("net_config", "service_monitor_interval")),
                                                    is_valid_ipsla_interval)
        }

        if (config["aci_config"]["vmm_domain"]["type"] == "OpenShift"):
            del extra_checks["net_config/extern_static"]

        if flavor_opts.get("apic", {}).get("use_kubeapi_vlan", True):
            checks["net_config/kubeapi_vlan"] = (
                get(("net_config", "kubeapi_vlan")), required)

    # Allow deletion of resources without isname check
    if get(("provision", "prov_apic")) is False and not is_calico_flavor(config["flavor"]):
        checks["aci_config/system_id"] = \
            (get(("aci_config", "system_id")), required)

    # Versions
    if not is_calico_flavor(config["flavor"]):
        for field in flavor_opts.get('version_fields', VERSION_FIELDS):
            checks[field] = (get(("registry", field)), required)

    if flavor_opts.get("apic", {}).get("associate_aep_to_nested_inside_domain",
                                       False):
        checks["aci_config/vmm_domain/nested_inside/type"] = (
            get(("aci_config", "vmm_domain", "nested_inside", "type")),
            required)

    if not is_chained_mode(config) and get(("aci_config", "vmm_domain", "encap_type")) == "vlan":
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

    if not is_chained_mode(config) and get(("aci_config", "vmm_domain", "nested_inside", "duplicate_file_router_default_svc")):
        checks["aci_config/vmm_domain/nested_inside/installer_provisioned_lb_ip"] = \
            (get(("aci_config", "vmm_domain", "nested_inside", "installer_provisioned_lb_ip")),
             required)

    if get(("provision", "prov_apic")) is not None:
        checks.update({
            # auth for API access
            "aci_config/apic_login/username":
            (get(("aci_config", "apic_login", "username")), required),
            "aci_config/apic_login/password":
            (get(("aci_config", "apic_login", "password")), required),
        })

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


def chained_config_validate_preexisting(config, prov_apic):
    try:
        if prov_apic is not None:
            apic = get_apic(config)
            if apic is None:
                return False

            secondary_aep_name = config["aci_config"]["secondary_aep"]
            secondary_aep = apic.get_aep(secondary_aep_name)
            if secondary_aep is None:
                err("Secondary AEP %s not defined in the APIC. Please create secondary AEP and try again." % secondary_aep_name)
                return False

            if config["user_config"]["chained_cni_config"]["skip_node_network_provisioning"]:
                return True

            aep_name = config["aci_config"]["aep"]
            aep = apic.get_aep(aep_name)
            if aep is None:
                err("AEP %s not defined in the APIC. Please create AEP and try again." % aep_name)
                return False

            if config["user_config"]["aci_config"].get("physical_domain", {}).get("domain", False):
                phydom_name = config["user_config"]["aci_config"]["physical_domain"]["domain"]
                phydom = apic.get_phys_dom(phydom_name)
                if phydom is None:
                    err("Physical domain %s not defined in the APIC. Please create and try again." % phydom_name)
                    return False

            if (config["user_config"]["aci_config"].get("vmm_domain", {}).get("domain", False)) and (
                    config["user_config"]["aci_config"].get("vmm_domain", {}).get("type", False)):
                vmm_name = config["user_config"]["aci_config"]["vmm_domain"]["domain"]
                vmm_type = config["user_config"]["aci_config"]["vmm_domain"]["type"]
                vmm = apic.get_vmm_dom(vmm_type, vmm_name)
                if vmm is None:
                    err("VMM domain %s not defined in the APIC. Please create and try again." % vmm_name)
                    return False

            vrf_tenant = config["aci_config"]["vrf"]["tenant"]
            vrf_name = config["aci_config"]["vrf"]["name"]
            vrf_dn = config["aci_config"]["vrf"]["dn"]
            l3out_name = config["aci_config"]["l3out"]["name"]
            vrf = apic.get_vrf(vrf_dn)
            if vrf is None:
                err("VRF %s/%s not defined in the APIC.Please create VRF and try again." %
                    (vrf_tenant, vrf_name))
                return False

            l3out = apic.get_l3out(vrf_tenant, l3out_name)
            if l3out:
                # get l3out context and check if it's the same as vrf in
                # input config
                result = apic.check_l3out_vrf(vrf_tenant, l3out_name, vrf_name, vrf_dn)
                if not result:
                    info("L3out and Kubernetes EPGs are configured in different VRFs")
    except Exception as e:
        warn("Unable to validate resources on APIC: {}".format(e))
    return True


def config_validate_preexisting(config, prov_apic):
    try:
        if isOverlay(config["flavor"]):
            return True

        if prov_apic is not None and not is_chained_mode(config):
            apic = get_apic(config)
            if apic is None:
                return False

            aep_name = config["aci_config"]["aep"]
            aep = apic.get_aep(aep_name)
            if aep is None:
                warn("AEP not defined in the APIC: %s" % aep_name)

            vrf_tenant = config["aci_config"]["vrf"]["tenant"]
            vrf_name = config["aci_config"]["vrf"]["name"]
            vrf_dn = config["aci_config"]["vrf"]["dn"]
            l3out_name = config["aci_config"]["l3out"]["name"]
            vrf = apic.get_vrf(vrf_dn)
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
                result = apic.check_l3out_vrf(vrf_tenant, l3out_name, vrf_name, vrf_dn)
                if not result:
                    info("L3out and Kubernetes EPGs are configured in different VRFs")

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


def calico_config_validate_preexisting(config, prov_apic):
    try:
        apic = None
        if prov_apic is not None:
            apic = get_apic(config)
            if apic is None:
                return False
            for rack in config["topology"]["rack"]:
                for leaf in rack["leaf"]:
                    if "local_ip" not in leaf:
                        err("Please provide only anchor leaf nodes in the input file. Non-anchor leaf node provided is %s" % leaf["id"])
                        return False
            aep_name = config["aci_config"]["cluster_l3out"]["aep"]
            vrf_tenant = config["aci_config"]["vrf"]["tenant"]
            vrf_name = config["aci_config"]["vrf"]["name"]
            vrf_dn = config["aci_config"]["vrf"]["dn"]
            l3out_name = config["aci_config"]["l3out"]["name"]
            aep = apic.get_aep(aep_name)
            if aep is None:
                err("AEP %s not created on the APIC. Please create the AEP and try again" % aep_name)
                return False
            check_local_asn = apic.get_local_asn()
            aci_as_number = config["aci_config"]["cluster_l3out"]["bgp"]["peering"]["aci_as_number"]
            if str(aci_as_number) != check_local_asn:
                err("aci_as_number %s provided in the input file does not match the BGP route reflector asn %s on the APIC. "
                    "This check is only made if -a option is used. Please ensure the flavor manifests that are generated from"
                    "this step with -a are used instead of previous ones you may have had." % (aci_as_number, check_local_asn))
                return False
            tenant = apic.get_tenant(vrf_tenant)
            if tenant is None:
                err("Tenant %s not created on the APIC. Please create the tenant and try again" % vrf_tenant)
                return False
            vrf = apic.get_vrf(vrf_dn)
            if vrf is None:
                err("VRF %s/%s not created on the APIC. Please create the vrf and try again" % (vrf_tenant, vrf_name))
                return False
            l3out = apic.get_l3out(vrf_tenant, l3out_name)
            if l3out is None:
                err("External l3Out %s/%s not created on the APIC. Please create the external l3out and try again " % (vrf_tenant, l3out_name))
                return False
            map_l3out_vrf = apic.check_l3out_vrf(vrf_tenant, l3out_name, vrf_name, vrf_dn)
            if not map_l3out_vrf:
                err("VRF is not mapped to L3out %s/%s on the APIC. Please fix the configuration and try again" % (vrf_tenant, l3out_name))
                return False
            else:
                check_ext_l3out_epg = apic.check_ext_l3out_epg(vrf_tenant, l3out_name)
                if check_ext_l3out_epg is None:
                    err("External l3out %s/%s does not have an external EPG configured on the APIC. Please fix the configuration and try again" %
                        (vrf_tenant, l3out_name))
                    return False
    except Exception as e:
        warn("Unable to validate resources on APIC: {}".format(e))
    return True


def generate_sample(filep, flavor):
    if flavor in ["cloud", "eks"]:
        data = pkgutil.get_data('acc_provision', 'templates/overlay-provision-config.yaml')
    elif flavor == "aks":
        data = pkgutil.get_data('acc_provision', 'templates/aks-provision-config.yaml')
    elif flavor == "calico-3.23.2":
        data = pkgutil.get_data('acc_provision', 'templates/calico-provision-config.yaml')
    elif flavor == "openshift-sdn-ovn-baremetal":
        data = pkgutil.get_data('acc_provision', 'templates/chained-mode-provision-config.yaml')
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
        info("  Private key file: \"%s\"" % key_file)
        info("  Certificate file: \"%s\"" % cert_file)
        with open(cert_file, "rb") as certp:
            cert_data = certp.read()
        with open(key_file, "rb") as keyp:
            key_data = keyp.read()
    return key_data, cert_data, reused


def is_ipv4_address(addr):
    try:
        ipaddress.IPv4Network(addr)
        return True
    except ValueError:
        return False


def is_ipv6_address(addr):
    try:
        ipaddress.IPv6Network(addr)
        return True
    except ValueError:
        return False


def regex_match_filter(string, pattern):
    if string is Undefined:
        return string
    return re.match(pattern, string) is not None


def enumerate_filter(iterable):
    if iterable is Undefined:
        return iterable
    return enumerate(iterable)


def get_jinja_template(file):
    env = Environment(
        loader=PackageLoader('acc_provision', 'templates'),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True
    )
    env.filters['base64enc'] = lambda s: base64.b64encode(s).decode("ascii")
    env.filters['json'] = json_indent
    env.filters['yaml'] = yaml_indent
    env.filters['yaml_quote'] = yaml_quote
    env.filters['list_unicode_strings'] = list_unicode_strings
    env.filters['regex_match'] = regex_match_filter
    env.filters['enumerate'] = enumerate_filter
    env.globals['is_ipv6'] = is_ipv6_address
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
    if (config['multus']['disable'] is True) and (gen_inst_files or gen_cnet_file):
        cnetfile_name = 'cluster-network-03-config.yaml'
        extra_files.append(cnetfile_name)

    if gen_inst_files:
        masterfile_name = '99-master-kubelet-node-ip.yaml'
        workerfile_name = '99-worker-kubelet-node-port.yaml'
        extra_files.append(masterfile_name)
        extra_files.append(workerfile_name)

    if config["flavor"] == "openshift-4.6-esx":
        workerfile_name = '99-worker-kubelet-node-ip.yaml'
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


def generate_rancher_yaml(config, operator_output, operator_tar, operator_cr_output):
    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-network-provider-cluster.yaml')
        outname = operator_output
        # At this time, we do not use the aci-containers-operator with Rancher.
        # The template to generate ACI CNI components is upstream in RKE code
        # Here we generate the input file to feed into RKE, which looks almost
        # the same as the acc-provision_input file

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file.
        if operator_output == "-":
            outname = "<stdout>"
            operator_output = sys.stdout
        info("Writing Rancher network provider portion of cluster.yml to %s" % outname)
        info("Use this network provider section in the cluster.yml you use with RKE")
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(template.render(config=config))
        else:
            template.stream(config=config).dump(operator_output)


def generate_rancher_1_3_13_yaml(config, operator_output, operator_tar, operator_cr_output):
    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-network-provider-cluster-1-3-13.yaml')
        outname = operator_output
        # At this time, we do not use the aci-containers-operator with Rancher.
        # The template to generate ACI CNI components is upstream in RKE code
        # Here we generate the input file to feed into RKE, which looks almost
        # the same as the acc-provision_input file

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file.
        if operator_output == "-":
            outname = "<stdout>"
            operator_output = sys.stdout
        info("Writing Rancher network provider portion of cluster.yml to %s" % outname)
        info("Use this network provider section in the cluster.yml you use with RKE")
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(template.render(config=config))
        else:
            template.stream(config=config).dump(operator_output)


def generate_rancher_1_3_17_yaml(config, operator_output, operator_tar, operator_cr_output):
    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-network-provider-cluster-1-3-17.yaml')
        outname = operator_output
        # At this time, we do not use the aci-containers-operator with Rancher.
        # The template to generate ACI CNI components is upstream in RKE code
        # Here we generate the input file to feed into RKE, which looks almost
        # the same as the acc-provision_input file

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file.
        if operator_output == "-":
            outname = "<stdout>"
            operator_output = sys.stdout
        info("Writing Rancher network provider portion of cluster.yml to %s" % outname)
        info("Use this network provider section in the cluster.yml you use with RKE")
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(template.render(config=config))
        else:
            template.stream(config=config).dump(operator_output)


def generate_rancher_1_3_18_yaml(config, operator_output, operator_tar, operator_cr_output):
    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-network-provider-cluster-1-3-18.yaml')
        outname = operator_output
        # At this time, we do not use the aci-containers-operator with Rancher.
        # The template to generate ACI CNI components is upstream in RKE code
        # Here we generate the input file to feed into RKE, which looks almost
        # the same as the acc-provision_input file

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file.
        if operator_output == "-":
            outname = "<stdout>"
            operator_output = sys.stdout
        info("Writing Rancher network provider portion of cluster.yml to %s" % outname)
        info("Use this network provider section in the cluster.yml you use with RKE")
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(template.render(config=config))
        else:
            template.stream(config=config).dump(operator_output)


def generate_rancher_1_3_20_yaml(config, operator_output, operator_tar, operator_cr_output):
    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-network-provider-cluster-1-3-20.yaml')
        outname = operator_output
        # At this time, we do not use the aci-containers-operator with Rancher.
        # The template to generate ACI CNI components is upstream in RKE code
        # Here we generate the input file to feed into RKE, which looks almost
        # the same as the acc-provision_input file

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file.
        if operator_output == "-":
            outname = "<stdout>"
            operator_output = sys.stdout
        info("Writing Rancher network provider portion of cluster.yml to %s" % outname)
        info("Use this network provider section in the cluster.yml you use with RKE")
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(template.render(config=config))
        else:
            template.stream(config=config).dump(operator_output)


def generate_rancher_1_4_6_yaml(config, operator_output, operator_tar, operator_cr_output):
    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-network-provider-cluster-1-4-6.yaml')
        outname = operator_output
        # At this time, we do not use the aci-containers-operator with Rancher.
        # The template to generate ACI CNI components is upstream in RKE code
        # Here we generate the input file to feed into RKE, which looks almost
        # the same as the acc-provision_input file

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file.
        if operator_output == "-":
            outname = "<stdout>"
            operator_output = sys.stdout
        info("Writing Rancher network provider portion of cluster.yml to %s" % outname)
        info("Use this network provider section in the cluster.yml you use with RKE")
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(template.render(config=config))
        else:
            template.stream(config=config).dump(operator_output)


def generate_rancher_1_3_21_yaml(config, operator_output, operator_tar, operator_cr_output):
    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-network-provider-cluster-1-3-21.yaml')
        outname = operator_output
        # At this time, we do not use the aci-containers-operator with Rancher.
        # The template to generate ACI CNI components is upstream in RKE code
        # Here we generate the input file to feed into RKE, which looks almost
        # the same as the acc-provision_input file

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file.
        if operator_output == "-":
            outname = "<stdout>"
            operator_output = sys.stdout
        info("Writing Rancher network provider portion of cluster.yml to %s" % outname)
        info("Use this network provider section in the cluster.yml you use with RKE")
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(template.render(config=config))
        else:
            template.stream(config=config).dump(operator_output)


def generate_rancher_1_4_9_yaml(config, operator_output, operator_tar, operator_cr_output):
    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-network-provider-cluster-1-4-9.yaml')
        outname = operator_output
        # At this time, we do not use the aci-containers-operator with Rancher.
        # The template to generate ACI CNI components is upstream in RKE code
        # Here we generate the input file to feed into RKE, which looks almost
        # the same as the acc-provision_input file

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file.
        if operator_output == "-":
            outname = "<stdout>"
            operator_output = sys.stdout
        info("Writing Rancher network provider portion of cluster.yml to %s" % outname)
        info("Use this network provider section in the cluster.yml you use with RKE")
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(template.render(config=config))
        else:
            template.stream(config=config).dump(operator_output)


def generate_rancher_1_3_24_yaml(config, operator_output, operator_tar, operator_cr_output):
    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-network-provider-cluster-1-3-24.yaml')
        outname = operator_output
        # At this time, we do not use the aci-containers-operator with Rancher.
        # The template to generate ACI CNI components is upstream in RKE code
        # Here we generate the input file to feed into RKE, which looks almost
        # the same as the acc-provision_input file

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file.
        if operator_output == "-":
            outname = "<stdout>"
            operator_output = sys.stdout
        info("Writing Rancher network provider portion of cluster.yml to %s" % outname)
        info("Use this network provider section in the cluster.yml you use with RKE")
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(template.render(config=config))
        else:
            template.stream(config=config).dump(operator_output)


def generate_rancher_1_4_13_yaml(config, operator_output, operator_tar, operator_cr_output):
    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-network-provider-cluster-1-4-13.yaml')
        outname = operator_output
        # At this time, we do not use the aci-containers-operator with Rancher.
        # The template to generate ACI CNI components is upstream in RKE code
        # Here we generate the input file to feed into RKE, which looks almost
        # the same as the acc-provision_input file

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file.
        if operator_output == "-":
            outname = "<stdout>"
            operator_output = sys.stdout
        info("Writing Rancher network provider portion of cluster.yml to %s" % outname)
        info("Use this network provider section in the cluster.yml you use with RKE")
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(template.render(config=config))
        else:
            template.stream(config=config).dump(operator_output)


def generate_rancher_1_5_3_yaml(config, operator_output, operator_tar, operator_cr_output):
    if operator_output and operator_output != "/dev/null":
        template = get_jinja_template('aci-network-provider-cluster-1-5-3.yaml')
        outname = operator_output
        # At this time, we do not use the aci-containers-operator with Rancher.
        # The template to generate ACI CNI components is upstream in RKE code
        # Here we generate the input file to feed into RKE, which looks almost
        # the same as the acc-provision_input file

        # If no output containers(-o) deployment file is provided, print to stdout.
        # Else, save to file.
        if operator_output == "-":
            outname = "<stdout>"
            operator_output = sys.stdout
        info("Writing Rancher network provider portion of cluster.yml to %s" % outname)
        info("Use this network provider section in the cluster.yml you use with RKE")
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(template.render(config=config))
        else:
            template.stream(config=config).dump(operator_output)


def is_calico_flavor(flavor):
    return SafeDict(FLAVORS[flavor]).get("calico_cni")


def is_chained_mode(config):
    return True if config.get("chained_cni_config") and (
        config["chained_cni_config"].get("secondary_interface_chaining") or config[
            "chained_cni_config"].get("primary_interface_chaining")) else False


def generate_calico_deployment_files(config, network_operator_output):
    config['net_config']['node_subnet'] = config['net_config']['node_subnet'][0]
    config['net_config']['pod_subnet'] = config['net_config']['pod_subnet'][0]
    config['net_config']['extern_dynamic'] = config['net_config']['extern_dynamic'][0]

    filenames = ["tigera_operator.yaml", "custom_resources_aci_calico.yaml", "custom_resources_calicoctl.yaml"]
    if network_operator_output and network_operator_output != "/dev/null":
        calico_crds_template = get_jinja_template('tigera-operator.yaml')
        calico_crds_output = calico_crds_template.render(config=config)
        calico_crs_template = get_jinja_template('custom-resources-aci-calico.yaml')
        calico_crs_output = calico_crs_template.render(config=config)
        calicoctl_template = get_jinja_template('calicoctl.yaml')
        calicoctl_output = calicoctl_template.render(config=config)

        bgp_peer = ''
        bgp_node = ''
        calico_bgp_peer_template = get_jinja_template('calico-bgp-peer.yaml')
        calico_node_template = get_jinja_template('calico-node.yaml')
        for item in config["topology"]["rack"]:
            for node_name in item["node"]:
                configTemp = dict()
                configTemp["node_name"] = node_name["name"]
                configTemp["id"] = item["id"]
                bgp_node = bgp_node + "\n---\n" + calico_node_template.render(config=configTemp)
            for leaf in item["leaf"]:
                if "local_ip" in leaf:
                    configTemp = dict(config)
                    configTemp["local_ip"] = leaf["local_ip"]
                    configTemp["peer_name"] = leaf["local_ip"].replace(".", "-")
                    configTemp["id"] = item["id"]
                    bgp_peer = bgp_peer + "\n---\n" + calico_bgp_peer_template.render(config=configTemp)

        calico_bgp_config_template = get_jinja_template('calico-bgp-config.yaml')
        calico_bgp_config_output = calico_bgp_config_template.render(config=config)

        tigera_operator_yaml = calico_crds_output
        custom_resources_aci_calico_yaml = calico_crs_output + "\n---\n" + calicoctl_output + bgp_node
        custom_resources_calicoctl_yaml = calico_bgp_config_output + bgp_peer
        acc_provision_yaml = get_jinja_template('acc-provision-configmap.yaml').render(config=config)
        custom_resources_aci_calico_yaml += "\n---\n" + acc_provision_yaml
        with open("custom_resources_aci_calico.yaml", "w") as fh:
            fh.write(custom_resources_aci_calico_yaml)
        with open("custom_resources_calicoctl.yaml", "w") as fh:
            fh.write(custom_resources_calicoctl_yaml)
        with open("tigera_operator.yaml", "w") as fh:
            fh.write(tigera_operator_yaml)

        if "tar.gz" not in network_operator_output:
            err("Please provide the ouput file name in tar.gz format")
            return False
        with tarfile.open(network_operator_output, mode='w:gz') as tar:
            for name in filenames:
                tar.add(name, arcname=os.path.basename(name))
                os.remove(name)
            tar.close()

        print("Generated the deployment tar file")


def gendpu(config, dpu_output_file):
    template = get_jinja_template('dpu-containers.yaml')
    outname = dpu_output_file
    info("Writing DPU kubernetes configuration to  %s" % outname)
    with open(dpu_output_file, "w") as fh:
        fh.write(template.render(config=config))


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

        chained_mode_yaml_output = {}
        if is_chained_mode(config):
            file_path = config["chained_cni_config"].get("vlans_file")
            if file_path:
                all_resources = prepare_nadvlanmap(file_path)
                if all_resources:
                    chained_mode_yaml_output["nadvlan_map"] = yaml.dump(
                        all_resources, default_flow_style=False)
                else:
                    print("File is empty or with invalid contents: ", file_path)
                    config["chained_cni_config"]["vlans_file"] = ''
            chained_mode_yaml_output["fabric_vlan_pool"] = (yaml.dump(
                config["chained_cni_config"]["secondary_vlans"],
                default_flow_style=False)).rstrip('\n')
        if chained_mode_yaml_output:
            temp = ''.join(template.stream(config=config,
                                           chained_mode_input=chained_mode_yaml_output))
        else:
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
        if config["flavor"] != "k8s-overlay":
            oper_cmap_template = get_jinja_template('aci-operators-configmap.yaml')
            cmap_temp = ''.join(oper_cmap_template.stream(config=config))

            op_template = get_jinja_template('aci-operators.yaml')
            output_from_parsed_template = op_template.render(config=config)

            # Generate acioperator CRD from template and add it to top
            op_crd_template = get_jinja_template('aci-operators-crd.yaml')
            op_crd_output = op_crd_template.render(config=config)

            acc_provision_crd_template = get_jinja_template('acc-provision-crd.yaml')
            acc_provision_crd_temp = ''.join(acc_provision_crd_template.stream(config=config))
            acc_provision_oper_cmap_template = get_jinja_template('acc-provision-configmap.yaml')
            acc_provision_oper_cmap_temp = ''.join(acc_provision_oper_cmap_template.stream(config=config))
            new_parsed_yaml = [op_crd_output] + parsed_temp[:cmap_idx] + [acc_provision_crd_temp] + [cmap_temp] + [acc_provision_oper_cmap_temp] + parsed_temp[cmap_idx:] + [output_from_parsed_template]

            new_deployment_file = '---'.join(new_parsed_yaml)
        else:
            new_deployment_file = temp

        # print(new_deployment_file)
        if operator_output != sys.stdout:
            with open(operator_output, "w") as fh:
                fh.write(new_deployment_file)
        else:
            op_template.stream(config=config).dump(operator_output)

        if config["flavor"] != "k8s-overlay":
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
        if config["flavor"] != "k8s-overlay":
            info("Writing ACI CNI operator tar to %s" % tar_path)
        info("Apply infrastructure YAML using:")
        info("  %s apply -f %s" %
             (config["kube_config"]["kubectl"], applyname))
        if not config["provision"]["upgrade_cluster"]:
            info("Delete stale objects from older deployments using:")
            info("  %s -n %s delete %s -l "
                 " 'aci-containers-config-version,"
                 "aci-containers-config-version notin (%s)'" %
                 (config["kube_config"]["kubectl"],
                  config["kube_config"]["system_namespace"],
                  ",".join(kube_objects),
                  str(config["registry"]["configuration_version"])))
    return config


def generate_apic_config(flavor_opts, config, prov_apic, apic_file):
    apic = None
    if prov_apic is not None:
        apic = get_apic(config)
    configurator = ApicKubeConfig(config, apic)
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
                cluster_l3out_vrf_details = configurator.get_cluster_l3out_vrf_details()
                cluster_l3out_tenant = cluster_l3out_vrf_details["tenant"]
                vrf_tenant = config["aci_config"]["vrf"]["tenant"]
                cluster_tenant = config["aci_config"]["cluster_tenant"]
                old_naming = config["aci_config"]["use_legacy_kube_naming_convention"]
                pre_existing_tenant = config["aci_config"]["use_pre_existing_tenant"]
                if is_calico_flavor(config["flavor"]):
                    l3out_name = config["aci_config"]["cluster_l3out"]["name"]
                    apic.unprovision(apic_config, system_id, cluster_l3out_tenant, vrf_tenant, cluster_tenant, old_naming, config, pre_existing_tenant,
                                     l3out_name=l3out_name, cluster_l3out_vrf_details=cluster_l3out_vrf_details)
                else:
                    apic.unprovision(apic_config, system_id, cluster_l3out_tenant, vrf_tenant, cluster_tenant, old_naming, config, pre_existing_tenant)
            ret = False if apic.errors > 0 else True
    return ret


def get_apic(config):
    if config["aci_config"].get("apic_oobm_ip"):
        apic_host = config["aci_config"]["apic_oobm_ip"]
    else:
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
    parser.add_argument(
        '--upgrade', action='store_true', default=False,
        help='generate kubernetes deployment file for cluster upgrade')
    parser.add_argument(
        '--disable-multus', default='true', metavar='disable_multus',
        help='true/false to disable/enable multus in cluster')
    # This argument is set to True and used internally by the acc-provision-operator when invoking acc-provision. It is not meant to be invoked directly by the user from stand-alone acc-provision and hence set to False by default here and suppressed as well.
    parser.add_argument(
        '--operator-mode', default=False,
        help=argparse.SUPPRESS, metavar='operator_mode')
    parser.add_argument(
        '-s', '--dpu', default=None, metavar='file',
        help='output file for your dpu kubernetes deployment')
    parser.add_argument(
        '--apic-oobm-ip', default=None, metavar='ip',
        help='APIC out of band management IP for day0 configuration')
    parser.add_argument(
        '--skip-app-profile-check', action='store_true', default=False,
        help='skip app profiles presence check while tenant deletion')
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
    """Check if subnets are overlapping."""
    if is_calico_flavor(config["flavor"]):
        subnet_info = {
            "cluster_svc_subnet": config["net_config"]["cluster_svc_subnet"]
        }
    else:
        subnet_info = {
            "node_svc_subnet": config["net_config"]["node_svc_subnet"]
        }

    counter = 0

    if not isinstance(config["net_config"]["pod_subnet"], list):
        subnet_info[-1] = config["net_config"]["pod_subnet"]
    else:
        pod_subnets = []
        for pod_subnet in config["net_config"]["pod_subnet"]:
            pod_subnets.append(pod_subnet)
        for pod_subnet in pod_subnets:
            subnet_info[counter] = pod_subnet
            counter += 1

    if not isinstance(config["net_config"]["node_subnet"], list):
        subnet_info[-1] = config["net_config"]["node_subnet"]
    else:
        node_subnets = []
        for node_subnet in config["net_config"]["node_subnet"]:
            node_subnets.append(node_subnet)
        # counter = 0
        for node_subnet in node_subnets:
            subnet_info[counter] = node_subnet
            counter += 1

    if not isinstance(config["net_config"]["extern_dynamic"], list):
        subnet_info[-1] = config["net_config"]["extern_dynamic"]
    else:
        extern_dynamics = []
        for extern_dynamic in config["net_config"]["extern_dynamic"]:
            extern_dynamics.append(extern_dynamic)
        # counter = 0
        for extern_dynamic in extern_dynamics:
            subnet_info[counter] = extern_dynamic
            counter += 1

    # Don't have extern_static field set for OpenShift flavors
    if not is_calico_flavor(config["flavor"]) and config["net_config"]["extern_static"]:
        if not isinstance(config["net_config"]["extern_static"], list):
            subnet_info[-1] = config["net_config"]["extern_static"]
        else:
            extern_statics = []
            for subnet in config["net_config"]["extern_static"]:
                extern_statics.append(subnet)
            # counter = 0
            for subnet in extern_statics:
                subnet_info[counter] = subnet
                counter += 1

    for sub1, sub2 in combinations(subnet_info.values(), r=2):
        # Checking if sub1 and sub2 are IPv4 or IPv6
        rtr1, _ = sub1.split("/")
        ip1 = ipaddress.ip_address(rtr1)
        rtr2, _ = sub2.split("/")
        ip2 = ipaddress.ip_address(rtr2)
        if ip1.version == 4 and ip2.version == 4:
            net1, net2 = ipaddress.IPv4Network(sub1, strict=False), ipaddress.IPv4Network(sub2, strict=False)
        elif ip1.version == 6 and ip2.version == 6:
            net1, net2 = ipaddress.IPv6Network(sub1, strict=False), ipaddress.IPv6Network(sub2, strict=False)
        else:
            continue
        out = net1.overlaps(net2)
        if out:
            return False
    return True


def check_image_pull_secret(config):
    # Check if the image_pull_secret is valid
    image_pull_secret = config["registry"]["image_pull_secret"]
    # This is the regex used by kubectl to validate objects names
    pattern = "[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*"
    if not re.fullmatch(pattern, str(image_pull_secret)):
        return False
    return True


def has_multi_subnet(config):
    subnet_types = ["pod_subnet", "node_subnet", "extern_dynamic"]
    for subnet_type in subnet_types:
        if isinstance(config["net_config"][subnet_type], list):
            return False
    return True


def is_support_dualstack(flavor):
    version = flavor.split("-")[1]
    support_k8s_version = "1.21"
    support_openshift_version = "4.8"
    if version >= support_k8s_version:
        return True

    if version >= support_openshift_version:
        return True

    return False


def process_subnet_value(subnet_value, subnet_info):
    if not isinstance(subnet_value, list):
        subnet_info.append(subnet_value)
    else:
        for subnet in subnet_value:
            subnet_info.append(subnet)


def get_subnet_list(config):
    subnet_info = []
    if "net_config" not in config:
        return subnet_info

    net_config = config["net_config"]
    if not is_chained_mode(config):
        process_subnet_value(net_config.get("pod_subnet", []), subnet_info)
        process_subnet_value(net_config.get("extern_dynamic", []), subnet_info)
        process_subnet_value(net_config.get("extern_static", []), subnet_info)
    process_subnet_value(net_config.get("node_subnet", []), subnet_info)

    return subnet_info


def is_dualstack_config(config):
    subnet_info = get_subnet_list(config)
    subnet_type = determine_subnet_type(subnet_info)
    if subnet_type == "DualStack":
        return True
    return False


def determine_subnet_type(subnet_info):
    if len(subnet_info) == 0:
        return ""

    has_ipv4 = False
    has_ipv6 = False

    for subnet in subnet_info:
        rtr, _ = subnet.split("/")
        try:
            ip = ipaddress.ip_address(rtr)
        except Exception as e:
            err("%s is malformed. %s" % (subnet, str(e)))
            sys.exit(1)
        if ip.version == 4:
            has_ipv4 = True
        elif ip.version == 6:
            has_ipv6 = True

    if has_ipv4 and has_ipv6:
        return "DualStack"
    elif has_ipv4:
        return "IPv4"
    elif has_ipv6:
        return "IPv6"
    else:
        return ""


def get_subnet_types(config):
    if "net_config" not in config:
        return False

    net_config = config["net_config"]

    pod_subnet, node_subnet, extern_static, extern_dynamic = [], [], [], []
    process_subnet_value(net_config.get("pod_subnet", []), pod_subnet)
    process_subnet_value(net_config.get("node_subnet", []), node_subnet)
    process_subnet_value(net_config.get("extern_static", []), extern_static)
    process_subnet_value(net_config.get("extern_dynamic", []), extern_dynamic)

    return determine_subnet_type(pod_subnet), determine_subnet_type(node_subnet), determine_subnet_type(extern_static), determine_subnet_type(extern_dynamic)


def is_valid_dualstack_config(config):
    if "net_config" not in config:
        return False, ""

    pod_subnet_type, node_subnet_type, extern_static_type, extern_dynamic_type = get_subnet_types(config)

    if node_subnet_type != "DualStack":
        return False, "Node Subnet " + " ".join(config['net_config']['node_subnet']) + " does not have IPv6"
    if node_subnet_type != "DualStack" and pod_subnet_type == "DualStack":
        return False, "Pod Subnet " + " ".join(config['net_config']['pod_subnet']) + " has IPv6 but Node Subnet " + " ".join(config['net_config']['node_subnet']) + " does not have IPv6"

    if extern_static_type == "DualStack" or extern_dynamic_type == "DualStack":
        if pod_subnet_type == "DualStack" and node_subnet_type == "DualStack":
            return True, ""
        return False, "If extern_static " + " ".join(config['net_config']['extern_static']) + " or extern_dynamic " + " ".join(config['net_config']['extern_dynamic']) + " configured with IPv6, then pod_subnet " + " ".join(config['net_config']['pod_subnet']) + " and node_subnet " + " ".join(config['net_config']['node_subnet']) + " must have IPv6."

    return True, ""


def provision(args, apic_file, no_random):
    config_file = args.config
    output_file = args.output
    output_tar = args.output_tar
    operator_cr_output_file = args.aci_operator_cr
    upgrade_cluster = args.upgrade

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

    if args.operator_mode:
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
        "unprovision": {
            "skip_app_profile_check": args.skip_app_profile_check,
        },
        "operator_mode": args.operator_mode,
    }

    if args.apic_oobm_ip:
        config['aci_config']['apic_oobm_ip'] = args.apic_oobm_ip

    if upgrade_cluster:
        output_tar = "/dev/null"
        config["provision"]["upgrade_cluster"] = True

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
    user_config = config_user(flavor, config_file)
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

    config['user_config'] = copy.deepcopy(user_config)
    deep_merge(config, user_config)

    if is_chained_mode(config):
        if flavor != 'openshift-sdn-ovn-baremetal':
            err("Chained mode is not supported with flavor " + flavor)
            return False

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

    # Verify for Dualstack
    if is_dualstack_config(config) and not is_support_dualstack(flavor):
        err(" Dualstack feature is not supported. Please upgrade to Kubernetes version 1.21 or later or OpenShift version 4.8 or later.")
        return False

    if is_dualstack_config(config):
        valid, message = is_valid_dualstack_config(config)
        if not valid:
            err("Please provide a valid Dualstack configuration with both IPv4 and IPv6 addresses for node and pod subnets.")
            err(message)
            return False

    if is_calico_flavor(config["flavor"]) and has_multi_subnet(config):
        err(" Multisubnet feature is not supported in calico.")
        return False

    get = lambda t: functools.reduce(lambda x, y: x and x.get(y), t, config)
    if is_chained_mode(config):
        if get(("aci_config", "vmm_domain", "mcast_range", "start")):
            warn(("mcast_range option is not used in %s flavor with chained mode" % config["flavor"]))
        if get(("aci_config", "vmm_domain", "encap_type")):
            warn(("encap_type option is not used in %s flavor with chained mode" % config["flavor"]))
        if get(("aci_config", "vmm_domain", "nested_inside", "installer_provisioned_lb_ip")):
            warn(("nested_inside option is not used in %s flavor with chained mode" % config["flavor"]))

    deep_merge(config, config_default())

    if is_chained_mode(config):
        # TODO: Currently setting primary_cni_path for chained mode with openshift-sdn-ovn-baremetal flavor.
        # For other flavors needs to be derived from flavor.
        if flavor == "openshift-sdn-ovn-baremetal":
            config["chained_cni_config"][
                "primary_cni_path"] = "/mnt/cni-conf/cni/net.d/10-ovn-kubernetes.conf"
        if not user_config.get("aci_config", {}).get("vmm_domain"):
            config["aci_config"]["vmm_domain"] = None

    if (args.disable_multus == 'false' or is_chained_mode(config)):
        config['multus']['disable'] = False

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
    if not is_chained_mode(config) and not check_overlapping_subnets(config):
        err("overlapping subnets found in configuration input file")
        return False

    # Verify that image_pull_secret is a valid K8s secret name and not a YAML string
    if "registry" in config.keys() and "image_pull_secret" in config["registry"]:
        if not check_image_pull_secret(config):
            err("Invalid image_pull_secret value, it must be a valid DNS subdomain name.")
            return False

    # Adjust config based on convention/apic data
    if is_chained_mode(config):
        adj_config = config_adjust_chained_mode(args, config, no_random)
        config["chained_cni_config"]["secondary_vlans"] = prepare_secondary_vlans(config)
        normalized_vlans = normalize_vlans(config["chained_cni_config"]["secondary_vlans"])
        config["chained_cni_config"]["secondary_vlans"] = group_in_ranges(normalized_vlans)
    else:
        adj_config = config_adjust(args, config, prov_apic, no_random)
    deep_merge(config, adj_config)

    if is_calico_flavor(config["flavor"]) and not calico_config_validate_preexisting(config, prov_apic):
        return False
    elif is_chained_mode(config) and not chained_config_validate_preexisting(config, prov_apic):
        return False
    else:
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
        if not exists(certfile) or not exists(keyfile):
            if is_calico_flavor(config["flavor"]):
                info("Generating certs for calico based kubernetes controller")
            else:
                info("Generating certs for kubernetes controller")
        else:
            if is_calico_flavor(config["flavor"]):
                info("Reusing existing certs for network-operator")
            else:
                info("Reusing existing certs for calico based kubernetes controller")
        key_data, cert_data, reused = generate_cert(username, certfile, keyfile)
    config["aci_config"]["sync_login"]["key_data"] = key_data
    config["aci_config"]["sync_login"]["cert_data"] = cert_data
    config["aci_config"]["sync_login"]["cert_reused"] = reused

    if is_calico_flavor(config["flavor"]):
        print("Using flavor: ", config["flavor"])
        gen = flavor_opts.get("template_generator", generate_calico_deployment_files)
        if not callable(gen):
            gen = globals()[gen]
        gen(config, output_tar)

        ret = generate_apic_config(flavor_opts, config, prov_apic, apic_file)
        return ret

    if config["registry"]["aci_cni_operator_version"] is not None:
        config["registry"]["aci_containers_operator_version"] = config["registry"]["aci_cni_operator_version"]
        config["registry"]["acc_provision_operator_version"] = config["registry"]["aci_cni_operator_version"]

    if flavor in ["cloud", "aks", "eks"]:
        if prov_apic is None:
            return True
        print("Configuring cAPIC")
        config["aci_config"]["capic"] = True

        apic = get_apic(config)
        if apic is None:
            print("APIC login failed")
            return False
        cloud_prov = CloudProvision(apic, config, args)
        return cloud_prov.Run(flavor_opts, generate_kube_yaml)

    # generate output files; and program apic if needed
    gen = flavor_opts.get("template_generator", generate_kube_yaml)

    if args.dpu:
        if config["dpu_config"].get("enable"):
            dpu_output_file = args.dpu
            gendpu(config, dpu_output_file)
        else:
            err("Cannot generate DPU kubernetes Yaml file: dpu_config not enabled in acc_provision input file")

    if not callable(gen):

        gen = globals()[gen]
    gen(config, output_file, output_tar, operator_cr_output_file)

    if flavor == "k8s-overlay":
        return True

    if (config['aci_config']['vmm_domain'] and config['net_config']['second_kubeapi_portgroup'] and prov_apic is not None):
        apic = get_apic(config)
        nested_vswitch_vlanpool = apic.get_vmmdom_vlanpool_tDn(config['aci_config']['vmm_domain']['nested_inside']['name'])
        config['aci_config']['vmm_domain']['nested_inside']['vlan_pool'] = nested_vswitch_vlanpool

    if is_chained_mode(config) and config["user_config"]["chained_cni_config"].get("secondary_vlans"):
        config["chained_cni_config"]["secondary_vlans"] = normalized_vlans
    ret = generate_apic_config(flavor_opts, config, prov_apic, apic_file)
    return ret


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

    if args.disable_multus is not None and (args.disable_multus != 'true' and args.disable_multus != 'false'):
        err("Invalid configuration for disable_multus:" + args.disable_multus + " <Valid values: true/false>")
        sys.exit(1)

    if args.apic_oobm_ip and is_valid_ip(args.apic_oobm_ip) is False:
        err("Invalid apic-oobm-ip address: " + args.apic_oobm_ip)
        sys.exit(1)

    if args.skip_app_profile_check and not args.delete:
        err("Invalid configuration for skip_app_profile_check: To be used with the -d option.")
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
