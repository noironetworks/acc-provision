"""check if overlapping subnets are present in acc provision config file."""
import ipaddr
import os
import yaml

from itertools import combinations


def load_provision_config(config_file):
    """load acc provision config file."""
    if os.path.isfile(config_file):
        with open(config_file, 'r') as stream:
            try:
                return yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                msg = "Unable to load acc provision yaml. Reason: %s" % exc
                raise(Exception(msg))
    else:
        raise(Exception("%s file not found" % config_file))


def get_subnets(acc_provison_config_info):
    """get subnets info from acc provison config file."""
    ndict = {}  # dictionary to store subnets
    try:
        netc = acc_provison_config_info['net_config']
        ndict['pod_subnet'] = netc['pod_subnet']
        ndict['extern_static'] = netc['extern_static']
        ndict['node_subnet'] = netc['node_subnet']
        ndict['extern_dynamic'] = netc['extern_dynamic']
        ndict['node_svc_subnet'] = netc['node_svc_subnet']
    except KeyError:
        msg = ("Invalid acc provision config file provided")
        raise(Exception(msg))
    return ndict


def check_overlaping_subnets(provision_config_file_path):
    """check if subnets are overlapping."""
    acc_provison_config_info = load_provision_config(
        provision_config_file_path)
    subnet_info = get_subnets(acc_provison_config_info)
    for sub1, sub2 in combinations(subnet_info.values(), r=2):
        net1, net2 = ipaddr.IPNetwork(sub1), ipaddr.IPNetwork(sub2)
        out = net1.overlaps(net2)
        if out:
            raise(Exception("Overlapping subnet found"))
