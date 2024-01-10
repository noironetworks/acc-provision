from __future__ import print_function, unicode_literals

import ast
import collections
import filecmp
import functools
import os
import shutil
import ssl
import sys
import tempfile
import tarfile
import json

import base64
import copy

from . import acc_provision
from . import fake_apic

from ruamel.yaml import YAML
yml = YAML()
yml.allow_duplicate_keys = True
yml.width = 1000
yml.preserve_quotes = True

debug = False


def in_testdir(f):
    @functools.wraps(f)
    def wrapper(*args, **kwds):
        os.chdir("testdata")
        try:
            ret = f(*args, **kwds)
        except Exception:
            raise
        finally:
            os.chdir("..")
        return ret
    return wrapper


@in_testdir
def test_base_case_simple():
    run_provision(
        "base_case.inp.yaml",
        "base_case.kube.yaml",
        "base_case_tar",
        "base_case_operator_cr.kube.yaml",
        "base_case.apic.txt"
    )


@in_testdir
def test_base_case_apic_5_2_3():
    run_provision(
        "base_case_apic_5_2_3.inp.yaml",
        None,
        None,
        None,
        "base_case_apic_5_2_3.apic.txt"
    )


@in_testdir
def test_base_case_operator_mode():
    run_provision(
        "base_case.inp.yaml",
        "base_case_operator_mode.kube.yaml",
        None,
        None,
        None,
        overrides={"operator_mode": True}
    )


@in_testdir
def test_base_case_upgrade():
    run_provision(
        "base_case.inp.yaml",
        "base_case_upgrade.kube.yaml",
        None,
        None,
        None,
        overrides={"upgrade": True}
    )


@in_testdir
def test_base_case_snat():
    run_provision(
        "base_case_snat.inp.yaml",
        "base_case_snat.kube.yaml",
        None,
        None,
        "base_case.apic.txt"
    )


@in_testdir
def test_versions_base_case():
    run_provision(
        "version_wrong_url.inp.yaml",
        "base_case.kube.yaml",
        None,
        None,
        "base_case.apic.txt"
    )


@in_testdir
def test_base_case_ipv6():
    run_provision(
        "base_case_ipv6.inp.yaml",
        "base_case_ipv6.kube.yaml",
        None,
        None,
        "base_case_ipv6.apic.txt"
    )


@in_testdir
def test_vlan_case():
    run_provision(
        "vlan_case.inp.yaml",
        "vlan_case.kube.yaml",
        None,
        None,
        "vlan_case.apic.txt"
    )


@in_testdir
def test_nested_vlan():
    run_provision(
        "nested-vlan.inp.yaml",
        "nested-vlan.kube.yaml",
        None,
        None,
        "nested-vlan.apic.txt"
    )


@in_testdir
def test_nested_vxlan():
    run_provision(
        "nested-vxlan.inp.yaml",
        "nested-vxlan.kube.yaml",
        None,
        None,
        "nested-vxlan.apic.txt"
    )


@in_testdir
def test_nested_portgroup():
    run_provision(
        "nested-portgroup.inp.yaml",
        "nested-portgroup.kube.yaml",
        None,
        None,
        "nested-portgroup.apic.txt"
    )


@in_testdir
def test_nested_elag():
    run_provision(
        "nested-elag.inp.yaml",
        "nested-elag.kube.yaml",
        None,
        None,
        "nested-elag.apic.txt"
    )


@in_testdir
def test_with_comments():
    run_provision(
        "with_comments.inp.yaml",
        "with_comments.kube.yaml",
        None,
        None,
        "with_comments.apic.txt"
    )


@in_testdir
def test_with_overrides():
    run_provision(
        "with_overrides.inp.yaml",
        "with_overrides.kube.yaml",
        None,
        None,
        "with_overrides.apic.txt",
    )


@in_testdir
def test_with_wait_for_timer():
    run_provision(
        "with_wait_for_network.inp.yaml",
        "with_wait_for_network.kube.yaml",
        None,
        None,
        "with_wait_for_network.apic.txt",
    )


@in_testdir
def test_multiple_subnets():
    run_provision(
        "multiple_subnets.inp.yaml",
        "multiple_subnets.kube.yaml",
        None,
        None,
        "multiple_subnets.apic.txt",
    )


@in_testdir
def test_dualstack_base():
    run_provision(
        "dualstack_base.inp.yaml",
        "dualstack_base.kube.yaml",
        None,
        None,
        "dualstack_base.apic.txt",
    )


@in_testdir
def test_dualstack_only_ipv4():
    run_provision(
        "dualstack_only_ipv4.inp.yaml",
        "dualstack_only_ipv4.kube.yaml",
        None,
        None,
        "dualstack_only_ipv4.apic.txt",
    )


@in_testdir
def test_dualstack_node_subnet():
    run_provision(
        "dualstack_node_subnet.inp.yaml",
        "dualstack_node_subnet.kube.yaml",
        None,
        None,
        "dualstack_node_subnet.apic.txt",
    )


@in_testdir
def test_dualstack_pod_and_node_subnet():
    run_provision(
        "dualstack_pod_and_node_subnet.inp.yaml",
        "dualstack_pod_and_node_subnet.kube.yaml",
        None,
        None,
        "dualstack_pod_and_node_subnet.apic.txt",
    )


@in_testdir
def test_dualstack_extern_static():
    run_provision(
        "dualstack_extern_static.inp.yaml",
        "dualstack_extern_static.kube.yaml",
        None,
        None,
        "dualstack_extern_static.apic.txt",
    )


@in_testdir
def test_dualstack_extern_dynamic():
    run_provision(
        "dualstack_extern_dynamic.inp.yaml",
        "dualstack_extern_dynamic.kube.yaml",
        None,
        None,
        "dualstack_extern_dynamic.apic.txt",
    )


@in_testdir
def test_dualstack_invalid():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            run_provision(
                "dualstack_invalid.inp.yaml",
                None,
                None,
                None,
                None,
            )
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("dualstack_invalid.stdout.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


@in_testdir
def test_dualstack_pod_subnet_invalid():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            run_provision(
                "dualstack_pod_subnet_invalid.inp.yaml",
                None,
                None,
                None,
                None,
            )
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("dualstack_pod_subnet_invalid.stdout.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


@in_testdir
def test_dualstack_extern_dynamic_invalid():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            run_provision(
                "dualstack_extern_dynamic_invalid.inp.yaml",
                None,
                None,
                None,
                None,
            )
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("dualstack_extern_dynamic_invalid.stdout.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


@in_testdir
def test_dualstack_extern_static_invalid():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            run_provision(
                "dualstack_extern_static_invalid.inp.yaml",
                None,
                None,
                None,
                None,
            )
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("dualstack_extern_static_invalid.stdout.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


@in_testdir
def test_malformed():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            run_provision(
                "malformed.inp.yaml",
                None,
                None,
                None,
                None,
            )
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("malformed.stdout.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


@in_testdir
def test_with_tenant_l3out():
    run_provision(
        "with_tenant_l3out.inp.yaml",
        "with_tenant_l3out.kube.yaml",
        None,
        None,
        "with_tenant_l3out.apic.txt"
    )


@in_testdir
def test_with_interface_mtu():
    run_provision(
        "with_interface_mtu.inp.yaml",
        "with_interface_mtu.kube.yaml",
        None,
        None,
        "with_interface_mtu.apic.txt"
    )


@in_testdir
def test_with_interface_mtu_headroom():
    run_provision(
        "with_interface_mtu_headroom.inp.yaml",
        "with_interface_mtu_headroom.kube.yaml",
        None,
        None,
        "with_interface_mtu_headroom.apic.txt"
    )


@in_testdir
def test_with_apic_refreshtime():
    run_provision(
        "with_refreshtime.inp.yaml",
        "with_refreshtime.kube.yaml",
        None,
        None,
        "base_case.apic.txt",
    )


@in_testdir
def test_with_pbr_tracking_non_snat():
    run_provision(
        "with_pbr_non_snat.inp.yaml",
        "with_pbr_non_snat.kube.yaml",
        None,
        None,
        "base_case.apic.txt",
    )


@in_testdir
def test_pod_external_access():
    run_provision(
        "pod_ext_access.inp.yaml",
        "pod_ext_access.kube.yaml",
        None,
        None,
        "pod_ext_access.apic.txt"
    )


@in_testdir
def test_enable_opflex_agent_prometheus():
    run_provision(
        "enable_opflex_agent_prometheus.inp.yaml",
        "enable_opflex_agent_prometheus.kube.yaml",
        None,
        None,
        "enable_opflex_agent_prometheus.apic.txt"
    )


@in_testdir
def test_flavor_openshift_310():
    run_provision(
        "flavor_openshift.inp.yaml",
        "flavor_openshift_310.kube.yaml",
        None,
        None,
        "flavor_openshift_310.apic.txt",
        overrides={"flavor": "openshift-3.10"}
    )


@in_testdir
def test_flavor_openshift_311():
    run_provision(
        "flavor_openshift.inp.yaml",
        "flavor_openshift_311.kube.yaml",
        None,
        None,
        "flavor_openshift_311.apic.txt",
        overrides={"flavor": "openshift-3.11"}
    )


@in_testdir
def test_flavor_openshift_43():
    run_provision(
        "flavor_openshift.inp.yaml",
        "flavor_openshift_43.kube.yaml",
        "flavor_openshift_43_tar",
        None,
        "flavor_openshift_43.apic.txt",
        overrides={"flavor": "openshift-4.3"}
    )


@in_testdir
def test_flavor_openshift_44_openstack():
    run_provision(
        "flavor_openshift_44_openstack.inp.yaml",
        "flavor_openshift_44_openstack.kube.yaml",
        "flavor_openshift_44_openstack_tar",
        None,
        "flavor_openshift_44_openstack.apic.txt",
        overrides={"flavor": "openshift-4.4-openstack"}
    )


@in_testdir
def test_flavor_openshift_45_openstack():
    run_provision(
        "flavor_openshift_45_openstack.inp.yaml",
        "flavor_openshift_45_openstack.kube.yaml",
        "flavor_openshift_45_openstack_tar",
        None,
        "flavor_openshift_45_openstack.apic.txt",
        overrides={"flavor": "openshift-4.5-openstack"}
    )


@in_testdir
def test_flavor_openshift_47_openstack():
    run_provision(
        "flavor_openshift_47_openstack.inp.yaml",
        "flavor_openshift_47_openstack.kube.yaml",
        "flavor_openshift_47_openstack_tar",
        None,
        "flavor_openshift_47_openstack.apic.txt",
        overrides={"flavor": "openshift-4.7-openstack"}
    )


@in_testdir
def test_flavor_openshift_46_openstack():
    run_provision(
        "flavor_openshift_46_openstack.inp.yaml",
        "flavor_openshift_46_openstack.kube.yaml",
        "flavor_openshift_46_openstack_tar",
        None,
        "flavor_openshift_46_openstack.apic.txt",
        overrides={"flavor": "openshift-4.6-openstack"}
    )


@in_testdir
def test_flavor_openshift_48_openstack():
    run_provision(
        "flavor_openshift_48_openstack.inp.yaml",
        "flavor_openshift_48_openstack.kube.yaml",
        "flavor_openshift_48_openstack_tar",
        None,
        "flavor_openshift_48_openstack.apic.txt",
        overrides={"flavor": "openshift-4.8-openstack"}
    )


@in_testdir
def test_flavor_openshift_49_openstack():
    run_provision(
        "flavor_openshift_49_openstack.inp.yaml",
        "flavor_openshift_49_openstack.kube.yaml",
        "flavor_openshift_49_openstack_tar",
        None,
        "flavor_openshift_49_openstack.apic.txt",
        overrides={"flavor": "openshift-4.9-openstack"}
    )


@in_testdir
def test_flavor_openshift_410_openstack():
    run_provision(
        "flavor_openshift_410_openstack.inp.yaml",
        "flavor_openshift_410_openstack.kube.yaml",
        "flavor_openshift_410_openstack_tar",
        None,
        "flavor_openshift_410_openstack.apic.txt",
        overrides={"flavor": "openshift-4.10-openstack"}
    )


@in_testdir
def test_flavor_openshift_411_openstack():
    run_provision(
        "flavor_openshift_411_openstack.inp.yaml",
        "flavor_openshift_411_openstack.kube.yaml",
        "flavor_openshift_411_openstack_tar",
        None,
        "flavor_openshift_411_openstack.apic.txt",
        overrides={"flavor": "openshift-4.11-openstack"}
    )


@in_testdir
def test_flavor_openshift_412_openstack():
    run_provision(
        "flavor_openshift_412_openstack.inp.yaml",
        "flavor_openshift_412_openstack.kube.yaml",
        "flavor_openshift_412_openstack_tar",
        None,
        "flavor_openshift_412_openstack.apic.txt",
        overrides={"flavor": "openshift-4.12-openstack"}
    )


@in_testdir
def test_flavor_openshift_413_openstack():
    run_provision(
        "flavor_openshift_413_openstack.inp.yaml",
        "flavor_openshift_413_openstack.kube.yaml",
        "flavor_openshift_413_openstack_tar",
        None,
        "flavor_openshift_413_openstack.apic.txt",
        overrides={"flavor": "openshift-4.13-openstack"}
    )


@in_testdir
def test_flavor_openshift_414_openstack():
    run_provision(
        "flavor_openshift_414_openstack.inp.yaml",
        "flavor_openshift_414_openstack.kube.yaml",
        "flavor_openshift_414_openstack_tar",
        None,
        "flavor_openshift_414_openstack.apic.txt",
        overrides={"flavor": "openshift-4.14-openstack"}
    )


@in_testdir
def test_flavor_openshift_47_esx():
    run_provision(
        "flavor_openshift_47_esx.inp.yaml",
        "flavor_openshift_47_esx.kube.yaml",
        "flavor_openshift_47_esx_tar",
        None,
        "flavor_openshift_47_esx.apic.txt",
        overrides={"flavor": "openshift-4.7-esx"}
    )


@in_testdir
def test_flavor_openshift_48_esx():
    run_provision(
        "flavor_openshift_48_esx.inp.yaml",
        "flavor_openshift_48_esx.kube.yaml",
        "flavor_openshift_48_esx_tar",
        None,
        "flavor_openshift_48_esx.apic.txt",
        overrides={"flavor": "openshift-4.8-esx"}
    )


@in_testdir
def test_flavor_openshift_49_esx():
    run_provision(
        "flavor_openshift_49_esx.inp.yaml",
        "flavor_openshift_49_esx.kube.yaml",
        "flavor_openshift_49_esx_tar",
        None,
        "flavor_openshift_49_esx.apic.txt",
        overrides={"flavor": "openshift-4.9-esx"}
    )


@in_testdir
def test_flavor_openshift_410_esx():
    run_provision(
        "flavor_openshift_410_esx.inp.yaml",
        "flavor_openshift_410_esx.kube.yaml",
        "flavor_openshift_410_esx_tar",
        None,
        "flavor_openshift_410_esx.apic.txt",
        overrides={"flavor": "openshift-4.10-esx"}
    )


@in_testdir
def test_flavor_openshift_411_esx():
    run_provision(
        "flavor_openshift_411_esx.inp.yaml",
        "flavor_openshift_411_esx.kube.yaml",
        "flavor_openshift_411_esx_tar",
        None,
        "flavor_openshift_411_esx.apic.txt",
        overrides={"flavor": "openshift-4.11-esx"}
    )


@in_testdir
def test_flavor_openshift_412_esx():
    run_provision(
        "flavor_openshift_412_esx.inp.yaml",
        "flavor_openshift_412_esx.kube.yaml",
        "flavor_openshift_412_esx_tar",
        None,
        "flavor_openshift_412_esx.apic.txt",
        overrides={"flavor": "openshift-4.12-esx"}
    )


@in_testdir
def test_flavor_openshift_413_esx():
    run_provision(
        "flavor_openshift_413_esx.inp.yaml",
        "flavor_openshift_413_esx.kube.yaml",
        "flavor_openshift_413_esx_tar",
        None,
        "flavor_openshift_413_esx.apic.txt",
        overrides={"flavor": "openshift-4.13-esx"}
    )


@in_testdir
def test_flavor_openshift_413_baremetal():
    run_provision(
        "flavor_openshift_413_baremetal.inp.yaml",
        "flavor_openshift_413_baremetal.kube.yaml",
        "flavor_openshift_413_baremetal_tar",
        None,
        "flavor_openshift_413_baremetal.apic.txt",
        overrides={"flavor": "openshift-4.13-baremetal"}
    )


@in_testdir
def test_flavor_openshift_412_baremetal():
    run_provision(
        "flavor_openshift_412_baremetal.inp.yaml",
        "flavor_openshift_412_baremetal.kube.yaml",
        "flavor_openshift_412_baremetal_tar",
        None,
        "flavor_openshift_412_baremetal.apic.txt",
        overrides={"flavor": "openshift-4.12-baremetal"}
    )


@in_testdir
def test_flavor_openshift_sdn_ovn_baremetal():
    run_provision(
        "flavor_openshift_sdn_ovn_baremetal.inp.yaml",
        "flavor_openshift_sdn_ovn_baremetal.kube.yaml",
        "flavor_openshift_sdn_ovn_baremetal_tar",
        None,
        "flavor_openshift_sdn_ovn_baremetal.apic.txt",
        overrides={"flavor": "openshift-sdn-ovn-baremetal"}
    )


@in_testdir
def test_flvr_openshift_sdn_ovn_baremetal_primary():
    run_provision(
        "flvr_openshift_sdn_ovn_baremetal_primary.inp.yaml",
        "flvr_openshift_sdn_ovn_baremetal_primary.kube.yaml",
        "flvr_openshift_sdn_ovn_baremetal_primary_tar",
        None,
        "flvr_openshift_sdn_ovn_baremetal_primary.apic.txt",
        overrides={"flavor": "openshift-sdn-ovn-baremetal"}
    )


@in_testdir
def test_flvr_openshift_sdn_ovn_baremetal_secondary_with_primary():
    run_provision(
        "flvr_openshift_sdn_ovn_baremetal_secondary_with_primary.inp.yaml",
        "flvr_openshift_sdn_ovn_baremetal_secondary_with_primary.kube.yaml",
        "flvr_openshift_sdn_ovn_baremetal_secondary_with_primary_tar",
        None,
        "flvr_openshift_sdn_ovn_baremetal_secondary_with_primary.apic.txt",
        overrides={"flavor": "openshift-sdn-ovn-baremetal"}
    )


@in_testdir
def test_preexisting_tenant_chained_mode():
    run_provision(
        "with_preexisting_tenant_chained_mode.inp.yaml",
        "with_preexisting_tenant_chained_mode.kube.yaml",
        None,
        None,
        "with_preexisting_tenant_chained_mode.apic.txt",
        overrides={"flavor": "openshift-sdn-ovn-baremetal"}
    )


@in_testdir
def test_override_skip_node_network_provision():
    run_provision(
        "override_skip_node_network_provision.inp.yaml",
        "override_skip_node_network_provision.kube.yaml",
        None,
        None,
        "override_skip_node_network_provision.apic.txt",
        overrides={"flavor": "openshift-sdn-ovn-baremetal"}
    )


@in_testdir
def test_chained_mode_without_l3out():
    run_provision(
        "chained_mode_without_l3out.inp.yaml",
        "chained_mode_without_l3out.kube.yaml",
        None,
        None,
        "chained_mode_without_l3out.apic.txt",
        overrides={"flavor": "openshift-sdn-ovn-baremetal"}
    )


@in_testdir
def test_chained_mode_without_phys_domains():
    run_provision(
        "chained_mode_without_phys_domains.inp.yaml",
        "chained_mode_without_phys_domains.kube.yaml",
        None,
        None,
        "chained_mode_without_phys_domains.apic.txt",
        overrides={"flavor": "openshift-sdn-ovn-baremetal"}
    )


@in_testdir
def test_override_use_global_scope_vlan():
    run_provision(
        "override_use_global_scope_vlan.inp.yaml",
        "override_use_global_scope_vlan.kube.yaml",
        None,
        None,
        "override_use_global_scope_vlan.apic.txt",
        overrides={"flavor": "openshift-sdn-ovn-baremetal"}
    )


@in_testdir
def test_chained_mode_nad_vlan_map():
    run_provision(
        "chained_mode_nad_vlan_map.inp.yaml",
        "chained_mode_nad_vlan_map.kube.yaml",
        "chained_mode_nad_vlan_map_tar",
        None,
        "chained_mode_nad_vlan_map.apic.txt",
        overrides={"flavor": "openshift-sdn-ovn-baremetal"}
    )


@in_testdir
def test_flavor_openshift_411_baremetal():
    run_provision(
        "flavor_openshift_411_baremetal.inp.yaml",
        "flavor_openshift_411_baremetal.kube.yaml",
        "flavor_openshift_411_baremetal_tar",
        None,
        "flavor_openshift_411_baremetal.apic.txt",
        overrides={"flavor": "openshift-4.11-baremetal"}
    )


@in_testdir
def test_flavor_openshift_410_baremetal():
    run_provision(
        "flavor_openshift_410_baremetal.inp.yaml",
        "flavor_openshift_410_baremetal.kube.yaml",
        "flavor_openshift_410_baremetal_tar",
        None,
        "flavor_openshift_410_baremetal.apic.txt",
        overrides={"flavor": "openshift-4.10-baremetal"}
    )


@in_testdir
def test_flavor_openshift_49_baremetal():
    run_provision(
        "flavor_openshift_49_baremetal.inp.yaml",
        "flavor_openshift_49_baremetal.kube.yaml",
        "flavor_openshift_49_baremetal_tar",
        None,
        "flavor_openshift_49_baremetal.apic.txt",
        overrides={"flavor": "openshift-4.9-baremetal"}
    )


@in_testdir
def test_flavor_openshift_48_baremetal():
    run_provision(
        "flavor_openshift_48_baremetal.inp.yaml",
        "flavor_openshift_48_baremetal.kube.yaml",
        "flavor_openshift_48_baremetal_tar",
        None,
        "flavor_openshift_48_baremetal.apic.txt",
        overrides={"flavor": "openshift-4.8-baremetal"}
    )


@in_testdir
def test_flavor_openshift_47_baremetal():
    run_provision(
        "flavor_openshift_47_baremetal.inp.yaml",
        "flavor_openshift_47_baremetal.kube.yaml",
        "flavor_openshift_47_baremetal_tar",
        None,
        "flavor_openshift_47_baremetal.apic.txt",
        overrides={"flavor": "openshift-4.7-baremetal"}
    )


@in_testdir
def test_flavor_openshift_46_baremetal():
    run_provision(
        "flavor_openshift_46_baremetal.inp.yaml",
        "flavor_openshift_46_baremetal.kube.yaml",
        "flavor_openshift_46_baremetal_tar",
        None,
        "flavor_openshift_46_baremetal.apic.txt",
        overrides={"flavor": "openshift-4.6-baremetal"}
    )


@in_testdir
def test_flavor_openshift_46_esx():
    run_provision(
        "flavor_openshift_46_esx.inp.yaml",
        "flavor_openshift_46_esx.kube.yaml",
        "flavor_openshift_46_esx_tar",
        None,
        "flavor_openshift_46_esx.apic.txt",
        overrides={"flavor": "openshift-4.6-esx"}
    )


@in_testdir
def test_flavor_openshift_45_esx():
    run_provision(
        "flavor_openshift_45_esx.inp.yaml",
        "flavor_openshift_45_esx.kube.yaml",
        "flavor_openshift_45_esx_tar",
        None,
        "flavor_openshift_45_esx.apic.txt",
        overrides={"flavor": "openshift-4.5-esx"}
    )


@in_testdir
def test_flavor_openshift_44_esx():
    run_provision(
        "flavor_openshift_44_esx.inp.yaml",
        "flavor_openshift_44_esx.kube.yaml",
        "flavor_openshift_44_esx_tar",
        None,
        "flavor_openshift_44_esx.apic.txt",
        overrides={"flavor": "openshift-4.4-esx"}
    )


@in_testdir
def test_flavor_dockerucp_30():
    run_provision(
        "base_case.inp.yaml",
        "flavor_dockerucp.kube.yaml",
        None,
        None,
        "flavor_dockerucp.apic.txt",
        overrides={"flavor": "docker-ucp-3.0"}
    )


@in_testdir
def test_flavor_localhost():
    run_provision(
        "flavor_localhost.inp.yaml",
        "flavor_localhost.kube.yaml",
        None,
        None,
        None,
        overrides={"flavor": "k8s-overlay"}
    )


@in_testdir
def test_flavor_cloud_base():

    with open("apic_test_data.json") as data_file:
        data = json.loads(data_file.read())
    apic = fake_apic.start_fake_apic(50000, data["gets"], data["deletes"])

    def clean_apic():
        apic.shutdown()
        return False

    run_provision(
        "flavor_cloud.inp.yaml",
        "flavor_cloud.kube.yaml",
        "cloud_tar",
        None,
        overrides={"flavor": "cloud", "apic": True, "password": "test"},
        cleanupFunc=clean_apic
    )
    apic.shutdown()


@in_testdir
def test_flavor_aks_base():
    with open("apic_aks_test_data.json") as data_file:
        data = json.loads(data_file.read())
    apic = fake_apic.start_fake_apic(50001, data["gets"], data["deletes"])

    def clean_apic():
        apic.shutdown()
        return False

    run_provision(
        "flavor_aks.inp.yaml",
        "flavor_aks.kube.yaml",
        None,
        None,
        overrides={"flavor": "aks", "apic": True, "password": "test"},
        cleanupFunc=clean_apic
    )
    apic.shutdown()


@in_testdir
def test_flavor_eks_base():
    with open("apic_eks_test_data.json") as data_file:
        data = json.loads(data_file.read())
    apic = fake_apic.start_fake_apic(50002, data["gets"], data["deletes"])

    def clean_apic():
        apic.shutdown()
        return False

    run_provision(
        "flavor_eks.inp.yaml",
        "flavor_eks.kube.yaml",
        None,
        None,
        overrides={"flavor": "eks", "apic": True, "password": "test"},
        cleanupFunc=clean_apic
    )
    apic.shutdown()


@in_testdir
def test_flavor_cloud_delete():
    with open("apic_delete_data.json") as data_file:
        data = json.loads(data_file.read())
    apic = fake_apic.start_fake_apic(50000, data["gets"], data["deletes"])

    def clean_apic():
        apic.shutdown()
        return False

    assert (len(fake_apic.fake_deletes) != 0)
    run_provision(
        "flavor_cloud.inp.yaml",
        None,
        None,
        None,
        overrides={"flavor": "cloud", "apic": True, "password": "test", "delete": True},
        cleanupFunc=clean_apic
    )
    apic.shutdown()
    # verify all deletes were executed
    assert (len(fake_apic.fake_deletes) == 0)


@in_testdir
def test_flavor_aks_delete():
    with open("apic_aks_delete_data.json") as data_file:
        data = json.loads(data_file.read())
    apic = fake_apic.start_fake_apic(50001, data["gets"], data["deletes"])

    def clean_apic():
        apic.shutdown()
        return False

    assert (len(fake_apic.fake_deletes) != 0)
    run_provision(
        "flavor_aks.inp.yaml",
        None,
        None,
        None,
        overrides={"flavor": "aks", "apic": True, "password": "test", "delete": True}, cleanupFunc=clean_apic
    )
    apic.shutdown()
    # verify all deletes were executed
    assert (len(fake_apic.fake_deletes) == 0)


@in_testdir
def test_flavor_eks_delete():
    with open("apic_eks_delete_data.json") as data_file:
        data = json.loads(data_file.read())
    apic = fake_apic.start_fake_apic(50002, data["gets"], data["deletes"])

    def clean_apic():
        apic.shutdown()
        return False

    assert (len(fake_apic.fake_deletes) != 0)
    run_provision(
        "flavor_eks.inp.yaml",
        None,
        None,
        None,
        overrides={"flavor": "eks", "apic": True, "password": "test", "delete": True}, cleanupFunc=clean_apic
    )
    apic.shutdown()
    # verify all deletes were executed
    assert (len(fake_apic.fake_deletes) == 0)


@in_testdir
def test_conflicting_infravlan():
    run_provision(
        "conflicting_infravlan.inp.yaml",
        "base_case.kube.yaml",
        None,
        None,
        "base_case.apic.txt",
        overrides={"infra_vlan": 4093}
    )


@in_testdir
def test_with_no_istio():
    run_provision(
        "with_no_install_istio.inp.yaml",
        "with_no_install_istio.kube.yaml",
        None,
        None,
        "base_case.apic.txt"
    )


@in_testdir
def test_with_default_profile():
    run_provision(
        "with_istio_default_profile.inp.yaml",
        "with_istio_default_profile.kube.yaml",
        None,
        None,
        "base_case.apic.txt"
    )


@in_testdir
def test_new_naming_convention_simple():
    run_provision(
        "with_new_naming_convention.inp.yaml",
        "with_new_naming_convention.kube.yaml",
        None,
        "with_new_naming_convention_operator_cr.kube.yaml",
        "with_new_naming_convention.apic.txt"
    )


@in_testdir
def test_new_naming_convention_openshift():
    run_provision(
        "with_new_naming_convention.inp.yaml",
        "with_new_naming_convention_openshift.kube.yaml",
        None,
        None,
        "with_new_naming_convention_openshift.apic.txt",
        overrides={"flavor": "openshift-3.9"}
    )


@in_testdir
def test_new_naming_convention_dockerucp():
    run_provision(
        "with_new_naming_convention.inp.yaml",
        "with_new_naming_convention_dockerucp.kube.yaml",
        None,
        None,
        "with_new_naming_convention_dockerucp.apic.txt",
        overrides={"flavor": "docker-ucp-3.0"}
    )


@in_testdir
def test_preexisting_tenant():
    run_provision(
        "with_preexisting_tenant.inp.yaml",
        "with_preexisting_tenant.kube.yaml",
        None,
        None,
        "with_preexisting_tenant.apic.txt"
    )


@in_testdir
def test_with_no_drop_log():
    run_provision(
        "with_no_drop_log.inp.yaml",
        "with_no_drop_log.kube.yaml",
        None,
        None,
        "base_case.apic.txt"
    )


@in_testdir
def test_sriov_config():
    run_provision(
        "with_sriov_config_input.yaml",
        "with_sriov_config_kube.yaml",
        None,
        None,
        "base_case.apic.txt"
    )


@in_testdir
def test_no_sriov_config():
    run_provision(
        "with_no_sriov_config_input.yaml",
        "with_no_sriov_config_kube.yaml",
        None,
        None,
        "base_case.apic.txt"
    )


@in_testdir
def test_no_dpu_config():
    run_provision(
        "with_no_dpu_config_input.yaml",
        "with_no_dpu_config_kube.yaml",
        None,
        None,
        "base_case.apic.txt"
    )


@in_testdir
def test_dpu_config():
    run_provision(
        "with_dpu_config_input.yaml",
        "with_dpu_config_kube.yaml",
        None,
        None,
        "base_case.apic.txt"
    )


@in_testdir
def test_sriov_with_no_deviceinfo():
    run_provision(
        "with_sriov_config_no_deviceinfo_input.yaml",
        "with_sriov_config_no_deviceinfo_kube.yaml",
        None,
        None,
        "base_case.apic.txt"
    )


@in_testdir
def test_flavor_RKE2_kubernetes_1_24_base():
    run_provision(
        "flavor_RKE2_kubernetes_1_24.inp.yaml",
        "flavor_RKE2_kubernetes_1_24.kube.yaml",
        None,
        None,
        "flavor_RKE2_kubernetes_1_24.apic.txt",
        overrides={"flavor": "RKE2-kubernetes-1.24"}
    )


@in_testdir
def test_flavor_RKE2_kubernetes_1_25_base():
    run_provision(
        "flavor_RKE2_kubernetes_1_25.inp.yaml",
        "flavor_RKE2_kubernetes_1_25.kube.yaml",
        None,
        None,
        "flavor_RKE2_kubernetes_1_25.apic.txt",
        overrides={"flavor": "RKE2-kubernetes-1.25"}
    )


@in_testdir
def test_flavor_RKE2_kubernetes_1_26_base():
    run_provision(
        "flavor_RKE2_kubernetes_1_26.inp.yaml",
        "flavor_RKE2_kubernetes_1_26.kube.yaml",
        None,
        None,
        "flavor_RKE2_kubernetes_1_26.apic.txt",
        overrides={"flavor": "RKE2-kubernetes-1.26"}
    )


@in_testdir
def test_flavor_RKE_1_2_3_base():
    run_provision(
        "flavor_RKE_1_2_3.inp.yaml",
        "flavor_RKE_1_2_3.rke.yaml",
        None,
        None,
        "flavor_RKE_1_2_3.apic.txt",
        overrides={"flavor": "RKE-1.2.3"}
    )


@in_testdir
def test_flavor_RKE_1_3_13_base():
    run_provision(
        "flavor_RKE_1_3_13.inp.yaml",
        "flavor_RKE_1_3_13.rke.yaml",
        None,
        None,
        "flavor_RKE_1_3_13.apic.txt",
        overrides={"flavor": "RKE-1.3.13"}
    )


@in_testdir
def test_flavor_RKE_1_3_17_base():
    run_provision(
        "flavor_RKE_1_3_17.inp.yaml",
        "flavor_RKE_1_3_17.rke.yaml",
        None,
        None,
        "flavor_RKE_1_3_17.apic.txt",
        overrides={"flavor": "RKE-1.3.17"}
    )


@in_testdir
def test_flavor_RKE_1_3_18_base():
    run_provision(
        "flavor_RKE_1_3_18.inp.yaml",
        "flavor_RKE_1_3_18.rke.yaml",
        None,
        None,
        "flavor_RKE_1_3_18.apic.txt",
        overrides={"flavor": "RKE-1.3.18"}
    )


@in_testdir
def test_flavor_RKE_1_3_20_base():
    run_provision(
        "flavor_RKE_1_3_20.inp.yaml",
        "flavor_RKE_1_3_20.rke.yaml",
        None,
        None,
        "flavor_RKE_1_3_20.apic.txt",
        overrides={"flavor": "RKE-1.3.20"}
    )


@in_testdir
def test_flavor_RKE_1_3_21_base():
    run_provision(
        "flavor_RKE_1_3_21.inp.yaml",
        "flavor_RKE_1_3_21.rke.yaml",
        None,
        None,
        "flavor_RKE_1_3_21.apic.txt",
        overrides={"flavor": "RKE-1.3.21"}
    )


@in_testdir
def test_flavor_RKE_1_3_24_base():
    run_provision(
        "flavor_RKE_1_3_24.inp.yaml",
        "flavor_RKE_1_3_24.rke.yaml",
        None,
        None,
        "flavor_RKE_1_3_24.apic.txt",
        overrides={"flavor": "RKE-1.3.24"}
    )


@in_testdir
def test_flavor_RKE_1_4_6_base():
    run_provision(
        "flavor_RKE_1_4_6.inp.yaml",
        "flavor_RKE_1_4_6.rke.yaml",
        None,
        None,
        "flavor_RKE_1_4_6.apic.txt",
        overrides={"flavor": "RKE-1.4.6"}
    )


@in_testdir
def test_flavor_RKE_1_4_9_base():
    run_provision(
        "flavor_RKE_1_4_9.inp.yaml",
        "flavor_RKE_1_4_9.rke.yaml",
        None,
        None,
        "flavor_RKE_1_4_9.apic.txt",
        overrides={"flavor": "RKE-1.4.9"}
    )


@in_testdir
def test_flavor_RKE_1_4_13_base():
    run_provision(
        "flavor_RKE_1_4_13.inp.yaml",
        "flavor_RKE_1_4_13.rke.yaml",
        None,
        None,
        "flavor_RKE_1_4_13.apic.txt",
        overrides={"flavor": "RKE-1.4.13"}
    )


@in_testdir
def test_flavor_RKE_1_5_3_base():
    run_provision(
        "flavor_RKE_1_5_3.inp.yaml",
        "flavor_RKE_1_5_3.rke.yaml",
        None,
        None,
        "flavor_RKE_1_5_3.apic.txt",
        overrides={"flavor": "RKE-1.5.3"}
    )


@in_testdir
def test_sample():
    with tempfile.NamedTemporaryFile("wb") as tmpout:
        sys.stdout = tmpout
        try:
            args = get_args(sample=True)
            acc_provision.main(args, no_random=True)
        finally:
            sys.stdout = sys.__stdout__
        assert filecmp.cmp(tmpout.name, "../acc_provision/templates/provision-config.yaml", shallow=False)
        run_provision(tmpout.name, "sample.kube.yaml", None)


@in_testdir
def test_devnull_errors():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            args = get_args()
            print(acc_provision.main(args, no_random=True))
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("devnull.stderr.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


@in_testdir
def test_helpmsg():
    with tempfile.NamedTemporaryFile("w") as tmpout:
        origout = sys.stdout
        sys.stdout = tmpout
        try:
            sys.argv = ["acc_provision.py", "--help"]
            acc_provision.main(no_random=True)
        except SystemExit:
            pass
        finally:
            sys.stdout = origout
        tmpout.flush()
        assert filecmp.cmp(tmpout.name, "help.stdout.txt", shallow=False)


@in_testdir
def test_list_flavors_msg():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            sys.argv = ["acc_provision.py", "--list-flavors"]
            print(acc_provision.main(no_random=True))
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("list_flavors.stdout.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


@in_testdir
def test_overlapping_subnets():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            run_provision(
                "with_overlapping_subnets.inp.yaml",
                None,
                None,
                None,
                None
            )
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("overlapping_subnets.stdout.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


@in_testdir
def test_image_pull_secret():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            run_provision(
                "with_image_pull_secret.inp.yaml",
                None,
                None,
                None,
                None
            )
        except SystemExit:
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("image_pull_secret.stdout.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


@in_testdir
def test_preexisting_kube_convention():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            run_provision(
                "with_preexisting_kube_convention.inp.yaml",
                None,
                None,
                None
            )
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("error_preexisting_kube_convention.stdout.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


@in_testdir
def test_flavor_calico_3_23_2():
    run_provision(
        "flavor_calico-3.23.2.inp.yaml",
        None,
        "flavor_calico-3.23.2_tar",
        None,
        "flavor_calico-3.23.2.apic.txt",
        overrides={"flavor": "calico-3.23.2"}
    )


@in_testdir
def test_flvr_calico_3_23_2_multiple_vrf_uc1():
    run_provision(
        "flavor_calico_3.23.2_multiple_vrf_uc1.inp.yaml",
        None,
        "flavor_calico_3.23.2_multiple_vrf_uc1_tar",
        None,
        "flavor_calico_3.23.2_multiple_vrf_uc1.apic.txt",
        overrides={"flavor": "calico-3.23.2"}
    )


@in_testdir
def test_flvr_calico_3_23_2_multiple_vrf_uc2():
    run_provision(
        "flavor_calico_3.23.2_multiple_vrf_uc2.inp.yaml",
        None,
        "flavor_calico_3.23.2_multiple_vrf_uc2_tar",
        None,
        "flavor_calico_3.23.2_multiple_vrf_uc2.apic.txt",
        overrides={"flavor": "calico-3.23.2"}
    )


@in_testdir
def test_flvr_calico_3_23_2_multiple_vrf_uc3():
    run_provision(
        "flavor_calico_3.23.2_multiple_vrf_uc3.inp.yaml",
        None,
        "flavor_calico_3.23.2_multiple_vrf_uc3_tar",
        None,
        "flavor_calico_3.23.2_multiple_vrf_uc3.apic.txt",
        overrides={"flavor": "calico-3.23.2"}
    )


@in_testdir
def test_flavor_with_cluster_svc_export_calico_3_23_2():
    run_provision(
        "flavor_with_cluster_svc_export_calico-3.23.2.inp.yaml",
        None,
        "flavor_with_cluster_svc_export_calico-3.23.2_tar",
        None,
        "flavor_with_cluster_svc_export_calico-3.23.2.apic.txt",
        overrides={"flavor": "calico-3.23.2"}
    )


@in_testdir
def test_flvr_openshift_44_esx_vDS_6_6_above():
    run_provision(
        "flavor_openshift_44_esx_vDS_6_6_above.inp.yaml",
        "flavor_openshift_44_esx_vDS_6_6_above.kube.yaml",
        "flavor_openshift_44_esx_vDS_6_6_above_tar",
        None,
        "flavor_openshift_44_esx_vDS_6_6_above.apic.txt",
        overrides={"flavor": "openshift-4.4-esx"}
    )


@in_testdir
def test_flvr_openshift_45_esx_vDS_6_6_above():
    run_provision(
        "flavor_openshift_45_esx_vDS_6_6_above.inp.yaml",
        "flavor_openshift_45_esx_vDS_6_6_above.kube.yaml",
        "flavor_openshift_45_esx_vDS_6_6_above_tar",
        None,
        "flavor_openshift_45_esx_vDS_6_6_above.apic.txt",
        overrides={"flavor": "openshift-4.5-esx"}
    )


@in_testdir
def test_flvr_openshift_46_esx_vDS_6_6_above():
    run_provision(
        "flavor_openshift_46_esx_vDS_6_6_above.inp.yaml",
        "flavor_openshift_46_esx_vDS_6_6_above.kube.yaml",
        "flavor_openshift_46_esx_vDS_6_6_above_tar",
        None,
        "flavor_openshift_46_esx_vDS_6_6_above.apic.txt",
        overrides={"flavor": "openshift-4.6-esx"}
    )


@in_testdir
def test_flvr_openshift_47_esx_vDS_6_6_above():
    run_provision(
        "flavor_openshift_47_esx_vDS_6_6_above.inp.yaml",
        "flavor_openshift_47_esx_vDS_6_6_above.kube.yaml",
        "flavor_openshift_47_esx_vDS_6_6_above_tar",
        None,
        "flavor_openshift_47_esx_vDS_6_6_above.apic.txt",
        overrides={"flavor": "openshift-4.7-esx"}
    )


@in_testdir
def test_flvr_openshift_48_esx_vDS_6_6_above():
    run_provision(
        "flavor_openshift_48_esx_vDS_6_6_above.inp.yaml",
        "flavor_openshift_48_esx_vDS_6_6_above.kube.yaml",
        "flavor_openshift_48_esx_vDS_6_6_above_tar",
        None,
        "flavor_openshift_48_esx_vDS_6_6_above.apic.txt",
        overrides={"flavor": "openshift-4.8-esx"}
    )


@in_testdir
def test_flvr_openshift_49_esx_vDS_6_6_above():
    run_provision(
        "flavor_openshift_49_esx_vDS_6_6_above.inp.yaml",
        "flavor_openshift_49_esx_vDS_6_6_above.kube.yaml",
        "flavor_openshift_49_esx_vDS_6_6_above_tar",
        None,
        "flavor_openshift_49_esx_vDS_6_6_above.apic.txt",
        overrides={"flavor": "openshift-4.9-esx"}
    )


@in_testdir
def test_flvr_openshift_410_esx_vDS_6_6_above():
    run_provision(
        "flavor_openshift_410_esx_vDS_6_6_above.inp.yaml",
        "flavor_openshift_410_esx_vDS_6_6_above.kube.yaml",
        "flavor_openshift_410_esx_vDS_6_6_above_tar",
        None,
        "flavor_openshift_410_esx_vDS_6_6_above.apic.txt",
        overrides={"flavor": "openshift-4.10-esx"}
    )


@in_testdir
def test_flvr_openshift_411_esx_vDS_6_6_above():
    run_provision(
        "flavor_openshift_411_esx_vDS_6_6_above.inp.yaml",
        "flavor_openshift_411_esx_vDS_6_6_above.kube.yaml",
        "flavor_openshift_411_esx_vDS_6_6_above_tar",
        None,
        "flavor_openshift_411_esx_vDS_6_6_above.apic.txt",
        overrides={"flavor": "openshift-4.11-esx"}
    )


@in_testdir
def test_flavor_openshift_invalid_systemid():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            run_provision(
                "flavor_openshift_invalid_systemid.inp.yaml",
                None,
                None,
                None,
                None,
                overrides={"flavor": "openshift-4.13-esx"}
            )
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("flavor_openshift_invalid_systemid.stdout.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


@in_testdir
def test_apic_oobm_ip():
    run_provision(
        "apic_oobm_ip.inp.yaml",
        None,
        None,
        None,
        "apic_oobm_ip.apic.txt",
        overrides={"apic_oobm_ip": "10.30.120.101"}
    )


@in_testdir
def test_invalid_apic_oobm_ip():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            run_provision(
                "apic_oobm_ip.inp.yaml",
                None,
                None,
                None,
                None,
                overrides={"apic_oobm_ip": "10.30.120.101/24"}
            )
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("invalid_apic_oobm_ip.stdout.txt", "r") as stderr:
            assert tmperr.read() == stderr.read()


def get_args(**overrides):
    arg = {
        "config": None,
        "output": None,
        "output_tar": None,
        "aci_operator_cr": None,
        "apic_proxy": None,
        "apicfile": None,
        "apic": False,
        "delete": False,
        "username": "admin",
        "password": "",
        "sample": False,
        "timeout": None,
        "debug": True,
        "list_flavors": False,
        "flavor": "kubernetes-1.27",
        "version_token": "dummy",
        "release": False,
        "test_data_out": None,
        "skip_kafka_certs": True,
        "upgrade": False,
        "disable_multus": 'true',
        "operator_mode": False,
        "chained": False,
        # infra_vlan is not part of command line input, but we do
        # pass it as a command line arg in unit tests to pass in
        # configuration which would otherwise be discovered from
        # the APIC
        "infra_vlan": None,
        "dpu": None,
        "apic_oobm_ip": None,
        "test_run": True,
        "compare_kube_yaml_aci_op_cm_in_plain_text": True,
        "skip_app_profile_check": False
    }
    argc = collections.namedtuple('argc', list(arg.keys()))
    args = argc(**arg)
    args = args._replace(**overrides)
    return args


def copy_file(expectedyaml, output, debug, generated):
    if expectedyaml is not None:
        if debug:
            shutil.copyfile(output.name, generated)


def convert_aci_op_cm_to_base64(kube_yaml_file, kind="ConfigMap", name="aci-operator-config", base64_convert="no_convert"):
    # Convert aci-operator-config config-map to base64 encode/decode/no-convert format
    converted_yaml = []
    for k_yaml in kube_yaml_file:
        converted_yaml.append(copy.deepcopy(k_yaml))
        for _, v in k_yaml.items():
            if v == kind and k_yaml['metadata']['name'] == name:
                aci_op_cm_yaml = copy.deepcopy(k_yaml)
                try:
                    if kind == "ConfigMap" and name == "aci-operator-config":
                        spec = ast.literal_eval(aci_op_cm_yaml['data']['spec'])
                    elif kind == "AciContainersOperator" and name == "acicnioperator":
                        spec = aci_op_cm_yaml['spec']
                except Exception:
                    if kind == "ConfigMap" and name == "aci-operator-config":
                        spec = aci_op_cm_yaml['data']['spec']

                if base64_convert == "encode":
                    base64_encoded_config = base64.b64encode(spec['config'].encode('ascii')).decode("ascii")
                    spec['config'] = base64_encoded_config
                elif base64_convert == "decode":
                    base64_decoded_config = base64.b64decode(spec['config']).decode("ascii")
                    spec['config'] = base64_decoded_config

                if kind == "ConfigMap" and name == "aci-operator-config":
                    aci_op_cm_yaml['data']['spec'] = spec
                elif kind == "AciContainersOperator" and name == "acicnioperator":
                    aci_op_cm_yaml['spec'] = spec

                converted_yaml.remove(k_yaml)
                converted_yaml.append(aci_op_cm_yaml)
                break
    return converted_yaml


def compare_kube_yaml(expectedyaml, output, debug, generated, cleanupFunc):
    if expectedyaml is None:
        return True

    exp_fh = open(expectedyaml, "r")
    expected_yaml_file = list(yml.load_all(exp_fh))
    gen_fh = output.read()
    generated_yaml_file = list(yml.load_all(gen_fh))

    kind = "ConfigMap"
    name = "aci-operator-config"

    if generated == "/tmp/generated_operator_cr.yaml":
        kind = "AciContainersOperator"
        name = "acicnioperator"

    # 1 Load generated *.kube.yaml
    prepare_gen_yamls_list = convert_aci_op_cm_to_base64(generated_yaml_file, kind=kind, name=name)
    # 2 Load expected *.kube.yaml, find aci-operator-config configmap and convert it to base64 encode format
    prepare_exp_yamls_list = convert_aci_op_cm_to_base64(expected_yaml_file, kind=kind, name=name, base64_convert="encode")
    # 3 Load generated *.kube.yaml, find aci-operator-config configmap and convert it to plaintext
    #   and store back to /tmp/generated_kube.yaml to be used in fix-testdata.sh
    store_gen_yaml_with_aci_op_cm_as_plain_text = convert_aci_op_cm_to_base64(generated_yaml_file, kind=kind, name=name, base64_convert="decode")
    with open(generated, 'w') as fh:
        yml.dump_all(store_gen_yaml_with_aci_op_cm_as_plain_text, fh)

    # 4 Compare generated and expected kube.yaml
    # assert prepare_gen_yamls_list == prepare_exp_yamls_list, cleanupFunc()
    return prepare_gen_yamls_list == prepare_exp_yamls_list


def compare_yaml(expectedyaml, output, debug, generated, cleanupFunc):
    if expectedyaml is not None:
        with open(expectedyaml, "r") as expected:
            outputtxt = output.read()
            expectedtxt = expected.read()
            assert outputtxt == expectedtxt, cleanupFunc()


def compare_tar(expected, output, debug, generated, cleanupFunc):
    if expected is not None:
        tmp_dir = "tmp_tar"
        tar_output = tarfile.open(mode="r:gz", name=output, encoding="utf-8")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        os.mkdir(tmp_dir)
        tar_output.extractall(path=tmp_dir)
        result = filecmp.dircmp(expected, tmp_dir)
        test_left = len(result.left_only)
        test_right = len(result.right_only)
        test_diff = len(result.diff_files)
        shutil.rmtree((tmp_dir))
        assert test_left == 0, cleanupFunc()
        assert test_right == 0, cleanupFunc()
        assert test_diff == 0, cleanupFunc()


def compare_tar_plaintext(expected, output, debug, generated, cleanupFunc):
    if expected is not None:
        tmp_dir = "tmp_tar"
        tar_output = tarfile.open(mode="r:gz", name=output, encoding="utf-8")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        os.mkdir(tmp_dir)
        tar_output.extractall(path=tmp_dir)

        # 1 Load generated *-ConfigMap-aci-operator-config.yaml
        ignore_files_list = []
        prepare_gen_yamls_list = []
        fname_pattern = "-ConfigMap-aci-operator-config.yaml"
        for fname in os.listdir(tmp_dir):
            ignore_files_list.append(fname)
            if fname.endswith(fname_pattern):
                fname = tmp_dir + "/" + fname
                gen_fh = open(fname, "r")
                generated_yaml_file = yml.load_all(gen_fh)
                prepare_gen_yamls_list = convert_aci_op_cm_to_base64(generated_yaml_file)
                break

        # 2 Load expected *-ConfigMap-aci-operator-config.yaml, find aci-operator-config configmap
        #   and convert it to base64 encode format
        prepare_exp_yamls_list = []
        for fname in os.listdir(expected):
            if fname.endswith(fname_pattern):
                fname = expected + "/" + fname
                exp_fh = open(fname, "r")
                expected_yaml_file = yml.load_all(exp_fh)
                prepare_exp_yamls_list = convert_aci_op_cm_to_base64(expected_yaml_file, base64_convert="encode")
                break

        # 3 Load generated *-ConfigMap-aci-operator-config.yaml, find aci-operator-config configmap
        #   and convert it to plaintext and store back to /tmp/generated_operator.tar.gz to be used in fix-testdata.sh
        new_tmp_tar_dir = "/tmp/new_tmp_tar"
        tar_output = tarfile.open(mode="r:gz", name=generated, encoding="utf-8")
        shutil.rmtree(new_tmp_tar_dir, ignore_errors=True)
        os.mkdir(new_tmp_tar_dir)
        tar_output.extractall(path=new_tmp_tar_dir)

        generated_tar_files_list = os.listdir(new_tmp_tar_dir)

        cwd = os.getcwd()
        os.chdir(new_tmp_tar_dir)
        for fname in generated_tar_files_list:
            if fname.endswith(fname_pattern):
                gen_fh = open(fname, "r")
                generated_yaml_file = yml.load_all(gen_fh)
                store_gen_yaml_with_aci_op_cm_as_plain_text = convert_aci_op_cm_to_base64(generated_yaml_file, base64_convert="decode")
                with open(fname, 'w') as fh:
                    yml.dump_all(store_gen_yaml_with_aci_op_cm_as_plain_text, fh)
                break

        os.remove(generated)
        tar = tarfile.open(generated, "w:gz", encoding="utf-8")
        for name in generated_tar_files_list:
            tar.add(name)
        tar.close()

        # 4 Compare generated and expected *-ConfigMap-aci-operator-config.yaml and other files in the tar folder
        assert prepare_gen_yamls_list == prepare_exp_yamls_list, cleanupFunc()

        os.chdir(cwd)
        result = filecmp.dircmp(expected, tmp_dir, ignore=ignore_files_list)
        test_left = len(result.left_only)
        test_right = len(result.right_only)
        test_diff = len(result.diff_files)
        shutil.rmtree(tmp_dir)
        assert test_left == 0, cleanupFunc()
        assert test_right == 0, cleanupFunc()
        assert test_diff == 0, cleanupFunc()


def return_false():
    return False


def run_provision(inpfile, expectedkube=None, expectedtar=None,
                  expectedoperatorcr=None, expectedapic=None, overrides={},
                  cleanupFunc=return_false):
    # Exec main
    with tempfile.NamedTemporaryFile("w+") as output, tempfile.NamedTemporaryFile("w+") as operator_cr_output, tempfile.NamedTemporaryFile("w+") as apicfile, tempfile.NamedTemporaryFile('w+', suffix='.tar.gz') as out_tar:

        args = get_args(config=inpfile, output=output.name, output_tar=out_tar.name, aci_operator_cr=operator_cr_output.name, **overrides)
        acc_provision.main(args, apicfile.name, no_random=True)

        copy_file(expectedkube, output, args.debug, "/tmp/generated_kube.yaml")
        copy_file(expectedoperatorcr, operator_cr_output, args.debug, "/tmp/generated_operator_cr.yaml")
        copy_file(expectedapic, apicfile, args.debug, "/tmp/generated_apic.txt")
        copy_file(expectedtar, out_tar, args.debug, "/tmp/generated_operator.tar.gz")

        if args.compare_kube_yaml_aci_op_cm_in_plain_text:
            result_kube_yaml = compare_kube_yaml(expectedkube, output, args.debug, "/tmp/generated_kube.yaml", cleanupFunc)
            result_op_cr = compare_kube_yaml(expectedoperatorcr, operator_cr_output, args.debug, "/tmp/generated_operator_cr.yaml", cleanupFunc)
            compare_tar_plaintext(expectedtar, out_tar.name, args.debug, "/tmp/generated_operator.tar.gz", cleanupFunc)
            assert result_kube_yaml is True, cleanupFunc()
            assert result_op_cr is True, cleanupFunc()
        else:
            compare_yaml(expectedkube, output, args.debug, "/tmp/generated_kube.yaml", cleanupFunc)
            compare_tar(expectedtar, out_tar.name, args.debug, "/tmp/generated_operator.tar.gz", cleanupFunc)
            compare_yaml(expectedoperatorcr, operator_cr_output, args.debug, "/tmp/generated_operator_cr.yaml", cleanupFunc)

        compare_yaml(expectedapic, apicfile, args.debug, "/tmp/generated_apic.txt", cleanupFunc)


@in_testdir
def test_certificate_generation_kubernetes():
    create_certificate("base_case.inp.yaml", "user.crt", output='temp.yaml', aci_operator_cr='temp_operator_cr.yaml')


@in_testdir
def test_normalize_cidr():
    ipv4 = acc_provision.normalize_cidr('10.8.0.1/16')
    assert ipv4 == '10.8.0.0/16'
    ipv6 = acc_provision.normalize_cidr('2001:db8::8a2e:370:0001/16')
    assert ipv6 == '2001::/16'


def create_certificate(input_file, cert_file, **overrides):
    temp = tempfile.mkdtemp()
    old_working_directory = os.getcwd()
    shutil.copyfile(input_file, temp + '/' + input_file)
    os.chdir(temp)
    try:
        args = get_args(config=input_file, **overrides)
        acc_provision.main(args, no_random=True)
        cert_data = ssl._ssl._test_decode_cert(os.path.join(temp, cert_file))
        assert cert_data['serialNumber'] == '03E8'
        assert cert_data['issuer'][0][0][1] == 'US'
        assert cert_data['issuer'][1][0][1] == 'Cisco Systems'
    finally:
        os.chdir(old_working_directory)
