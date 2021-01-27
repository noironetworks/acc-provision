from __future__ import print_function, unicode_literals

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


from . import acc_provision
from . import fake_apic


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
        overrides={"flavor": "k8s-localhost"}
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
def test_flavor_cloud_delete():
    with open("apic_delete_data.json") as data_file:
        data = json.loads(data_file.read())
    apic = fake_apic.start_fake_apic(50000, data["gets"], data["deletes"])

    def clean_apic():
        apic.shutdown()
        return False

    assert(len(fake_apic.fake_deletes) != 0)
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
    assert(len(fake_apic.fake_deletes) == 0)


@in_testdir
def test_flavor_aks_delete():
    with open("apic_aks_delete_data.json") as data_file:
        data = json.loads(data_file.read())
    apic = fake_apic.start_fake_apic(50001, data["gets"], data["deletes"])

    def clean_apic():
        apic.shutdown()
        return False

    assert(len(fake_apic.fake_deletes) != 0)
    run_provision(
        "flavor_aks.inp.yaml",
        None,
        None,
        None,
        overrides={"flavor": "aks", "apic": True, "password": "test", "delete": True}, cleanupFunc=clean_apic
    )
    apic.shutdown()
    # verify all deletes were executed
    assert(len(fake_apic.fake_deletes) == 0)


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
def test_with_drop_log():
    run_provision(
        "with_drop_log.inp.yaml",
        "with_drop_log.kube.yaml",
        None,
        None,
        "base_case.apic.txt"
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
    run_provision(
        "flavor_RKE_1_2_3.inp2.yaml",
        "flavor_RKE_1_2_3.rke2.yaml",
        None,
        None,
        "flavor_RKE_1_2_3.apic2.txt",
        overrides={"flavor": "RKE-1.2.3"}
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
        "flavor": "kubernetes-1.15",
        "version_token": "dummy",
        "release": False,
        "test_data_out": None,
        "skip_kafka_certs": True,
        "upgrade": False,
        "disable_multus": 'true',
        # infra_vlan is not part of command line input, but we do
        # pass it as a command line arg in unit tests to pass in
        # configuration which would otherwise be discovered from
        # the APIC
        "infra_vlan": None,
    }
    argc = collections.namedtuple('argc', list(arg.keys()))
    args = argc(**arg)
    args = args._replace(**overrides)
    return args


def copy_file(expectedyaml, output, debug, generated):
    if expectedyaml is not None:
        if debug:
            shutil.copyfile(output.name, generated)


def compare_yaml(expectedyaml, output, debug, generated, cleanupFunc):
    if expectedyaml is not None:
        with open(expectedyaml, "r") as expected:
            assert output.read() == expected.read(), cleanupFunc()


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

        compare_yaml(expectedkube, output, args.debug, "/tmp/generated_kube.yaml", cleanupFunc)
        compare_yaml(expectedoperatorcr, operator_cr_output, args.debug, "/tmp/generated_operator_cr.yaml", cleanupFunc)
        compare_yaml(expectedapic, apicfile, args.debug, "/tmp/generated_apic.txt", cleanupFunc)
        compare_tar(expectedtar, out_tar.name, args.debug, "/tmp/generated_operator.tar.gz", cleanupFunc)


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
