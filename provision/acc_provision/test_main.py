from __future__ import print_function, unicode_literals

import collections
import filecmp
import functools
import os
import shutil
import ssl
import sys
import tempfile

from . import acc_provision


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
def test_base_case():
    run_provision(
        "base_case.inp.yaml",
        "base_case.kube.yaml",
        "base_case.apic.txt"
    )


@in_testdir
def test_base_case_snat():
    run_provision(
        "base_case_snat.inp.yaml",
        "base_case_snat.kube.yaml",
        "base_case.apic.txt"
    )


@in_testdir
def test_versions_base_case():
    run_provision(
        "version_wrong_url.inp.yaml",
        "base_case.kube.yaml",
        "base_case.apic.txt"
    )


@in_testdir
def test_base_case_ipv6():
    run_provision(
        "base_case_ipv6.inp.yaml",
        "base_case_ipv6.kube.yaml",
        "base_case_ipv6.apic.txt"
    )


@in_testdir
def test_vlan_case():
    run_provision(
        "vlan_case.inp.yaml",
        "vlan_case.kube.yaml",
        "vlan_case.apic.txt"
    )


@in_testdir
def test_nested_vlan():
    run_provision(
        "nested-vlan.inp.yaml",
        "nested-vlan.kube.yaml",
        "nested-vlan.apic.txt"
    )


@in_testdir
def test_nested_vxlan():
    run_provision(
        "nested-vxlan.inp.yaml",
        "nested-vxlan.kube.yaml",
        "nested-vxlan.apic.txt"
    )


@in_testdir
def test_nested_portgroup():
    run_provision(
        "nested-portgroup.inp.yaml",
        "nested-portgroup.kube.yaml",
        "nested-portgroup.apic.txt"
    )


@in_testdir
def test_nested_elag():
    run_provision(
        "nested-elag.inp.yaml",
        "nested-elag.kube.yaml",
        "nested-elag.apic.txt"
    )


@in_testdir
def test_with_comments():
    run_provision(
        "with_comments.inp.yaml",
        "with_comments.kube.yaml",
        "with_comments.apic.txt"
    )


@in_testdir
def test_with_overrides():
    run_provision(
        "with_overrides.inp.yaml",
        "with_overrides.kube.yaml",
        "with_overrides.apic.txt"
    )


@in_testdir
def test_with_tenant_l3out():
    run_provision(
        "with_tenant_l3out.inp.yaml",
        "with_tenant_l3out.kube.yaml",
        "with_tenant_l3out.apic.txt"
    )


@in_testdir
def test_with_interface_mtu():
    run_provision(
        "with_interface_mtu.inp.yaml",
        "with_interface_mtu.kube.yaml",
        "with_interface_mtu.apic.txt"
    )


@in_testdir
def test_with_apic_refreshtime():
    run_provision(
        "with_refreshtime.inp.yaml",
        "with_refreshtime.kube.yaml",
        "base_case.apic.txt",
    )


@in_testdir
def test_with_pbr_tracking_non_snat():
    run_provision(
        "with_pbr_non_snat.inp.yaml",
        "with_pbr_non_snat.kube.yaml",
        "base_case.apic.txt",
    )


@in_testdir
def test_pod_external_access():
    run_provision(
        "pod_ext_access.inp.yaml",
        "pod_ext_access.kube.yaml",
        "pod_ext_access.apic.txt"
    )


@in_testdir
def test_flavor_openshift_39():
    run_provision(
        "base_case.inp.yaml",
        "flavor_openshift.kube.yaml",
        "flavor_openshift.apic.txt",
        overrides={"flavor": "openshift-3.9"}
    )


@in_testdir
def test_flavor_dockerucp_30():
    run_provision(
        "base_case.inp.yaml",
        "base_case.kube.yaml",
        "flavor_dockerucp.apic.txt",
        overrides={"flavor": "docker-ucp-3.0"}
    )


@in_testdir
def test_flavor_cloudfoundry_10():
    run_provision(
        "flavor_cf_10.inp.yaml",
        "flavor_cf_10.cf.yaml",
        "flavor_cf_10.apic.txt",
        overrides={"flavor": "cloudfoundry-1.0"}
    )


@in_testdir
def test_flavor_localhost():
    run_provision(
        "flavor_localhost.inp.yaml",
        "flavor_localhost.kube.yaml",
        None,
        overrides={"flavor": "k8s-localhost"}
    )


@in_testdir
def test_conflicting_infravlan():
    run_provision(
        "conflicting_infravlan.inp.yaml",
        "base_case.kube.yaml",
        "base_case.apic.txt",
        overrides={"infra_vlan": 4093}
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
def test_flavor_cf_devnull_errors():
    with tempfile.NamedTemporaryFile("w+") as tmperr:
        sys.stderr = tmperr
        try:
            args = get_args(flavor="cloudfoundry-1.0")
            print(acc_provision.main(args, no_random=True))
        except SystemExit:
            # expected to exit with errors
            pass
        finally:
            tmperr.flush()
            sys.stderr = sys.__stderr__
            tmperr.seek(0)
        with open("flavor_cf_devnull.stderr.txt", "r") as stderr:
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


def get_args(**overrides):
    arg = {
        "config": None,
        "output": None,
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


def run_provision(inpfile, expectedkube=None, expectedapic=None,
                  overrides={}):
    # Exec main
    with tempfile.NamedTemporaryFile("w+") as output, tempfile.NamedTemporaryFile("w+") as apicfile:
        args = get_args(config=inpfile, output=output.name, **overrides)
        acc_provision.main(args, apicfile.name, no_random=True)
        if expectedkube is not None:
            if args.debug:
                shutil.copyfile(output.name, '/tmp/generated_kube.yaml')
            with open(expectedkube, "r") as expected:
                assert output.read() == expected.read()
        if expectedapic is not None:
            if args.debug:
                shutil.copyfile(apicfile.name, '/tmp/generated_apic.txt')
            with open(expectedapic, "r") as expected:
                assert apicfile.read() == expected.read()


@in_testdir
def test_certificate_generation_kubernetes():
    create_certificate("base_case.inp.yaml", "user.crt", output='temp.yaml')


@in_testdir
def test_certificate_generation_cloud_foundry():
    create_certificate("flavor_cf_10.inp.yaml", "user.crt", output='temp.yaml', flavor="cloudfoundry-1.0")


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
