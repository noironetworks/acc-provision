rm -rf /tmp/generated*
rm -rf /tmp/cluster*
rm -rf /tmp/99*

pushd provision/

python -m pytest acc_provision -x -k test_flavor_cloud_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/cloud_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_cloud.kube.yaml
cp /tmp/cluster-network-* testdata/cloud_tar/
rm -rf /tmp/generated*
rm -rf /tmp/cluster*
rm -rf /tmp/99*
python -m pytest acc_provision -x -k test_flavor_cloud_base

python -m pytest acc_provision -x -k test_flavor_openshift_43
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_43_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_43.kube.yaml
cp /tmp/cluster-network-* testdata/flavor_openshift_43_tar/
cp /tmp/99-* testdata/flavor_openshift_43_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python -m pytest acc_provision -x -k test_flavor_openshift_43

python -m pytest acc_provision -x -k test_flavor_openshift_44_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_44_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_44_esx.kube.yaml
cp /tmp/cluster-network-* testdata/flavor_openshift_44_esx_tar/
cp /tmp/99-* testdata/flavor_openshift_44_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python -m pytest acc_provision -x -k test_flavor_openshift_44_esx

python -m pytest acc_provision -x -k test_flavor_openshift_44_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_44_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_44_openstack.kube.yaml
cp /tmp/cluster-network-* testdata/flavor_openshift_44_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_44_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python -m pytest acc_provision -x -k test_flavor_openshift_44_openstack

python -m pytest acc_provision -x -k test_flavor_openshift_45_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_45_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_45_openstack.kube.yaml
cp /tmp/cluster-network-* testdata/flavor_openshift_45_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_45_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python -m pytest acc_provision -x -k test_flavor_openshift_45_openstack

python -m pytest acc_provision -x -k test_flavor_aks
cp /tmp/generated_kube.yaml testdata/flavor_aks.kube.yaml
python -m pytest acc_provision -x -k test_flavor_aks
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -x -k test_base_case_simple
pushd /tmp/
tar xvf generated_operator.tar.gz
popd
rm testdata/base_case_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/base_case.kube.yaml
cp /tmp/generated_apic.txt testdata/base_case.apic.txt
cp /tmp/generated_operator_cr.yaml testdata/base_case_operator_cr.kube.yaml
cp /tmp/cluster-network-* testdata/base_case_tar/
rm -rf /tmp/generated_*
rm -rf /tmp/cluster*
python -m pytest acc_provision -x -k test_base_case_simple

python -m pytest acc_provision -k test_flavor_openshift_310
cp /tmp/generated_kube.yaml testdata/flavor_openshift_310.kube.yaml
python -m pytest acc_provision -k test_flavor_openshift_310
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_flavor_openshift_311
cp /tmp/generated_kube.yaml testdata/flavor_openshift_311.kube.yaml
python -m pytest acc_provision -k test_flavor_openshift_311
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_with_drop_log
cp /tmp/generated_kube.yaml testdata/with_drop_log.kube.yaml
python -m pytest acc_provision -k test_with_drop_log
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_with_no_drop_log
cp /tmp/generated_kube.yaml testdata/with_no_drop_log.kube.yaml
python -m pytest acc_provision -k test_with_no_drop_log
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_vlan_case
cp /tmp/generated_kube.yaml testdata/vlan_case.kube.yaml
python -m pytest acc_provision -k test_vlan_case
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_with_no_istio
cp /tmp/generated_kube.yaml testdata/with_no_install_istio.kube.yaml
python -m pytest acc_provision -k test_with_no_istio
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_preexisting_tenant
cp /tmp/generated_kube.yaml testdata/with_preexisting_tenant.kube.yaml
python -m pytest acc_provision -k test_preexisting_tenant
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_flavor_dockerucp_30
cp /tmp/generated_kube.yaml testdata/flavor_dockerucp.kube.yaml
python -m pytest acc_provision -k test_flavor_dockerucp_30
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_new_naming_convention_dockerucp
cp /tmp/generated_kube.yaml testdata/with_new_naming_convention_dockerucp.kube.yaml
python -m pytest acc_provision -k test_new_naming_convention_dockerucp
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_new_naming_convention_openshift
cp /tmp/generated_kube.yaml testdata/with_new_naming_convention_openshift.kube.yaml
python -m pytest acc_provision -k test_new_naming_convention_openshift
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_base_case_upgrade
cp /tmp/generated_kube.yaml testdata/base_case_upgrade.kube.yaml
python -m pytest acc_provision -k test_base_case_upgrade
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_sample
cp /tmp/generated_kube.yaml testdata/sample.kube.yaml
python -m pytest acc_provision -k test_sample
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_with_default_profile
cp /tmp/generated_kube.yaml testdata/with_istio_default_profile.kube.yaml
python -m pytest acc_provision -k test_with_default_profile
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_new_naming_convention_simple
cp /tmp/generated_kube.yaml testdata/with_new_naming_convention.kube.yaml
cp /tmp/generated_operator_cr.yaml testdata/with_new_naming_convention_operator_cr.kube.yaml
python -m pytest acc_provision -k test_new_naming_convention_simple
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_with_apic_refreshtime
cp /tmp/generated_kube.yaml testdata/with_refreshtime.kube.yaml
python -m pytest acc_provision -k test_with_apic_refreshtime
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_with_tenant_l3out
cp /tmp/generated_kube.yaml testdata/with_tenant_l3out.kube.yaml
python -m pytest acc_provision -k test_with_tenant_l3out
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_with_interface_mtu
cp /tmp/generated_kube.yaml testdata/with_interface_mtu.kube.yaml
cp /tmp/generated_apic.txt testdata/with_interface_mtu.apic.txt
python -m pytest acc_provision -k test_with_interface_mtu
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_with_overrides
cp /tmp/generated_kube.yaml testdata/with_overrides.kube.yaml
cp /tmp/generated_apic.txt testdata/with_overrides.apic.txt
python -m pytest acc_provision -k test_with_overrides
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_nested_vlan
cp /tmp/generated_kube.yaml testdata/nested-vlan.kube.yaml
cp /tmp/generated_apic.txt testdata/nested-vlan.apic.txt
python -m pytest acc_provision -k test_nested_vlan
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_versions_base_case

python -m pytest acc_provision -k test_nested_portgroup
cp /tmp/generated_kube.yaml testdata/nested-portgroup.kube.yaml
cp /tmp/generated_apic.txt testdata/nested-portgroup.apic.txt
python -m pytest acc_provision -k test_nested_portgroup
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_base_case_ipv6
cp /tmp/generated_kube.yaml testdata/base_case_ipv6.kube.yaml
cp /tmp/generated_apic.txt testdata/base_case_ipv6.apic.txt
python -m pytest acc_provision -k test_base_case_ipv6
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_pod_external_access
cp /tmp/generated_kube.yaml testdata/pod_ext_access.kube.yaml
cp /tmp/generated_apic.txt testdata/pod_ext_access.apic.txt
python -m pytest acc_provision -k test_pod_external_access
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_flavor_localhost
cp /tmp/generated_kube.yaml testdata/flavor_localhost.kube.yaml
python -m pytest acc_provision -k test_flavor_localhost
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_nested_vxlan
cp /tmp/generated_kube.yaml testdata/nested-vxlan.kube.yaml
cp /tmp/generated_apic.txt testdata/nested-vxlan.apic.txt
python -m pytest acc_provision -k test_nested_vxlan
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_nested_elag
cp /tmp/generated_kube.yaml testdata/nested-elag.kube.yaml
cp /tmp/generated_apic.txt testdata/nested-elag.apic.txt
python -m pytest acc_provision -k test_nested_elag
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_base_case_snat
cp /tmp/generated_kube.yaml testdata/base_case_snat.kube.yaml
python -m pytest acc_provision -k test_base_case_snat
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_conflicting_infravlan
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_with_comments
cp /tmp/generated_kube.yaml testdata/with_comments.kube.yaml
cp /tmp/generated_apic.txt testdata/with_comments.apic.txt
python -m pytest acc_provision -k test_with_comments
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python -m pytest acc_provision -k test_with_pbr_tracking_non_snat
cp /tmp/generated_kube.yaml testdata/with_pbr_non_snat.kube.yaml
python -m pytest acc_provision -k test_with_pbr_tracking_non_snat
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

popd
