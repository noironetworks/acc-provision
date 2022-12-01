rm -rf /tmp/generated*
rm -rf /tmp/cluster*
rm -rf /tmp/99*

pushd provision/

python3 -m pytest acc_provision -x -k test_flavor_cloud_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/cloud_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_cloud.kube.yaml
cp /tmp/cluster-network-* testdata/cloud_tar/
rm -rf /tmp/generated*
rm -rf /tmp/cluster*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_cloud_base

python3 -m pytest acc_provision -x -k test_flavor_openshift_43
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_43_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_43.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_43.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_43_tar/
cp /tmp/99-* testdata/flavor_openshift_43_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_43

python3 -m pytest acc_provision -x -k test_flavor_openshift_44_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_44_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_44_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_44_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_44_esx_tar/
cp /tmp/99-* testdata/flavor_openshift_44_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_44_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_44_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_44_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_44_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_44_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_44_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_44_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_44_openstack

python3 -m pytest acc_provision -x -k test_flavor_openshift_45_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_45_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_45_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_45_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_45_esx_tar/
cp /tmp/99-* testdata/flavor_openshift_45_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_45_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_45_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_45_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_45_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_45_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_45_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_45_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_45_openstack

python3 -m pytest acc_provision -x -k test_flavor_openshift_46_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_46_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_46_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_46_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_46_esx_tar/
cp /tmp/99-* testdata/flavor_openshift_46_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_46_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_47_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_47_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_47_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_47_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_47_esx_tar/
cp /tmp/99-* testdata/flavor_openshift_47_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_47_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_48_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_48_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_48_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_48_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_48_esx_tar/
cp /tmp/99-* testdata/flavor_openshift_48_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_48_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_49_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_49_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_49_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_49_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_49_esx_tar/
cp /tmp/99-* testdata/flavor_openshift_49_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_49_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_410_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_410_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_410_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_410_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_410_esx_tar/
cp /tmp/99-* testdata/flavor_openshift_410_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_410_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_411_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_411_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_411_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_411_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_411_esx_tar/
cp /tmp/99-* testdata/flavor_openshift_411_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_411_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_46_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_46_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_46_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_46_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_46_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_46_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_46_openstack

python3 -m pytest acc_provision -x -k test_flavor_openshift_47_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_47_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_47_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_47_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_47_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_47_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_47_openstack

python3 -m pytest acc_provision -x -k test_flavor_openshift_48_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_48_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_48_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_48_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_48_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_48_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_48_openstack

python3 -m pytest acc_provision -x -k test_flavor_openshift_49_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_49_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_49_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_49_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_49_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_49_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_49_openstack

python3 -m pytest acc_provision -x -k test_flavor_openshift_410_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_410_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_410_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_410_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_410_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_410_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_410_openstack

python3 -m pytest acc_provision -x -k test_flavor_openshift_411_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_411_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_411_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_411_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_411_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_411_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_411_openstack

python3 -m pytest acc_provision -x -k test_flavor_aks
cp /tmp/generated_kube.yaml testdata/flavor_aks.kube.yaml
python3 -m pytest acc_provision -x -k test_flavor_aks
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -x -k test_flavor_eks_base
cp /tmp/generated_kube.yaml testdata/flavor_eks.kube.yaml
python3 -m pytest acc_provision -x -k test_flavor_eks_base
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -x -k test_base_case_simple
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
python3 -m pytest acc_provision -x -k test_base_case_simple

python3 -m pytest acc_provision -k test_base_case_upgrade
cp /tmp/generated_kube.yaml testdata/base_case_upgrade.kube.yaml
python3 -m pytest acc_provision -k test_base_case_upgrade
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_2_3_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_2_3_tar/*.yaml
cp /tmp/cluster-network-* testdata/flavor_RKE_1_2_3_tar/
cp /tmp/99-* testdata/flavor_RKE_1_2_3_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_2_3_base

python3 -m pytest acc_provision -k test_flavor_openshift_310
cp /tmp/generated_kube.yaml testdata/flavor_openshift_310.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_310.apic.txt
python3 -m pytest acc_provision -k test_flavor_openshift_310
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_flavor_openshift_311
cp /tmp/generated_kube.yaml testdata/flavor_openshift_311.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_311.apic.txt
python3 -m pytest acc_provision -k test_flavor_openshift_311
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_with_drop_log
cp /tmp/generated_kube.yaml testdata/with_drop_log.kube.yaml
python3 -m pytest acc_provision -k test_with_drop_log
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_with_no_drop_log
cp /tmp/generated_kube.yaml testdata/with_no_drop_log.kube.yaml
python3 -m pytest acc_provision -k test_with_no_drop_log
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_vlan_case
cp /tmp/generated_kube.yaml testdata/vlan_case.kube.yaml
cp /tmp/generated_apic.txt testdata/vlan_case.apic.txt
python3 -m pytest acc_provision -k test_vlan_case
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_with_no_istio
cp /tmp/generated_kube.yaml testdata/with_no_install_istio.kube.yaml
python3 -m pytest acc_provision -k test_with_no_istio
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_preexisting_tenant
cp /tmp/generated_kube.yaml testdata/with_preexisting_tenant.kube.yaml
cp /tmp/generated_apic.txt testdata/with_preexisting_tenant.apic.txt
python3 -m pytest acc_provision -k test_preexisting_tenant
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_flavor_dockerucp_30
cp /tmp/generated_kube.yaml testdata/flavor_dockerucp.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_dockerucp.apic.txt
python3 -m pytest acc_provision -k test_flavor_dockerucp_30
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_new_naming_convention_dockerucp
cp /tmp/generated_kube.yaml testdata/with_new_naming_convention_dockerucp.kube.yaml
cp /tmp/generated_apic.txt testdata/with_new_naming_convention_dockerucp.apic.txt
python3 -m pytest acc_provision -k test_new_naming_convention_dockerucp
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_new_naming_convention_openshift
cp /tmp/generated_kube.yaml testdata/with_new_naming_convention_openshift.kube.yaml
cp /tmp/generated_apic.txt testdata/with_new_naming_convention_openshift.apic.txt
python3 -m pytest acc_provision -k test_new_naming_convention_openshift
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_sample
cp /tmp/generated_kube.yaml testdata/sample.kube.yaml
python3 -m pytest acc_provision -k test_sample
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_with_default_profile
cp /tmp/generated_kube.yaml testdata/with_istio_default_profile.kube.yaml
python3 -m pytest acc_provision -k test_with_default_profile
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_new_naming_convention_simple
cp /tmp/generated_kube.yaml testdata/with_new_naming_convention.kube.yaml
cp /tmp/generated_apic.txt testdata/with_new_naming_convention.apic.txt
cp /tmp/generated_operator_cr.yaml testdata/with_new_naming_convention_operator_cr.kube.yaml
python3 -m pytest acc_provision -k test_new_naming_convention_simple
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_with_apic_refreshtime
cp /tmp/generated_kube.yaml testdata/with_refreshtime.kube.yaml
python3 -m pytest acc_provision -k test_with_apic_refreshtime
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_with_tenant_l3out
cp /tmp/generated_kube.yaml testdata/with_tenant_l3out.kube.yaml
cp /tmp/generated_apic.txt testdata/with_tenant_l3out.apic.txt
python3 -m pytest acc_provision -k test_with_tenant_l3out
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -x -k "test_with_interface_mtu and not test_with_interface_mtu_headroom"
cp /tmp/generated_kube.yaml testdata/with_interface_mtu.kube.yaml
cp /tmp/generated_apic.txt testdata/with_interface_mtu.apic.txt
python3 -m pytest acc_provision -x -k "test_with_interface_mtu and not test_with_interface_mtu_headroom"
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_with_interface_mtu_headroom
cp /tmp/generated_kube.yaml testdata/with_interface_mtu_headroom.kube.yaml
cp /tmp/generated_apic.txt testdata/with_interface_mtu_headroom.apic.txt
python3 -m pytest acc_provision -k test_with_interface_mtu_headroom
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_with_overrides
cp /tmp/generated_kube.yaml testdata/with_overrides.kube.yaml
cp /tmp/generated_apic.txt testdata/with_overrides.apic.txt
python3 -m pytest acc_provision -k test_with_overrides
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_with_wait_for_timer
cp /tmp/generated_kube.yaml testdata/with_wait_for_network.kube.yaml
cp /tmp/generated_apic.txt testdata/with_wait_for_network.apic.txt
python3 -m pytest acc_provision -k test_with_wait_for_timer
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_nested_vlan
cp /tmp/generated_kube.yaml testdata/nested-vlan.kube.yaml
cp /tmp/generated_apic.txt testdata/nested-vlan.apic.txt
python3 -m pytest acc_provision -k test_nested_vlan
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_versions_base_case

python3 -m pytest acc_provision -k test_nested_portgroup
cp /tmp/generated_kube.yaml testdata/nested-portgroup.kube.yaml
cp /tmp/generated_apic.txt testdata/nested-portgroup.apic.txt
python3 -m pytest acc_provision -k test_nested_portgroup
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_base_case_ipv6
cp /tmp/generated_kube.yaml testdata/base_case_ipv6.kube.yaml
cp /tmp/generated_apic.txt testdata/base_case_ipv6.apic.txt
python3 -m pytest acc_provision -k test_base_case_ipv6
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_pod_external_access
cp /tmp/generated_kube.yaml testdata/pod_ext_access.kube.yaml
cp /tmp/generated_apic.txt testdata/pod_ext_access.apic.txt
python3 -m pytest acc_provision -k test_pod_external_access
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_enable_opflex_agent_prometheus
cp /tmp/generated_kube.yaml testdata/enable_opflex_agent_prometheus.kube.yaml
cp /tmp/generated_apic.txt testdata/enable_opflex_agent_prometheus.apic.txt
python3 -m pytest acc_provision -k test_enable_opflex_agent_prometheus
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_flavor_localhost
cp /tmp/generated_kube.yaml testdata/flavor_localhost.kube.yaml
python3 -m pytest acc_provision -k test_flavor_localhost
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_nested_vxlan
cp /tmp/generated_kube.yaml testdata/nested-vxlan.kube.yaml
cp /tmp/generated_apic.txt testdata/nested-vxlan.apic.txt
python3 -m pytest acc_provision -k test_nested_vxlan
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_nested_elag
cp /tmp/generated_kube.yaml testdata/nested-elag.kube.yaml
cp /tmp/generated_apic.txt testdata/nested-elag.apic.txt
python3 -m pytest acc_provision -k test_nested_elag
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_base_case_snat
cp /tmp/generated_kube.yaml testdata/base_case_snat.kube.yaml
python3 -m pytest acc_provision -k test_base_case_snat
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_conflicting_infravlan
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_with_comments
cp /tmp/generated_kube.yaml testdata/with_comments.kube.yaml
cp /tmp/generated_apic.txt testdata/with_comments.apic.txt
python3 -m pytest acc_provision -k test_with_comments
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_with_pbr_tracking_non_snat
cp /tmp/generated_kube.yaml testdata/with_pbr_non_snat.kube.yaml
python3 -m pytest acc_provision -k test_with_pbr_tracking_non_snat
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_sriov_config
cp /tmp/generated_kube.yaml testdata/with_sriov_config_kube.yaml
python3 -m pytest acc_provision -k test_sriov_config
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_no_sriov_config
cp /tmp/generated_kube.yaml testdata/with_no_sriov_config_kube.yaml
python3 -m pytest acc_provision -k test_no_sriov_config
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99

python3 -m pytest acc_provision -k test_no_dpu_config
cp /tmp/generated_kube.yaml testdata/with_no_dpu_config_kube.yaml
python3 -m pytest acc_provision -k test_no_dpu_config
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99

python3 -m pytest acc_provision -k test_dpu_config
cp /tmp/generated_kube.yaml testdata/with_dpu_config_kube.yaml
python3 -m pytest acc_provision -k test_dpu_config
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99

python3 -m pytest acc_provision -k test_sriov_with_no_deviceinfo
cp /tmp/generated_kube.yaml testdata/with_sriov_config_no_deviceinfo_kube.yaml
python3 -m pytest acc_provision -k test_sriov_with_no_deviceinfo
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99

python3 -m pytest acc_provision -x -k test_flavor_openshift_411_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_411_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_411_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_411_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_411_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_411_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_411_baremetal

python3 -m pytest acc_provision -x -k test_flavor_openshift_410_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_410_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_410_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_410_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_410_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_410_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_410_baremetal

python3 -m pytest acc_provision -x -k test_flavor_openshift_49_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_49_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_49_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_49_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_49_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_49_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_49_baremetal

python3 -m pytest acc_provision -x -k test_flavor_openshift_48_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_48_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_48_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_48_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_48_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_48_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_48_baremetal

python3 -m pytest acc_provision -x -k test_flavor_openshift_47_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_47_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_47_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_47_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_47_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_47_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_47_baremetal

python3 -m pytest acc_provision -x -k test_flavor_openshift_46_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_46_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_46_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_46_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_46_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_46_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_46_baremetal

python3 -m pytest acc_provision -k test_base_case_operator_mode
cp /tmp/generated_kube.yaml testdata/base_case_operator_mode.kube.yaml
python3 -m pytest acc_provision -k test_base_case_operator_mode
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -x -k test_flavor_calico_3_23_2 
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_calico-3.23.2_tar/*.yaml
cp /tmp/generated_apic.txt testdata/flavor_calico-3.23.2.apic.txt
cp /tmp/cluster-network-* testdata/flavor_calico-3.23.2_tar/
cp /tmp/custom_resources_aci_calico.yaml testdata/flavor_calico-3.23.2_tar/
cp /tmp/custom_resources_calicoctl.yaml testdata/flavor_calico-3.23.2_tar/
cp /tmp/tigera_operator.yaml testdata/flavor_calico-3.23.2_tar/
rm -rf /tmp/generated*
python3 -m pytest acc_provision -x -k test_flavor_calico_3_23_2

python3 -m pytest acc_provision -x -k test_flavor_calico_3_23_2_base_case 
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_calico-3.23.2_base_case_tar/*.yaml
cp /tmp/generated_apic.txt testdata/flavor_calico-3.23.2_base_case.apic.txt
cp /tmp/cluster-network-* testdata/flavor_calico-3.23.2_base_case_tar/
cp /tmp/custom_resources_aci_calico.yaml testdata/flavor_calico-3.23.2_base_case_tar/
cp /tmp/custom_resources_calicoctl.yaml testdata/flavor_calico-3.23.2_base_case_tar/
cp /tmp/tigera_operator.yaml testdata/flavor_calico-3.23.2_base_case_tar/
rm -rf /tmp/generated*
python3 -m pytest acc_provision -x -k test_flavor_calico_3_23_2_base_case 

python3 -m pytest acc_provision -x -k test_flavor_calico_3_23_2_overrides  
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_calico-3.23.2_overrides_tar/*.yaml
cp /tmp/generated_apic.txt testdata/flavor_calico-3.23.2_overrides.apic.txt
cp /tmp/cluster-network-* testdata/flavor_calico-3.23.2_overrides_tar/
cp /tmp/custom_resources_aci_calico.yaml testdata/flavor_calico-3.23.2_overrides_tar/
cp /tmp/custom_resources_calicoctl.yaml testdata/flavor_calico-3.23.2_overrides_tar/
cp /tmp/tigera_operator.yaml testdata/flavor_calico-3.23.2_overrides_tar/
rm -rf /tmp/generated*
python3 -m pytest acc_provision -x -k test_flavor_calico_3_23_2_overrides

popd
