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

python3 -m pytest acc_provision -x -k test_flavor_openshift_414_agent_based_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_414_agent_based_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_414_agent_based_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_414_agent_based_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_414_agent_based_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_414_agent_based_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_414_agent_based_baremetal



python3 -m pytest acc_provision -x -k test_flavor_openshift_414_agent_based_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_414_agent_based_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_414_agent_based_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_414_agent_based_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_414_agent_based_esx_tar/
cp /tmp/99-* testdata/flavor_openshift_414_agent_based_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_414_agent_based_esx

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
cp /tmp/apic.json testdata/flavor_openshift_44_esx_tar/apic.json
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
cp /tmp/apic.json testdata/flavor_openshift_45_esx_tar/apic.json
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
cp /tmp/apic.json testdata/flavor_openshift_46_esx_tar/apic.json
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
cp /tmp/apic.json testdata/flavor_openshift_47_esx_tar/apic.json
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
cp /tmp/apic.json testdata/flavor_openshift_48_esx_tar/apic.json
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
cp /tmp/apic.json testdata/flavor_openshift_49_esx_tar/apic.json
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
cp /tmp/apic.json testdata/flavor_openshift_410_esx_tar/apic.json
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
cp /tmp/apic.json testdata/flavor_openshift_411_esx_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_411_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_411_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_412_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_412_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_412_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_412_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_412_esx_tar/
cp /tmp/apic.json testdata/flavor_openshift_412_esx_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_412_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_412_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_413_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_413_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_413_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_413_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_413_esx_tar/
cp /tmp/apic.json testdata/flavor_openshift_413_esx_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_413_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_413_esx

python3 -m pytest acc_provision -x -k test_flv_openshift_414_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_414_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_414_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_414_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_414_esx_tar/
cp /tmp/apic.json testdata/flavor_openshift_414_esx_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_414_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flv_openshift_414_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_415_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_415_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_415_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_415_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_415_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_415_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_415_baremetal


python3 -m pytest acc_provision -x -k test_flavor_openshift_415_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_415_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_415_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_415_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_415_esx_tar/
cp /tmp/apic.json testdata/flavor_openshift_415_esx_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_415_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_415_esx

python3 -m pytest acc_provision -x -k test_flavor_openshift_415_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_415_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_415_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_415_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_415_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_415_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_415_openstack

python3 -m pytest acc_provision -x -k test_flavor_openshift_414_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_414_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_414_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_414_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_414_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_414_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_414_openstack

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

python3 -m pytest acc_provision -x -k test_flavor_openshift_412_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_412_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_412_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_412_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_412_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_412_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_412_openstack

python3 -m pytest acc_provision -x -k test_flavor_openshift_413_openstack
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_413_openstack_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_413_openstack.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_413_openstack.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_413_openstack_tar/
cp /tmp/99-* testdata/flavor_openshift_413_openstack_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_413_openstack


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

python3 -m pytest acc_provision -x -k test_flavor_RKE2_kubernetes_1_24_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE2_kubernetes_1_24_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE2_kubernetes_1_24.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE2_kubernetes_1_24.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_RKE2_kubernetes_1_24_tar/
cp /tmp/99-* testdata/flavor_RKE2_kubernetes_1_24_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE2_kubernetes_1_24_base

python3 -m pytest acc_provision -x -k test_flavor_RKE2_kubernetes_1_25_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE2_kubernetes_1_25_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE2_kubernetes_1_25.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE2_kubernetes_1_25.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_RKE2_kubernetes_1_25_tar/
cp /tmp/99-* testdata/flavor_RKE2_kubernetes_1_25_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE2_kubernetes_1_25_base

python3 -m pytest acc_provision -x -k test_flavor_RKE2_kubernetes_1_26_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE2_kubernetes_1_26_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE2_kubernetes_1_26.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE2_kubernetes_1_26.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_RKE2_kubernetes_1_26_tar/
cp /tmp/99-* testdata/flavor_RKE2_kubernetes_1_26_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE2_kubernetes_1_26_base

python3 -m pytest acc_provision -x -k test_flavor_RKE2_kubernetes_1_27_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE2_kubernetes_1_27_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE2_kubernetes_1_27.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE2_kubernetes_1_27.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_RKE2_kubernetes_1_27_tar/
cp /tmp/99-* testdata/flavor_RKE2_kubernetes_1_27_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE2_kubernetes_1_27_base

python3 -m pytest acc_provision -x -k test_flavor_RKE2_kubernetes_1_28_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE2_kubernetes_1_28_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE2_kubernetes_1_28.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE2_kubernetes_1_28.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_RKE2_kubernetes_1_28_tar/
cp /tmp/99-* testdata/flavor_RKE2_kubernetes_1_28_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE2_kubernetes_1_28_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_2_3_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_2_3_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_2_3.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_2_3.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_2_3_tar/
cp /tmp/99-* testdata/flavor_RKE_1_2_3_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_2_3_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_13_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_3_13_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_3_13.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_3_13.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_3_13_tar/
cp /tmp/99-* testdata/flavor_RKE_1_3_13_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_13_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_17_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_3_17_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_3_17.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_3_17.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_3_17_tar/
cp /tmp/99-* testdata/flavor_RKE_1_3_17_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_17_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_18_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_3_18_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_3_18.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_3_18.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_3_18_tar/
cp /tmp/99-* testdata/flavor_RKE_1_3_18_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_18_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_20_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_3_20_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_3_20.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_3_20.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_3_20_tar/
cp /tmp/99-* testdata/flavor_RKE_1_3_20_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_20_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_21_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_3_21_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_3_21.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_3_21.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_3_21_tar/
cp /tmp/99-* testdata/flavor_RKE_1_3_21_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_21_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_4_6_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_4_6_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_4_6.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_4_6.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_4_6_tar/
cp /tmp/99-* testdata/flavor_RKE_1_4_6_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_4_6_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_24_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_3_24_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_3_24.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_3_24.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_3_24_tar/
cp /tmp/99-* testdata/flavor_RKE_1_3_24_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_3_24_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_4_9_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_4_9_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_4_9.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_4_9.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_4_9_tar/
cp /tmp/99-* testdata/flavor_RKE_1_4_9_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_4_9_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_4_13_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_4_13_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_4_13.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_4_13.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_4_13_tar/
cp /tmp/99-* testdata/flavor_RKE_1_4_13_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_4_13_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_4_16_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_4_16_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_4_16.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_4_16.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_4_16_tar/
cp /tmp/99-* testdata/flavor_RKE_1_4_16_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_4_16_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_4_20_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_4_20_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_4_20.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_4_20.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_4_20_tar/
cp /tmp/99-* testdata/flavor_RKE_1_4_20_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_4_20_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_5_3_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_5_3_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_5_3.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_5_3.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_5_3_tar/
cp /tmp/99-* testdata/flavor_RKE_1_5_3_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_5_3_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_5_6_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_5_6_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_5_6.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_5_6.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_5_6_tar/
cp /tmp/99-* testdata/flavor_RKE_1_5_6_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_5_6_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_5_11_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_5_11_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_5_11.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_5_11.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_5_11_tar/
cp /tmp/99-* testdata/flavor_RKE_1_5_11_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_5_11_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_5_12_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_5_12_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_5_12.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_5_12.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_5_12_tar/
cp /tmp/99-* testdata/flavor_RKE_1_5_12_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_5_12_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_6_0_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_6_0_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_6_0.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_6_0.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_6_0_tar/
cp /tmp/99-* testdata/flavor_RKE_1_6_0_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_6_0_base

python3 -m pytest acc_provision -x -k test_flavor_RKE_1_6_1_base
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_RKE_1_6_1_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_RKE_1_6_1.rke.yaml
cp /tmp/generated_apic.txt testdata/flavor_RKE_1_6_1.apic.txt
cp /tmp/cluster-network-* testdata/flavor_RKE_1_6_1_tar/
cp /tmp/99-* testdata/flavor_RKE_1_6_1_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_RKE_1_6_1_base

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

python3 -m pytest acc_provision -k test_multiple_subnets
cp /tmp/generated_kube.yaml testdata/multiple_subnets.kube.yaml
cp /tmp/generated_apic.txt testdata/multiple_subnets.apic.txt
python3 -m pytest acc_provision -k test_multiple_subnets
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_dualstack_base
cp /tmp/generated_kube.yaml testdata/dualstack_base.kube.yaml
cp /tmp/generated_apic.txt testdata/dualstack_base.apic.txt
python3 -m pytest acc_provision -k test_dualstack_base
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_dualstack_only_ipv4
cp /tmp/generated_kube.yaml testdata/dualstack_only_ipv4.kube.yaml
cp /tmp/generated_apic.txt testdata/dualstack_only_ipv4.apic.txt
python3 -m pytest acc_provision -k test_dualstack_only_ipv4
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_dualstack_node_subnet
cp /tmp/generated_kube.yaml testdata/dualstack_node_subnet.kube.yaml
cp /tmp/generated_apic.txt testdata/dualstack_node_subnet.apic.txt
python3 -m pytest acc_provision -k test_dualstack_node_subnet
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_dualstack_pod_and_node_subnet
cp /tmp/generated_kube.yaml testdata/dualstack_pod_and_node_subnet.kube.yaml
cp /tmp/generated_apic.txt testdata/dualstack_pod_and_node_subnet.apic.txt
python3 -m pytest acc_provision -k test_dualstack_pod_and_node_subnet
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_dualstack_extern_static
cp /tmp/generated_kube.yaml testdata/dualstack_extern_static.kube.yaml
cp /tmp/generated_apic.txt testdata/dualstack_extern_static.apic.txt
python3 -m pytest acc_provision -k test_dualstack_extern_static
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

python3 -m pytest acc_provision -k test_dualstack_extern_dynamic
cp /tmp/generated_kube.yaml testdata/dualstack_extern_dynamic.kube.yaml
cp /tmp/generated_apic.txt testdata/dualstack_extern_dynamic.apic.txt
python3 -m pytest acc_provision -k test_dualstack_extern_dynamic
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

python3 -m pytest acc_provision -x -k test_flv_openshift_414_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_414_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_414_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_414_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_414_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_414_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flv_openshift_414_baremetal

python3 -m pytest acc_provision -x -k test_flavor_openshift_413_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_413_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_413_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_413_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_413_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_413_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_413_baremetal

python3 -m pytest acc_provision -x -k test_flavor_openshift_412_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_412_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_412_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_412_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_412_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_412_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_412_baremetal

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

python3 -m pytest acc_provision -x -k test_flavor_calico_3_26_3
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_calico-3.26.3_tar/*.yaml
cp /tmp/generated_apic.txt testdata/flavor_calico-3.26.3.apic.txt
cp /tmp/custom_resources_aci_calico.yaml testdata/flavor_calico-3.26.3_tar/
cp /tmp/custom_resources_calicoctl.yaml testdata/flavor_calico-3.26.3_tar/
cp /tmp/tigera_operator.yaml testdata/flavor_calico-3.26.3_tar/
python3 -m pytest acc_provision -x -k test_flavor_calico_3_26_3
rm -rf /tmp/generated*
rm -rf /tmp/cluster*
rm -rf /tmp/custom*
rm -rf /tmp/tigera*


python3 -m pytest acc_provision -x -k test_flvr_calico_3_26_3_multiple_vrf_uc1
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_calico_3.26.3_multiple_vrf_uc1_tar/*.yaml
cp /tmp/generated_apic.txt testdata/flavor_calico_3.26.3_multiple_vrf_uc1.apic.txt
cp /tmp/custom_resources_aci_calico.yaml testdata/flavor_calico_3.26.3_multiple_vrf_uc1_tar
cp /tmp/custom_resources_calicoctl.yaml testdata/flavor_calico_3.26.3_multiple_vrf_uc1_tar
cp /tmp/tigera_operator.yaml testdata/flavor_calico_3.26.3_multiple_vrf_uc1_tar
python3 -m pytest acc_provision -x -k test_flvr_calico_3_26_3_multiple_vrf_uc1
rm -rf /tmp/generated*
rm -rf /tmp/cluster*
rm -rf /tmp/custom*
rm -rf /tmp/tigera*

python3 -m pytest acc_provision -x -k test_flvr_calico_3_26_3_multiple_vrf_uc2
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_calico_3.26.3_multiple_vrf_uc2_tar/*.yaml
cp /tmp/generated_apic.txt testdata/flavor_calico_3.26.3_multiple_vrf_uc2.apic.txt
cp /tmp/custom_resources_aci_calico.yaml testdata/flavor_calico_3.26.3_multiple_vrf_uc2_tar
cp /tmp/custom_resources_calicoctl.yaml testdata/flavor_calico_3.26.3_multiple_vrf_uc2_tar
cp /tmp/tigera_operator.yaml testdata/flavor_calico_3.26.3_multiple_vrf_uc2_tar
python3 -m pytest acc_provision -x -k test_flvr_calico_3_26_3_multiple_vrf_uc2
rm -rf /tmp/generated*
rm -rf /tmp/cluster*
rm -rf /tmp/custom*
rm -rf /tmp/tigera*

python3 -m pytest acc_provision -x -k test_flvr_calico_3_26_3_multiple_vrf_uc3
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_calico_3.26.3_multiple_vrf_uc3_tar/*.yaml
cp /tmp/generated_apic.txt testdata/flavor_calico_3.26.3_multiple_vrf_uc3.apic.txt
cp /tmp/custom_resources_aci_calico.yaml testdata/flavor_calico_3.26.3_multiple_vrf_uc3_tar
cp /tmp/custom_resources_calicoctl.yaml testdata/flavor_calico_3.26.3_multiple_vrf_uc3_tar
cp /tmp/tigera_operator.yaml testdata/flavor_calico_3.26.3_multiple_vrf_uc3_tar
python3 -m pytest acc_provision -x -k test_flvr_calico_3_26_3_multiple_vrf_uc3
rm -rf /tmp/generated*
rm -rf /tmp/cluster*
rm -rf /tmp/custom*
rm -rf /tmp/tigera*

python3 -m pytest acc_provision -x -k test_flavor_with_cluster_svc_export_calico_3_26_3
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_with_cluster_svc_export_calico-3.26.3_tar/*.yaml
cp /tmp/generated_apic.txt testdata/flavor_with_cluster_svc_export_calico-3.26.3.apic.txt
cp /tmp/custom_resources_aci_calico.yaml testdata/flavor_with_cluster_svc_export_calico-3.26.3_tar/
cp /tmp/custom_resources_calicoctl.yaml testdata/flavor_with_cluster_svc_export_calico-3.26.3_tar/
cp /tmp/tigera_operator.yaml testdata/flavor_with_cluster_svc_export_calico-3.26.3_tar/
python3 -m pytest acc_provision -x -k test_flavor_with_cluster_svc_export_calico_3_26_3
rm -rf /tmp/generated*
rm -rf /tmp/cluster*
rm -rf /tmp/custom*
rm -rf /tmp/tigera*


python3 -m pytest acc_provision -x -k test_flvr_openshift_44_esx_vDS_6_6_above
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_44_esx_vDS_6_6_above_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_44_esx_vDS_6_6_above.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_44_esx_vDS_6_6_above.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_44_esx_vDS_6_6_above_tar/
cp /tmp/apic.json testdata/flavor_openshift_44_esx_vDS_6_6_above_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_44_esx_vDS_6_6_above_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flvr_openshift_44_esx_vDS_6_6_above

python3 -m pytest acc_provision -x -k test_flvr_openshift_45_esx_vDS_6_6_above
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_45_esx_vDS_6_6_above_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_45_esx_vDS_6_6_above.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_45_esx_vDS_6_6_above.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_45_esx_vDS_6_6_above_tar/
cp /tmp/apic.json testdata/flavor_openshift_45_esx_vDS_6_6_above_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_45_esx_vDS_6_6_above_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flvr_openshift_45_esx_vDS_6_6_above

python3 -m pytest acc_provision -x -k test_flvr_openshift_46_esx_vDS_6_6_above
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_46_esx_vDS_6_6_above_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_46_esx_vDS_6_6_above.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_46_esx_vDS_6_6_above.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_46_esx_vDS_6_6_above_tar/
cp /tmp/apic.json testdata/flavor_openshift_46_esx_vDS_6_6_above_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_46_esx_vDS_6_6_above_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flvr_openshift_46_esx_vDS_6_6_above

python3 -m pytest acc_provision -x -k test_flvr_openshift_47_esx_vDS_6_6_above
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_47_esx_vDS_6_6_above_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_47_esx_vDS_6_6_above.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_47_esx_vDS_6_6_above.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_47_esx_vDS_6_6_above_tar/
cp /tmp/apic.json testdata/flavor_openshift_47_esx_vDS_6_6_above_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_47_esx_vDS_6_6_above_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flvr_openshift_47_esx_vDS_6_6_above

python3 -m pytest acc_provision -x -k test_flvr_openshift_48_esx_vDS_6_6_above
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_48_esx_vDS_6_6_above_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_48_esx_vDS_6_6_above.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_48_esx_vDS_6_6_above.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_48_esx_vDS_6_6_above_tar/
cp /tmp/apic.json testdata/flavor_openshift_48_esx_vDS_6_6_above_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_48_esx_vDS_6_6_above_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flvr_openshift_48_esx_vDS_6_6_above

python3 -m pytest acc_provision -x -k test_flvr_openshift_49_esx_vDS_6_6_above
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_49_esx_vDS_6_6_above_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_49_esx_vDS_6_6_above.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_49_esx_vDS_6_6_above.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_49_esx_vDS_6_6_above_tar/
cp /tmp/apic.json testdata/flavor_openshift_49_esx_vDS_6_6_above_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_49_esx_vDS_6_6_above_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flvr_openshift_49_esx_vDS_6_6_above

python3 -m pytest acc_provision -x -k test_flvr_openshift_410_esx_vDS_6_6_above
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_410_esx_vDS_6_6_above_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_410_esx_vDS_6_6_above.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_410_esx_vDS_6_6_above.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_410_esx_vDS_6_6_above_tar/
cp /tmp/apic.json testdata/flavor_openshift_410_esx_vDS_6_6_above_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_410_esx_vDS_6_6_above_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flvr_openshift_410_esx_vDS_6_6_above

python3 -m pytest acc_provision -x -k test_flvr_openshift_411_esx_vDS_6_6_above
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_411_esx_vDS_6_6_above_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_411_esx_vDS_6_6_above.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_411_esx_vDS_6_6_above.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_411_esx_vDS_6_6_above_tar/
cp /tmp/apic.json testdata/flavor_openshift_411_esx_vDS_6_6_above_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_411_esx_vDS_6_6_above_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flvr_openshift_411_esx_vDS_6_6_above

python3 -m pytest acc_provision -x -k test_flavor_openshift_sdn_ovn_baremetal
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flavor_openshift_sdn_ovn_baremetal_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_sdn_ovn_baremetal.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_sdn_ovn_baremetal.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_sdn_ovn_baremetal_tar/
cp /tmp/99-* testdata/flavor_openshift_sdn_ovn_baremetal_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_sdn_ovn_baremetal

python3 -m pytest acc_provision -x -k test_flvr_openshift_sdn_ovn_baremetal_primary
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flvr_openshift_sdn_ovn_baremetal_primary_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flvr_openshift_sdn_ovn_baremetal_primary.kube.yaml
cp /tmp/generated_apic.txt testdata/flvr_openshift_sdn_ovn_baremetal_primary.apic.txt
cp /tmp/cluster-network-* testdata/flvr_openshift_sdn_ovn_baremetal_primary_tar/
cp /tmp/99-* testdata/flvr_openshift_sdn_ovn_baremetal_primary_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flvr_openshift_sdn_ovn_baremetal_primary

python3 -m pytest acc_provision -x -k test_flvr_openshift_sdn_ovn_baremetal_secondary_with_primary
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/flvr_openshift_sdn_ovn_baremetal_secondary_with_primary_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flvr_openshift_sdn_ovn_baremetal_secondary_with_primary.kube.yaml
cp /tmp/generated_apic.txt testdata/flvr_openshift_sdn_ovn_baremetal_secondary_with_primary.apic.txt
cp /tmp/cluster-network-* testdata/flvr_openshift_sdn_ovn_baremetal_secondary_with_primary_tar/
cp /tmp/99-* testdata/flvr_openshift_sdn_ovn_baremetal_secondary_with_primary_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flvr_openshift_sdn_ovn_baremetal_secondary_with_primary

python3 -m pytest acc_provision -x -k test_chained_mode_without_l3out
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
cp /tmp/generated_kube.yaml testdata/chained_mode_without_l3out.kube.yaml
cp /tmp/generated_apic.txt testdata/chained_mode_without_l3out.apic.txt
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_chained_mode_without_l3out

python3 -m pytest acc_provision -x -k test_chained_mode_without_phys_domains
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
cp /tmp/generated_kube.yaml testdata/chained_mode_without_phys_domains.kube.yaml
cp /tmp/generated_apic.txt testdata/chained_mode_without_phys_domains.apic.txt
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_chained_mode_without_phys_domains

python3 -m pytest acc_provision -x -k test_override_skip_node_network_provision
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
cp /tmp/generated_kube.yaml testdata/override_skip_node_network_provision.kube.yaml
cp /tmp/generated_apic.txt testdata/override_skip_node_network_provision.apic.txt
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_override_skip_node_network_provision

python3 -m pytest acc_provision -x -k test_override_use_global_scope_vlan
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
cp /tmp/generated_kube.yaml testdata/override_use_global_scope_vlan.kube.yaml
cp /tmp/generated_apic.txt testdata/override_use_global_scope_vlan.apic.txt
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_override_use_global_scope_vlan

python3 -m pytest acc_provision -x -k test_preexisting_tenant_chained_mode
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
cp /tmp/generated_kube.yaml testdata/with_preexisting_tenant_chained_mode.kube.yaml
cp /tmp/generated_apic.txt testdata/with_preexisting_tenant_chained_mode.apic.txt
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_preexisting_tenant_chained_mode

python3 -m pytest acc_provision -x -k test_chained_mode_nad_vlan_map
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/chained_mode_nad_vlan_map_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/chained_mode_nad_vlan_map.kube.yaml
cp /tmp/generated_apic.txt testdata/chained_mode_nad_vlan_map.apic.txt
cp /tmp/cluster-network-* testdata/chained_mode_nad_vlan_map_tar/
cp /tmp/99-* testdata/chained_mode_nad_vlan_map_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_chained_mode_nad_vlan_map

python3 -m pytest acc_provision -x -k test_automatic_chaining_insertion_without_local_cert_manager
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
cp /tmp/generated_kube.yaml testdata/automatic_chaining_insertion_without_local_cert_manager.kube.yaml
cp /tmp/generated_apic.txt testdata/automatic_chaining_insertion_without_local_cert_manager.apic.txt
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_automatic_chaining_insertion_without_local_cert_manager

python3 -m pytest acc_provision -x -k test_automatic_chaining_insertion_with_local_cert_manager
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
cp /tmp/generated_kube.yaml testdata/automatic_chaining_insertion_with_local_cert_manager.kube.yaml
cp /tmp/generated_apic.txt testdata/automatic_chaining_insertion_with_local_cert_manager.apic.txt
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_automatic_chaining_insertion_with_local_cert_manager

python3 -m pytest acc_provision -x -k test_chained_mode_ovs_cni_support
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/chained_mode_ovs_cni_support_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/chained_mode_ovs_cni_support.kube.yaml
cp /tmp/generated_apic.txt testdata/chained_mode_ovs_cni_support.apic.txt
cp /tmp/cluster-network-* testdata/chained_mode_ovs_cni_support_tar/
cp /tmp/99-* testdata/chained_mode_ovs_cni_support_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_chained_mode_ovs_cni_support

rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_apic_oobm_ip
cp /tmp/generated_apic.txt testdata/apic_oobm_ip.apic.txt
python3 -m pytest acc_provision -x -k test_apic_oobm_ip


python3 -m pytest acc_provision -x -k test_flavor_k8s_aci_cilium
cp /tmp/generated_kube.yaml testdata/flavor_k8s_aci_cilium.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_k8s_aci_cilium.apic.txt
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm -rf testdata/flavor_k8s_aci_cilium_tar/*
cp /tmp/cluster-network-* testdata/flavor_k8s_aci_cilium_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_k8s_aci_cilium

python3 -m pytest acc_provision -x -k test_flavor_openshift_414_aci_cilium_esx
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm -rf testdata/flavor_openshift_414_aci_cilium_esx_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/flavor_openshift_414_aci_cilium_esx.kube.yaml
cp /tmp/generated_apic.txt testdata/flavor_openshift_414_aci_cilium_esx.apic.txt
cp /tmp/cluster-network-* testdata/flavor_openshift_414_aci_cilium_esx_tar/
cp /tmp/apic.json testdata/flavor_openshift_414_aci_cilium_esx_tar/apic.json
cp /tmp/99-* testdata/flavor_openshift_414_aci_cilium_esx_tar/
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_flavor_openshift_414_aci_cilium_esx


python3 -m pytest acc_provision -k test_aci_cilium_chaining
cp /tmp/generated_kube.yaml testdata/enable_aci_cilium_chaining.kube.yaml
python3 -m pytest acc_provision -k test_aci_cilium_chaining
rm -rf /tmp/cluster*
rm -rf /tmp/generated*
rm -rf /tmp/99*

popd
