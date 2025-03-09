rm -rf /tmp/generated*
rm -rf /tmp/cluster*
rm -rf /tmp/99*

pushd provision/


python3 -m pytest acc_provision -x -k test_acc_unporvision_changes
pushd /tmp/
tar xfz generated_operator.tar.gz
popd
rm testdata/cloud_tar/*.yaml
cp /tmp/generated_kube.yaml testdata/without_shared_tanet_ap.kube.yaml
cp /tmp/cluster-network-* testdata/cloud_tar/
rm -rf /tmp/generated*
rm -rf /tmp/cluster*
rm -rf /tmp/99*
python3 -m pytest acc_provision -x -k test_acc_unporvision_changes


popd
