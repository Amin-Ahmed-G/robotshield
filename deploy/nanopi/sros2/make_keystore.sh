#!/bin/bash
# Create the SROS2 keystore on the LAPTOP (keep the CA private keys there).
#
#   ./make_keystore.sh ~/robot_fw_keystore 10
#
# Produces:
#   <keystore>/                 full keystore incl. CA private keys (stay on laptop)
#   <keystore>-gateway.tgz      only what the gateway needs: public CA certs,
#                               signed governance and the /firewall enclave
set -euo pipefail
KEYSTORE=${1:?usage: make_keystore.sh <keystore_dir> <untrusted_domain_id>}
DOMAIN=${2:?usage: make_keystore.sh <keystore_dir> <untrusted_domain_id>}
set +u; source /opt/ros/jazzy/setup.bash; set -u

# Governance and permissions embed the domain id at creation time.
export ROS_DOMAIN_ID=$DOMAIN
if [ ! -d "$KEYSTORE" ]; then
    ros2 security create_keystore "$KEYSTORE"
fi
for enclave in /firewall /laptop; do
    ros2 security create_enclave "$KEYSTORE" "$enclave"
done
chmod -R go-rwx "$KEYSTORE"

tar -C "$KEYSTORE" -czf "${KEYSTORE%/}-gateway.tgz" \
    public/identity_ca.cert.pem public/permissions_ca.cert.pem public/ca.cert.pem \
    enclaves/governance.p7s enclaves/firewall
echo "Laptop keystore: $KEYSTORE (enclave /laptop)"
echo "Copy to gateway:  ${KEYSTORE%/}-gateway.tgz"
