#!/bin/bash
# Started by robot-firewall.service. Environment comes from
# /etc/robot_firewall/firewall.env (EnvironmentFile=).
source /opt/ros/jazzy/setup.bash
source /opt/robot_firewall_ws/install/setup.bash

PARAMS=/etc/robot_firewall/firewall_params.yaml
COUNTERS=/run/robot_firewall/nft_counters.json
INCIDENTS=/var/log/robot_firewall/incidents.jsonl

if [ "${FIREWALL_IMPL:-rust}" = rust ]; then
    exec /usr/local/lib/robot_firewall/robot_firewall \
        --untrusted-domain "${UNTRUSTED_DOMAIN}" \
        --trusted-domain "${TRUSTED_DOMAIN}" \
        --enclave "${FIREWALL_ENCLAVE}" \
        --config "$PARAMS" \
        --set "nft_counters_file=$COUNTERS" \
        --set "incident_log_path=$INCIDENTS" \
        --set "siem_syslog=${SIEM_SYSLOG:-}" \
        --set "siem_format=${SIEM_FORMAT:-cef}"
fi

exec /opt/robot_firewall_ws/install/monitor_py/lib/monitor_py/firewall_node \
    --untrusted-domain "${UNTRUSTED_DOMAIN}" \
    --trusted-domain "${TRUSTED_DOMAIN}" \
    --enclave "${FIREWALL_ENCLAVE}" \
    --ros-args \
    --params-file "$PARAMS" \
    -p nft_counters_file:=$COUNTERS \
    -p incident_log_path:=$INCIDENTS
