# Source on the laptop before running attack_sim_node / firewall_dashboard /
# ros2 CLI against the gateway:   source laptop_env.sh ~/robot_fw_keystore 10
export ROS_SECURITY_KEYSTORE=$(realpath "${1:-$HOME/robot_fw_keystore}")
export ROS_DOMAIN_ID=${2:-10}
export ROS_SECURITY_ENABLE=true
export ROS_SECURITY_STRATEGY=Enforce
# Every node in these processes uses the /laptop enclave.
export ROS_SECURITY_ENCLAVE_OVERRIDE=/laptop
export RMW_IMPLEMENTATION=rmw_fastrtps_cpp
