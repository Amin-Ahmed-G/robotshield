#!/bin/bash
# Build the Rust firewall workspace against ROS 2 Jazzy.
#   ./build.sh --release                      # everything
#   ./build.sh --release -p robot_firewall    # gateway only (NanoPi)
#   ./build.sh --release -p firewall_console  # GUI only (laptop)
set -e
cd "$(dirname "$0")"
set +u
source /opt/ros/jazzy/setup.bash
if [ ! -e /opt/ros/jazzy/lib/libtest_msgs__rosidl_typesupport_c.so ]; then
    echo "rclrs links against test_msgs. Install it first:" >&2
    echo "  sudo apt install ros-jazzy-test-msgs" >&2
    exit 1
fi
exec cargo build "$@"
