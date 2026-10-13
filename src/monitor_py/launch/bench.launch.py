"""
Single-machine bench: robot sim, firewall and attack sim.

Robot sim on the trusted domain, attack sim on the untrusted domain; run the
dashboard in a separate terminal.

  ros2 launch monitor_py bench.launch.py
  # other terminal:
  ROS_DOMAIN_ID=10 ros2 run monitor_py firewall_dashboard
"""
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument, SetEnvironmentVariable
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():
    params = os.path.join(get_package_share_directory('monitor_py'),
                          'config', 'firewall_params.yaml')
    untrusted = LaunchConfiguration('untrusted_domain')
    trusted = LaunchConfiguration('trusted_domain')
    return LaunchDescription([
        DeclareLaunchArgument('untrusted_domain', default_value='10'),
        DeclareLaunchArgument('trusted_domain', default_value='20'),
        DeclareLaunchArgument('params_file', default_value=params),
        # Keep the bench on this machine only.
        SetEnvironmentVariable('ROS_AUTOMATIC_DISCOVERY_RANGE', 'LOCALHOST'),
        Node(package='monitor_py', executable='robot_sim_node', output='screen',
             additional_env={'ROS_DOMAIN_ID': trusted}),
        Node(package='monitor_py', executable='firewall_node', output='screen',
             arguments=['--untrusted-domain', untrusted, '--trusted-domain', trusted],
             parameters=[LaunchConfiguration('params_file')]),
        Node(package='monitor_py', executable='attack_sim_node', output='screen',
             additional_env={'ROS_DOMAIN_ID': untrusted}),
    ])
