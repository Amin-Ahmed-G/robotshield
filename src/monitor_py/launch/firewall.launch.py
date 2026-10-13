"""
Gateway board launch: the firewall only.

Security and discovery settings
come from the environment (see deploy/nanopi/robot-firewall.service).
"""
import os

from ament_index_python.packages import get_package_share_directory
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():
    params = os.path.join(get_package_share_directory('monitor_py'),
                          'config', 'firewall_params.yaml')
    return LaunchDescription([
        DeclareLaunchArgument('untrusted_domain', default_value='10'),
        DeclareLaunchArgument('trusted_domain', default_value='20'),
        DeclareLaunchArgument('enclave', default_value=''),
        DeclareLaunchArgument('params_file', default_value=params),
        Node(package='monitor_py', executable='firewall_node', output='screen',
             arguments=['--untrusted-domain', LaunchConfiguration('untrusted_domain'),
                        '--trusted-domain', LaunchConfiguration('trusted_domain'),
                        '--enclave', LaunchConfiguration('enclave')],
             parameters=[LaunchConfiguration('params_file')]),
    ])
