"""
Laptop side launch: attack simulator / commander.

Run the dashboard in its own terminal (it redraws the screen):

  ros2 launch monitor_py laptop.launch.py
  ROS_DOMAIN_ID=10 ros2 run monitor_py firewall_dashboard
"""
from launch import LaunchDescription
from launch.actions import DeclareLaunchArgument
from launch.substitutions import LaunchConfiguration
from launch_ros.actions import Node


def generate_launch_description():
    domain = LaunchConfiguration('domain')
    return LaunchDescription([
        DeclareLaunchArgument('domain', default_value='10'),
        Node(package='monitor_py', executable='attack_sim_node', output='screen',
             additional_env={'ROS_DOMAIN_ID': domain}),
    ])
