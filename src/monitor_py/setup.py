from glob import glob

from setuptools import find_packages, setup

package_name = 'monitor_py'

setup(
    name=package_name,
    version='0.2.0',
    packages=find_packages(exclude=['test']),
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
        ('share/' + package_name + '/launch', glob('launch/*.launch.py')),
        ('share/' + package_name + '/config', glob('config/*.yaml')),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='aarock17',
    maintainer_email='aminahmedg2005@gmail.com',
    description='Joint state monitoring and a two-domain robot command firewall',
    license='MIT',
    extras_require={
        'test': [
            'pytest',
        ],
    },
    entry_points={
        'console_scripts': [
            'firewall_node = monitor_py.firewall_node:main',
            'firewall_dashboard = monitor_py.firewall_dashboard:main',
            'robot_sim_node = monitor_py.robot_sim_node:main',
            'attack_sim_node = monitor_py.attack_sim_node:main',
            'joint_monitor_node = monitor_py.joint_monitor_node:main',
            # Old name kept for existing scripts; now the command-following robot sim.
            'joint_state_publisher_node = monitor_py.robot_sim_node:main',
        ],
    },
)
