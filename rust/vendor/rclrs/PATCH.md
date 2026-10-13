# Vendored rclrs 0.7.0 (patched)

Upstream: https://crates.io/crates/rclrs/0.7.0 (Apache-2.0).

rclrs 0.7.0 is the last release built against `rosidl_runtime_rs` 0.6, which is
what the ROS 2 Jazzy binary message crates (`/opt/ros/jazzy/share/*/rust`) use.

Changes:

- `src/lib.rs`: `#![allow(...)]` for warnings newer rustc versions raise in
  upstream code (no behaviour change).
- `src/node/graph.rs`:
  `TopicEndpointInfo` gains `pub endpoint_gid: [u8; 16]`, filled from
  `rmw_topic_endpoint_info_t::endpoint_gid`.

The robot firewall uses it to map `MessageInfo::publisher_gid` of every
incoming command to the publishing node, so commands from non-allowlisted
publishers are dropped individually instead of forcing a full lockdown.
