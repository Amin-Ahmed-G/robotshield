# Benchmarks

Run from the repo root, with ROS 2 Jazzy and `install/` sourced, and the Rust gateway built in release mode (`rust/build.sh --release`).

```bash
(cd rust && cargo run --release -p fw_core --example inspect_bench) > bench/results/rules_rust.json
python3 bench/bench_rules.py > bench/results/rules_python.json
for m in direct rust python; do python3 bench/gateway_latency.py $m; done
python3 bench/attack_timeline.py
python3 bench/plot_results.py       # -> docs/perf_*.png, docs/v1_vs_v2.png
```

`results/` holds the raw data behind the charts in `docs/`.
