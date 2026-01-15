

```shell
docker exec -it xdp-sender ping 172.20.0.10
```

```shell
docker exec -it xdp-receiver bpftool map dump pinned /sys/fs/bpf/eth0/xdp_stats_map
docker exec -it xdp-receiver /xdp/xdp_stats --dev eth0
```