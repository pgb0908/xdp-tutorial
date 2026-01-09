
```shell
docker exec sample01-hello_world-bpf-loader-1 cat /sys/kernel/debug/tracing/trace_pipe

docker exec sample01-hello_world-bpf-loader-1 echo "hello"
```