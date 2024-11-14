# bpf_monitor

**Generate vmlinux.h**
```
mkdir vmlinux
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux/vmlinux.h
```