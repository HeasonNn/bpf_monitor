#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "vmlinux.h"

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(void *ctx) {
  bpf_printk("mmap called\n");
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(void *ctx) {
  bpf_printk("mprotect called\n");
  return 0;
}

char LICENSE[] SEC("license") = "GPL";