#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

// eBPF 程序的路径
#define BPF_PROGRAM_PATH "./mmap_monitor.bpf.o"

// 提高内存锁定限制
void set_memlock_limit()
{
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
    {
        perror("setrlimit");
        exit(EXIT_FAILURE);
    }
}

volatile sig_atomic_t stop = 0;

// 处理 Ctrl+C 信号
void handle_signal(int sig)
{
    stop = 1;
    printf("\nexit.\n");
    exit(0);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    int err;

    // 提高内存锁定限制
    set_memlock_limit();

    // 加载 eBPF 对象文件
    obj = bpf_object__open_file(BPF_PROGRAM_PATH, NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "Error opening BPF program: %s\n",
                strerror(-libbpf_get_error(obj)));
        return 1;
    }

    // 加载 eBPF 程序到内核
    err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "Error loading BPF program: %s\n", strerror(-err));
        return 1;
    }

    // 获取 eBPF 程序的句柄
    struct bpf_program *prog_mmap =
        bpf_object__find_program_by_name(obj, "trace_mmap");
    struct bpf_program *prog_mprotect =
        bpf_object__find_program_by_name(obj, "trace_mprotect");
    if (!prog_mmap || !prog_mprotect)
    {
        fprintf(stderr, "Failed to find eBPF programs\n");
        return 1;
    }

    // Replace the kprobe attachment with tracepoint attachment
    struct bpf_link *mmap_link =
        bpf_program__attach_tracepoint(prog_mmap, "syscalls", "sys_enter_mmap");
    if (!mmap_link)
    {
        fprintf(stderr, "Failed to attach tracepoint to sys_enter_mmap: %s\n",
                strerror(-libbpf_get_error(mmap_link)));
        return 1;
    }

    struct bpf_link *mprotect_link = bpf_program__attach_tracepoint(
        prog_mprotect, "syscalls", "sys_enter_mprotect");
    if (!mprotect_link)
    {
        fprintf(stderr,
                "Failed to attach tracepoint to sys_enter_mprotect: %s\n",
                strerror(-libbpf_get_error(mprotect_link)));
        return 1;
    }

    printf("Monitoring mmap and mprotect calls. Press Ctrl+C to stop.\n");

    // 设置信号处理程序
    signal(SIGINT, handle_signal);

    // 读取 trace_pipe 中的输出
    FILE *trace_pipe = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
    if (!trace_pipe)
    {
        perror("fopen trace_pipe");
        return 1;
    }

    char buffer[256];
    while (!stop && fgets(buffer, sizeof(buffer), trace_pipe))
    {
        printf("%s", buffer);
    }

    fclose(trace_pipe);

    bpf_link__destroy(mmap_link);
    bpf_link__destroy(mprotect_link);
    bpf_object__close(obj);

    return 0;
}