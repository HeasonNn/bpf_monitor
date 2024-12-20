#include "ebpf_nat.h"

static void sig_int(int signo)
{
    exiting = 1;
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: ./ebpf_nat [dev_name] \n");
        printf("eg:    ./ebpf_nat ens34 \n");
        return EXIT_FAIL;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR)
    {
        fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
        return EXIT_FAIL;
    }

    char *dev_name = argv[1];
    return run_ebpf_nat(dev_name);
}