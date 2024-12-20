#include "ebpf_nat.h"
#include "event_handler.h"
#include "macros.h"

#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: ./ebpf_nat [dev_name] \n");
        printf("eg:    ./ebpf_nat ens34 \n");
        return EXIT_FAIL;
    }

    char *dev_name = argv[1];

    if (init_ebpf_nat(dev_name))
    {
        return EXIT_FAIL;
    }

    run();

    return EXIT_OK;
}