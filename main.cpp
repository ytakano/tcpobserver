#include <stdlib.h>
#include <unistd.h>

#include <iostream>

#include "tcptrace.hpp"

extern char *optarg;

char *progname;

void usage();

int
main(int argc, char **argv)
{
    int   opt;
    char *cmd = NULL;
    pid_t pid = 0;

    progname = argv[0];

    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
        case 'p':
            pid = atoi(optarg);
            break;
        default:
            usage();
            return 0;
        }
    }

    if (pid == 0) {
        if (argc < 2) {
            usage();
            return 0;
        } else {
            cmd = argv[1];
            tcptrace tracer(cmd);
        }
    } else {
        tcptrace tracer(pid);
    }
}

void
usage()
{
    std::cout << progname << " command | -p pid" << std::endl;
}
