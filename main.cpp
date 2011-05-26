#include <stdlib.h>
#include <unistd.h>

#include <iostream>

#if defined __x86_64__
    #include "tcptrace_x86_64.hpp"
#elif defined __i386__
    #include "tcptrace_x86.hpp"
#endif

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
            tracer.do_trace();
        }
    } else {
        tcptrace tracer(pid);
        tracer.do_trace();
    }
}

void
usage()
{
    std::cout << progname << " [command | -p pid]" << std::endl;
}
