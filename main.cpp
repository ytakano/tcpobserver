#include <unistd.h>

#include <iostream>

extern char *optarg;

char *progname;

void usage();

int
main(int argc, char **argv)
{
    int   opt;
    char *child = NULL;
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
            child = argv[1];
        }
    }
}

void
usage()
{
    std::cout << progname << "command | -p pid" << std::endl;
}
