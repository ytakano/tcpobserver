#include "tcptrace.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sstream>

tcptrace::tcptrace(pid_t pid) : m_is_exec(false), m_pid(pid),
                                m_is_entering(false)
{
    if (instance != NULL) {
        throw "too many instance";
    }

    instance = this;

    set_sa_handler();

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        PRINT_ERROR();
        exit(-1);
    }
}

tcptrace::tcptrace(char *cmd) : m_is_exec(true), m_is_entering(false)
{
    if (instance != NULL) {
        throw "too many instance";
    }

    instance = this;

    set_sa_handler();
    create_child(cmd);
}

void
tcptrace::set_sa_handler()
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = signal_handler;
    sa.sa_flags   = SA_RESTART;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
}

void
signal_handler(int signum)
{
    switch (signum) {
    case SIGCHLD:
        wait(NULL);
        exit(0);
        break;
    default:
        tcptrace::instance->cleanup();
    }
}

void
tcptrace::cleanup()
{
    if (m_is_exec) {
        kill(m_pid, SIGCONT);
        kill(m_pid, SIGTERM);
        exit(0);
    } else {
        ptrace(PTRACE_DETACH, m_pid, NULL, NULL);
        exit(0);
    }
}

void
tcptrace::create_child(char *cmd)
{
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        PRINT_ERROR();
        exit(-1);
    }

    if (pid == 0) {
        // child process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            PRINT_ERROR();
            exit(-1);
        }


        std::string cmd_str(cmd);
        std::vector<std::string> argv_vec;
        char ** argv;

        split(cmd_str, argv_vec);

        argv = new char*[argv_vec.size()];
        for (int i = 0; i < argv_vec.size(); i++) {
            argv[i] = const_cast<char*>(argv_vec[i].c_str());
        }

        if (execvp(argv[0], argv) < 0) {
            PRINT_ERROR();
            exit(-1);
        }
    } else {
        m_pid = pid;
    }
}

void
tcptrace::split(std::string str, std::vector<std::string> &result)
{
    std::istringstream iss(str);

    result.clear();

    do {
        std::string sub;
        iss >> sub;
        result.push_back(sub);
    } while (iss);
}

void
tcptrace::do_trace()
{
#ifdef __x86_64__
    unsigned long scno;
#else
    long int scno;
#endif // __x86_64__

    for (;;) {
        if (ptrace(PTRACE_SYSCALL, m_pid, NULL, NULL) < 0) {
            PRINT_ERROR();
            cleanup();
        }

        wait(NULL);

        if (m_is_entering) {
#ifdef __x86_64__
            scno = ptrace(PTRACE_PEEKUSER, m_pid, ORIG_RAX * 8, NULL);
#else
            scno = ptrace(PTRACE_PEEKUSER, m_pid, ORIG_RAX * 4, NULL);
#endif // __x86_64__

            std::cout << "system call number: " << scno << std::endl;
        } else {
        }

        m_is_entering = !m_is_entering;
    }
}
