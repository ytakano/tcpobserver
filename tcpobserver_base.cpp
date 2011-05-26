#include "tcpobserver_base.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <sstream>

tcpobserver_base *tcpobserver_base::instance;

tcpobserver_base::tcpobserver_base(pid_t pid) : m_pid(pid), m_is_exec(false),
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

    wait(NULL);

    do_trace();
}

tcpobserver_base::tcpobserver_base(char *cmd) : m_is_exec(true),
                                                m_is_entering(false)
{
    if (instance != NULL) {
        throw "too many instance";
    }

    instance = this;

    set_sa_handler();
    create_child(cmd);
}

tcpobserver_base::~tcpobserver_base()
{

}

void
tcpobserver_base::set_sa_handler()
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = signal_handler;
    sa.sa_flags   = SA_RESTART;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
}

void
signal_handler(int signum)
{
    tcpobserver_base::instance->cleanup();
}

void
tcpobserver_base::cleanup()
{
    if (m_is_exec) {
        ptrace(PTRACE_DETACH, m_pid, NULL, NULL);

        kill(m_pid, SIGCONT);
        kill(m_pid, SIGTERM);

        wait(NULL);

        exit(0);
    } else {
        ptrace(PTRACE_DETACH, m_pid, NULL, NULL);
        exit(0);
    }
}

void
tcpobserver_base::create_child(char *cmd)
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
        std::vector<std::string>::size_type i;
        char ** argv;

        split(cmd_str, argv_vec);

        argv = new char*[argv_vec.size()];
        for (i = 0; i < argv_vec.size() - 1; i++) {
            argv[i] = const_cast<char*>(argv_vec[i].c_str());
        }
        argv[argv_vec.size() - 1] = NULL;

        if (execvp(argv[0], argv) < 0) {
            PRINT_ERROR();
            exit(-1);
        }
    } else {
        m_pid = pid;
        wait(NULL);
    }
}

void
tcpobserver_base::split(std::string str, std::vector<std::string> &result)
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
tcpobserver_base::do_trace()
{
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, m_pid, NULL, NULL) < 0) {
            cleanup();
        }

        wait(NULL);

        if (m_is_entering)
            before_syscall();
        else
            after_syscall();

        m_is_entering = !m_is_entering;
    }
}
