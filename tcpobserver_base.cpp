#include "tcpobserver_base.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/reg.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <sstream>

#define PTRACE_OPTS PTRACE_O_TRACECLONE

#define WIFCLONE(STATUS) (((STATUS & 0xff0000) >> 16) == PTRACE_EVENT_CLONE)


tcpobserver_base *tcpobserver_base::instance;

tcpobserver_base::tcpobserver_base(pid_t pid) : m_parent(pid), m_is_exec(false)
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

    m_pid.insert(pid);
    m_is_entering[pid] = true;

    wait(NULL);

    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_OPTS) < 0) {
        PRINT_ERROR();
        exit(-1);
    }
}

tcpobserver_base::tcpobserver_base(char *cmd) : m_is_exec(true)
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
    std::set<pid_t>::iterator it;

    if (m_is_exec) {
        for (it = m_pid.begin(); it != m_pid.end(); ++it) {
            ptrace(PTRACE_DETACH, *it, NULL, NULL);

            kill(*it, SIGCONT);
            kill(*it, SIGTERM);
        }

        exit(0);
    } else {
        for (it = m_pid.begin(); it != m_pid.end(); ++it) {
            ptrace(PTRACE_DETACH, *it, NULL, NULL);
            kill(*it, SIGCONT);
        }

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
        m_pid.insert(pid);
        m_is_entering[pid] = true;

        waitpid(-1, NULL, __WALL);

        if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_OPTS) < 0) {
            PRINT_ERROR();
            exit(-1);
        }

        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
            PRINT_ERROR();
            exit(-1);
        }
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
    pid_t pid;
    int   status;

    while (m_pid.size() > 0) {
        pid = waitpid(-1, &status, __WALL);

        if (pid < 0) {
            PRINT_ERROR();
            cleanup();
            break;
        }

        if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
           WIFCLONE(status)) {
            pid_t newpid;
            if(ptrace(PTRACE_GETEVENTMSG, pid, 0, &newpid) < -1) {
                PRINT_ERROR();
                cleanup();
                break;
            }

            m_pid.insert(newpid);
            m_is_entering[newpid] = true;

            ptrace(PTRACE_SYSCALL, newpid, 0, 0);

            ptrace(PTRACE_SYSCALL, pid, 0, 0);

            continue;
        }

        if(WIFEXITED(status)) {
            m_pid.erase(pid);
            m_is_entering.erase(pid);

            continue;
        } else if(WIFSIGNALED(status)) {
            m_pid.erase(pid);
            m_is_entering.erase(pid);

            continue;
        } else if(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            if (m_is_entering[pid])
                before_syscall(pid);
            else
                after_syscall(pid);

            m_is_entering[pid] = !m_is_entering[pid];
        }

        if(ptrace(PTRACE_SYSCALL, pid, 1, NULL) < 0) {
            PRINT_ERROR();
            cleanup();
            break;
        }
    }
}

double
tcpobserver_base::get_datetime()
{
    timeval tv;

    gettimeofday(&tv, NULL);

    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

void
tcpobserver_base::read_data(pid_t pid, void *buf, void *addr, size_t len)
{
    long val;

    for (;;) {
        if (len >= sizeof(val)) {
            val = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);

            memcpy(buf, &val, sizeof(val));

            buf  = (char*)buf + sizeof(val);
            addr = (char*)addr + sizeof(val);

            len -= sizeof(val);
        } else {
            val = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);

            memcpy(buf, &val, len);

            return;
        }
    }
}

void
tcpobserver_base::write_data(pid_t pid, void *buf, void *addr, size_t len)
{
    long val;

    for (;;) {
        if (len > sizeof(val)) {
            memcpy(&val, buf, sizeof(val));
            ptrace(PTRACE_POKEDATA, pid, addr, (void*)val);

            buf  = (char*)buf + sizeof(val);
            addr = (char*)buf + sizeof(val);
            len -= sizeof(val);
        } else {
            long orig;

            orig = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);

            memcpy(&val, buf, len);
            memcpy((char*)&val + len, (char*)&orig + len, sizeof(val) - len);

            ptrace(PTRACE_POKEDATA, pid, addr, (void*)val);

            return;
        }
    }
}

void
tcpobserver_base::proc_removed(pid_t pid)
{

}
