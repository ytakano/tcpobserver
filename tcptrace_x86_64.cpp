#include "tcptrace_x86_64.hpp"

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <iostream>
#include <string>

#ifdef __x86_64__

const unsigned long tcptrace::syscall_socket  =  41;
const unsigned long tcptrace::syscall_bind    =  49;
const unsigned long tcptrace::syscall_listen  =  50;
const unsigned long tcptrace::syscall_accept  =  43;
const unsigned long tcptrace::syscall_accept4 = 288;
const unsigned long tcptrace::syscall_connect =  42;
const unsigned long tcptrace::syscall_close   =   3;

tcptrace::tcptrace(pid_t pid) : tcptrace_base(pid)
{

}

tcptrace::tcptrace(char *cmd) : tcptrace_base(cmd)
{

}

tcptrace::~tcptrace()
{

}

void
tcptrace::before_syscall()
{
    m_scno = ptrace(PTRACE_PEEKUSER, m_pid, ORIG_RAX * 8, NULL);
    std::cout << "system call number: " << m_scno << std::endl;

    switch (m_scno) {
    case syscall_socket:
        entering_socket();
        break;
    }
}

void
tcptrace::entering_socket()
{
    m_socket_args.domain   = ptrace(PTRACE_PEEKUSER, m_pid, RDI * 8, NULL);
    m_socket_args.type     = ptrace(PTRACE_PEEKUSER, m_pid, RSI * 8, NULL);
    m_socket_args.protocol = ptrace(PTRACE_PEEKUSER, m_pid, RDX * 8, NULL);
}

void
tcptrace::after_syscall()
{
    switch (m_scno) {
    case syscall_socket:
        exiting_socket();
        break;
    }
}

void
tcptrace::exiting_socket()
{
    int fd;

    fd = ptrace(PTRACE_PEEKUSER, m_pid, ORIG_RAX * 8, NULL);

    if ((m_socket_args.domain == AF_INET || m_socket_args.domain == AF_INET6) &&
        m_socket_args.type == SOCK_STREAM && m_socket_args.protocol == 0 &&
        fd != -1) {
        std::string domain;

        if (m_socket_args.domain == AF_INET)
            domain = "IPv4";
        else
            domain = "IPv6";

        std::cout << "socket "
                  << domain << "@protocol "
                  << fd << "@fd"
                  << std::endl;
    }
}

#endif // __x86_64__
