#include "tcpobserver_x86_64.hpp"

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <iostream>
#include <string>

#ifdef __x86_64__

const unsigned long tcpobserver::syscall_socket  =  41;
const unsigned long tcpobserver::syscall_bind    =  49;
const unsigned long tcpobserver::syscall_listen  =  50;
const unsigned long tcpobserver::syscall_accept  =  43;
const unsigned long tcpobserver::syscall_accept4 = 288;
const unsigned long tcpobserver::syscall_connect =  42;
const unsigned long tcpobserver::syscall_close   =   3;

tcpobserver::tcpobserver(pid_t pid) : tcpobserver_base(pid)
{
        std::cout.precision(18);
}

tcpobserver::tcpobserver(char *cmd) : tcpobserver_base(cmd)
{
        std::cout.precision(18);
}

tcpobserver::~tcpobserver()
{

}

void
tcpobserver::before_syscall()
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
tcpobserver::entering_socket()
{
    m_socket_args.domain   = ptrace(PTRACE_PEEKUSER, m_pid, RDI * 8, NULL);
    m_socket_args.type     = ptrace(PTRACE_PEEKUSER, m_pid, RSI * 8, NULL);
    m_socket_args.protocol = ptrace(PTRACE_PEEKUSER, m_pid, RDX * 8, NULL);
}

void
tcpobserver::after_syscall()
{
    switch (m_scno) {
    case syscall_socket:
        exiting_socket();
        break;
    }
}

void
tcpobserver::exiting_socket()
{
    int fd;

    fd = ptrace(PTRACE_PEEKUSER, m_pid, RAX * 8, NULL);

    if ((m_socket_args.domain == AF_INET || m_socket_args.domain == AF_INET6) &&
        m_socket_args.type == SOCK_STREAM &&
        (m_socket_args.protocol == IPPROTO_TCP ||
         m_socket_args.protocol == 0) && fd != -1) {
        double datetime;
        std::string domain;

        if (m_socket_args.domain == AF_INET)
            domain = "IPv4";
        else
            domain = "IPv6";

        datetime = get_datetime();

        std::cout << datetime << "@datetime "
                  << "socket@op "
                  << domain << "@protocol "
                  << fd << "@fd"
                  << std::endl;
    }
}

#endif // __x86_64__
