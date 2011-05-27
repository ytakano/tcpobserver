#include "tcpobserver_x86_64.hpp"

#include <sys/ptrace.h>
#include <sys/reg.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <stdint.h>

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
    std::cerr.precision(19);
}

tcpobserver::tcpobserver(char *cmd) : tcpobserver_base(cmd)
{
    std::cerr.precision(19);
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
    case syscall_bind:
        entering_bind();
        break;
    case syscall_listen:
        entering_listen();
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
tcpobserver::entering_bind()
{
    m_bind_args.sockfd  = ptrace(PTRACE_PEEKUSER, m_pid, RDI * 8, NULL);
    m_bind_args.addr    = (sockaddr*)ptrace(PTRACE_PEEKUSER, m_pid, RSI * 8,
                                            NULL);
    m_bind_args.addrlen = ptrace(PTRACE_PEEKUSER, m_pid, RDX * 8, NULL);
}

void
tcpobserver::entering_listen()
{
    m_listen_args.sockfd = ptrace(PTRACE_PEEKUSER, m_pid, RDI * 8, NULL);
}

void
tcpobserver::after_syscall()
{
    switch (m_scno) {
    case syscall_socket:
        exiting_socket();
        break;
    case syscall_bind:
        exiting_bind();
        break;
    case syscall_listen:
        exiting_listen();
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

        m_fd_set.insert(fd);

        datetime = get_datetime();

        std::cerr << datetime << "@datetime "
                  << "socket@op "
                  << fd << "@fd"
                  << domain << "@protocol "
                  << std::endl;
    }
}

void
tcpobserver::exiting_bind()
{
    int result;

    result = ptrace(PTRACE_PEEKUSER, m_pid, RAX * 8, NULL);

    if (result < 0)
        return;

    if (m_bind_args.addrlen < sizeof(long))
        return;


    sockaddr_storage saddr;
    std::string      domain;
    double           datetime;
    uint16_t         port;
    char             addr[64];

    read_data(&saddr, m_bind_args.addr, sizeof(long));

    switch (saddr.ss_family) {
    case AF_INET:
    {
        sockaddr_in *saddr_in;

        if (m_bind_args.addrlen < sizeof(sockaddr_in))
            return;

        read_data(&saddr, m_bind_args.addr, sizeof(sockaddr_in));

        saddr_in = (sockaddr_in*)&saddr;

        inet_ntop(AF_INET, &saddr_in->sin_addr, addr, sizeof(addr));
        port   = ntohs(saddr_in->sin_port);
        domain = "IPv4";
        break;
    }
    case AF_INET6:
    {
        sockaddr_in6 *saddr_in6;

        if (m_bind_args.addrlen < sizeof(sockaddr_in6))
            return;

        read_data(&saddr, m_bind_args.addr, sizeof(sockaddr_in6));

        saddr_in6 = (sockaddr_in6*)&saddr;

        inet_ntop(AF_INET6, &saddr_in6->sin6_addr, addr, sizeof(addr));

        port   = ntohs(saddr_in6->sin6_port);
        domain = "IPv6";
        break;
    }
    default:
        return;
    }

    datetime = get_datetime();

    std::cerr << datetime << "@datetime "
              << "bind@op "
              << m_bind_args.sockfd << "@fd "
              << domain << "@protocol "
              << addr << "@addr "
              << port << "@port"
              << std::endl;
}

void
tcpobserver::exiting_listen()
{
    int result;

    result = ptrace(PTRACE_PEEKUSER, m_pid, RAX * 8, NULL);

    if (result < 0)
        return;


    double datetime;

    std::cerr << datetime << "@datetime "
              << "listen@op "
              << fd << "@fd"
              << std::endl;
}

#endif // __x86_64__
