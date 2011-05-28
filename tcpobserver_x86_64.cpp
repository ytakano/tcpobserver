#include "tcpobserver_x86_64.hpp"

#include <sys/ptrace.h>
#include <sys/reg.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <stdint.h>
#include <string.h>

#include <iostream>
#include <iomanip>
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

}

tcpobserver::tcpobserver(char *cmd) : tcpobserver_base(cmd)
{

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
    case syscall_accept:
    case syscall_accept4:
        entering_accept();
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
tcpobserver::entering_accept()
{
    m_accept_args.sockfd  = ptrace(PTRACE_PEEKUSER, m_pid, RDI * 8, NULL);
    m_accept_args.addr    = (sockaddr*)ptrace(PTRACE_PEEKUSER, m_pid, RSI * 8,
                                             NULL);
    m_accept_args.addrlen = (socklen_t*)ptrace(PTRACE_PEEKUSER, m_pid, RDX * 8,
                                               NULL);

    if (m_accept_args.addr == NULL) {
        unsigned long rsp;
        unsigned long size;
        unsigned long rem;
        void *p_saddr;
        void *p_slen;

        rsp = ptrace(PTRACE_PEEKUSER, m_pid, RSP * 8, NULL);
        m_accept_args.rsp = rsp;

        size = sizeof(sockaddr_storage) + sizeof(socklen_t);

        rem  = size % 16;
        size = (size == 0) ? size : size + 16 - rem;
        rsp -= size;

        p_saddr = (void*)(m_accept_args.rsp - sizeof(sockaddr_storage));
        p_slen  = (void*)(m_accept_args.rsp - sizeof(sockaddr_storage) -
                          sizeof(socklen_t));

        m_accept_args.addr    = (sockaddr*)p_saddr;
        m_accept_args.addrlen = (socklen_t*)p_slen;


        sockaddr_storage saddr;
        socklen_t        slen;

        memset(&saddr, 0, sizeof(saddr));
        slen = sizeof(saddr);

        write_data(&saddr, p_saddr, sizeof(saddr));
        write_data(&slen, p_slen, sizeof(slen));
        

        ptrace(PTRACE_POKEUSER, m_pid, RSP * 8, (void*)rsp);
        ptrace(PTRACE_POKEUSER, m_pid, RSI * 8, p_saddr);
        ptrace(PTRACE_POKEUSER, m_pid, RDX * 8, p_slen);
    } else {
        m_accept_args.rsp = 0;
    }
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
    case syscall_accept:
    case syscall_accept4:
        exiting_accept();
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

        std::cerr << std::setprecision(19)
                  << datetime << "@datetime "
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

    std::cerr << std::setprecision(19)
              << datetime << "@datetime "
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

    datetime = get_datetime();

    std::cerr << std::setprecision(19)
              << datetime << "@datetime "
              << "listen@op "
              << m_listen_args.sockfd << "@fd"
              << std::endl;
}

void
tcpobserver::exiting_accept()
{
    if (m_accept_args.rsp != 0)
        ptrace(PTRACE_POKEUSER, m_pid, RSP * 8, (void*)m_accept_args.rsp);

    m_accept_args.rsp = 0;


    int result;

    result = ptrace(PTRACE_PEEKUSER, m_pid, RAX * 8, NULL);

    if (result < 0)
        return;


    sockaddr_storage saddr;
    std::string      domain;
    double           datetime;
    uint16_t         port;
    char             addr[64];

    read_data(&saddr, m_accept_args.addr, sizeof(long));

    switch (saddr.ss_family) {
    case AF_INET:
    {
        sockaddr_in *saddr_in;
        socklen_t    slen;

        read_data(&slen, m_accept_args.addrlen, sizeof(slen));

        if (slen < sizeof(sockaddr_in))
            return;

        read_data(&saddr, m_accept_args.addr, sizeof(sockaddr_in));

        saddr_in = (sockaddr_in*)&saddr;

        inet_ntop(AF_INET, &saddr_in->sin_addr, addr, sizeof(addr));
        port   = ntohs(saddr_in->sin_port);
        domain = "IPv4";
        break;
    }
    case AF_INET6:
    {
        sockaddr_in6 *saddr_in6;
        socklen_t     slen;

        read_data(&slen, m_accept_args.addrlen, sizeof(slen));

        if (slen < sizeof(sockaddr_in6))
            return;

        read_data(&saddr, m_accept_args.addr, sizeof(sockaddr_in6));

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

    std::cerr << std::setprecision(19)
              << datetime << "@datetime "
              << "accept@op "
              << m_accept_args.sockfd << "@listen_fd "
              << result << "@fd "
              << domain << "@protocol "
              << addr << "@addr "
              << port << "@port "
              << std::endl;
}

#endif // __x86_64__
