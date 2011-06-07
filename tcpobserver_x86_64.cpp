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
tcpobserver::before_syscall(pid_t pid)
{
    long scno;

    scno = ptrace(PTRACE_PEEKUSER, pid, ORIG_RAX * 8, NULL);

    m_proc[pid].m_scno = scno;

    switch (scno) {
    case syscall_socket:
        entering_socket(pid);
        break;
    case syscall_bind:
        entering_bind(pid);
        break;
    case syscall_listen:
        entering_listen(pid);
        break;
    case syscall_accept:
    case syscall_accept4:
        entering_accept(pid);
        break;
    case syscall_connect:
        entering_connect(pid);
        break;
    case syscall_close:
        entering_close(pid);
        break;
    }
}

void
tcpobserver::entering_socket(pid_t pid)
{
    m_proc[pid].m_domain   = ptrace(PTRACE_PEEKUSER, pid, RDI * 8, NULL);
    m_proc[pid].m_type     = ptrace(PTRACE_PEEKUSER, pid, RSI * 8, NULL);
    m_proc[pid].m_protocol = ptrace(PTRACE_PEEKUSER, pid, RDX * 8, NULL);
}

void
tcpobserver::entering_bind(pid_t pid)
{
    m_proc[pid].m_sockfd = ptrace(PTRACE_PEEKUSER, pid, RDI * 8, NULL);
    m_proc[pid].m_addr   = (sockaddr*)ptrace(PTRACE_PEEKUSER, pid, RSI * 8,
                                              NULL);
    m_proc[pid].m_addrlen  = ptrace(PTRACE_PEEKUSER, pid, RDX * 8, NULL);
}

void
tcpobserver::entering_listen(pid_t pid)
{
    m_proc[pid].m_sockfd = ptrace(PTRACE_PEEKUSER, pid, RDI * 8, NULL);
}

void
tcpobserver::entering_accept(pid_t pid)
{
    m_proc[pid].m_sockfd    = ptrace(PTRACE_PEEKUSER, pid, RDI * 8, NULL);
    m_proc[pid].m_addr      = (sockaddr*)ptrace(PTRACE_PEEKUSER, pid, RSI * 8,
                                                NULL);
    m_proc[pid].m_p_addrlen = (socklen_t*)ptrace(PTRACE_PEEKUSER, pid, RDX * 8,
                                                 NULL);

    if (m_proc[pid].m_addr == NULL) {
        unsigned long rsp;
        unsigned long size;
        unsigned long rem;
        void *p_saddr;
        void *p_slen;

        rsp = ptrace(PTRACE_PEEKUSER, pid, RSP * 8, NULL);
        m_proc[pid].m_rsp = rsp;

        size = sizeof(sockaddr_storage) + sizeof(socklen_t);

        rem  = size % 16;
        size = (size == 0) ? size : size + 16 - rem;
        rsp -= size;

        p_saddr = (void*)(m_proc[pid].m_rsp - sizeof(sockaddr_storage));
        p_slen  = (void*)(m_proc[pid].m_rsp - sizeof(sockaddr_storage) -
                          sizeof(socklen_t));

        m_proc[pid].m_addr      = (sockaddr*)p_saddr;
        m_proc[pid].m_p_addrlen = (socklen_t*)p_slen;


        sockaddr_storage saddr;
        socklen_t        slen;

        memset(&saddr, 0, sizeof(saddr));
        slen = sizeof(saddr);

        write_data(pid, &saddr, p_saddr, sizeof(saddr));
        write_data(pid, &slen, p_slen, sizeof(slen));
        

        ptrace(PTRACE_POKEUSER, pid, RSP * 8, (void*)rsp);
        ptrace(PTRACE_POKEUSER, pid, RSI * 8, p_saddr);
        ptrace(PTRACE_POKEUSER, pid, RDX * 8, p_slen);
    } else {
        m_proc[pid].m_rsp = 0;
    }
}

void
tcpobserver::entering_connect(pid_t pid)
{
    m_proc[pid].m_sockfd  = ptrace(PTRACE_PEEKUSER, pid, RDI * 8, NULL);
    m_proc[pid].m_addr    = (sockaddr*)ptrace(PTRACE_PEEKUSER, pid, RSI * 8,
                                              NULL);
    m_proc[pid].m_addrlen = ptrace(PTRACE_PEEKUSER, pid, RDX * 8, NULL);
}

void
tcpobserver::entering_close(pid_t pid)
{
    m_proc[pid].m_sockfd = ptrace(PTRACE_PEEKUSER, pid, RDI * 8, NULL);

    if (m_fd_set.find(m_proc[pid].m_sockfd) == m_fd_set.end())
        m_proc[pid].m_sockfd = -1;
}

void
tcpobserver::after_syscall(pid_t pid)
{
    long rax, orig_rax;

    rax = ptrace(PTRACE_PEEKUSER, pid, 8 * RAX, NULL);
    orig_rax = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL);

    switch (m_proc[pid].m_scno) {
    case syscall_socket:
        exiting_socket(pid);
        break;
    case syscall_bind:
        exiting_bind(pid);
        break;
    case syscall_listen:
        exiting_listen(pid);
        break;
    case syscall_accept:
    case syscall_accept4:
        exiting_accept(pid);
        break;
    case syscall_connect:
        exiting_connect(pid);
        break;
    case syscall_close:
        exiting_close(pid);
        break;
    }
}

void
tcpobserver::exiting_socket(pid_t pid)
{
    int fd;

    fd = ptrace(PTRACE_PEEKUSER, pid, RAX * 8, NULL);

    if ((m_proc[pid].m_domain == AF_INET || m_proc[pid].m_domain == AF_INET6) &&
        m_proc[pid].m_type == SOCK_STREAM &&
        (m_proc[pid].m_protocol == IPPROTO_TCP ||
         m_proc[pid].m_protocol == 0) && fd != -1) {
        double datetime;
        std::string domain;

        if (m_proc[pid].m_domain == AF_INET)
            domain = "IPv4";
        else
            domain = "IPv6";

        m_fd_set.insert(fd);

        datetime = get_datetime();

        std::cerr << std::setprecision(19)
                  << "datetime@" << datetime
                  << " op@socket"
                  << " fd@" << fd
                  << " protocol@" << domain
                  << " pid@" << pid
                  << std::endl;
    }
}

void
tcpobserver::exiting_bind(pid_t pid)
{
    int result;

    result = ptrace(PTRACE_PEEKUSER, pid, RAX * 8, NULL);

    if (result != 0)
        return;

    if (m_proc[pid].m_addrlen < sizeof(long))
        return;


    sockaddr_storage saddr;
    std::string      domain;
    double           datetime;
    uint16_t         port;
    char             addr[64];

    read_data(pid, &saddr, m_proc[pid].m_addr, sizeof(long));

    switch (saddr.ss_family) {
    case AF_INET:
    {
        sockaddr_in *saddr_in;

        if (m_proc[pid].m_addrlen < sizeof(sockaddr_in))
            return;

        read_data(pid, &saddr, m_proc[pid].m_addr, sizeof(sockaddr_in));

        saddr_in = (sockaddr_in*)&saddr;

        inet_ntop(AF_INET, &saddr_in->sin_addr, addr, sizeof(addr));
        port   = ntohs(saddr_in->sin_port);
        domain = "IPv4";

        break;
    }
    case AF_INET6:
    {
        sockaddr_in6 *saddr_in6;

        if (m_proc[pid].m_addrlen < sizeof(sockaddr_in6))
            return;

        read_data(pid, &saddr, m_proc[pid].m_addr, sizeof(sockaddr_in6));

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

    m_fd_set.insert(m_proc[pid].m_sockfd);

    std::cerr << std::setprecision(19)
              << "datetime@" << datetime
              << " op@bind"
              << " fd@" << m_proc[pid].m_sockfd
              << " protocol@" << domain
              << " addr@" << addr
              << " port@" << port
              << " pid@" << pid
              << std::endl;
}

void
tcpobserver::exiting_listen(pid_t pid)
{
    int result;

    result = ptrace(PTRACE_PEEKUSER, pid, RAX * 8, NULL);

    if (result < 0)
        return;


    double datetime;

    datetime = get_datetime();

    m_fd_set.insert(m_proc[pid].m_sockfd);

    std::cerr << std::setprecision(19)
              << "datetime@" << datetime
              << " op@listen"
              << " fd@" << m_proc[pid].m_sockfd
              << " pid@" << pid
              << std::endl;
}

void
tcpobserver::exiting_accept(pid_t pid)
{
    if (m_proc[pid].m_rsp != 0)
        ptrace(PTRACE_POKEUSER, pid, RSP * 8, (void*)m_proc[pid].m_rsp);

    m_proc[pid].m_rsp = 0;


    int result;

    result = ptrace(PTRACE_PEEKUSER, pid, RAX * 8, NULL);

    if (result < 0)
        return;


    sockaddr_storage saddr;
    std::string      domain;
    double           datetime;
    uint16_t         port;
    char             addr[64];

    read_data(pid, &saddr, m_proc[pid].m_addr, sizeof(long));

    switch (saddr.ss_family) {
    case AF_INET:
    {
        sockaddr_in *saddr_in;
        socklen_t    slen;

        read_data(pid, &slen, m_proc[pid].m_p_addrlen, sizeof(slen));

        if (slen < sizeof(sockaddr_in))
            return;

        read_data(pid, &saddr, m_proc[pid].m_addr, sizeof(sockaddr_in));

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

        read_data(pid, &slen, m_proc[pid].m_p_addrlen, sizeof(slen));

        if (slen < sizeof(sockaddr_in6))
            return;

        read_data(pid, &saddr, m_proc[pid].m_addr, sizeof(sockaddr_in6));

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

    m_fd_set.insert(m_proc[pid].m_sockfd);
    m_fd_set.insert(result);

    std::cerr << std::setprecision(19)
              << "datetime@" << datetime
              << " op@accept"
              << " listen_fd@" << m_proc[pid].m_sockfd
              << " fd@" << result
              << " protocol@" << domain
              << " addr@" << addr
              << " port@" << port
              << " pid@" << pid
              << std::endl;
}

void
tcpobserver::exiting_connect(pid_t pid)
{
    int result;

    result = ptrace(PTRACE_PEEKUSER, pid, RAX * 8, NULL);

    if (result < 0)
        return;

    if (m_proc[pid].m_addrlen < sizeof(long))
        return;


    sockaddr_storage saddr;
    std::string      domain;
    double           datetime;
    uint16_t         port;
    char             addr[64];

    read_data(pid, &saddr, m_proc[pid].m_addr, sizeof(long));

    switch (saddr.ss_family) {
    case AF_INET:
    {
        sockaddr_in *saddr_in;

        if (m_proc[pid].m_addrlen < sizeof(sockaddr_in))
            return;

        read_data(pid, &saddr, m_proc[pid].m_addr, sizeof(sockaddr_in));

        saddr_in = (sockaddr_in*)&saddr;

        inet_ntop(AF_INET, &saddr_in->sin_addr, addr, sizeof(addr));
        port   = ntohs(saddr_in->sin_port);
        domain = "IPv4";

        break;
    }
    case AF_INET6:
    {
        sockaddr_in6 *saddr_in6;

        if (m_proc[pid].m_addrlen < sizeof(sockaddr_in6))
            return;

        read_data(pid, &saddr, m_proc[pid].m_addr, sizeof(sockaddr_in6));

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

    m_fd_set.insert(result);

    std::cerr << std::setprecision(19)
              << "datetime@" << datetime
              << " op@connect"
              << " fd@" << result
              << " protocol@" << domain
              << " addr@" << addr
              << " port@" << port
              << " pid@" << pid
              << std::endl;
}

void
tcpobserver::exiting_close(pid_t pid)
{
    if (m_proc[pid].m_sockfd < 0)
        return;


    double datetime;

    datetime = get_datetime();

    std::cerr << std::setprecision(19)
              << "datetime@" << datetime
              << " op@close"
              << " fd@" << m_proc[pid].m_sockfd
              << " pid@" << pid
              << std::endl;

    m_fd_set.erase(m_proc[pid].m_sockfd);
}

void
tcpobserver::proc_removed(pid_t pid)
{
    m_proc.erase(pid);
}

#endif // __x86_64__
