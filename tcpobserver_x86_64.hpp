#ifndef TCPOBSERVER_X86_64_HPP
#define TCPOBSERVER_X86_64_HPP

#include "tcpobserver_base.hpp"

#include <sys/types.h>
#include <sys/socket.h>

#include <set>

#ifdef __x86_64__

class tcpobserver : public tcpobserver_base
{
public:
    tcpobserver(pid_t pid);
    tcpobserver(char *cmd);

    ~tcpobserver();

protected:
    virtual void before_syscall(pid_t pid);
    virtual void after_syscall(pid_t pid);

private:
    static const unsigned long syscall_socket;
    static const unsigned long syscall_bind;
    static const unsigned long syscall_listen;
    static const unsigned long syscall_accept;
    static const unsigned long syscall_accept4;
    static const unsigned long syscall_connect;
    static const unsigned long syscall_close;

    struct socket_args {
        int domain;
        int type;
        int protocol;
    };

    struct bind_args {
        int       sockfd;
        sockaddr *addr;
        socklen_t addrlen;
    };

    struct listen_args {
        int sockfd;
    };

    struct accept_args {
        int           sockfd;
        sockaddr     *addr;
        socklen_t    *addrlen;
        unsigned long rsp;
    };

    struct connect_args {
        int       sockfd;
        sockaddr *addr;
        socklen_t addrlen;
    };

    struct proc_info {
        unsigned long m_scno;
        int           m_domain;
        int           m_type;
        int           m_protocol;
        int           m_sockfd;
        sockaddr     *m_addr;
        socklen_t     m_addrlen;
        socklen_t    *m_p_addrlen;
        unsigned long m_rsp;
    };

    std::set<int> m_fd_set;
    std::map<pid_t, proc_info> m_proc;


    // for socket
    void entering_socket(pid_t pid);
    void exiting_socket(pid_t pid);

    // for bind
    void entering_bind(pid_t pid);
    void exiting_bind(pid_t pid);

    // for listen
    void entering_listen(pid_t pid);
    void exiting_listen(pid_t pid);

    // for accept and accept4
    void entering_accept(pid_t pid);
    void exiting_accept(pid_t pid);

    // for connect
    void entering_connect(pid_t pid);
    void exiting_connect(pid_t pid);

    // for close
    void entering_close(pid_t pid);
    void exiting_close(pid_t pid);

    // process was removed
    virtual void proc_removed(pid_t pid);
};

#endif // __x86_64__

#endif // TCPOBSERVER_X86_64_HPP
