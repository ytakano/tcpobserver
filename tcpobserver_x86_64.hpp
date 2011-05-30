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
    virtual void before_syscall();
    virtual void after_syscall();

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

    unsigned long m_scno;
    std::set<int> m_fd_set;
    socket_args   m_socket_args;
    bind_args     m_bind_args;
    listen_args   m_listen_args;
    accept_args   m_accept_args;
    connect_args  m_connect_args;
    int           m_close_arg;

    // for socket
    void entering_socket();
    void exiting_socket();

    // for bind
    void entering_bind();
    void exiting_bind();

    // for listen
    void entering_listen();
    void exiting_listen();

    // for accept and accept4
    void entering_accept();
    void exiting_accept();

    // for connect
    void entering_connect();
    void exiting_connect();

    // for close
    void entering_close();
    void exiting_close();
};

#endif // __x86_64__

#endif // TCPOBSERVER_X86_64_HPP
