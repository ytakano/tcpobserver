#ifndef TCPTRACE_X86_64_HPP
#define TCPTRACE_X86_64_HPP

#include "tcptrace_base.hpp"

#ifdef __x86_64__

class tcptrace : public tcptrace_base
{
public:
    tcptrace(pid_t pid);
    tcptrace(char *cmd);

    ~tcptrace();

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

    unsigned long m_scno;
    socket_args   m_socket_args;

    void entering_socket();
    void exiting_socket();
};

#endif // __x86_64__

#endif // TCPTRACE_X86_64_HPP
