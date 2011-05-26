#ifndef TCPOBSERVER_X86_HPP
#define TCPOBSERVER_X86_HPP

#include "tcpobserver_base.hpp"

#ifdef __i386__

class tcpobserver : public tcpobserver_base
{
public:
    tcpobserver(pid_t pid);
    tcpobserver(char *cmd);

    ~tcpobserver();

protected:
    virtual void before_syscall();
    virtual void after_syscall();
};

#endif // __i386__

#endif // TCPOBSERVER_X86_HPP
