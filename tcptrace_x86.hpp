#ifndef TCPTRACE_X86_HPP
#define TCPTRACE_X86_HPP

#include "tcptrace_base.hpp"

#ifdef __i386__

class tcptrace : public tcptrace_base
{
public:
    tcptrace(pid_t pid);
    tcptrace(char *cmd);

    ~tcptrace();

protected:
    virtual void before_syscall();
    virtual void after_syscall();
};

#endif // __i386__

#endif // TCPTRACE_X86_HPP
