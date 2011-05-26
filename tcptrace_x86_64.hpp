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
    virtual void beore_syscall();
    virtual void after_syscall();
};

#endif // __x86_64__

#endif // TCPTRACE_X86_64_HPP
