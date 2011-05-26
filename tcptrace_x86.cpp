#include "tcptrace_x86.hpp"

#ifdef __i386__

tcptrace::tcptrace(pid_t pid) : tcptrace_base(pid)
{

}

tcptrace::tcptrace(char *cmd) : tcptrace_base(cmd)
{

}

tcptrace::~tcptrace()
{

}

void
tcptrace::before_syscall()
{
    long int scno;

    scno = ptrace(PTRACE_PEEKUSER, m_pid, ORIG_EAX * 4, NULL);
    std::cout << "system call number: " << scno << std::endl;
}

void
tcptrace::after_syscall()
{

}

#endif // __i386__
