#include "tcptrace_x86_64.hpp"

#ifdef __x86_64__

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
    unsigned long scno;

    scno = ptrace(PTRACE_PEEKUSER, m_pid, ORIG_RAX * 8, NULL);
    std::cout << "system call number: " << scno << std::endl;
}

void
tcptrace::after_syscall()
{

}

#endif // __x86_64__
