#include "tcpobserver_x86.hpp"

#include <sys/ptrace.h>
#include <sys/reg.h>

#include <iostream>

#ifdef __i386__

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
    long int scno;

    scno = ptrace(PTRACE_PEEKUSER, m_pid, ORIG_EAX * 4, NULL);
    std::cout << "system call number: " << scno << std::endl;
}

void
tcpobserver::after_syscall()
{

}

#endif // __i386__
