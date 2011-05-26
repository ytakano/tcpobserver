#ifndef TCPTRACE_BASE_HPP
#define TCPTRACE_BASE_HPP

#include <unistd.h>

#include <string>
#include <vector>

#define PRINT_ERROR()                                                   \
    do {                                                                \
        std::ostringstream os;                                          \
        os << __FILE__ << ":" << __LINE__;                              \
        perror(os.str().c_str());                                       \
    } while (0)

void signal_handler(int signum);

class tcptrace_base {
public:
    tcptrace_base(pid_t pid);
    tcptrace_base(char *cmd);
    virtual ~tcptrace_base();

    static tcptrace_base *instance;

protected:
    virtual void before_syscall() = 0;
    virtual void after_syscall()  = 0;

private:
    void    set_sa_handler();
    void    create_child(char *cmd);
    void    cleanup();
    void    split(std::string str, std::vector<std::string> &result);
    void    do_trace();

    bool    m_is_exec;
    pid_t   m_pid;
    bool    m_is_entering;

    friend void signal_handler(int signum);
};

#endif // TCPTRACE_BASE_HPP
