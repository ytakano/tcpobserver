#ifndef TCPTRACE_HPP
#define TCPTRACE_HPP

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

class tcptrace {
public:
    tcptrace(pid_t pid);
    tcptrace(char *cmd);

    static tcptrace *instance;

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

#endif // TCPTRACE_HPP
