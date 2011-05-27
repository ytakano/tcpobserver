#ifndef TCPOBSERVER_BASE_HPP
#define TCPOBSERVER_BASE_HPP

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

class tcpobserver_base {
public:
    tcpobserver_base(pid_t pid);
    tcpobserver_base(char *cmd);
    virtual ~tcpobserver_base();

    void    do_trace();

    static tcpobserver_base *instance;

protected:
    virtual void before_syscall() = 0;
    virtual void after_syscall()  = 0;

    double  get_datetime();
    void    read_data(void *buf, void *addr, size_t len);

    pid_t   m_pid;

private:
    void    set_sa_handler();
    void    create_child(char *cmd);
    void    cleanup();
    void    split(std::string str, std::vector<std::string> &result);

    bool    m_is_exec;
    bool    m_is_entering;

    friend void signal_handler(int signum);
};

#endif // TCPOBSERVER_BASE_HPP
