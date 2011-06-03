#ifndef TCPOBSERVER_BASE_HPP
#define TCPOBSERVER_BASE_HPP

#include <unistd.h>

#include <map>
#include <set>
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
    virtual void before_syscall(pid_t pid) = 0;
    virtual void after_syscall(pid_t pid)  = 0;

    virtual void proc_removed(pid_t pid);

    double  get_datetime();
    void    read_data(pid_t pid, void *buf, void *addr, size_t len);
    void    write_data(pid_t pid, void *buf, void *addr, size_t len);

    pid_t           m_parent;
    std::set<pid_t> m_pid;

private:
    void    set_sa_handler();
    void    create_child(char *cmd);
    void    cleanup();
    void    split(std::string str, std::vector<std::string> &result);

    bool    m_is_exec;
    std::map<pid_t, bool> m_is_entering;

    friend void signal_handler(int signum);
};

#endif // TCPOBSERVER_BASE_HPP
