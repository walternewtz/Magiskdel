#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <base.hpp>

#define READ 0
#define WRITE 1

#define VLOGDG(tag, from, to) LOGD("%-8s: %s <- %s\n", tag, to, from)

using namespace std;


bool is_dir_exist(const char *s){
    struct stat st;
    if(stat(s,&st) == 0)
        if(st.st_mode & S_IFDIR != 0)
            return true;
    return false;
}



pid_t popen2(char **command, int *infp, int *outfp) {

    int p_stdin[2], p_stdout[2];
    pid_t pid;

    if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0)
        return -1;

    pid = fork();

    if (pid < 0)
        return pid;
    else if (pid == 0)
    {
        close(p_stdin[WRITE]);
        dup2(p_stdin[READ], READ);
        close(p_stdout[READ]);
        dup2(p_stdout[WRITE], WRITE);

        execv(*command, command);
        _exit(1);
    }

    if (infp == NULL)
        close(p_stdin[WRITE]);
    else
        *infp = p_stdin[WRITE];

    if (outfp == NULL)
        close(p_stdout[READ]);
    else
        *outfp = p_stdout[READ];

    return pid;
}

int bind_mount_(const char *from, const char *to) {
    int ret = xmount(from, to, nullptr, MS_BIND, nullptr);
    if (ret == 0)
        VLOGDG("bind_mnt", from, to);
    return ret;
}

int tmpfs_mount(const char *from, const char *to){
    int ret = xmount(from, to, "tmpfs", 0, "mode=755");
    if (ret == 0)
        VLOGDG("mnt_tmp", "tmpfs", to);
    return ret;
}


