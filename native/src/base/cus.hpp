#pragma once
#include <sys/wait.h>
#include <signal.h>

bool is_dir_exist(const char *s);
pid_t popen2(char **command, int *infp, int *outfp);


struct pstream {
    pid_t pid;
    int in,out;
    int open(char **command){
        return pid = popen2(command,&in,&out);
    }
    void term(){
        if (pid >= 0){
            kill(pid, SIGKILL);
            waitpid(pid,0,0);
            pid = -1;
        }
        close(in);
        close(out);
        in = -1;
        out = -1;
    }
    void init(){
        pid= -1;
        in= -1;
        out= -1;
    }
};

int bind_mount_(const char *from, const char *to);
int tmpfs_mount(const char *from, const char *to);

