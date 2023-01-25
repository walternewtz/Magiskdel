#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>

#include <base.hpp>

#define READ 0
#define WRITE 1

#define VLOGDG(tag, from, to) LOGD("%-8s: %s <- %s\n", tag, to, from)

using namespace std;


bool is_dir_exist(const char *s){
    struct stat st;
    if(stat(s,&st) == 0)
        if((st.st_mode & S_IFDIR) != 0)
            return true;
    return false;
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

// implement my own method to get only lowercase string
char *random_strc(int n){
    FILE *urandom = fopen("/dev/urandom", "re");
    if (urandom == nullptr) return nullptr;
    char *str = new char[n+1];
    if (str == nullptr) {
        fclose(urandom);
        return nullptr;
    }
    for (int i=0;i<n;i++){
        str[i] = 'a' + (fgetc(urandom) % ('z'-'a'+1));
    }
    fclose(urandom);
    return str;
}

int get_random(int from, int to){
    FILE *urandom = fopen("/dev/urandom", "re");
    if (urandom == nullptr) return from;
    int tmp, s=0, n = to-from+1;
    while (n!=0){
        do {
            tmp = fgetc(urandom);
        } while ( !(tmp >= '0' && tmp <= '9') );
        s = s*10 + tmp - '0';
        n/=10;
    }
    return from + s % (to-from+1);
}

long xptrace(int request, pid_t pid, void *addr, void *data) {
    long ret = ptrace(request, pid, addr, data);
    if (ret < 0)
        PLOGE("ptrace %d", pid);
    return ret;
}

