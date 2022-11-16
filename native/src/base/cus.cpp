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


