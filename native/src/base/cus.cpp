#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <base.hpp>

using namespace std;


bool is_dir_exist(const char *s){
    struct stat st;
    if(stat(s,&st) == 0)
        if(st.st_mode & S_IFDIR != 0)
            return true;
    return false;
}
