#include <cinttypes>
#include <base.hpp>

#include "zygisk.hpp"

using namespace std;

namespace {

struct map_info {
    uintptr_t start;
    uintptr_t end;
    uintptr_t off;
    int perms;
    unsigned long inode;

    map_info() : start(0), end(0), off(0), perms(0), inode(0) {}
};

} // namespace

template<typename Func>
static void parse_maps(int pid, Func fn) {
    char file[32];

    // format: start-end perms offset dev inode path
    sprintf(file, "/proc/%d/maps", pid);
    file_readline(true, file, [=](string_view l) -> bool {
        char *line = (char *) l.data();
        map_info info;
        char perm[5];
        int path_off;

        if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %*x:%*x %lu %n%*s",
                   &info.start, &info.end, perm, &info.off, &info.inode, &path_off) != 5)
            return true;

        // Parse permissions
        if (perm[0] != '-')
            info.perms |= PROT_READ;
        if (perm[1] != '-')
            info.perms |= PROT_WRITE;
        if (perm[2] != '-')
            info.perms |= PROT_EXEC;

        return fn(info, line + path_off);
    });
}

static vector<map_info> find_maps(const char *name) {
    vector<map_info> maps;
    parse_maps(getpid(), [=, &maps](const map_info &info, const char *path) -> bool {
        if (strcmp(path, name) == 0)
            maps.emplace_back(info);
        return true;
    });
    return maps;
}

std::pair<void *, size_t> find_map_range(const char *name, unsigned long inode) {
    vector<map_info> maps = find_maps(name);
    uintptr_t start = 0u;
    uintptr_t end = 0u;
    for (const auto &map : maps) {
        if (map.inode == inode) {
            if (start == 0) {
                start = map.start;
                end = map.end;
            } else if (map.start == end) {
                end = map.end;
            }
        }
    }
    LOGD("found map %s with start = %zx, end = %zx\n", name, start, end);
    return make_pair(reinterpret_cast<void *>(start), end - start);
}

uintptr_t get_function_off(int pid, uintptr_t addr, char *lib) {
    uintptr_t off = 0;
    parse_maps(pid, [=, &off](const map_info &info, const char *path) -> bool {
        if (addr >= info.start && addr < info.end) {
            if (lib)
                strcpy(lib, path);
            off = addr - info.start + info.off;
            return false;
        }
        return true;
    });
    return off;
}

uintptr_t get_function_addr(int pid, const char *lib, uintptr_t off) {
    uintptr_t addr = 0;
    parse_maps(pid, [=, &addr](const map_info &info, const char *path) -> bool {
        if (strcmp(path, lib) == 0 && (info.perms & PROT_EXEC)) {
            addr = info.start - info.off + off;
            return false;
        }
        return true;
    });
    return addr;
}
