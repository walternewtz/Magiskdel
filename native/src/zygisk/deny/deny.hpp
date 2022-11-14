#pragma once

#include <string_view>
#include <functional>
#include <map>
#include <atomic>

#include <daemon.hpp>

#define ISOLATED_MAGIC "isolated"

#define SIGTERMTHRD SIGUSR1

namespace DenyRequest {
enum : int {
    ENFORCE,
    DISABLE,
    ADD,
    REMOVE,
    LIST,
    STATUS,
    START_MONITOR,
    STOP_MONITOR,
    CHECK_PID,
    SULIST_STATUS,

    END
};
}

namespace DenyResponse {
enum : int {
    OK,
    ENFORCED,
    NOT_ENFORCED,
    ITEM_EXIST,
    ITEM_NOT_EXIST,
    INVALID_PKG,
    NO_NS,
    ERROR,
    SULIST_ENFORCED,
    SULIST_NOT_ENFORCED,
    SULIST_NO_DISABLE,

    END
};
}

// CLI entries
int enable_deny(bool props = true);
int disable_deny();
int add_list(int client);
int rm_list(int client);
void ls_list(int client);

// Utility functions
bool is_deny_target(int uid, std::string_view process, int max_len = 1024);
void crawl_procfs(const std::function<bool(int)> &fn);

// Revert
void revert_daemon(int pid, int client = -1);
void su_daemon(int pid);
void revert_unmount(int pid = -1);
//void cleanup_preload();
void do_check_pid(int client);

//Event
void disable_monitor();
void enable_monitor();


extern std::atomic<bool> denylist_enforced;
extern std::atomic<bool> do_monitor;
