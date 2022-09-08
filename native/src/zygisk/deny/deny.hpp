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
    WHITELIST,
    BLACKLIST,

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
    WHITELIST_ENFORCED,

    END
};
}

// CLI entries
int enable_deny(bool props = true);
int enable_whitelist();
int disable_deny();
int disable_whitelist();
int add_list(int client);
int rm_list(int client);
void ls_list(int client);

// Utility functions
bool is_deny_target(int uid, std::string_view process, int max_len = 1024);
void crawl_procfs(const std::function<bool(int)> &fn);

// Revert
void revert_unmount(int pid = -1);
void cleanup_preload();

extern int sys_ui_app_id;
extern std::atomic<bool> denylist_enforced;
extern std::atomic<bool> hide_whitelist;
