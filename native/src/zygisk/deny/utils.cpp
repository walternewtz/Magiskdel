#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <set>
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <vector>
#include <bitset>
#include <string>
#include <cinttypes>
#include <poll.h>


#include <daemon.hpp>
#include <magisk.hpp>
#include <base.hpp>
#include <db.hpp>
#include <resetprop.hpp>

#include "deny.hpp"


#define SNET_PROC    "com.google.android.gms.unstable"
#define GMS_PKG      "com.google.android.gms"

using namespace std;

atomic_flag skip_pkg_rescan;

atomic_flag *p_skip_pkg_rescan = &skip_pkg_rescan;

// For the following data structures:
// If package name == ISOLATED_MAGIC, or app ID == -1, it means isolated service

// Package name -> list of process names
static unique_ptr<map<string, set<string, StringCmp>, StringCmp>> pkg_to_procs_;
#define pkg_to_procs (*pkg_to_procs_)

// app ID -> list of pkg names (string_view points to a pkg_to_procs key)
static unique_ptr<map<int, set<string_view>>> app_id_to_pkgs_;
#define app_id_to_pkgs (*app_id_to_pkgs_)

// Locks the data structures above
static pthread_mutex_t data_lock = PTHREAD_MUTEX_INITIALIZER;

atomic<bool> denylist_enforced = false;

atomic<bool> hide_whitelist = false;

atomic<bool> do_monitor = true;

extern bool uid_granted_root(int uid);

// Process monitoring
pthread_t monitor_thread;
void proc_monitor();
static pstream ps_a, ps_b;
static bool monitoring = false;
static int fork_pid = 0;

static void kill_pipe(){
    ps_a.term();
    ps_b.term();
}

static void fflush_logcat(){
    exec_command_sync("/system/bin/logcat", "-b", "all", "-c");
}

#define do_kill (denylist_enforced)

static void rescan_apps() {
    LOGD("hide: rescanning apps\n");

    app_id_to_pkgs.clear();

    auto data_dir = xopen_dir(APP_DATA_DIR);
    if (!data_dir)
        return;
    dirent *entry;
    while ((entry = xreaddir(data_dir.get()))) {
        // For each user
        int dfd = xopenat(dirfd(data_dir.get()), entry->d_name, O_RDONLY);
        if (auto dir = xopen_dir(dfd)) {
            while ((entry = xreaddir(dir.get()))) {
                // For each package
                struct stat st{};
                xfstatat(dfd, entry->d_name, &st, 0);
                int app_id = to_app_id(st.st_uid);
                if (auto it = pkg_to_procs.find(entry->d_name); it != pkg_to_procs.end()) {
                    app_id_to_pkgs[app_id].insert(it->first);
                }
            }
        } else {
            close(dfd);
        }
    }
}

static void update_pkg_uid(const string &pkg, bool remove) {
    auto data_dir = xopen_dir(APP_DATA_DIR);
    if (!data_dir)
        return;
    dirent *entry;
    struct stat st{};
    char buf[PATH_MAX] = {0};
    // For each user
    while ((entry = xreaddir(data_dir.get()))) {
        ssprintf(buf, sizeof(buf), "%s/%s", entry->d_name, pkg.data());
        if (fstatat(dirfd(data_dir.get()), buf, &st, 0) == 0) {
            int app_id = to_app_id(st.st_uid);
            if (remove) {
                if (auto it = app_id_to_pkgs.find(app_id); it != app_id_to_pkgs.end()) {
                    it->second.erase(pkg);
                    if (it->second.empty()) {
                        app_id_to_pkgs.erase(it);
                    }
                }
            } else {
                app_id_to_pkgs[app_id].insert(pkg);
            }
            break;
        }
    }
}

// Leave /proc fd opened as we're going to read from it repeatedly
static DIR *procfp;

void crawl_procfs(const std::function<bool(int)> &fn) {
    rewinddir(procfp);
    dirent *dp;
    int pid;
    while ((dp = readdir(procfp))) {
        pid = parse_int(dp->d_name);
        if (pid > 0 && !fn(pid))
            break;
    }
}

static inline bool str_eql(string_view a, string_view b) { return a == b; }

template<bool str_op(string_view, string_view) = &str_eql>
static bool proc_name_match(int pid, string_view name) {
    char buf[4019];
    sprintf(buf, "/proc/%d/cmdline", pid);
    if (auto fp = open_file(buf, "re")) {
        fgets(buf, sizeof(buf), fp.get());
        if (str_op(buf, name)) {
            LOGD("hide_daemon: kill PID=[%d] (%s)\n", pid, buf);
            return true;
        }
    }
    return false;
}

static bool proc_context_match(int pid, string_view context) {
    char buf[PATH_MAX];
    sprintf(buf, "/proc/%d/attr/current", pid);
    if (auto fp = open_file(buf, "re")) {
        fgets(buf, sizeof(buf), fp.get());
        if (str_starts(buf, context)) {
            return true;
        }
    }
    return false;
}

template<bool matcher(int, string_view) = &proc_name_match>
static void kill_process(const char *name, bool multi = false) {
    crawl_procfs([=](int pid) -> bool {
        if (matcher(pid, name)) {
            kill(pid, SIGKILL);
            LOGD("hide_daemon: kill PID=[%d] (%s)\n", pid, name);
            return multi;
        }
        return true;
    });
}

static bool validate(const char *pkg, const char *proc) {
    bool pkg_valid = false;
    bool proc_valid = true;

    if (str_eql(pkg, ISOLATED_MAGIC)) {
        pkg_valid = true;
        for (char c; (c = *proc); ++proc) {
            if (isalnum(c) || c == '_' || c == '.')
                continue;
            if (c == ':')
                break;
            proc_valid = false;
            break;
        }
    } else {
        for (char c; (c = *pkg); ++pkg) {
            if (isalnum(c) || c == '_')
                continue;
            if (c == '.') {
                pkg_valid = true;
                continue;
            }
            pkg_valid = false;
            break;
        }

        for (char c; (c = *proc); ++proc) {
            if (isalnum(c) || c == '_' || c == ':' || c == '.')
                continue;
            proc_valid = false;
            break;
        }
    }
    return pkg_valid && proc_valid;
}

static bool add_hide_set(const char *pkg, const char *proc) {
    auto p = pkg_to_procs[pkg].emplace(proc);
    if (!p.second)
        return false;
    LOGI("hidelist add: [%s/%s]\n", pkg, proc);
    if (!do_kill)
        return true;
    if (str_eql(pkg, ISOLATED_MAGIC)) {
        // Kill all matching isolated processes
        kill_process<&proc_name_match<str_starts>>(proc, true);
    } else {
        kill_process(proc);
    }
    return true;
}

static void clear_data() {
    pkg_to_procs_.reset(nullptr);
    app_id_to_pkgs_.reset(nullptr);
}

static bool ensure_data() {
    if (pkg_to_procs_)
        return true;

    LOGI("hidelist: initializing internal data structures\n");

    default_new(pkg_to_procs_);
    char *err = db_exec("SELECT * FROM hidelist", [](db_row &row) -> bool {
        add_hide_set(row["package_name"].data(), row["process"].data());
        return true;
    });
    db_err_cmd(err, goto error)

    default_new(app_id_to_pkgs_);
    rescan_apps();

    
    return true;

error:
    clear_data();
    return false;
}

static int add_list(const char *pkg, const char *proc) {
    if (proc[0] == '\0')
        proc = pkg;

    if (!validate(pkg, proc))
        return DenyResponse::INVALID_PKG;

    {
        mutex_guard lock(data_lock);
        if (!ensure_data())
            return DenyResponse::ERROR;
        if (!add_hide_set(pkg, proc))
            return DenyResponse::ITEM_EXIST;
        auto it = pkg_to_procs.find(pkg);
        update_pkg_uid(it->first, false);
    }

    // Add to database
    char sql[4096];
    ssprintf(sql, sizeof(sql),
            "INSERT INTO hidelist (package_name, process) VALUES('%s', '%s')", pkg, proc);
    char *err = db_exec(sql);
    db_err_cmd(err, return DenyResponse::ERROR)
    return DenyResponse::OK;
}

int add_list(int client) {
    string pkg = read_string(client);
    string proc = read_string(client);
    return add_list(pkg.data(), proc.data());
}

static int rm_list(const char *pkg, const char *proc) {
    {
        mutex_guard lock(data_lock);
        if (!ensure_data())
            return DenyResponse::ERROR;

        bool remove = false;

        auto it = pkg_to_procs.find(pkg);
        if (it != pkg_to_procs.end()) {
            if (proc[0] == '\0') {
                update_pkg_uid(it->first, true);
                pkg_to_procs.erase(it);
                remove = true;
                LOGI("hidelist rm: [%s]\n", pkg);
            } else if (it->second.erase(proc) != 0) {
                remove = true;
                LOGI("hidelist rm: [%s/%s]\n", pkg, proc);
                if (it->second.empty()) {
                    update_pkg_uid(it->first, true);
                    pkg_to_procs.erase(it);
                }
            }
        }

        if (!remove)
            return DenyResponse::ITEM_NOT_EXIST;
    }

    char sql[4096];
    if (proc[0] == '\0')
        ssprintf(sql, sizeof(sql), "DELETE FROM hidelist WHERE package_name='%s'", pkg);
    else
        ssprintf(sql, sizeof(sql),
                "DELETE FROM hidelist WHERE package_name='%s' AND process='%s'", pkg, proc);
    char *err = db_exec(sql);
    db_err_cmd(err, return DenyResponse::ERROR)
    return DenyResponse::OK;
}

int rm_list(int client) {
    string pkg = read_string(client);
    string proc = read_string(client);
    return rm_list(pkg.data(), proc.data());
}

void ls_list(int client) {
    {
        mutex_guard lock(data_lock);
        if (!ensure_data()) {
            write_int(client, static_cast<int>(DenyResponse::ERROR));
            return;
        }

        write_int(client,static_cast<int>(DenyResponse::OK));

        for (const auto &[pkg, procs] : pkg_to_procs) {
            for (const auto &proc : procs) {
                write_int(client, pkg.size() + proc.size() + 1);
                xwrite(client, pkg.data(), pkg.size());
                xwrite(client, "|", 1);
                xwrite(client, proc.data(), proc.size());
            }
        }
    }
    write_int(client, 0);
    close(client);
}

static void update_deny_config() {
    char sql[64];
    sprintf(sql, "REPLACE INTO settings (key,value) VALUES('%s',%d)",
        DB_SETTING_KEYS[DENYLIST_CONFIG], denylist_enforced.load());
    char *err = db_exec(sql);
    db_err(err);
}

static void update_whitelist_config(){
    char sql[64];
    sprintf(sql, "REPLACE INTO settings (key,value) VALUES('%s',%d)",
        DB_SETTING_KEYS[WHITELIST_CONFIG], hide_whitelist.load());
    char *err = db_exec(sql);
    db_err(err);
}

static int new_daemon_thread(void(*entry)()) {
    thread_entry proxy = [](void *entry) -> void * {
        reinterpret_cast<void(*)()>(entry)();
        return nullptr;
    };
    return new_daemon_thread(proxy, (void *) entry);
}

int enable_whitelist(){
    if (hide_whitelist)
        return DenyResponse::OK;
    else if (!denylist_enforced)
         return DenyResponse:: NOT_ENFORCED;
         
    LOGI("* Enable MagiskHideAll\n");

    hide_whitelist = true;
    update_whitelist_config();
    return DenyResponse::OK;
}

int disable_whitelist(){
    if (!hide_whitelist)
        return DenyResponse::OK;

    LOGI("* Disable MagiskHideAll\n");

    hide_whitelist = false;
    update_whitelist_config();
    return DenyResponse::OK;
}


int enable_deny(bool props) {
    if (denylist_enforced) {
        return DenyResponse::OK;
    } else {
        mutex_guard lock(data_lock);

        if (access("/proc/self/ns/mnt", F_OK) != 0) {
            LOGW("The kernel does not support mount namespace\n");
            return DenyResponse::NO_NS;
        }

        if (procfp == nullptr && (procfp = opendir("/proc")) == nullptr)
            return DenyResponse::ERROR;

        LOGI("* Enable MagiskHide\n");
        
        if (props) hide_sensitive_props();
        denylist_enforced = true;

        if (!ensure_data()) {
            denylist_enforced = false;
            return DenyResponse::ERROR;
        }
        if (!zygisk_enabled && do_monitor) {
            auto ret1 = new_daemon_thread(&proc_monitor);
            if (ret1){
                // cannot start monitor_proc, return daemon error
                return DenyResponse::ERROR;
            }
            monitoring = true;
        }

        // On Android Q+, also kill blastula pool and all app zygotes
        if (SDK_INT >= 29) {
            kill_process("usap32", true);
            kill_process("usap64", true);
            kill_process<&proc_context_match>("u:r:app_zygote:s0", true);
        }
    }

    update_deny_config();

    return DenyResponse::OK;
}

void enable_monitor(){
	if (do_monitor) return;
	do_monitor = true;
	LOGI("* Enable proc_monitor\n");
}

void disable_monitor(){
	if (!do_monitor) return;
    do_monitor = false;
    LOGI("* Disable proc_monitor\n");
    if (monitoring) {
        pthread_kill(monitor_thread, SIGTERMTHRD);
        monitoring = false;
    }
}

int disable_deny() {
    if (denylist_enforced) {
        denylist_enforced = false;
        LOGI("* Disable MagiskHide\n");
    }
    if (!zygisk_enabled && monitoring) {
        pthread_kill(monitor_thread, SIGTERMTHRD);
        monitoring = false;
    }
    update_deny_config();

    return DenyResponse::OK;
}

void initialize_denylist() {
    if (!denylist_enforced) {
        db_settings dbs;
        get_db_settings(dbs, DENYLIST_CONFIG);
        if (dbs[DENYLIST_CONFIG])
            enable_deny(false);
    }
}

void reset_sensitive_props() {
    if (denylist_enforced) {
        hide_sensitive_props();
        db_settings dbs;
        get_db_settings(dbs, WHITELIST_CONFIG);
        if (dbs[WHITELIST_CONFIG])
            enable_whitelist();
    }
}

bool is_deny_target(int uid, string_view process, int max_len) {
    mutex_guard lock(data_lock);
    if (!ensure_data())
        return false;

    if (!p_skip_pkg_rescan->test_and_set())
        rescan_apps();

    int app_id = to_app_id(uid);
    int manager_app_id = get_manager();
    
    if (denylist_enforced && hide_whitelist){
        if (uid_granted_root(uid) || (to_app_id(uid) == manager_app_id) || (app_id == 0))
            return false;
        return true;
    }
    
    if (app_id >= 90000) {
        if (auto it = pkg_to_procs.find(ISOLATED_MAGIC); it != pkg_to_procs.end()) {
            for (const auto &s : it->second) {
                if (s.length() > max_len && process.length() > max_len && str_starts(s, process))
                    return true;
                if (str_starts(process, s))
                    return true;
            }
        }
        return false;
    } else {
        auto it = app_id_to_pkgs.find(app_id);
        if (it == app_id_to_pkgs.end())
            return false;
        for (const auto &pkg : it->second) {
            if (pkg_to_procs.find(pkg)->second.count(process))
                return true;
        }
        for (const auto &s : it->second) {
            if (s.length() > max_len && process.length() > max_len && str_starts(s, process))
                return true;
            if (s == process)
                return true;
        }
    }
    return false;
}

// MAGISKHIDE PROPS

static const char *prop_key[] =
        {"ro.boot.vbmeta.device_state", "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
         "ro.boot.veritymode", "ro.boot.warranty_bit", "ro.warranty_bit",
         "ro.debuggable", "ro.secure", "ro.build.type", "ro.build.tags",
         "ro.vendor.boot.warranty_bit", "ro.vendor.warranty_bit",
         "vendor.boot.vbmeta.device_state", "vendor.boot.verifiedbootstate", "sys.oem_unlock_allowed",
         nullptr};

static const char *prop_val[] =
        {"locked", "green", "1",
         "enforcing", "0", "0",
         "0", "1", "user", "release-keys",
         "0", "0",
         "locked", "green", "0",
         nullptr};

static const char *prop_suffix[] =
         {"build.type", "build.tags", nullptr};

static const char *prop_val2[] =
         {"user", "release-keys", nullptr};

static void hide_prefix_props(const char *suffix_name, const char *val){
    char buf[4098];
    const char *prop_prefix[] =
         {"system", "system_ext", "vendor",
          "product", "odm", "oem",
          "vendor_dlkm", nullptr};
    for (int i = 0; prop_prefix[i]; ++i) {
        sprintf(buf, "ro.%s.%s", prop_prefix[i], suffix_name);
        auto value = getprop(buf);
        if (!value.empty() && value != val)
            setprop(buf, val, false);
    }
}


void hide_sensitive_props() {
    LOGI("hide: Reset sensitive props\n");

    for (int i = 0; prop_key[i]; ++i) {
        setprop(prop_key[i], prop_val[i], false);
    }

    for (int i = 0; prop_suffix[i]; ++i)
        hide_prefix_props(prop_suffix[i], prop_val2[i]);

    // Hide that we booted from recovery when magisk is in recovery mode
    auto bootmode = getprop("ro.bootmode");
    if (!bootmode.empty() && str_contains(bootmode, "recovery"))
        setprop("ro.bootmode", "unknown", false);
    bootmode = getprop("ro.boot.mode");
    if (!bootmode.empty() && str_contains(bootmode, "recovery"))
        setprop("ro.boot.mode", "unknown", false);
    bootmode = getprop("vendor.boot.mode");
    if (!bootmode.empty() && str_contains(bootmode, "recovery"))
        setprop("vendor.boot.mode", "unknown", false);

    // Xiaomi cross region flash
    auto hwc = getprop("ro.boot.hwc");
    if (!hwc.empty() && str_contains(hwc, "CN"))
        setprop("ro.boot.hwc", "GLOBAL", false);
    auto hwcountry = getprop("ro.boot.hwcountry");
    if (!hwcountry.empty() && str_contains(hwcountry, "China"))
        setprop("ro.boot.hwcountry", "GLOBAL", false);

    // disable zygote pre-forking
    auto usap_enabled = getprop("persist.device_config.runtime_native.usap_pool_enabled");
    if (!usap_enabled.empty())
        setprop("persist.device_config.runtime_native.usap_pool_enabled", "false", false);

    auto selinux = getprop("ro.build.selinux");
    if (!selinux.empty())
        delprop("ro.build.selinux");
}

// PROCESS MONITOR


static int inotify_fd = -1;

static void new_zygote(int pid);

/******************
 * Data structures
 ******************/

#define PID_MAX 32768
struct pid_set {
    bitset<PID_MAX>::const_reference operator[](size_t pos) const { return set[pos - 1]; }
    bitset<PID_MAX>::reference operator[](size_t pos) { return set[pos - 1]; }
    void reset() { set.reset(); }
private:
    bitset<PID_MAX> set;
};

// true if pid is monitored
static pid_set attaches;

// zygote pid -> mnt ns
static map<int, struct stat> zygote_map;

/********
 * Utils
 ********/

static inline int read_ns(const int pid, struct stat *st) {
    char path[32];
    sprintf(path, "/proc/%d/ns/mnt", pid);
    return stat(path, st);
}

static int parse_ppid(int pid) {
    char path[32];
    int ppid;

    sprintf(path, "/proc/%d/stat", pid);

    auto stat = open_file(path, "re");
    if (!stat)
        return -1;

    // PID COMM STATE PPID .....
    fscanf(stat.get(), "%*d %*s %*c %d", &ppid);

    return ppid;
}

static bool zombie_pid(int pid) {
    char path[32];
    char status;

    sprintf(path, "/proc/%d/stat", pid);

    auto stat = open_file(path, "re");
    if (!stat)
        return true;

    // PID COMM STATE PPID .....
    fscanf(stat.get(), "%*d %*s %c %*d", &status);

    if (status == 'Z') return true;
    return false;
}

static bool is_zygote_done() {
    return zygote_map.size() >= 1;
}



static bool check_process(int pid, const char *process = 0, const char *context = 0, const char *exe = 0) {
    char path[128];
    char buf[1024];
    FILE *fprocess;
    ssize_t len;

    if (!process) goto check_context;
    sprintf(path, "/proc/%d/cmdline", pid);
    fprocess = fopen(path, "re");
    if (!fprocess) return false;
    fscanf(fprocess, "%s", buf);
    fclose(fprocess);
    if (strcmp(buf, process) != 0) return false;

    check_context:
    if (!context) goto check_exe;
    sprintf(path, "/proc/%d/attr/current", pid);
    fprocess = fopen(path, "re");
    if (!fprocess) return false;
    fscanf(fprocess, "%s", buf);
    fclose(fprocess);
    if (strcmp(buf, context) != 0) return false;
    
    check_exe:
    if (!exe) goto final;
    sprintf(path, "/proc/%d/exe", pid);
    len = readlink(path, buf, sizeof(buf)-1);
    if (len != -1) {
      buf[len] = '\0';
    }
    if (strcmp(buf, exe) != 0) return false;

    final:
    return true;
}

static bool check_process2(int pid, const char *process, const char *context, const char *exe){
    if (access("/sys/fs/selinux",F_OK) == 0)
        return check_process(pid,process,context,exe);
    return check_process(pid,process,0,exe);
}

static bool not_zygote_process(int pid_){
    return !check_process2(pid_, "zygote", "u:r:zygote:s0", "/system/bin/app_process32")  
            && !check_process2(pid_, "zygote", "u:r:zygote:s0", "/system/bin/app_process64")
            && !check_process2(pid_, "zygote", "u:r:zygote:s0", "/system/bin/app_process")
            && !check_process2(pid_, "zygote64", "u:r:zygote:s0", "/system/bin/app_process64") 
            && !check_process2(pid_, "zygote32", "u:r:zygote:s0", "/system/bin/app_process32")
            && !check_process2(pid_, "zygote32", "u:r:zygote:s0", "/system/bin/app_process");
}

static bool is_zygote_process(int pid_){
    return !not_zygote_process(pid_);
}

static void check_zygote() {
    crawl_procfs([](int pid) -> bool {
        if (is_zygote_process(pid) && parse_ppid(pid) == 1)
            new_zygote(pid);
        return true;
    });
    if (is_zygote_done()) {
        // Stop periodic scanning
        timeval val { .tv_sec = 0, .tv_usec = 0 };
        itimerval interval { .it_interval = val, .it_value = val };
        setitimer(ITIMER_REAL, &interval, nullptr);
    }
}

#define APP_PROC "/system/bin/app_process"

static void setup_inotify() {
    inotify_fd = inotify_init1(IN_CLOEXEC);
    if (inotify_fd < 0)
        return;

    // Setup inotify asynchronous I/O
    fcntl(inotify_fd, F_SETFL, O_ASYNC);
    struct f_owner_ex ex = {
        .type = F_OWNER_TID,
        .pid = gettid()
    };
    fcntl(inotify_fd, F_SETOWN_EX, &ex);

    // Monitor app_process
    if (access(APP_PROC "32", F_OK) == 0) {
        inotify_add_watch(inotify_fd, APP_PROC "32", IN_ACCESS);
        if (access(APP_PROC "64", F_OK) == 0)
            inotify_add_watch(inotify_fd, APP_PROC "64", IN_ACCESS);
    } else {
        inotify_add_watch(inotify_fd, APP_PROC, IN_ACCESS);
    }
}

/************************
 * Async signal handlers
 ************************/

static void inotify_event(int) {
    // Make sure we can actually read stuffs
    // or else the whole thread will be blocked.
    struct pollfd pfd = {
        .fd = inotify_fd,
        .events = POLLIN,
        .revents = 0
    };
    if (poll(&pfd, 1, 0) <= 0)
        return;  // Nothing to read
    check_zygote();
}

static void term_thread(int) {
    LOGD("proc_monitor: cleaning up\n");
    zygote_map.clear();
    attaches.reset();
    close(inotify_fd);
    inotify_fd = -1;
    fork_pid = 0;
    kill_pipe();
    // Restore all signal handlers that was set
    sigset_t set;
    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
    struct sigaction act{};
    act.sa_handler = SIG_DFL;
    sigaction(SIGTERMTHRD, &act, nullptr);
    sigaction(SIGIO, &act, nullptr);
    sigaction(SIGALRM, &act, nullptr);
    LOGD("proc_monitor: terminate\n");
    pthread_exit(nullptr);
}

static bool check_pid(int pid) {
    char path[128];
    char cmdline[1024];
    char context[1024];
    struct stat st;
    sprintf(path, "/proc/%d", pid);
    if (stat(path, &st)) {
        // Process died unexpectedly, ignore
        return true;
    }
    int uid = st.st_uid;
    // check context to know zygote is being forked into app process
    sprintf(path, "/proc/%d/attr/current", pid);
    if (auto f = open_file(path, "re")) {
        fgets(context, sizeof(context), f.get());
    } else {
        // Process died unexpectedly, ignore
        return true;
    }

    sprintf(path, "/proc/%d/cmdline", pid);
    if (auto f = open_file(path, "re")) {
        fgets(cmdline, sizeof(cmdline), f.get());
    } else {
        // Process died unexpectedly, ignore
        return true;
    }

    // if cmdline == zygote and context is changed, zygote is being forked into app process
    if ((cmdline == "zygote"sv || cmdline == "zygote32"sv || cmdline == "zygote64"sv) && context != "u:r:zygote:s0"sv){
        // this is pre-initialized app zygote
        if (strstr(context, "u:r:app_zygote:s0"))
            goto check_and_hide;

        // wait until pre-initialized
        for (int i=0; cmdline != "<pre-initialized>"sv; i++) {
            if (i>=300000) return true; // we don't want it stuck forever
            // update cmdline
            if (auto f = open_file(path, "re")) {
                fgets(cmdline, sizeof(cmdline), f.get());
            } else {
                // Process died unexpectedly, ignore
                return true;
            }
            usleep(10);
        }
    }

check_and_hide:
    
    // UID hasn't changed
    if (uid == 0)
        return false;

    if (cmdline == "zygote"sv || cmdline == "zygote32"sv || cmdline == "zygote64"sv ||
        cmdline == "usap32"sv || cmdline == "usap64"sv)
        return false;

    // app process is being initialized
    // it should happen in short time
    for (int i=0;cmdline == "<pre-initialized>"sv; i++) {
        if (i>=300000) goto not_target; // we don't want it stuck forever
        if (auto f = open_file(path, "re")) {
            fgets(cmdline, sizeof(cmdline), f.get());
        } else {
            // Process died unexpectedly, ignore
            return true;
        }
        usleep(10);
    }

    // read process name again to make sure
    if (auto f = open_file(path, "re")) {
        fgets(cmdline, sizeof(cmdline), f.get());
    } else {
        // Process died unexpectedly, ignore
        return true;
    }

    // stop app process as soon as possible and do check if this process is target or not
    kill(pid, SIGSTOP);

    if (!is_deny_target(uid, cmdline, 95)) {
        goto not_target;
    }

    // Ensure ns is separated
    read_ns(pid, &st);
    for (auto &zit : zygote_map) {
        if (zit.second.st_ino == st.st_ino &&
            zit.second.st_dev == st.st_dev) {
            // ns not separated, abort
            // Android 11+, all zygote child will have seperated ns, so this should not happen
            LOGW("proc_monitor: skip [%s] PID=[%d] UID=[%d]\n", cmdline, pid, uid);
            goto not_target;
        }
    }

    // Finally this is our target
    // We stop target process and do all unmounts
    // The hide daemon will resume the process after hiding it
    LOGI("proc_monitor: [%s] PID=[%d] UID=[%d]\n", cmdline, pid, uid);

    // hide magisk
    revert_daemon(pid);
    return true;

not_target:
    kill(pid, SIGCONT);
    return true;
}

static bool is_root_process(int pid){
    char path[128];
    struct stat st;
    sprintf(path, "/proc/%d", pid);
    if (stat(path, &st)) {
        // Process died unexpectedly, ignore
        return false;
    }
    int uid = st.st_uid;
    return uid == 0;
}

static void new_zygote(int pid) {
    struct stat st;
    if (read_ns(pid, &st))
        return;

    auto it = zygote_map.find(pid);
    if (it != zygote_map.end()) {
        // Update namespace info
        it->second = st;
        return;
    }

    LOGI("proc_monitor: ptrace zygote PID=[%d]\n", pid);
    zygote_map[pid] = st;
}

#define DETACH_AND_CONT { detach_pid(pid); continue; }

void do_check_fork() {
    int pid = fork_pid;
    fork_pid = 0;
    if (pid == 0)
        return;
    int i=0;
    // zygote child process need a mount of time to seperate mount namespace
    while (!check_pid(pid)){
        if (i>=300000) break;
        i++;
        usleep(10);
    }
}

void do_check_pid(int client){
    int pid = read_int(client);
    fork_pid = pid;
    new_daemon_thread(&do_check_fork);
}

void proc_monitor() {
    monitor_thread = pthread_self();

    // Backup original mask
    sigset_t orig_mask;
    pthread_sigmask(SIG_SETMASK, nullptr, &orig_mask);

    sigset_t unblock_set;
    sigemptyset(&unblock_set);
    sigaddset(&unblock_set, SIGTERMTHRD);

    struct sigaction act{};
    sigfillset(&act.sa_mask);
    act.sa_handler = SIG_IGN;
    sigaction(SIGTERMTHRD, &act, nullptr);
    sigaction(SIGIO, &act, nullptr);
    sigaction(SIGALRM, &act, nullptr);

    // Temporary unblock to clear pending signals
    pthread_sigmask(SIG_UNBLOCK, &unblock_set, nullptr);
    pthread_sigmask(SIG_SETMASK, &orig_mask, nullptr);

    act.sa_handler = term_thread;
    sigaction(SIGTERMTHRD, &act, nullptr);

    act.sa_handler = inotify_event;
    sigaction(SIGIO, &act, nullptr);
    act.sa_handler = [](int){ check_zygote(); };
    sigaction(SIGALRM, &act, nullptr);

    setup_inotify();

    check_zygote();
    if (!is_zygote_done()) {
        // Periodic scan every 250ms
        timeval val { .tv_sec = 0, .tv_usec = 250000 };
        itimerval interval { .it_interval = val, .it_value = val };
        setitimer(ITIMER_REAL, &interval, nullptr);
    }

    pid_t pipe_fp = -1;
    int pipe_in,pipe_out;
    ps_a.init();
    ps_b.init();
    char *command[] = {"/system/bin/logcat", 
	    "--uid=0", "Zygote:*", "*:S", 0};
    char *command_[] = {"/system/bin/logcat",
	    "Zygote:*", "*:S", 0};
    char *command2[] = {"/system/bin/logcat", 
        "-b", "events", "-s", 
		"boot_progress_pms_ready",
        "-s", "am_proc_start", 0};
    char buf[4098];
    char log_pid[10];
    char pid[10];
    int p;
    int ret;
    struct pollfd pfd[1];

    if (SDK_INT < 29) goto am_proc_start; // Android 9 and below

    while(1){
        pthread_sigmask(SIG_UNBLOCK, &unblock_set, nullptr);
        // check if pipe is dead, maybe logd is off?
        if (!zombie_pid(pipe_fp)) goto collect_log;
        kill_pipe();
        fflush_logcat();
        ps_a.open(command);
        ps_b.open(command_);
        sleep(1);
        if (zombie_pid(ps_a.pid)){
            LOGD("proc_monitor: logcat failback\n");
            ps_a.term();
            pipe_fp = ps_b.pid;
            pipe_in = ps_b.in;
            pipe_out = ps_b.out;
        } else {
            ps_b.term();
            pipe_fp = ps_a.pid;
            pipe_in = ps_a.in;
            pipe_out = ps_a.out;
        }
        LOGD("proc_monitor: new pipe PID=[%d]\n", pipe_fp);
        continue;

        collect_log:
        pfd[0].fd = pipe_out;
        pfd[0].events = POLLIN;
        ret = poll(pfd, 1, 1000);
        if(ret <= 0)
            continue; // timeout
        read(pipe_out, buf, sizeof(buf));
        sscanf(buf, "%*s %*s %d", &p);
        if (!is_root_process(p)) continue;
        if (not_zygote_process(p)) continue;

        // filter logcat to know if zygote fork new process
        const char *log = strstr(buf, "Forked child process");
        // new zygote
        if (strstr(buf, "Calling ZygoteHooks.beginPreload()")) {
            if (not_zygote_process(p)) continue;
            check_zygote();
            continue;
        }
        if (!log) continue;
        sscanf(log, "Forked child process %s", pid);
        
        pthread_sigmask(SIG_SETMASK, &orig_mask, nullptr);
        // zygote fork event detected, check if this is target app
        //LOGD("proc_monitor: zygote new fork PID=[%s]\n", pid);
        // fork new process, check pid and do revert unmount
        fork_pid = atoi(pid);
        new_daemon_thread(&do_check_fork);
    }
    
    am_proc_start:

    while (1){
        pthread_sigmask(SIG_UNBLOCK, &unblock_set, nullptr);
        // check if pipe is dead, maybe logd is off?
        if (!zombie_pid(pipe_fp)) goto collect_log_;
        kill_pipe();
        fflush_logcat();
        pipe_fp = ps_a.open(command2);
        sleep(1);
        pipe_in = ps_a.in;
        pipe_out = ps_a.out;
        LOGD("proc_monitor: new pipe PID=[%d]\n", pipe_fp);
        continue;

        collect_log_:
        pfd[0].fd = pipe_out;
        pfd[0].events = POLLIN;
        ret = poll(pfd, 1, 1000);
        if(ret <= 0)
             continue; // timeout
        read(pipe_out, buf, sizeof(buf));

        const char *log = strstr(buf, "[");

        // new zygote
        if (strstr(buf, "boot_progress_pms_ready") && !log) {
            check_zygote();
            continue;
        }
        // filter logcat to get pid
        if (!log) continue;
        sscanf(log, "[%*d,%d", &p);
        // any process can print log with custom name
        // check if this is really system_server log
        pthread_sigmask(SIG_SETMASK, &orig_mask, nullptr);
        // zygote fork event detected, check if this is target app
        //LOGD("proc_monitor: zygote new fork PID=[%s]\n", pid);
        // fork new process, check pid and do revert unmount
        fork_pid = p;
        new_daemon_thread(&do_check_fork);
    }
}
