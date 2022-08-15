#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <linux/input.h>
#include <libgen.h>
#include <vector>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include <magisk.hpp>
#include <db.hpp>
#include <base.hpp>
#include <daemon.hpp>
#include <resetprop.hpp>
#include <selinux.hpp>

#include "core.hpp"

#define TRIGGER_BL "/dev/.magisk_ztrigger"

#define VLOGD(tag, from, to) LOGD("%-8s: %s <- %s\n", tag, to, from)

static int bind_mount(const char *from, const char *to) {
    int ret = xmount(from, to, nullptr, MS_BIND, nullptr);
    if (ret == 0)
        VLOGD("bind_mnt", from, to);
    return ret;
}

static int tmpfs_mount(const char *from, const char *to){
    int ret = xmount(from, to, "tmpfs", 0, "mode=755");
    if (ret == 0)
        VLOGD("mnt_tmp", "tmpfs", to);
    return ret;
}



using namespace std;

static const char *F2FS_SYSFS_PATH = nullptr;

static bool safe_mode = false;
bool zygisk_enabled = false;

/*********
 * Setup *
 *********/

#define MNT_DIR_IS(dir) (me->mnt_dir == string_view(dir))
#define MNT_TYPE_IS(type) (me->mnt_type == string_view(type))
#define SETMIR(b, part) ssprintf(b, sizeof(b), "%s/" MIRRDIR "/" #part, MAGISKTMP.data())
#define SETBLK(b, part) ssprintf(b, sizeof(b), "%s/" BLOCKDIR "/" #part, MAGISKTMP.data())

#define do_mount_mirror(part) {     \
    SETMIR(buf1, part);             \
    SETBLK(buf2, part);             \
    unlink(buf2);                   \
    mknod(buf2, S_IFBLK | 0600, st.st_dev); \
    xmkdir(buf1, 0755);             \
    int flags = 0;                  \
    auto opts = split_ro(me->mnt_opts, ",");\
    for (string_view s : opts) {    \
        if (s == "ro") {            \
            flags |= MS_RDONLY;     \
            break;                  \
        }                           \
    }                               \
    xmount(buf2, buf1, me->mnt_type, flags, nullptr); \
    LOGI("mount: %s\n", buf1);      \
}

#define mount_orig_mirror(dir, part) \
if (MNT_DIR_IS("/" #dir)  \
    && !MNT_TYPE_IS("tmpfs") \
    && !MNT_TYPE_IS("overlay") \
    && lstat(me->mnt_dir, &st) == 0) { \
    do_mount_mirror(part); \
    break;                 \
}

#define mount_mirror(part) mount_orig_mirror(part, part)

#define link_mirror(part) \
SETMIR(buf1, part); \
if (access("/system/" #part, F_OK) == 0 && access(buf1, F_OK) != 0) { \
    xsymlink("./system/" #part, buf1); \
    LOGI("link: %s\n", buf1); \
}

#define link_orig_dir(dir, part) \
if (MNT_DIR_IS(dir) && !MNT_TYPE_IS("tmpfs") && !MNT_TYPE_IS("overlay")) { \
    SETMIR(buf1, part);          \
    rmdir(buf1);                 \
    xsymlink(dir, buf1);         \
    LOGI("link: %s\n", buf1);    \
    break;                       \
}

#define link_orig(part) link_orig_dir("/" #part, part)

static void recreate_sbin(const char *mirror, bool use_bind_mount) {
    auto dp = xopen_dir(mirror);
    int src = dirfd(dp.get());
    char buf[4096];
    char mbuf[4096];
    for (dirent *entry; (entry = xreaddir(dp.get()));) {
        string sbin_path = "/sbin/"s + entry->d_name;
        struct stat st;
        fstatat(src, entry->d_name, &st, AT_SYMLINK_NOFOLLOW);
        sprintf(buf, "%s/%s", mirror, entry->d_name);
        sprintf(mbuf, "%s/%s", MAGISKTMP.data(), entry->d_name);
        if (access(mbuf, F_OK) == 0) continue;
        if (S_ISLNK(st.st_mode)) {
            xreadlinkat(src, entry->d_name, buf, sizeof(buf));
            xsymlink(buf, sbin_path.data());
            VLOGD("create", buf, sbin_path.data());
        } else {
            if (use_bind_mount) {
                auto mode = st.st_mode & 0777;
                // Create dummy
                if (S_ISDIR(st.st_mode))
                    xmkdir(sbin_path.data(), mode);
                else
                    close(xopen(sbin_path.data(), O_CREAT | O_WRONLY | O_CLOEXEC, mode));

                bind_mount(buf, sbin_path.data());
            } else {
                xsymlink(buf, sbin_path.data());
                VLOGD("create", buf, sbin_path.data());
            }
        }
    }
}

static void bind_magisk_bins(const char *mirror) {
    auto dp = xopen_dir(mirror);
    int src = dirfd(dp.get());
    char buf[4096];
    for (dirent *entry; (entry = xreaddir(dp.get()));) {
        string sbin_path = "/sbin/"s + entry->d_name;
        struct stat st;
        fstatat(src, entry->d_name, &st, AT_SYMLINK_NOFOLLOW);
        if (S_ISLNK(st.st_mode)) {
            xreadlinkat(src, entry->d_name, buf, sizeof(buf));
            xsymlink(buf, sbin_path.data());
            VLOGD("create", buf, sbin_path.data());
        } else {
            sprintf(buf, "%s/%s", mirror, entry->d_name);
            string bufc(buf);
            if (bufc == MAGISKTMP + "/" INTLROOT) continue;
            auto mode = st.st_mode & 0777;
            // Create dummy
            if (S_ISDIR(st.st_mode))
                xmkdir(sbin_path.data(), mode);
            else
                close(xopen(sbin_path.data(), O_CREAT | O_WRONLY | O_CLOEXEC, mode));
            bind_mount(buf, sbin_path.data());
        }
    }
}

static void mount_mirrors() {
    char buf1[4096];
    char buf2[4096];

    LOGI("* Mounting mirrors\n");

    parse_mnt("/proc/mounts", [&](mntent *me) {
        struct stat st{};
        do {
            mount_mirror(system)
            mount_mirror(vendor)
            mount_mirror(product)
            mount_mirror(system_ext)
            mount_mirror(data)
            mount_mirror(cache)
            mount_mirror(metadata)
            mount_mirror(persist)
            mount_orig_mirror(mnt/vendor/persist, persist)
            if (SDK_INT >= 24 && MNT_DIR_IS("/proc") && !strstr(me->mnt_opts, "hidepid=2")) {
                xmount(nullptr, "/proc", nullptr, MS_REMOUNT, "hidepid=2,gid=3009");
                break;
            }
        } while (false);
        return true;
    });
    SETMIR(buf1, system);
    if (access(buf1, F_OK) != 0) {
        xsymlink("./system_root/system", buf1);
        LOGI("link: %s\n", buf1);
        parse_mnt("/proc/mounts", [&](mntent *me) {
            struct stat st;
            if (MNT_DIR_IS("/") && me->mnt_type != "rootfs"sv && stat("/", &st) == 0) {
                do_mount_mirror(system_root)
                return false;
            }
            return true;
        });
    }
    link_mirror(vendor)
    link_mirror(product)
    link_mirror(system_ext)
}

static bool magisk_env() {
    char buf[4096];

    LOGI("* Initializing Magisk environment\n");

    preserve_stub_apk();
    string pkg;
    get_manager(0, &pkg);

    sprintf(buf, "%s/0/%s/install", APP_DATA_DIR,
            pkg.empty() ? "xxx" /* Ensure non-exist path */ : pkg.data());

    // Alternative binaries paths
    const char *alt_bin[] = { "/cache/data_adb/magisk", "/data/magisk", buf };
    struct stat st{};
    for (auto alt : alt_bin) {
        struct stat st{};
        if (lstat(alt, &st) == 0) {
            if (S_ISLNK(st.st_mode)) {
                unlink(alt);
                continue;
            }
            rm_rf(DATABIN);
           	cp_afc(alt, DATABIN);
           	rm_rf(alt);
            break;
        }
    }
    rm_rf("/cache/data_adb");

    // Directories in /data/adb
    if (!is_dir_exist(MODULEROOT)) rm_rf(MODULEROOT);
    xmkdir(DATABIN, 0755);
    xmkdir(MODULEROOT, 0755);
    xmkdir(SECURE_DIR "/post-fs-data.d", 0755);
    xmkdir(SECURE_DIR "/service.d", 0755);

    restore_databincon();

    if (access(DATABIN "/busybox", X_OK))
        return false;

    sprintf(buf, "%s/" BBPATH "/busybox", MAGISKTMP.data());
    mkdir(dirname(buf), 0755);
    cp_afc(DATABIN "/busybox", buf);
    exec_command_async(buf, "--install", "-s", dirname(buf));

    if (access(DATABIN "/magiskpolicy", X_OK) == 0) {
        sprintf(buf, "%s/magiskpolicy", MAGISKTMP.data());
        cp_afc(DATABIN "/magiskpolicy", buf);
    }

    return true;
}

void reboot() {
    if (RECOVERY_MODE)
        exec_command_sync("/system/bin/reboot", "recovery");
    else
        exec_command_sync("/system/bin/reboot");
}

static bool core_only(bool rm_trigger){
    if (access("/data/adb/.disable_magisk", F_OK) == 0 \
		|| access("/cache/.disable_magisk", F_OK) == 0 \
		|| access("/persist/.disable_magisk", F_OK) == 0 \
		|| access("/data/unencrypted/.disable_magisk", F_OK) == 0 \
		|| access("/metadata/.disable_magisk", F_OK) == 0 \
		|| access("/mnt/vendor/persist/.disable_magisk", F_OK) == 0){
        if (rm_trigger){
            rm_rf("/cache/.disable_magisk");
            rm_rf("/metadata/.disable_magisk");
            rm_rf("/persist/.disable_magisk");
            rm_rf("/data/unencrypted/.disable_magisk");
            rm_rf("/mnt/vendor/persist/.disable_magisk");
            rm_rf("/data/adb/.disable_magisk");
        }
        return true;
    }
    return false;
}
    

static bool check_data() {
    bool mnt = false;
    file_readline("/proc/mounts", [&](string_view s) {
        if (str_contains(s, " /data ") && !str_contains(s, "tmpfs")) {
            mnt = true;
            return false;
        }
        return true;
    });
    if (!mnt)
        return false;
    auto crypto = getprop("ro.crypto.state");
    if (!crypto.empty()) {
        if (crypto != "encrypted") {
            // Unencrypted, we can directly access data
            return true;
        } else {
            // Encrypted, check whether vold is started
            return !getprop("init.svc.vold").empty();
        }
    }
    // ro.crypto.state is not set, assume it's unencrypted
    return true;
}

static bool system_lnk(const char *path){
    char buff[4098];
    ssize_t len = readlink(path, buff, sizeof(buff)-1);
    if (len != -1) {
        return true;
    }
    return false;
}

static void simple_mount(const string &sdir, const string &ddir = "") {
    auto dir = xopen_dir(sdir.data());
    if (!dir) return;
    for (dirent *entry; (entry = xreaddir(dir.get()));) {
        string src = sdir + "/" + entry->d_name;
        string dest = ddir + "/" + entry->d_name;
        if (access(dest.data(), F_OK) == 0 && !system_lnk(dest.data())) {
        	if (entry->d_type == DT_LNK) continue;
            else if (entry->d_type == DT_DIR) {
                // Recursive
                simple_mount(src, dest);
            } else {
                LOGD("bind_mnt: %s <- %s\n", dest.data(), src.data());
                xmount(src.data(), dest.data(), nullptr, MS_BIND, nullptr);
            }
        }
    }
}


void early_mount(const char *magisk_tmp){
    LOGI("** early-mount start\n");
    char buf[4098];
    const char *part[]={
        "/vendor", "/product", "/system_ext",
        nullptr
    };

    const char *preinit_part[]={
        "/data/unencrypted", "/data/adb", "/persist", "/metadata", "/cache",
        nullptr
    };
    for (int i=0;preinit_part[i];i++) {
        sprintf(buf, "%s/" MIRRDIR "%s/.disable_magisk", magisk_tmp, preinit_part[i]);
        if (access(buf, F_OK) == 0) goto finish;
    }

    sprintf(buf, "%s/" MIRRDIR "/early-mount", magisk_tmp);
    fsetfilecon(xopen(buf, O_RDONLY | O_CLOEXEC), "u:object_r:system_file:s0");
    sprintf(buf, "%s/" MIRRDIR "/early-mount/skip_mount", magisk_tmp);
    if (access(buf, F_OK) == 0) goto finish;

    // SYSTEM
    sprintf(buf, "%s/" MIRRDIR "/early-mount/system", magisk_tmp);
    if (access(buf, F_OK) == 0)
    	simple_mount(buf, "/system");

    // VENDOR, PRODUCT, SYSTEM_EXT
    for (int i=0;part[i];i++) {
        sprintf(buf, "%s/" MIRRDIR "/early-mount/system%s", magisk_tmp, part[i]);
        if (access(buf, F_OK) == 0 && !system_lnk(part[i]))
            simple_mount(buf, part[i]);
    }

finish:
    const char *mirror_part[]={
        "/data", "/persist", "/metadata", "/cache",
        nullptr
    };
    for (int i=0;mirror_part[i];i++) {
        sprintf(buf, "%s/" MIRRDIR "%s", magisk_tmp, mirror_part[i]);
        umount2(buf, MNT_DETACH);
    }
}

void unlock_blocks() {
    int fd, dev, OFF = 0;

    auto dir = xopen_dir("/dev/block");
    if (!dir)
        return;
    dev = dirfd(dir.get());

    for (dirent *entry; (entry = readdir(dir.get()));) {
        if (entry->d_type == DT_BLK) {
            if ((fd = openat(dev, entry->d_name, O_RDONLY | O_CLOEXEC)) < 0)
                continue;
            if (ioctl(fd, BLKROSET, &OFF) < 0)
                PLOGE("unlock %s", entry->d_name);
            close(fd);
        }
    }
}

#define test_bit(bit, array) (array[bit / 8] & (1 << (bit % 8)))

static void rebind_early_to_mirr(){
    char buf[4098];
    char buf2[4098];
    

    const char *preinit_part[]={
        "/data/unencrypted", "/data/adb", "/persist", "/metadata", "/cache",
        nullptr
    };
    for (int i=0;preinit_part[i];i++) {
        sprintf(buf, "%s/" MIRRDIR "%s/.disable_magisk", MAGISKTMP.data(), preinit_part[i]);
        if (access(buf, F_OK) == 0) return;
    }

    sprintf(buf, "%s/" MIRRDIR "/early-mount/skip_mount", MAGISKTMP.data());
    if (access(buf, F_OK) == 0) return;
	
    // SYSTEM
    sprintf(buf, "%s/" MIRRDIR "/early-mount/system", MAGISKTMP.data());
    sprintf(buf2, "%s/" MIRRDIR "/system", MAGISKTMP.data());
    if (access(buf, F_OK) == 0)
    	simple_mount(buf, buf2);

    const char *part[]={
        "/vendor", "/product", "/system_ext",
        nullptr
    };

    // VENDOR, PRODUCT, SYSTEM_EXT
    for (int i=0;part[i];i++) {
        sprintf(buf, "%s/" MIRRDIR "/early-mount/system%s", MAGISKTMP.data(), part[i]);
        sprintf(buf2, "%s/" MIRRDIR "%s", MAGISKTMP.data(), part[i]);
        if (access(buf, F_OK) == 0 && !system_lnk(buf2))
            simple_mount(buf, buf2);
    }
}

static bool check_key_combo() {
    uint8_t bitmask[(KEY_MAX + 1) / 8];
    vector<int> events;
    constexpr char name[] = "/dev/.ev";

    // First collect candidate events that accepts volume down
    for (int minor = 64; minor < 96; ++minor) {
        if (xmknod(name, S_IFCHR | 0444, makedev(13, minor)))
            continue;
        int fd = open(name, O_RDONLY | O_CLOEXEC);
        unlink(name);
        if (fd < 0)
            continue;
        memset(bitmask, 0, sizeof(bitmask));
        ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(bitmask)), bitmask);
        if (test_bit(KEY_VOLUMEDOWN, bitmask))
            events.push_back(fd);
        else
            close(fd);
    }
    if (events.empty())
        return false;

    run_finally fin([&]{ std::for_each(events.begin(), events.end(), close); });

    // Check if volume down key is held continuously for more than 3 seconds
    for (int i = 0; i < 300; ++i) {
        bool pressed = false;
        for (const int &fd : events) {
            memset(bitmask, 0, sizeof(bitmask));
            ioctl(fd, EVIOCGKEY(sizeof(bitmask)), bitmask);
            if (test_bit(KEY_VOLUMEDOWN, bitmask)) {
                pressed = true;
                break;
            }
        }
        if (!pressed)
            return false;
        // Check every 10ms
        usleep(10000);
    }
    LOGD("KEY_VOLUMEDOWN detected: enter safe mode\n");
    return true;
}

#define F2FS_DEF_CP_INTERVAL "60"
#define F2FS_TUNE_CP_INTERVAL "200"
#define F2FS_DEF_GC_THREAD_URGENT_SLEEP_TIME "500"
#define F2FS_TUNE_GC_THREAD_URGENT_SLEEP_TIME "50"
#define BLOCK_SYSFS_PATH "/sys/block"
#define TUNE_DISCARD_MAX_BYTES "134217728"

static inline bool tune_f2fs_target(const char *device) {
    // Tune only SCSI (UFS), eMMC, NVMe and virtual devices
    return !strncmp(device, "sd", 2) ||
           !strncmp(device, "mmcblk", 6) ||
           !strncmp(device, "nvme", 4) ||
           !strncmp(device, "vd", 2) ||
           !strncmp(device, "xvd", 3);
}

static void __tune_f2fs(const char *dir, const char *device, const char *node,
                        const char *def, const char *val, bool wr_only) {
    char path[128], buf[32];
    int flags = F_OK | R_OK | W_OK;

    sprintf(path, "%s/%s/%s", dir, device, node);

    if (wr_only)
        flags &= ~R_OK;
    if (access(path, flags) != 0)
        return;

    int fd = xopen(path, wr_only ? O_WRONLY : O_RDWR);
    if (fd < 0)
        return;

    if (!wr_only) {
        ssize_t len;
        len = xread(fd, buf, sizeof(buf));
        if (buf[len - 1] == '\n')
            buf[len - 1] = '\0';
        if (strncmp(buf, def, len)) {
            // Something else changed this node from the kernel's default.
            // Pass.
            LOGI("node %s unnecessary for tuning\n", node);
            close(fd);
            return;
        }
    }

    xwrite(fd, val, strlen(val));
    close(fd);

    LOGI("node %s tuned to %s\n", path, val);
}

static void tune_f2fs() {
	// Check f2fs sys path
	if (access("/sys/fs/f2fs", F_OK) == 0)
        F2FS_SYSFS_PATH = "/sys/fs/f2fs";
    else if (access("/sys/fs/f2fs_dev", F_OK) == 0)
        F2FS_SYSFS_PATH = "/sys/fs/f2fs_dev";
    else {
        LOGI("/sys/fs/f2fs is not found, skip tuning!\n");
        return;
    }
	
	
    // Tune f2fs sysfs node
    if (auto dir = xopen_dir(F2FS_SYSFS_PATH); dir) {
        for (dirent *entry; (entry = readdir(dir.get()));) {
            if (entry->d_name == "."sv || entry->d_name == ".."sv || !tune_f2fs_target(entry->d_name))
                continue;

            __tune_f2fs(F2FS_SYSFS_PATH, entry->d_name, "cp_interval",
                F2FS_DEF_CP_INTERVAL, F2FS_TUNE_CP_INTERVAL, false);
            __tune_f2fs(F2FS_SYSFS_PATH, entry->d_name, "gc_urgent_sleep_time",
                F2FS_DEF_GC_THREAD_URGENT_SLEEP_TIME, F2FS_TUNE_GC_THREAD_URGENT_SLEEP_TIME, false);
        }
    }

    // Tune block discard limit
    if (auto dir = xopen_dir(BLOCK_SYSFS_PATH); dir) {
        for (dirent *entry; (entry = readdir(dir.get()));) {
            if (entry->d_name == "."sv || entry->d_name == ".."sv || !tune_f2fs_target(entry->d_name))
                continue;

            __tune_f2fs(BLOCK_SYSFS_PATH, entry->d_name, "queue/discard_max_bytes",
                nullptr, TUNE_DISCARD_MAX_BYTES, true);
        }
    }
}


/***********************
 * Boot Stage Handlers *
 ***********************/

static pthread_mutex_t stage_lock = PTHREAD_MUTEX_INITIALIZER;
extern int disable_deny();

void post_fs_data(int client) {
    close(client);

    mutex_guard lock(stage_lock);

    if (getenv("REMOUNT_ROOT"))
        xmount(nullptr, "/", nullptr, MS_REMOUNT | MS_RDONLY, nullptr);

    if (!check_data())
        goto unblock_init;

    DAEMON_STATE = STATE_POST_FS_DATA;
    setup_logfile(true);

    LOGI("** post-fs-data mode running\n");

    tune_f2fs();

    unlock_blocks();
    mount_mirrors();
    rebind_early_to_mirr();
    prune_su_access();

    if (MAGISKTMP != "/sbin" && access("/sbin", F_OK) == 0 && check_envpath("/sbin")){
        char ROOTMIRROR[512];
        sprintf(ROOTMIRROR, "%s/" MIRRDIR "/system_root", MAGISKTMP.data());
        char FAKEBLKDIR[512];
        sprintf(FAKEBLKDIR, "%s/" BLOCKDIR "/tmpfs", MAGISKTMP.data());
        if (access(ROOTMIRROR, F_OK) == 0){
            char SBINMIRROR[1024];
            sprintf(SBINMIRROR, "%s/sbin", ROOTMIRROR);
            tmpfs_mount(FAKEBLKDIR, "/sbin");
            setfilecon("/sbin", "u:object_r:rootfs:s0");
            recreate_sbin(SBINMIRROR, true);
        } else {
            xmount(nullptr, "/", nullptr, MS_REMOUNT, nullptr);
            rm_rf("/sbin_mirror");
            mkdir("/sbin_mirror", 0777);
            clone_attr("/sbin", "/sbin_mirror");
            link_path("/sbin", "/sbin_mirror");
            tmpfs_mount(FAKEBLKDIR, "/sbin");
            setfilecon("/sbin", "u:object_r:rootfs:s0");
            recreate_sbin("/sbin_mirror", true);
            rm_rf("/sbin_mirror");
            xmount(nullptr, "/", nullptr, MS_REMOUNT | MS_RDONLY, nullptr);
        }
        bind_magisk_bins(MAGISKTMP.data());
    }

    if (access(SECURE_DIR, F_OK) != 0) {
        if (SDK_INT < 24) {
            // There is no FBE pre 7.0, we can directly create the folder without issues
            xmkdir(SECURE_DIR, 0700);
        } else {
            // If the folder is not automatically created by Android,
            // do NOT proceed further. Manual creation of the folder
            // will have no encryption flag, which will cause bootloops on FBE devices.
            LOGE(SECURE_DIR " is not present, abort\n");
            goto early_abort;
        }
    }

    if (!magisk_env()) {
        LOGE("* Magisk environment incomplete, abort\n");
        goto early_abort;
    }

    if (getprop("persist.sys.safemode", true) == "1" || check_key_combo()) {
        safe_mode = true;
        // Disable all modules and denylist so next boot will be clean
        disable_modules();
        disable_deny();
    } else {
        if(core_only(false)){
            LOGI("** Core-only mode, skip loading modules\n");
        } else {
            exec_common_scripts("post-fs-data");
        }
        db_settings dbs;
        get_db_settings(dbs, ZYGISK_CONFIG);
        zygisk_enabled = dbs[ZYGISK_CONFIG];
        if (core_only(false)) prepare_modules();
		else handle_modules();
    }

early_abort:
    // We still do magic mount because root itself might need it
    magic_mount();
    DAEMON_STATE = STATE_POST_FS_DATA_DONE;

unblock_init:
    close(xopen(UNBLOCKFILE, O_RDONLY | O_CREAT, 0));
}

void late_start(int client) {
    close(client);

    mutex_guard lock(stage_lock);
    run_finally fin([]{ DAEMON_STATE = STATE_LATE_START_DONE; });
    setup_logfile(false);

    LOGI("** late_start service mode running\n");

    if (DAEMON_STATE < STATE_POST_FS_DATA_DONE || safe_mode)
        return;
    if (!core_only(false)) {
        exec_common_scripts("service");
        exec_module_scripts("service");
    }
}

void boot_complete(int client) {
    close(client);

    mutex_guard lock(stage_lock);
    DAEMON_STATE = STATE_BOOT_COMPLETE;
    setup_logfile(false);

    LOGI("** boot-complete triggered\n");
    rm_rf(TRIGGER_BL);
    if (safe_mode)
        return;
    initialize_denylist();
    reset_sensitive_props();

    // At this point it's safe to create the folder
    if (access(SECURE_DIR, F_OK) != 0)
        xmkdir(SECURE_DIR, 0700);

    // Ensure manager exists
    check_pkg_refresh();
    get_manager(0, nullptr, true);
}

void reboot_coreonly(){
    close(xopen("/data/unencrypted/.disable_magisk", O_RDONLY | O_CREAT, 0));
    close(xopen("/cache/.disable_magisk", O_RDONLY | O_CREAT, 0));
    close(xopen("/persist/.disable_magisk", O_RDONLY | O_CREAT, 0));
    close(xopen("/metadata/.disable_magisk", O_RDONLY | O_CREAT, 0));
    close(xopen("/mnt/vendor/persist/.disable_magisk", O_RDONLY | O_CREAT, 0));
    close(xopen("/data/adb/.disable_magisk", O_RDONLY | O_CREAT, 0));
    exec_command_sync("/system/bin/reboot", "recovery");
}



bool check_bootloop()
{
	int n=1;
	if (access(TRIGGER_BL, F_OK) != 0) {
		// not exist, we need create file with initial value
		FILE *ztrigger=fopen(TRIGGER_BL, "wb");
		if (ztrigger == NULL) return false; // failed
		fwrite(&n,1,sizeof(int),ztrigger);
		fclose(ztrigger);
	}
	FILE *ztrigger=fopen(TRIGGER_BL, "rb");
	if (ztrigger == NULL) return false; // failed
	fread(&n, 1, sizeof(int), ztrigger);
	fclose(ztrigger);
	// current number here
        if (n >= 8) {
            LOGI("anti_bootloop: zygote failed to start for 8 times, restart!\n");
            reboot_coreonly();
        } else LOGI("anti_bootloop: zygote_restart count = %d\n", n);
	
	ztrigger=fopen(TRIGGER_BL, "wb");
	if (ztrigger == NULL) return false; // failed
	n++; // increase the number
	fwrite(&n, 1, sizeof(int), ztrigger);
	fclose(ztrigger);
	return true;
}

void zygote_restart(int client) {
    close(client);

    LOGI("** zygote restarted\n");
    pkg_xml_ino = 0;
    db_settings dbs;
    get_db_settings(dbs, ANTI_BOOTLOOP);
    if (DAEMON_STATE < STATE_BOOT_COMPLETE && dbs[ANTI_BOOTLOOP])
        if (!check_bootloop()) LOGE("anti_bootloop: cannot run check\n");
    prune_su_access();
}
