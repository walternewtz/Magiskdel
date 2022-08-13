##################################
# Magisk app internal scripts
##################################

run_delay() {
  (sleep $1; $2)&
}

env_check() {
  for file in busybox magiskboot magiskinit util_functions.sh boot_patch.sh; do
    [ -f "$MAGISKBIN/$file" ] || return 1
  done
  if [ "$2" -ge 25000 ]; then
    [ -f "$MAGISKBIN/magiskpolicy" ] || return 1
  fi
  grep -xqF "MAGISK_VER='$1'" "$MAGISKBIN/util_functions.sh" || return 1
  grep -xqF "MAGISK_VER_CODE=$2" "$MAGISKBIN/util_functions.sh" || return 1
  return 0
}

cp_readlink() {
  if [ -z $2 ]; then
    cd $1
  else
    cp -af $1/. $2
    cd $2
  fi
  for file in *; do
    if [ -L $file ]; then
      local full=$(readlink -f $file)
      rm $file
      cp -af $full $file
    fi
  done
  chmod -R 755 .
  cd /
}

fix_env() {
  # Cleanup and make dirs
  rm -rf $MAGISKBIN/*
  if [ -d /data/unencrypted ]; then
      rm -rf $MAGISKBIN
      rm -rf /data/unencrypted/MAGISKBIN/*
      mkdir -p /data/unencrypted/MAGISKBIN
      ln -s ../unencrypted/MAGISKBIN $MAGISKBIN
  else
      mkdir -p $MAGISKBIN 2>/dev/null
  fi
  chmod 700 $NVBASE
  cp_readlink $1 $MAGISKBIN
  rm -rf $1
  chown -R 0:0 $MAGISKBIN
}

direct_install() {
  echo "- Flashing new boot image"
  flash_image $1/new-boot.img $2
  case $? in
    1)
      echo "! Insufficient partition size"
      return 1
      ;;
    2)
      echo "! $2 is read only"
      return 2
      ;;
  esac

  rm -f $1/new-boot.img
  fix_env $1
  run_migrations
  copy_sepolicy_rules

  return 0
}

run_uninstaller() {
  rm -rf /dev/tmp
  mkdir -p /dev/tmp/install
  unzip -o "$1" "assets/*" "lib/*" -d /dev/tmp/install
  INSTALLER=/dev/tmp/install sh /dev/tmp/install/assets/uninstaller.sh dummy 1 "$1"
}

restore_imgs() {
  [ -z $SHA1 ] && return 1
  local BACKUPDIR=/data/magisk_backup_$SHA1
  [ -d $BACKUPDIR ] || return 1

  get_flags
  find_boot_image

  for name in dtb dtbo; do
    [ -f $BACKUPDIR/${name}.img.gz ] || continue
    local IMAGE=$(find_block $name$SLOT)
    [ -z $IMAGE ] && continue
    flash_image $BACKUPDIR/${name}.img.gz $IMAGE
  done
  [ -f $BACKUPDIR/boot.img.gz ] || return 1
  flash_image $BACKUPDIR/boot.img.gz $BOOTIMAGE
}

post_ota() {
  cd $NVBASE
  cp -f $1 bootctl
  rm -f $1
  chmod 755 bootctl
  ./bootctl hal-info || return
  SLOT_NUM=0
  [ $(./bootctl get-current-slot) -eq 0 ] && SLOT_NUM=1
  ./bootctl set-active-boot-slot $SLOT_NUM
  cat << EOF > post-fs-data.d/post_ota.sh
/data/adb/bootctl mark-boot-successful
rm -f /data/adb/bootctl
rm -f /data/adb/post-fs-data.d/post_ota.sh
EOF
  chmod 755 post-fs-data.d/post_ota.sh
  cd /
}

add_hosts_module() {
  # Do not touch existing hosts module
  [ -d $MAGISKTMP/modules/hosts ] && return
  cd $MAGISKTMP/modules
  mkdir -p hosts/system/etc
  cat << EOF > hosts/module.prop
id=hosts
name=Systemless Hosts
version=1.0
versionCode=1
author=Magisk
description=Magisk app built-in systemless hosts module
EOF
  magisk --clone /system/etc/hosts hosts/system/etc/hosts
  touch hosts/update
  cd /
}

add_riru_core_module(){
    [ -d $MAGISKTMP/modules/riru-core ] && return
    mkdir -p $MAGISKTMP/modules/riru-core
    cat << EOF > $MAGISKTMP/modules/riru-core/module.prop
id=riru-core
name=Riru
version=N/A
versionCode=0
author=Rikka, yujincheng08
description=Riru module is not installed. Click update button to install the module.
updateJson=https://huskydg.github.io/external/riru-core/info.json
EOF
    cd /
}



adb_pm_install() {
  local tmp=/data/local/tmp/temp.apk
  cp -f "$1" $tmp
  chmod 644 $tmp
  su 2000 -c pm install -g $tmp || pm install -g $tmp || su 1000 -c pm install -g $tmp
  local res=$?
  rm -f $tmp
  if [ $res = 0 ]; then
    appops set "$2" REQUEST_INSTALL_PACKAGES allow
  fi
  return $res
}

check_boot_ramdisk() {
  # Create boolean ISAB
  ISAB=true
  [ -z $SLOT ] && ISAB=false

  # If we are A/B, then we must have ramdisk
  $ISAB && return 0

  # If we are using legacy SAR, but not A/B, assume we do not have ramdisk
  if grep ' / ' /proc/mounts | grep -q '/dev/root'; then
    # Override recovery mode to true
    RECOVERYMODE=true
    return 1
  fi

  return 0
}

check_encryption() {
  if $ISENCRYPTED; then
    if [ $SDK_INT -lt 24 ]; then
      CRYPTOTYPE="block"
    else
      # First see what the system tells us
      CRYPTOTYPE=$(getprop ro.crypto.type)
      if [ -z $CRYPTOTYPE ]; then
        # If not mounting through device mapper, we are FBE
        if grep ' /data ' /proc/mounts | grep -qv 'dm-'; then
          CRYPTOTYPE="file"
        else
          # We are either FDE or metadata encryption (which is also FBE)
          CRYPTOTYPE="block"
          grep -q ' /metadata ' /proc/mounts && CRYPTOTYPE="file"
        fi
      fi
    fi
  else
    CRYPTOTYPE="N/A"
  fi
}

##########################
# Non-root util_functions
##########################

mount_partitions() {
  [ "$(getprop ro.build.ab_update)" = "true" ] && SLOT=$(getprop ro.boot.slot_suffix)
  # Check whether non rootfs root dir exists
  SYSTEM_ROOT=false
  grep ' / ' /proc/mounts | grep -qv 'rootfs' && SYSTEM_ROOT=true
}

get_flags() {
  KEEPVERITY=$SYSTEM_ROOT
  ISENCRYPTED=false
  [ "$(getprop ro.crypto.state)" = "encrypted" ] && ISENCRYPTED=true
  KEEPFORCEENCRYPT=$ISENCRYPTED
  # Although this most certainly won't work without root, keep it just in case
  if [ -e /dev/block/by-name/vbmeta_a ] || [ -e /dev/block/by-name/vbmeta ]; then
    VBMETAEXIST=true
  else
    VBMETAEXIST=false
  fi
  # Preset PATCHVBMETAFLAG to false in the non-root case
  PATCHVBMETAFLAG=false
  # Make sure RECOVERYMODE has value
  [ -z $RECOVERYMODE ] && RECOVERYMODE=false
}

run_migrations() { return; }

grep_prop() { return; }

##############################
# Magisk Delta Custom script
##############################

# define
MAGISKSYSTEMDIR="/system/etc/init/magisk"

random_str(){
local FROM
local TO
FROM="$1"; TO="$2"
tr -dc A-Za-z0-9 </dev/urandom | head -c $(($FROM+$(($RANDOM%$(($TO-$FROM+1))))))
}

is_delta(){
if magisk -v | grep -q "\-delta"; then
    return 0
fi
return 1
}

unload_magisk(){
local MAGISKVERCODE="$(magisk -V)"
if [ ! "$MAGISKVERCODE" -lt "25200" ] && is_delta; then
    # revert magisk modifications
    magisk magiskhide --do-unmount $(pidof zygote) $(pidof zygote64)
    # stop magisk daemon
    killall -SIGKILL magiskd
else
    # use built-in command, which might cause freeze
    magisk --stop &
fi
}

magiskrc(){
local MAGISKTMP="/dev/$(random_str 6 14)"
local SELINUX="$1"

local suexec_seclabel="-"
local seclabel_service="u:r:su:s0"
local seclabel_exec="-"

if [ "$SELINUX" == true ]; then
    suexec_seclabel="u:r:su:s0"
    seclabel_service="u:r:magisk:s0"
    seclabel_exec="u:r:magisk:s0"
fi

cat <<EOF

on post-fs-data
    start logd
    start adbd
    mkdir $MAGISKTMP
    mount tmpfs tmpfs $MAGISKTMP mode=0755
    copy $MAGISKSYSTEMDIR/magisk64 $MAGISKTMP/magisk64
    chmod 0755 $MAGISKTMP/magisk64
    symlink ./$magisk_name $MAGISKTMP/magisk
    symlink ./magisk $MAGISKTMP/su
    symlink ./magisk $MAGISKTMP/resetprop
    symlink ./magisk $MAGISKTMP/magiskhide
    symlink ./magiskpolicy $MAGISKTMP/supolicy
    copy $MAGISKSYSTEMDIR/magisk32 $MAGISKTMP/magisk32
    chmod 0755 $MAGISKTMP/magisk32
    copy $MAGISKSYSTEMDIR/magiskinit $MAGISKTMP/magiskinit
    chmod 0755 $MAGISKTMP/magiskinit
    copy $MAGISKSYSTEMDIR/magiskpolicy $MAGISKTMP/magiskpolicy
    chmod 0755 $MAGISKTMP/magiskpolicy
    exec $suexec_seclabel root root -- $MAGISKTMP/magiskpolicy --live --magisk "allow * magisk_file lnk_file *"
    exec $seclabel_exec root root -- $MAGISKTMP/magiskinit -x manager $MAGISKTMP/stub.apk
    write /dev/.magisk_livepatch 0
    mkdir $MAGISKTMP/.magisk 700
    mkdir $MAGISKTMP/.magisk/mirror 700
    mkdir $MAGISKTMP/.magisk/block 700
    copy $MAGISKSYSTEMDIR/config $MAGISKTMP/.magisk/config
    rm /dev/.magisk_unblock
    exec $seclabel_exec root root -- $MAGISKTMP/magisk --post-fs-data
    wait /dev/.magisk_unblock 40
    rm /dev/.magisk_unblock
    rm /dev/.magisk_livepatch
    exec $seclabel_exec root root -- $MAGISKTMP/magisk --service

on property:sys.boot_completed=1
    mkdir /data/adb/magisk 755
    exec $seclabel_exec root root -- $MAGISKTMP/magisk --boot-complete
   
on property:init.svc.zygote=restarting
    exec $seclabel_exec root root -- $MAGISKTMP/magisk --zygote-restart
   
on property:init.svc.zygote=stopped
    exec $seclabel_exec root root -- $MAGISKTMP/magisk --zygote-restart


EOF
}

addond_magisk_system(){
cat << DELTA
#!/sbin/sh
#
# ADDOND_VERSION=2
#
# Magisk (System method) addon.d

. /tmp/backuptool.functions

list_files() {
cat <<EOF
etc/init/magisk/magisk32
etc/init/magisk/magisk64
etc/init/magisk/magiskinit
etc/init/magisk/magiskpolicy
etc/init/magisk.rc
EOF
}

case "\$1" in
  backup)
    list_files | while read FILE DUMMY; do
      backup_file \$S/"\$FILE"
    done
  ;;
  restore)
    list_files | while read FILE REPLACEMENT; do
      R=""
      [ -n "\$REPLACEMENT" ] && R="\$S/\$REPLACEMENT"
      [ -f "\$C/\$S/\$FILE" ] && restore_file \$S/"\$FILE" "\$R"
    done
  ;;
  pre-backup)
    # Stub
  ;;
  post-backup)
    # Stub
  ;;
  pre-restore)
    # Stub
  ;;
  post-restore)
    # Stub
  ;;
esac
DELTA
}

remount_check(){
    local mode="$1"
    local part="$(realpath "$2")"
    local ignore_not_exist="$3"
    local i
    if ! grep -q " $part " /proc/mounts && [ ! -z "$ignore_not_exist" ]; then
        return "$ignore_not_exist"
    fi
    mount -o "$mode,remount" "$part"
    local IFS=$'\t\n ,'
    for i in $(cat /proc/mounts | grep " $part " | awk '{ print $4 }'); do
        test "$i" == "$mode" && return 0
    done
    return 1
}

backup_restore(){
    # if gz is not found and orig file is found, backup to gz
    if [ ! -f "${1}.gz" ] && [ -f "$1" ]; then
        gzip -k "$1" && return 0
    elif [ -f "${1}.gz" ]; then
    # if gz found, restore from gz
        rm -rf "$1" && gzip -kdf "${1}.gz" && return 0
    fi
    return 1
}

cleanup_system_installation(){
    rm -rf "$MIRRORDIR${MAGISKSYSTEMDIR}"
    rm -rf "$MIRRORDIR${MAGISKSYSTEMDIR}.rc"
    backup_restore "$MIRRORDIR/system/etc/init/bootanim.rc" \
    && rm -rf "$MIRRORDIR/system/etc/init/bootanim.rc.gz"
    if [ -e "$MIRRORDIR${MAGISKSYSTEMDIR}" ] || [ -e "$MIRRORDIR${MAGISKSYSTEMDIR}.rc" ]; then
        return 1
    fi
}

remount_ro_system(){
    umount -l "$MIRRORDIR"
    rm -rf "$MIRRORDIR"
}

print_title_delta(){
    print_title "Magisk Delta (Systemless Mode)" "by HuskyDG"
    print_title "Powered by Magisk"
    return 0
}

warn_system_ro(){
    echo "! System partition is read-only"
    remount_ro_system
    return 1
}

is_rootfs(){
    local root_blkid="$(mountpoint -d /)"
    test "${root_blkid%:*}" == 0 && return 0
    return 1
}

mkblknode(){
    local blk_mm="$(mountpoint -d "$2" | sed "s/:/ /g")"
    mknod "$1" -m 666 b $blk_mm
}

force_mount(){
    { mount "$1" "$2" || mount -o ro "$1" "$2" \
    || mount -o ro -t ext4 "$1" "$2" \
    || mount -o ro -t f2fs "$1" "$2" \
    || mount -o rw -t ext4 "$1" "$2" \
    || mount -o rw -t f2fs "$1" "$2"; } 2>/dev/null
    remount_check rw "$2" || warn_system_ro
}

patch_sepolicy_file(){
    echo "- Patch sepolicy file"
    local sepol file
    for file in /vendor/etc/selinux/precompiled_sepolicy /system_root/odm/etc/selinux/precompiled_sepolicy /system/etc/selinux/precompiled_sepolicy /system_root/sepolicy /system_root/sepolicy_debug /system_root/sepolicy.unlocked; do
        if [ -f "$MIRRORDIR$file" ]; then
            sepol="$file"
            break
        fi
    done
    if [ -z "$sepol" ]; then
        echo "! Cannot find sepolicy file"
        cleanup_system_installation
        remount_ro_system
        return 1
    else
        echo "- Sepolicy file is $sepol"
        backup_restore "$MIRRORDIR$sepol"
        if ! is_rootfs && ! "$INSTALLDIR/magiskpolicy" --load "$MIRRORDIR$sepol" --save "$MIRRORDIR$sepol" --magisk "allow * magisk_file lnk_file *" "allow su * * *" "permissive su" &>/dev/null; then
            echo "! Sepolicy failed to patch"
            cleanup_system_installation
            remount_ro_system
            return 1
        fi
    fi
}

direct_install_system(){
    print_title "Magisk Delta (System Mode)" "by HuskyDG"
    print_title "Powered by Magisk"
    api_level_arch_detect
    local INSTALLDIR="$1"
    local SYSTEMMODE=false
    local RUNNING_MAGISK=false
    local vphonegaga_titan=false
    if pidof magiskd &>/dev/null && command -v magisk &>/dev/null; then
       local MAGISKTMP="$(magisk --path)/.magisk"
       getvar SYSTEMMODE
       RUNNING_MAGISK=true
    fi
    [ -z "$SYSTEMMODE" ] && SYSTEMMODE=false

    # if Magisk is running, not system mode and trigger file not found
    if $RUNNING_MAGISK && ! $SYSTEMMODE && [ ! -f /dev/.magisk_systemmode_allow ]; then
        echo "[!] Magisk (maybe) is installed into boot image"
        echo ""
        echo "  This option should be used for emulator only!"
        echo ""
        echo "  If you still want to install Magisk in /system"
        echo "  make sure:"
        echo "    + Magisk is not installed in boot image"
        echo "    + Boot image is restored to stock"
        echo ""
        sleep 3
        echo "! Press install again if you definitely did the above"
        rm -rf /dev/.magisk_systemmode_allow
        touch /dev/.magisk_systemmode_allow
        return 1
    fi
        
    echo "- Remount system partition as read-write"
    local MIRRORDIR="/dev/sysmount_mirror" ROOTDIR SYSTEMDIR VENDORDIR

    ROOTDIR="$MIRRORDIR/system_root"
    SYSTEMDIR="$MIRRORDIR/system"
    VENDORDIR="$MIRRORDIR/vendor"

    # make sure sysmount is clean
    umount -l "$MIRRORDIR" 2>/dev/null
    rm -rf "$MIRRORDIR"
    mkdir "$MIRRORDIR" || return 1
    mount -t tmpfs -o 'mode=0755' tmpfs "$MIRRORDIR" || return 1
    mkdir "$MIRRORDIR/block"
    if is_rootfs; then
        ROOTDIR=/
        mkblknode "$MIRRORDIR/block/system" /system
        mkdir "$SYSTEMDIR"
        force_mount "$MIRRORDIR/block/system" "$SYSTEMDIR" || return 1
    else
        mkblknode "$MIRRORDIR/block/system_root" /
        mkdir "$ROOTDIR"
        force_mount "$MIRRORDIR/block/system_root" "$ROOTDIR" || return 1
        ln -fs ./system_root/system "$SYSTEMDIR"
   fi

   # check if /vendor is seperated fs
   if mountpoint -q /vendor; then
        mkblknode "$MIRRORDIR/block/vendor" /vendor
        mkdir "$VENDORDIR"
        force_mount "$MIRRORDIR/block/vendor" "$VENDORDIR" || return 1
   else
        ln -fs ./system/vendor "$VENDORDIR"
   fi


    echo "- Copy files to system partition"
    cleanup_system_installation || return 1
    mkdir -p "$SYSTEMDIR/etc/init/magisk"
    local magisk_applet=magisk32 magisk_name=magisk32
    if [ "$IS64BIT" == true ]; then
        magisk_name=magisk64
        magisk_applet="magisk32 magisk64"
    fi
    for magisk in $magisk_applet magiskpolicy magiskinit; do
        cat "$INSTALLDIR/$magisk" >"$MIRRORDIR$MAGISKSYSTEMDIR/$magisk" || { echo "! Unable to write Magisk binaries to system"; echo "! Insufficient free space or system write protection"; cleanup_system_installation; return 1; }
    done
    echo "SYSTEMMODE=true" >"$MIRRORDIR$MAGISKSYSTEMDIR/config" 
    chcon -R u:object_r:system_file:s0 "$MIRRORDIR$MAGISKSYSTEMDIR"
    chmod -R 700 "$MIRRORDIR$MAGISKSYSTEMDIR"

    # test live patch
    local SELINUX=true
    if [ -d "/sys/fs/selinux" ]; then
        echo "- Check if kernel can use dynamic sepolicy patch"
        if ! "$INSTALLDIR/magiskpolicy" --live "permissive su" &>/dev/null; then
            echo "! Kernel does not support dynamic sepolicy patch"
            cleanup_system_installation
            remount_ro_system
            return 1
        fi
        if ! is_rootfs; then
            patch_sepolicy_file || return 1
        fi
    else
        SELINUX=false
        echo "- SeLinux is disabled, no need to patch!"
    fi
    echo "- Add init boot script"
    hijackrc="$MIRRORDIR/system/etc/init/magisk.rc"
    if [ -f "$MIRRORDIR/system/etc/init/bootanim.rc" ]; then
        backup_restore "$MIRRORDIR/system/etc/init/bootanim.rc" && hijackrc="$MIRRORDIR/system/etc/init/bootanim.rc"
    fi
    echo "$(magiskrc $SELINUX)" >>"$hijackrc" || return 1
    
    if [ -d "$MIRRORDIR/system/addon.d" ]; then
        echo "- Add Magisk survival script"
        rm -rf "$MIRRORDIR/system/addon.d/99-magisk.sh"
        echo "$addond_magisk_system" >"$MIRRORDIR/system/addon.d/99-magisk.sh"
    fi
    remount_ro_system
    fix_env "$INSTALLDIR"
    true
    return 0
}


coreonly(){
    local i presistdir="/data/adb /data/unencrypted /persist /mnt/vendor/persist /cache /metadata"
    if [ "$1" == "enable" ] || [ "$1" == "disable" ]; then
        for i in $presistdir; do
            rm -rf "$i/.disable_magisk"
            [ "$1" == "disable" ] || touch "$i/.disable_magisk"
        done
        return 0
    else
        for i in $presistdir; do
            [ -e "$i/.disable_magisk" ] && return 0
        done
        return 1
    fi
}

#############
# Initialize
#############

app_init() {
  mount_partitions
  RAMDISKEXIST=false
  check_boot_ramdisk && RAMDISKEXIST=true
  get_flags
  run_migrations
  SHA1=$(grep_prop SHA1 $MAGISKTMP/config)
  check_encryption
}

export BOOTMODE=true
