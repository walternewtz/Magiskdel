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
  install_addond "$3"
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

use_full_magisk(){
    [ "$(magisk --path)" == "/system/xbin" ] && return 1
    return 0
}


install_addond(){
    local installDir="$MAGISKBIN"
    local AppApkPath="$1"
    addond=/system/addon.d
    test ! -d $addond && return
    ui_print "- Adding addon.d survival script"
    BLOCKNAME="/dev/block/system_block.$(random_str 5 20)"
    rm -rf "$BLOCKNAME"
    if is_rootfs; then
        mkblknode "$BLOCKNAME" /system
    else
        mkblknode "$BLOCKNAME"  /
    fi
    blockdev --setrw "$BLOCKNAME"
    rm -rf "$BLOCKNAME"
    mount -o rw,remount /
    mount -o rw,remount /system
    rm -rf $addond/99-magisk.sh 2>/dev/null
    rm -rf $addond/magisk 2>/dev/null
    mkdir -p $addond/magisk
    cp -prLf "$installDir"/. $addond/magisk || { ui_print "! Failed to install addon.d"; return; }
    mv $addond/magisk/boot_patch.sh $addond/magisk/boot_patch.sh.in
    mv $addond/magisk/addon.d.sh $addond/99-magisk.sh
    cp "$AppApkPath" $addond/magisk/magisk.apk
    mount -o ro,remount /
    mount -o ro,remount /system
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
