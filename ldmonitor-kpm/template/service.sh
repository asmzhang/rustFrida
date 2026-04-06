#!/system/bin/sh
MODDIR=${0%/*}

# 等待系统完全启动，确保底层 KPM 基础设施准备完毕
wait_until_boot_complete() {
  while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
  done
}

wait_until_boot_complete

# 调用 ksud 的 kpm 命令，挂载我们的 KPM 模块
/data/adb/ksud kpm load "$MODDIR/@MODULE_NAME@.kpm"
