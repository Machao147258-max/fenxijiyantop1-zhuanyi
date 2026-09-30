#!/bin/sh
# transpute_check.sh —— 转译环境三连定性（在 adb shell / 设备上跑）
# 用法: sh transpute_check.sh <PID> <lib名字>
PID=${1:?pid}
LIB=${2:-libtarget.so}

echo "=== 1) lib 是不是 aarch64(转译)? (第18字节 b7=aarch64 / 3e=x86_64) ==="
# 用 maps 里找到的路径
P=$(grep "$LIB" /proc/$PID/maps | head -1 | awk '{print $NF}')
echo "path: $P"
[ -n "$P" ] && xxd -l 20 "$P"

echo "=== 2) 有没有 houdini? ==="
grep -m3 houdini /proc/$PID/maps

echo "=== 3) 这个 lib 在不在 maps? 在哪个地址段? ==="
grep "$LIB" /proc/$PID/maps

echo "=== 4) frida 模块表(仅 x86_64) vs maps(/arm64/) 数量 ==="
echo "ARM libs in maps: $(grep -c '/arm64/' /proc/$PID/maps)"

echo "=== 5) 前台? (后台冻结时 hook 无意义) ==="
dumpsys activity activities 2>/dev/null | grep topResumedActivity | head -1
