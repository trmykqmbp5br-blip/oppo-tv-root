# root 全过程（按时间线，含被推翻的阶段结论）

> 本文从原始工作记录抽取，**保留了失败的尝试和后续修正**，
> 目的是让整条推理链可复现。所有设备标识、内网地址、本地绝对路径、
> 密钥口令均已替换为占位符；占位符含义见仓库根目录 `README.md`。

## 设备背景

## 设备实际情况

| 项目 | 值 |
|---|---|
| 型号（`ro.product.model`） | `OPPOCNM652`（机身标注 A55UQB00，55 英寸） |
| 品牌 / 系统 | OPPO / ColorOS TV 2.x，Android 9（SDK 28） |
| 固件 | `PPR2.180905.006.A1` |
| 芯片 / 内存 | MediaTek MT9652 系列，1.7 GB 可用，只支持 32 位应用（`armeabi-v7a`） |
| 分辨率 | 系统上报 1920×1080 |

注意：这台和 Aerial 官方笔记里那台 `OPPOCNM652` 是**同一型号、同一固件**，所以那份笔记的结论可直接套用。


---

## 2026-11-07 root 探索：已拿到 uid=0 通道，系统应用仍受阻

### 结论

- **已成功**：本机可获得完整 `uid=0(root)` + 满 capability 的**任意命令执行通道**（不刷机、不改分区、重启失效、无常驻进程、无监听端口）。实测 `id` = `uid=0(root) gid=0(root)`。
- **未完成**：SELinux 仍 `Enforcing`，进程域固定 `u:r:system_app:s0`。`mount -o rw,remount /`、`setenforce 0`、读 `/proc/kallsyms`、读 `/proc/iomem` 全部被 AVC 拒绝，**所以目前无法把 Aerial 写进 `/system/priv-app`，也无法注入白名单**。
- 依据 `katriyda/oppo-k9-tv-root`（K9 / `OPPOCNM632` / m7332 的研究）。本机 `OPPOCNM652 / m7642 / 内核 4.9.118+` 同族，但**内核布局不同**。

### 通道原理

1. `dumpsys tvapisvc -cmd "sh <脚本>"` → `com.heytap.tvapiservice`（uid 1000 / `system_app` 域）执行任意 shell，stdout 落到 `/sdcard/<argv0>-exec-*.logtv`。命令按空格裸分词，复杂命令必须写成脚本。
2. 固件遗留 MStar 调试节点 `/dev/malloc`（`crw-rw-rw-`），`system_app` 域可 ioctl+mmap 读写内核物理内存；`shell` 域在 Enforcing 下不能 open（`dd` 读也返回 EINVAL，驱动只支持 ioctl+mmap）。
3. 扫描 MIU0 找 8×`uid=1000` 的 `struct cred`，patch 为 uid=0 + 满 caps，`getuid()` 自证、失败原样回滚。本机 cred 命中 `0x9a5xxxxx`（运行时变化），比 K9 探针扫描上限 `0x92000000` 还高。
4. 在 patch 后的 so 里注入 `execve("/system/bin/sh", {"sh","/sdcard/cmd.sh"})`，进程即变成 uid=0 shell，脚本内容随时可换。SELinux 硬编码写入那步已 NOP 掉。

### ⛔ 绝对不要照抄 K9 的 SELinux 地址

K9 方案把 `0x2137bdfc` 写 0 来关 SELinux。本机**只读 dump** 该地址，内容是 Wi-Fi 驱动调试字符串（`" prRetSwRfb->ucStaRecIdx(254) >= CFG_STA_REC_NUM(27)"` 等），**不是 enforcing 变量**；写下去只会污染内核内存且关不掉 SELinux。本机 `0x2122d590`（K9 的 `init_cred`）处也是别的结构体，与 K9 的 `04 00 00 00 … CAP_FULL_SET` 特征不符。

要继续，必须**动态定位**本机 `selinux_enforcing`（或改当前进程 SID），属于写内核物理内存的搜索操作，有 panic / 变砖风险，**未做**。

### 复现 root 命令通道（当前设备已就绪）

```bash
A=$ADB; $A connect <TV_IP>:5555
$A push cmd.sh /sdcard/cmd.sh      # 想以 uid=0 执行的命令
$A shell 'rm -f /sdcard/oat/arm/main2.odex /sdcard/oat/arm/main2.vdex; dumpsys tvapisvc -cmd "sh /sdcard/r1.sh"'
# 等 5~15 秒（cred 扫描），再读 cmd.sh 的输出文件
```

设备侧保留：`/sdcard/r1.sh`、`/sdcard/main2.jar`、`/sdcard/cmd.sh`、载体 APK `com.zz.libhost`（4KB，自签，无权限/无服务/无常驻）。工作区产物在 `tv-backup/root-20261107/`（研究仓库副本、各版 APK/so/jar、keystore、电视状态备份）。

**三个坑**：

- 每次 `adb install -r` 覆盖载体 APK，`/data/app/com.zz.libhost-<22位随机后缀>` 会变，`main2.jar` 里硬编码的路径必须同步重生成（等长替换后缀 + 重算 dex SHA1 / adler32），否则 `System.load` 失败。
- `/sdcard/oat/arm/main2.odex` 会缓存旧 dex，换 jar 前必须删，否则 ART 报 `ClassNotFoundException`（SIGABRT / 134）。
- 通道**不持久**：重启后 cred 复原、SELinux 回到 Enforcing，重跑一遍即可；不留 root 进程或端口。

### 已剔除的路由器升级脚本

`<UPGRADE_DIR>/upgrade.sh` 与 crontab 的 `0 21 * * 0 … # aerial-oppo-upgrade` 一行已移除，`/etc/init.d/cron restart` 生效。备份在路由器 `<ROUTER_BACKUP>/`（整目录 tar、`crontabs-root`、`retired/upgrade.sh`）。`/etc/sysupgrade.conf` 本来就没收录该目录，无残留引用。以后 Aerial 升级改为手工执行。

## 2026-11-07 20:45 续：变砖风险评估与内核布局探测

### 结论：本次要做的操作几乎不可能造成永久变砖

> **修正**：11-07 早先写的「想 root 只能拆机刷 eMMC」是针对**刷写分区**而言，对「写内核物理内存」不适用。上一章把风险说重了。

分层判断：

| 层级 | 后果 | 恢复方式 |
|---|---|---|
| 写错 RAM 里的内核数据 | kernel panic / 进程被杀 | **断电重启即恢复**，RAM 一断电全清空，flash 未动 |
| 系统起不来（软砖） | MBOOT 仍在 | U 盘强制升级、`recovery` 分区、`misc` 分区 |
| bootloader 物理损坏（硬砖） | 需拆机 | ISP 短接 / TTL 串口 / 编程器读 eMMC —— **本次操作碰不到这一层** |

实测依据：

1. **物理上碰不到 flash**。uid=0 + 满 capability 的 root shell 执行 `dd if=/dev/block/by-name/boot`、`MBOOT`、`recovery` 全部 `Permission denied`（域仍是 `u:r:system_app:s0`）。写比读更严，因此 `/dev/malloc` 改内存不可能误伤 eMMC 分区。
2. **只改 RAM**。cred patch 与后续可能的 enforcing 写入都在内存里，`reboot` 或拔电即全清，不留任何持久痕迹。root 通道本来就是「重启失效」设计。
3. **panic 有兜底**。cmdline 带 `PM51_ADDR=0x45870000,PM51_LEN=0x10000`（独立电源管理 8051，负责看门狗/待机）、`KDebug=1`、`console=ttyS0,115200`；MStar 平台 panic 后通常由 PM51 复位。最坏手动断电重启。
4. **刷机通道齐全且无签名校验**：`ro.boot.verifiedbootstate=orange`、cmdline `SECURITY=OFF`；分区表有 `MBOOT` + `MBOOTBAK`（双份 bootloader）、独立 `recovery`、`misc`、`upgrade`，共 36 个分区。MStar 通用救砖法是 FAT32 U 盘根目录放 `MstarUpgrade.bin` / `install.img`，按住机身音量+ 或待机键上电强制升级，黑屏也能盲刷。只有 U 盘也救不回才需要拆机 TTL/ISP。

**所以真正的风险不是变砖，而是短时 panic / 需要手动断电重启。** 动手前的安全网已经就位：电视状态与 APK 备份在 `tv-backup/root-20261107/`、路由器整目录与 crontab 备份在 `<ROUTER_BACKUP>/`、升级脚本已剔除、ADB `keep_adb` 保持开启（panic 重启后还能连回来）、root 通道三件套可重建。

### 本轮只读挖掘进展（全程未写内核内存）

**找到 K9 地址不适用的根因**：cmdline 显示

```
LX_MEM=0x23600000  LX_MEM2=0x52000000,0x4C200000
```

Linux 内核内存在第二块 `0x52000000~0x9E200000`。实测 cred 命中 `0x98973xxx`，而 K9 的 `selinux_enforcing=0x2137bdfc` / `init_cred=0x2122d590` 都在低端第一块，因此**照抄必然写到别的结构体**（已只读验证 `0x2137bdfc` 是 Wi-Fi 驱动调试字符串）。

**cred 结构已完整 dump**（用 `libcredview.so` 改扫描上限 `0x92000000 → 0xa0000000`，uid 常量保持 `1000`）：

```
CB 00000000989739c0
+0   usage=0x232
+4..35   8 个 id（探针已 patch 为 0）
+36  securebits=0
+40..79  5 组 capability（patch 为全 ff）
+88  0xFFFFFFC06AC7EF00   +120 0xFFFFFFC0576FD680
+128 0xFFFFFFC06A090580   +136 0xFFFFFF8009056D58
+144 0xFFFFFFC02E418380   +192 0xFFFFFFC069F73480
```

注意 `tvapisvc` 起的进程是 **uid=1000**（不是 2000），且 cred 在 `0x9897xxxx`，原版探针上限 `0x92000000` 扫不到——这是 10-29 探针 `CB=0` 的原因。

**改 SID 路线暂卡住**：想绕开 SELinux 最干净的办法是把当前进程 `cred->security->sid` 改成 kernel 域（小整数），但这需要把内核虚拟地址换算成 `/dev/malloc` 的物理地址。按 `PAGE_OFFSET=0xFFFFFFC000000000`、两种 `PHYS_OFFSET`（0 / 0x20000000）推导出 11 个候选地址全部只读 dump 过，**没有一个是 `task_security_struct`**（分别是压缩数据、随机数据、全零页、dex 数据）。说明本机内核映射与标准 arm64 线性映射不同，或 `security` 指针不在推测的偏移上。

**被 `system_app` 域拒绝的只读接口**（uid=0 也无效）：`/proc/kallsyms`、`/proc/iomem`、`/proc/config.gz`、`/proc/partitions`、`/proc/sys/kernel/panic`、`/proc/sys/kernel/kptr_restrict`（读+写都拒）、`/sys/fs/selinux/context`（拿 sid 的路被堵）。可读的只有 `/sys/fs/selinux/policy`、`/sys/fs/selinux/enforce`、`cmd deviceidle whitelist`（能列出白名单，是零风险绕路方案的线索）。

### 尚未执行的分叉（需明确选择）

- **A 继续只读定位**：解析 `/sys/fs/selinux/policy`、扫描内核 `.data` 特征，或找 `init_cred` 锚点。零风险，慢。
- **B 扫描 + 试写 + oracle 验证 + 立即回滚**：对候选 4 字节值写 0、立刻读 `/sys/fs/selinux/enforce` 判断是否变 permissive、未命中立即写回。自带回滚，但会短暂改内核变量，有 panic 可能（断电可恢复）。
- **C 不碰 `/system`**：用 uid=0 直接做 `cmd deviceidle whitelist +<pkg>`、保活与桌面白名单，绕过「必须写系统分区」这个前提。零风险，且能满足「Aerial 不被清理」的实际需求。

本轮所有产物：`tv-backup/root-20261107/root-research/tools/research/malloc/session-2026-10-30/` 下的 `libcredview-local.so`、`libcredview-4dump.so`、`libcredview-scan.so` 及对应 `libhost-*.apk`。现场已恢复为 `libhost-exec.apk`（可复用的 uid=0 通道），探针日志已清理，电视终检：Aerial 在、禁用 31、乐播 0、P2P GO 在、UDP 1900×2 在听、SELinux `Enforcing`、系统分区未改动。

## 2026-11-07 21:45 B 方案完成：SELinux 已可关，Aerial 已装成系统应用

### 结论（对前面章节的重大修正）

- **内核是 ARM64（AArch64）+ 32 位用户空间**。dump 里函数机器码是 `stp x29,x30` / `adrp` / `ret`，ARM64 镜像头 `ARM\x64` 在物理 `0x20280038` → `_text` 物理基址 **X = `0x20280000`**。之前按 32 位 ARM 的 `0xC0xxxxxx` literal 常量筛出来的候选全是噪声，这是两轮试写全不中的根因。
- **`selinux_enforcing` 物理地址 = `0x213AAD7C`**（4 字节 int，运行时值 1）。写 0 后实测 `getenforce` = **Permissive**。
- 至此 root 链路完整：`uid=0` + 满 caps + `mount -o rw,remount /` 可写 `/system`。K9 的 `0x2137bdfc` 仍然不能照抄（本机是别的数据）。

### 方法（离线分析 + 每个候选都带保存/验证/回滚）

1. 用 keystone 手写 ARM32 汇编注入载体 so（`build_probe.py` / `build_unified.py`），通过 `/dev/malloc` **只读** dump 物理 `0x20000000..0x24000000`（64MB）到 `/sdcard/wb_kcode.bin`，`adb pull` 成 `tv-backup/root-20261107/wb_kcode64.bin`。零写入。
2. 解析内核 kallsyms：`token_index` @ `0x20f4c000`、`token_table` @ `0x20f4bc00`、`markers` @ `0x20f4b600`、`kallsyms_offsets` @ `0x20ea7ba8`（41015 项）、`names` @ `0x20ecff09`。`sel_read_enforce` / `sel_write_enforce` / `enforcing_setup` / `avc_has_perm` 都能解码出来（`parse_kallsyms.py`）。
3. 本机 kallsyms **没有 `selinux_enforcing` 这个符号名**（与 K9 不同），改用 ARM64 数据流：扫 SELinux 代码区 `X+0x440000..X+0x480000` 的 `adrp` + `add` + `ldr/str w`，算出所有被读写的 32 位全局，筛「当前值 == 1」→ **22 个候选**（`find_enforcing.py`）。
4. 同一个 so 的 BATCH 模式（`wb_targets.bin` 存在时）逐地址 **保存原值 → 写 0 → `open("/sys/fs/selinux/enforce")` 并读内容验证 → 未命中立即写回**；命中保留 0。结果 `rc=2, target=0x213aad7c`，前 3 个候选已自动回滚。
   - 验证信号：Enforcing 下 `system_app` 域 open selinuxfs 被拒（EACCES）；enforcing 变量清 0 后 avc 全放行，open 成功且读出 `'0'`。
   - **`/dev/malloc` 的 mmap 只接受 `0x1000000`（16MB）粒度**，单页 `0x1000` 必失败——第一版 BATCH 全 `mapfail` 的原因。

### 已落地的操作

| 项 | 结果 |
|---|---|
| Aerial 系统应用 | `/system/app/Aerial/Aerial.apk`（3160326 B，与 `/data/app/com.oneplus.tv.launcher2-*/base.apk` md5 一致 `b9b919dc…`），root:root / 0644 / 标签 `u:object_r:system_file:s0` |
| deviceidle 白名单 | `cmd deviceidle whitelist +com.oneplus.tv.launcher2` → `Added:`，`user,com.oneplus.tv.launcher2,10055` |
| 系统分区 | `mount -o rw,remount /` 写入后已 `mount -o ro,remount /` 恢复只读 |
| SELinux 回滚 | `selinux_enforcing` 是内存变量，**重启自动回 Enforcing**，无需手工恢复 |
| 路由器升级脚本 | crontab 无 aerial 条目，`upgrade.sh` 归档在 `<ROUTER_BACKUP>/retired/`（已复核） |

装 `/system/app` 而不是 `/system/priv-app`，是为了避开 Android 9 的 privapp 权限白名单校验；`FLAG_SYSTEM` 一样生效，`AppSwitchBusiness` 的 `Utils.isSystemApp()` 判定通过，不会再被 3 秒强杀。

### 一步复现（以后再要 permissive）

地址已知，不必重新解析：把小端 4 字节 `7c ad 3a 21` 写进 `/sdcard/wb_targets.bin`，用 `wbhost-unified.apk` 版载体触发 `dumpsys tvapisvc -cmd "sh /sdcard/r1.sh"`；或任意能访问 `/dev/malloc` 的 so 直接对物理 `0x213AAD7C` 写 0。恢复用 `setenforce 1` 或重启。

### 重启终检（全部通过）

`adb reboot` 后 **约 4 分钟** ADB 才恢复——期间能 ping 通但 5555 及所有 TCP 端口超时（PMS 重新扫描系统分区较慢），WoL 无效，**等即可，不是变砖**。

- `sys.boot_completed=1`，`getenforce=Enforcing` → **SELinux 已自动回滚**（内存变量，天然不持久）。
- `dumpsys package com.oneplus.tv.launcher2` → `flags=[ SYSTEM HAS_CODE ALLOW_CLEAR_USER_DATA UPDATED_SYSTEM_APP LARGE_HEAP ]`。**`SYSTEM` 已生效**，`AppSwitchBusiness` 的 `Utils.isSystemApp()` 判定通过，不会再被 3 秒强杀；`UPDATED_SYSTEM_APP` 表示 `/data/app` 里那份被识别为系统应用的更新版本，原有壁纸/设置/默认桌面全部保留。
- `cmd deviceidle whitelist` → `user,com.oneplus.tv.launcher2,10055`（重启后仍在）。
- 当前焦点 `com.oneplus.tv.launcher2/app.orchard.tv.MainActivity`，Aerial 正常在前台；原桌面 `com.heytap.tv.launcher` 仍禁用。
- 投屏链路未受影响：A 类 5 个组件全启用、禁用数 31、乐播 0、`castservice` 在、`p2p-p2p0-0` GO 为 `192.168.49.1/24` UP。

若以后要撤销系统应用改动：删掉 `/system/app/Aerial/` 再重启即可（需要重新拿一次 permissive，已知地址一步到位）。

### 产物

`tv-backup/root-20261107/root-research/tools/research/malloc/session-2026-10-30/`：`build_probe.py`、`build_unified.py`（keystone 汇编 + jarsigner 打包）、`redex.py`（dex 等长替换 + 重算 SHA1/adler32）、`parse_kallsyms.py`、`find_enforcing.py`、`analyze_dump.py`、`wbinject-*.so` / `wbhost-*.apk`、`wb_targets.bin`。内存镜像在 `tv-backup/root-20261107/wb_kcode.bin`(32MB) 与 `wb_kcode64.bin`(64MB)。

## 2026-11-07 22:15 换成官方原版（未改包名）

用户要求「替换成原版的、没有改包名的那个」。已完成，冷启动实测通过。

### 实测推翻了本文档开头的旧结论

「必须改包名 + 补 `MODERN_HOME`」的前提是**只能用 `pm install` 装到 `/data`**。有 root 能把 APK 直接放进 `/system/app` 后：

- PMS 开机扫描**不会**执行 ColorOS 那条「HOME 类别包名白名单」检查（`INSTALL_FAILED_DUPLICATE_PERMISSION` 只发生在 `pm install` 路径）。
- 官方原版 `app.orchard.tv`（v1.86 / 3159642 B / md5 `fc98d6cdaed143f7cd45e019dafa726f`，官方签名）放进 `/system/app/AerialOfficial/AerialOfficial.apk` 后，PMS 直接给 `flags=[ SYSTEM … ]`；**开机不卡动画、不黑屏**，`cmd package set-home-activity app.orchard.tv/app.orchard.tv.MainActivity` 设默认成功，按 Home 稳定回到它。
- 结论：**不改包名、不补 `MODERN_HOME`、不改签名也能当桌面**，前提是能写 `/system`。

### 最终状态（冷启动实测）

| 项 | 值 |
|---|---|
| 桌面 | `app.orchard.tv/app.orchard.tv.MainActivity`，`isDefault=true`，按 Home 后焦点不变 |
| APK | `/system/app/AerialOfficial/AerialOfficial.apk`，`SYSTEM` flag，`system_file` 标签，0644 |
| 魔改版 | `com.oneplus.tv.launcher2` **已彻底卸载**，`/system/app/Aerial/` 已删除，PMS 里不存在 |
| 白名单 | 仅 `user,app.orchard.tv,10056` |
| SELinux | `Enforcing`（每次重启自动回滚） |
| 原厂桌面 | `com.heytap.tv.launcher` 仍禁用 |
| 投屏链路 | A 类 5 组件全启用、禁用数 31、乐播 0、castservice 在、`p2p-p2p0-0` UP |

### 两个坑

1. **光 `pm disable-user` 不够**：魔改版被标成 `enabled=0` 后，它的无障碍守护 `HomeGuardService` 仍会自启，开机时抢走前台（`mCurrentFocus` 一度是 `com.oneplus.tv.launcher2`）。必须 `pm uninstall -k --user 0 com.oneplus.tv.launcher2` **加上**删掉 `/system/app/Aerial/`，PMS 才会彻底清掉它。
2. 两个 HOME 并存时 `resolve-activity` 落 `ResolverActivity`（开机弹「选择桌面」）；`cmd package set-home-activity …` 立即解决。

### 回退到魔改版

把 `tv-backup/root-20261107/aerial-current.apk`（魔改版 v1.86，自签）放回 `/system/app/Aerial/Aerial.apk`，重新 `pm install` 到 `/data`，再 `cmd package set-home-activity com.oneplus.tv.launcher2/app.orchard.tv.MainActivity`。需要重新拿一次 permissive：写物理 `0x213AAD7C` 为 0 即可（一步到位，见上一章）。

### 现场残留

载体 APK `com.zz.libhost`（约 6KB，自签、无权限/无服务/无常驻）仍留在 `/data/app`，是 root 通道的一部分；不需要了可以 `pm uninstall com.zz.libhost` 一并清掉，同时删 `/sdcard/{r1.sh,main2.jar,cmd.sh,wb_targets.bin,wb_*.txt}`。
