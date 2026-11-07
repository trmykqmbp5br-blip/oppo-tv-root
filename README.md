# OPPO TV（OPPOCNM652 / m7642）root 研究记录

一台 OPPO 电视上，从「只能以 `system_app` 域执行 shell」走到
「`uid=0` + 可关闭 SELinux + 可写 `/system`」的完整过程，含所有失败尝试与修正。

> **仅用于自有设备的安全研究**。本仓库**不包含**任何二进制 exploit、APK、
> 签名密钥、dex/so 或内核内存镜像，只提供方法论与用于离线分析的源码。

## 适用环境

| 项 | 值 |
|---|---|
| 机型 | `OPPOCNM652` / `A55UQB00`，ColorOS TV 2.x / Android 9（SDK 28） |
| 固件 | `PPR2.180905.006.A1` |
| 芯片 | MStar m7642，**ARM64 内核 + 32 位用户空间** |
| 内核 | `4.9.118+` |

⚠️ 文中 `selinux_enforcing` 的物理地址 `0x213AAD7C`、kallsyms 各表偏移、
ARM64 镜像头位置**都只对应这一份固件**。换版本必须按 `docs/root-walkthrough.md`
的方法重新定位，照抄地址会写到无关的内核数据上。

## 结论摘要

1. `dumpsys tvapisvc -cmd "sh <脚本>"` 让 `system_app` 域执行任意 shell；
   固件遗留的 MStar 调试节点 `/dev/malloc` 可 ioctl+mmap 读写内核物理内存。
2. 扫描 `struct cred` 的 8 个 uid 字段并 patch 为 0 + 满 capability，
   得到非持久的 `uid=0` shell（重启失效、无常驻进程、无监听端口）。
3. 内核是 **ARM64**（不是 32 位 ARM）——这一点判断错会让候选地址全成噪声。
   用只读内存 dump 解析 kallsyms，再用 `adrp`/`ldr`/`str` 数据流定位
   「被 SELinux 代码读写、当前值为 1」的全局变量。
4. 对每个候选**保存原值 → 写 0 → 用 selinuxfs 验证 → 未命中立即写回**，
   命中即全局 Permissive。命中地址 `0x213AAD7C`。
5. 有了写 `/system` 的能力后，官方未改包名的 Aerial 可直接作为系统应用/默认桌面，
   不需要改包名或补厂商的桌面类别。

## 目录

| 文件 | 内容 |
|---|---|
| `docs/root-walkthrough.md` | 完整时间线：通道原理、变砖评估、地址定位、试写与回滚、系统应用落地、冷启动终检 |
| `tools/build_unified.py` | keystone 汇编注入 so（只读 dump / 批量试写双模式）+ jarsigner 打包 |
| `tools/build_probe.py` | 早期单地址/扫描版注入器，含 `struct info` ioctl 与 mmap 细节 |
| `tools/redex.py` | dex 中等长替换 APK 安装后缀并重算 SHA1 / adler32 |
| `tools/analyze_dump.py` | 离线统计内核虚拟地址常量、候选过滤 |
| `tools/parse_kallsyms.py` | 从内存镜像解析 `token_table` / `markers` / `offsets` / `names` |
| `tools/find_enforcing.py` | ARM64 `adrp + add + ldr/str w` 数据流定位目标全局 |

## 环境依赖

- Python 3 + `keystone-engine` + `capstone`（汇编/反汇编）
- JDK（`jarsigner`，v1 签名）；Android SDK `adb`、`aapt`、`zipalign`
- 一台能连到电视 ADB 的电脑，以及一个自签 keystore

使用前需要设置：

```bash
export KEYSTORE_PASS='<你的 keystore 口令>'   # build_probe.py / build_unified.py 签名用
export JDK_BIN='/path/to/jdk/bin'              # 可选，不设则用 PATH 里的 jarsigner
```

`tools/parse_kallsyms.py` 和 `tools/find_enforcing.py` 接受内存镜像路径作为
第一个参数（默认 `artifacts/wb_kcode64.bin`，该目录已被 `.gitignore` 排除）。

## 占位符说明

原始记录中的以下信息已全部替换，**上传内容与任何具体设备/网络无关**：

| 占位符 | 原含义 |
|---|---|
| `<TV_IP>` / `<ROUTER_IP>` / `<PC_IP>` / `<PHONE_IP>` | 内网 IPv4 地址 |
| `<TV_MAC>` / `<PHONE_MAC>` / `<SERIAL>` | 设备 MAC 与序列号 |
| `<ROUTER_KEY>` / `<ROUTER_BACKUP>` / `<UPGRADE_DIR>` | 路由器 SSH 私钥与本地目录名 |
| `<APK_SUFFIX>` | APK 安装目录的随机后缀 |
| `<JDK_BIN>` / `$ADB` / `<BUILD_HOST>` | 本地绝对路径与编译主机名 |

内核虚拟地址、物理地址、符号偏移等技术数据保留，因为它们是方法本身的一部分。
文中出现的 `192.168.49.1` 是 Android Wi-Fi Direct 规定的 GO 固定地址，属于公开协议常量，
不是任何具体设备的内网地址。

## 已知限制与风险

- 关 SELinux 是**改内核物理内存**，写错地址可能 panic；最坏情况需要断电重启
  或通过厂商 U 盘强刷恢复（本机 `MBOOT/MBOOTBAK/recovery/misc/upgrade` 分区齐全）。
- `selinux_enforcing` 是内存变量，**重启自动回到 Enforcing**，不需要手工恢复。
- 每次覆盖安装载体 APK，其安装目录后缀会变，dex 里硬编码的路径必须同步重生成，
  并清掉 `/sdcard/oat/arm/main2.odex|vdex`，否则 ART 报 `ClassNotFoundException`。
- `/dev/malloc` 的 mmap 只接受 `0x1000000`（16MB）粒度，单页映射会失败。
- 用户态是 32 位、内核是 64 位，两者不要混用地址换算。
