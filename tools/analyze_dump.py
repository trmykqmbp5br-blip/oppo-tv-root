#!/usr/bin/env python3
"""离线分析 /dev/malloc dump 出来的内核物理内存 (0x20000000..0x22000000)。

目标: 找出内核全局 int selinux_enforcing 的物理地址。
思路: 内核代码 literal pool 里会存放该变量的虚拟地址常量；
      出现次数多、且换算成物理地址后该处当前值恰为 1 的，就是高置信度候选。
"""
import sys, struct, collections, re, os

PHYS_BASE = 0x20000000
path = sys.argv[1] if len(sys.argv) > 1 else r'artifacts/wb_kcode.bin'
d = open(path, 'rb').read()
print('dump size', len(d), 'phys 0x%08x..0x%08x' % (PHYS_BASE, PHYS_BASE + len(d)))

# 1) 基本健康检查
nz = sum(1 for b in d[:0x100000] if b)
print('前 1MB 非零字节比例 %.1f%%' % (100.0 * nz / 0x100000))
for kw in [b'Linux version', b'selinux', b'enforcing', b'selinux_enforcing',
           b'SELinux', b'avc', b'init_task', b'swapper']:
    pos = [m.start() for m in re.finditer(re.escape(kw), d)]
    print('%-20s %3d 处, 首个 phys=0x%08x' % (kw.decode(), len(pos),
          (PHYS_BASE + pos[0]) if pos else 0))

# 2) 统计内核虚拟地址常量 (4 字节对齐)
u = struct.unpack('<%dI' % (len(d)//4), d[:len(d)//4*4])
cnt = collections.Counter(v for v in u if 0xC0000000 <= v < 0xC4000000)
print('\n不同内核虚拟地址常量: %d, 总出现 %d' % (len(cnt), sum(cnt.values())))
print('出现次数最多的 20 个:')
for v, c in cnt.most_common(20):
    print('  virt=0x%08x  count=%-5d' % (v, c))

# 3) 候选: 虚拟地址常量 -> 物理地址, 且该处值为 1
print('\n=== 候选 (delta=0xA0000000) ===')
rows = []
for v, c in cnt.items():
    p = v - 0xA0000000
    if PHYS_BASE <= p < PHYS_BASE + len(d) - 4:
        val = struct.unpack_from('<I', d, p - PHYS_BASE)[0]
        if val == 1:
            rows.append((c, v, p))
rows.sort(reverse=True)
for c, v, p in rows[:40]:
    print('  count=%-4d virt=0x%08x phys=0x%08x' % (c, v, p))
print('候选总数(值为1):', len(rows))

# 4) 其它 delta 的对照, 用来确认线性映射偏移
print('\n=== 各 delta 下 "高频 V 命中值为1" 的数量 ===')
for delta in (0x40000000, 0x60000000, 0x80000000, 0xA0000000,
              0xC0000000, 0x9E000000, 0xA0008000):
    hits = 0
    for v, c in cnt.items():
        p = v - delta
        if PHYS_BASE <= p < PHYS_BASE + len(d) - 4:
            if struct.unpack_from('<I', d, p - PHYS_BASE)[0] == 1:
                hits += 1
    print('  delta=0x%08x -> %d' % (delta, hits))

# 5) 找 kallsyms_addresses 特征: 连续递增的 0xC0xxxxxx 数组
print('\n=== 连续内核地址数组 (kallsyms 特征) ===')
best = []
run = []
for i, v in enumerate(u):
    if 0xC0000000 <= v < 0xC2000000 and (not run or v >= run[-1]):
        run.append(v)
    else:
        if len(run) >= 32:
            best.append((len(run), i - len(run), run[0], run[-1]))
        run = []
for n, i, a, b in sorted(best, reverse=True)[:8]:
    print('  %5d 个连续, phys=0x%08x, virt范围 0x%08x..0x%08x' %
          (n, PHYS_BASE + i*4, a, b))
