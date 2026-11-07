#!/usr/bin/env python3
"""从内核物理内存 dump 中解析 kallsyms，求 selinux_enforcing 的虚拟/物理地址。"""
import os
import struct

P = 0x20000000
DELTA = 0xA0000000
import sys
DUMP = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), '..', 'artifacts', 'wb_kcode64.bin')
d = open(DUMP, 'rb').read()

IDX_PHYS = 0x20f4c000
TBL_PHYS = 0x20f4bc00
ioff, toff = IDX_PHYS - P, TBL_PHYS - P
v = struct.unpack_from('<256H', d, ioff)
tokens = []
for off in v:
    e = d.index(b'\0', toff + off)
    tokens.append(d[toff + off:e].decode('latin1'))
print('token[0..5]', tokens[:5], '| 非空', sum(1 for x in tokens if x))

# ---- markers: token_table 之前, 8 字节步长的递增 u32 ----
mk_end = 0x20f4bb00 - P          # 最后一个 marker 值所在位置
mk = []
o = mk_end
while o > 0:
    x = struct.unpack_from('<I', d, o)[0]
    if mk and x >= mk[-1]:
        break
    mk.append(x)
    o -= 8
mk.reverse()
mk_start = o + 8
print('markers %d 个: 首=%d 末=%d(0x%x), 范围 phys=0x%08x..0x%08x' %
      (len(mk), mk[0], mk[-1], mk[-1], P + mk_start, P + mk_end))


def decode_name(pos):
    n = d[pos]
    if not (1 <= n <= 40):
        return None, 0
    try:
        return ''.join(tokens[d[pos + 1 + k]] for k in range(n)), n + 1
    except IndexError:
        return None, 0


# ---- 找 names 起点 ----
names_start = None
lo = mk_start - mk[-1] - 0x4000
hi = mk_start - mk[-1] + 0x4000
for guess in range(lo, hi, 4):
    if guess < 0 or guess + 128 > len(d):
        continue
    names, p, ok = [], guess, True
    for _ in range(8):
        nm, ln = decode_name(p)
        if not nm or len(nm) < 2 or not all(32 <= ord(c) < 127 for c in nm):
            ok = False
            break
        names.append(nm)
        p += ln
    if ok:
        names_start = guess
        print('names_start phys=0x%08x 前8符号=%s' % (P + guess, names))
        break
if names_start is None:
    raise SystemExit('!! names 起点定位失败')

# ---- num_syms / addresses ----
N = struct.unpack_from('<I', d, names_start - 4)[0]
addr_start = names_start - 4 - 4 * N
print('num_syms=%d, addresses phys=0x%08x' % (N, P + addr_start))
if 10000 < N < 200000 and addr_start >= 0:
    print('  addr[0]=0x%08x addr[1]=0x%08x addr[N-1]=0x%08x' %
          (struct.unpack_from('<I', d, addr_start)[0],
           struct.unpack_from('<I', d, addr_start + 4)[0],
           struct.unpack_from('<I', d, addr_start + 4*(N-1))[0]))

want = {'selinux_enforcing', 'selinux_enabled', 'sel_read_enforce',
        'sel_write_enforce', 'avc_has_perm', 'init_cred', 'selinux_state'}
found = {}
p = names_start
for i in range(N):
    nm, ln = decode_name(p)
    if nm is None:
        print('!! 第 %d 个符号解码中断 phys=0x%08x' % (i, P + p))
        break
    if nm in want:
        val = struct.unpack_from('<I', d, addr_start + 4*i)[0] if addr_start >= 0 else 0
        found[nm] = (i, val, val - DELTA)
        print('HIT %-20s idx=%-6d virt=0x%08x phys=0x%08x' %
              (nm, i, val, val - DELTA))
    p += ln
print('解码 %d 个符号, names 共 %d 字节' % (i + 1, p - names_start))

if 'selinux_enforcing' in found:
    i, virt, phys = found['selinux_enforcing']
    print('\n>>> selinux_enforcing phys=0x%08x virt=0x%08x' % (phys, virt))
    if 0 <= phys - P < len(d) - 4:
        print('>>> dump 中该处当前值 = 0x%08x' %
              struct.unpack_from('<I', d, phys - P)[0])
