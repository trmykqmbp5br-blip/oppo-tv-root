#!/usr/bin/env python3
"""ARM64 内核: 跟踪 adrp/add + ldr/str w 指令, 找出被代码读写的 32 位全局。
   目标 selinux_enforcing 当前值应为 1, 且会被 str w 写入。
"""
import os
import struct, collections
P = 0x20000000
X = 0x20280000
import sys
DUMP = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), '..', 'artifacts', 'wb_kcode64.bin')
d = open(DUMP, 'rb').read()


def rd32(p):
    o = p - P
    return struct.unpack_from('<I', d, o)[0] if 0 <= o < len(d) - 4 else None


def scan(start, end):
    reg = [None] * 32
    reads = collections.Counter()
    writes = collections.Counter()
    for off in range(start - P, end - P, 4):
        w = struct.unpack_from('<I', d, off)[0]
        pc = P + off
        # adrp xRd, page
        if (w & 0x9F000000) == 0x90000000:
            immlo = (w >> 29) & 3
            immhi = (w >> 5) & 0x7ffff
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            rd = w & 0x1f
            reg[rd] = ((pc & ~0xfff) + (imm << 12)) & 0xffffffffffffffff
            continue
        # add xRd, xRn, #imm (immediate, shift 0)
        if (w & 0x7F000000) == 0x11000000:
            rd = w & 0x1f
            rn = (w >> 5) & 0x1f
            imm = (w >> 10) & 0xfff
            if reg[rn] is not None:
                reg[rd] = (reg[rn] + imm) & 0xffffffffffffffff
            else:
                reg[rd] = None
            continue
        # ldr wRt,[xRn,#imm] / str wRt,[xRn,#imm]
        if (w & 0xFFC00000) in (0xB9400000, 0xB9000000):
            rn = (w >> 5) & 0x1f
            imm = ((w >> 10) & 0xfff) * 4
            if reg[rn] is not None:
                tgt = (reg[rn] + imm) & 0xffffffff
                if P <= tgt < P + len(d) - 4:
                    if (w & 0xFFC00000) == 0xB9400000:
                        reads[tgt] += 1
                    else:
                        writes[tgt] += 1
            continue
    return reads, writes


# selinuxfs + hooks + avc 代码区
reads, writes = scan(X + 0x00440000, X + 0x00480000)
print('读目标 %d 个, 写目标 %d 个' % (len(reads), len(writes)))
print('\n=== 被写且当前值为 1 的全局 (最可能是 enforcing) ===')
rows = [(writes[t] + reads[t], writes[t], reads[t], t, rd32(t)) for t in writes
        if rd32(t) == 1]
for tot, w, r, t, val in sorted(rows, reverse=True)[:30]:
    print('  phys=0x%08x  写=%d 读=%d  值=0x%08x' % (t, w, r, val))
print('\n=== 只读但值为 1、引用最多的全局 ===')
rows = [(reads[t], t, rd32(t)) for t in reads if rd32(t) == 1]
for c, t, val in sorted(rows, reverse=True)[:25]:
    print('  phys=0x%08x  读=%d  值=0x%08x' % (t, c, val))
