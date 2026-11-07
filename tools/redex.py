#!/usr/bin/env python3
"""把 main2.jar 内 dex 里的 APK 安装后缀做等长替换，并重算 dex 校验。

用法: python redex.py <新后缀>   例: python redex.py DwX_hGA3MhtxUTsPeocyyA==
"""
import sys, os, re, zipfile, hashlib, zlib, struct

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'main2-local.jar')
OUT = os.path.join(HERE, 'main2.jar')

def main():
    suffix = sys.argv[1].encode()
    dex = bytearray(zipfile.ZipFile(SRC).read('classes.dex'))
    m = re.search(rb'com\.zz\.libhost-[A-Za-z0-9_-]+==', bytes(dex))
    if not m:
        raise SystemExit('dex 内未找到 APK 路径字符串')
    old = m.group(0)
    new = b'com.zz.libhost-' + suffix
    if len(old) != len(new):
        raise SystemExit('后缀长度不等: old=%d new=%d (必须等长)' % (len(old), len(new)))
    print('[old]', old.decode())
    dex[m.start():m.end()] = new
    print('[new]', new.decode())
    dex[12:32] = hashlib.sha1(bytes(dex[32:])).digest()
    dex[8:12] = struct.pack('<I', zlib.adler32(bytes(dex[12:])) & 0xffffffff)
    with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('classes.dex', bytes(dex))
    print('[out]', OUT, os.path.getsize(OUT))

if __name__ == '__main__':
    main()
