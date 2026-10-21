# -*- coding: utf-8 -*-
import os
import sys
import struct
import hashlib
import zlib
import subprocess
import re

class AndroidMemTool:
    def __init__(self):
        self.dump_dir = "memory_dumps"
        self.dex_dir = "extracted_dex"
        self.so_dir = "extracted_so"
        
        for d in [self.dump_dir, self.dex_dir, self.so_dir]:
            if not os.path.exists(d):
                os.makedirs(d)

    def run_adb(self, cmd, root=False, get_output=False):
        """执行 adb 命令的底层封装"""
        if root:
            full_cmd = f'adb shell su -c "{cmd}"'
        else:
            full_cmd = f'adb shell {cmd}'
        
        try:
            if get_output:
                return subprocess.run(full_cmd, shell=True, capture_output=True, text=True, errors='ignore').stdout
            else:
                subprocess.run(full_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
        except Exception as e:
            print(f"[-] ADB 执行出错: {e}")
            return None

    def dump_memory(self, pid, min_size_mb=2):
        """1. 自动化 Dump 内存 (排除无用碎片)"""
        print(f"[*] 正在读取进程 {pid} 的内存映射...")
        maps = self.run_adb(f"cat /proc/{pid}/maps", root=True, get_output=True)
        if not maps:
            print("[-] 无法获取 maps，请检查 App 是否在运行且 root 权限正常。")
            return

        targets = []
        for line in maps.splitlines():
            parts = line.split()
            if len(parts) < 5: continue
            
            # 抓取可读写/可执行段，且包含 anon 或 dalvik
            if ('rw-p' in parts[1] or 'rwxp' in parts[1]) and ('[anon' in line or 'dalvik' in line):
                start_hex, end_hex = parts[0].split('-')
                start, end = int(start_hex, 16), int(end_hex, 16)
                size = end - start
                
                if size >= min_size_mb * 1024 * 1024:
                    name = parts[-1] if len(parts) > 5 else "anon"
                    clean_name = re.sub(r'[^a-zA-Z0-9_]', '', name)
                    targets.append((start, size, clean_name, start_hex))

        targets.sort(key=lambda x: x[1], reverse=True)
        print(f"[+] 找到 {len(targets)} 个大于 {min_size_mb}MB 的有效内存段。")

        for idx, (start, size, name, start_hex) in enumerate(targets):
            skip = start // 4096
            count = (size + 4095) // 4096
            file_name = f"dump_{idx}_{name}_{start_hex}.bin"
            remote_path = f"/sdcard/{file_name}"
            local_path = os.path.join(self.dump_dir, file_name)
            
            print(f"  [{idx+1}/{len(targets)}] 提取 {name} ({size/1024/1024:.2f} MB) -> skip:{skip} count:{count}")
            self.run_adb(f"dd if=/proc/{pid}/mem bs=4096 skip={skip} count={count} of={remote_path}", root=True)
            subprocess.run(f"adb pull {remote_path} {local_path}", shell=True, stdout=subprocess.DEVNULL)
            self.run_adb(f"rm {remote_path}", root=True)

        print(f"[+] 内存 Dump 完成！文件保存在 {self.dump_dir}/")


    def extract_dex(self):
        """2. 从 Dump 中提取并修复 DEX (修复梆梆抽取壳吞代码问题)"""
        magics = [b'dex\n035\x00', b'dex\n037\x00', b'dex\n039\x00']
        count = 0

        for file in os.listdir(self.dump_dir):
            if not file.endswith(".bin"): continue
            fpath = os.path.join(self.dump_dir, file)

            with open(fpath, "rb") as f:
                data = f.read()

            for magic in magics:
                offset = 0
                while True:
                    idx = data.find(magic, offset)
                    if idx == -1: break

                    if idx + 0x24 <= len(data):
                        # 【关键修复】：放弃读取头部声明的 file_size，直接截取到文件末尾
                        # 因为梆梆壳的 file_size 是假的，真代码全跟在后面
                        real_size = len(data) - idx

                        dex_data = bytearray(data[idx: idx + real_size])

                        # 强制修改头部大小为实际截取的长度
                        struct.pack_into("<I", dex_data, 0x20, real_size)

                        # 修复 SHA1 signature 和 Adler32 checksum
                        sig = hashlib.sha1(bytes(dex_data[0x20:])).digest()
                        dex_data[0x0C:0x20] = sig
                        chk = zlib.adler32(bytes(dex_data[0x0C:])) & 0xFFFFFFFF
                        struct.pack_into("<I", dex_data, 0x08, chk)

                        out_name = os.path.join(self.dex_dir, f"fix_{file}_{idx:x}.dex")
                        with open(out_name, "wb") as out_f:
                            out_f.write(dex_data)
                        print(f"[+] 提取并修复 DEX: {out_name} (大小: {real_size / 1024 / 1024:.2f} MB)")
                        count += 1
                    offset = idx + 4
        print(f"[*] DEX 提取完成，共 {count} 个，保存在 {self.dex_dir}/ (可直接拖入 Jadx)")



    def extract_so(self):
        """3. 从 Dump 中提取 SO (暴力防遗漏版：直接截取到内存块末尾)"""
        magic_elf = b'\x7fELF'
        count = 0

        for file in os.listdir(self.dump_dir):
            if not file.endswith(".bin"): continue
            fpath = os.path.join(self.dump_dir, file)

            with open(fpath, "rb") as f:
                data = f.read()

            offset = data.find(magic_elf)
            if offset != -1:
                # 【核心修改】：放弃解析复杂的 PHT/SHT 头，直接切到该内存块的末尾
                # 哪怕尾部带着其他的垃圾内存，IDA 也能自动识别或忽略
                remain = len(data) - offset

                # 如果你想设置一个最大上限，比如 100MB，防止切出个几百兆的怪物，
                # 可以加上 max_size = min(remain, 100 * 1024 * 1024)
                # 但在这里，全切是最安全的。
                total_size = remain

                print(f"[*] 发现 ELF 头 ({file} -> 0x{offset:x})，剩余内存 {total_size / 1024 / 1024:.2f} MB")

                so_data = data[offset: offset + total_size]
                out_name = os.path.join(self.so_dir, f"extract_{file}_{offset:x}.so")

                with open(out_name, "wb") as out_f:
                    out_f.write(so_data)
                print(f"    [+] 成功提取 SO: {out_name} (大小: {total_size / 1024 / 1024:.2f} MB)")
                count += 1

        print(f"[*] SO 提取完成，共 {count} 个，保存在 {self.so_dir}/ (可直接拖入 IDA)")


if __name__ == "__main__":
    tool = AndroidMemTool()
    print("=== 安卓内存自动化脱壳与提取工具 ===")
    print("1. 自动 Dump 内存 (过滤碎片)")
    print("2. 提取并修复 DEX")
    print("3. 提取并修复 SO")
    print("4. 一键执行全部流程 (Dump -> DEX -> SO)")
    
    choice = input("请选择操作 (1/2/3/4): ")
    
    if choice in ['1', '4']:
        target_pid = input("请输入目标应用的 PID: ")
        if target_pid.isdigit():
            tool.dump_memory(target_pid)
    
    if choice in ['2', '4']:
        tool.extract_dex()
        
    if choice in ['3', '4']:
        tool.extract_so()