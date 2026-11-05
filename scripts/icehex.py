import argparse
import collections
import math
import os
import struct
import subprocess
import sys


EXIT_OK = 0
EXIT_WARN = 1
EXIT_FATAL = 2

# 加密启发式阈值, 归一化熵口径 (0-1)
HEUR_ENC_AVG = 0.83
HEUR_ENC_MAX = 0.9
# 纯文本判定阈值, isspace 与 isgraph 两条块曲线均值之和
HEUR_TEXT_RATE = 0.95
# diff 相同区跳过时的块比对宽度
DIFF_BLK = 0x10000

ISSPACE = frozenset(b"\t\n\x0b\x0c\r ")
ISGRAPH = frozenset(range(0x21, 0x7F))

FORMAT_NAMES = {
    "ihex": "Intel HEX",
    "srec": "Motorola SREC",
    "elf": "ELF32",
    "bin": "裸二进制 (bin)",
}

ELF_MACHINES = {
    0: "None",
    8: "MIPS",
    20: "PowerPC",
    40: "ARM",
    62: "AMD64",
    83: "AVR",
    243: "RISC-V",
}

RISCV_OBJDUMP = (r"C:\MounRiver\MounRiver_Studio\toolchain"
                 r"\RISC-V Embedded GCC\bin\riscv-none-embed-objdump.exe")
RISCV_OBJDUMP_NAME = "riscv-none-embed-objdump.exe"
ARM_FROMELF_CANDIDATES = [
    r"D:\Keil_v5\ARM\ARMCLANG\bin\fromelf.exe",
    r"D:\Keil_v5\ARM\ARMCC\bin\fromelf.exe",
]

CM_SYSTEM_NAMES = [
    "SP_initial", "Reset", "NMI", "HardFault", "MemManage", "BusFault",
    "UsageFault", "Reserved", "Reserved", "Reserved", "Reserved", "SVC",
    "DebugMon", "Reserved", "PendSV", "SysTick",
]

RV_SYSTEM_NAMES = [
    "_start", "-", "NMI", "HardFault", "-", "Ecall_M", "-", "-", "Ecall_U",
    "BreakPoint", "-", "-", "SysTick", "-", "SW", "-",
]

# RV 前导特征指令字 (小端读入后的字值)
RV_INSN_JAL = 0x6F
RV_INSN_NOP = 0x00000013
RV_INSN_EBREAK = 0x00100073


class Fatal(Exception):
    """致命错误, 进程以退出码 2 终止"""


# ----------------------------------------------------------------
# 镜像数据模型: 按地址升序的连续数据段列表
# ----------------------------------------------------------------
class Image:

    def __init__(self):
        self._chunks = []
        self.segments = []

    def add(self, addr, data):
        if data:
            self._chunks.append((addr, data))

    def finalize(self):
        merged = []
        for addr, data in sorted(self._chunks, key=lambda c: c[0]):
            if merged:
                s, d = merged[-1]
                end = s + len(d)
                if addr <= end:
                    # 相邻段拼接, 重叠区以新数据为准
                    if addr < end:
                        d = d[:addr - s] + data
                    else:
                        d = d + data
                    merged[-1] = (s, d)
                    continue
            merged.append((addr, data))
        self.segments = merged

    @property
    def min_addr(self):
        return self.segments[0][0] if self.segments else 0

    @property
    def max_addr(self):
        if not self.segments:
            return -1
        s, d = self.segments[-1]
        return s + len(d) - 1

    @property
    def data_bytes(self):
        return sum(len(d) for _, d in self.segments)

    @property
    def bbox_span(self):
        if not self.segments:
            return 0
        return self.max_addr - self.min_addr + 1

    def contains(self, addr):
        for s, d in self.segments:
            if s > addr:
                return False
            if addr < s + len(d):
                return True
        return False

    def read(self, addr, size):
        for s, d in self.segments:
            if s > addr:
                return None
            if addr < s + len(d):
                if addr + size <= s + len(d):
                    off = addr - s
                    return d[off:off + size]
                return None
        return None

    def read_partial(self, addr, size):
        for s, d in self.segments:
            if s > addr:
                return None
            if addr < s + len(d):
                off = addr - s
                return d[off:off + size]
        return None

    def stream(self):
        parts = []
        marks = []
        off = 0
        for s, d in self.segments:
            marks.append((off, s))
            parts.append(d)
            off += len(d)
        return b"".join(parts), marks

    def offset_addr(self, marks, off):
        for o, s in reversed(marks):
            if off >= o:
                return s + (off - o)
        return None

    def gaps(self):
        out = []
        for i in range(len(self.segments) - 1):
            s, d = self.segments[i]
            nxt = self.segments[i + 1][0]
            gs = s + len(d)
            out.append((gs, nxt - 1, nxt - gs))
        return out


# ----------------------------------------------------------------
# 格式嗅探与解析层
# ----------------------------------------------------------------
def detect_format(path):
    with open(path, "rb") as f:
        head = f.read(512)
    if head[:4] == b"\x7fELF":
        return "elf"
    ws = b" \t\r\n\x0b\x0c"
    for i, b in enumerate(head):
        if b in ws:
            continue
        if b == 0x3A:
            return "ihex"
        if b == 0x53 and i + 1 < len(head) and 0x30 <= head[i + 1] <= 0x39:
            return "srec"
        return "bin"
    return "bin"


def parse_ihex(path, strict):
    img = Image()
    type_counts = collections.Counter()
    bad_count = 0
    first_bad = None
    entries = []
    base = 0

    def bad_line(reason, text):
        nonlocal bad_count, first_bad
        bad_count += 1
        if first_bad is None:
            first_bad = (reason, text)

    with open(path, "r", encoding="ascii", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if not line.startswith(":"):
                bad_line("行首非 ':'", line)
                continue
            try:
                rec = bytes.fromhex(line[1:])
            except ValueError:
                bad_line("含非法 hex 字符", line)
                continue
            if len(rec) < 5 or len(rec) != rec[0] + 5:
                bad_line("长度域与数据不符", line)
                continue
            if (sum(rec) & 0xFF) != 0:
                bad_line("校验和不符", line)
                continue
            byte_count = rec[0]
            offset = (rec[1] << 8) | rec[2]
            rtype = rec[3]
            payload = rec[4:4 + byte_count]
            type_counts[rtype] += 1
            if rtype == 0x01:
                break
            if rtype == 0x02:
                # 段基址 = 值 << 4, 与 16 位偏移做加法组合
                if byte_count != 2:
                    bad_line("段地址记录长度非 2", line)
                    continue
                base = ((payload[0] << 8) | payload[1]) << 4
            elif rtype == 0x04:
                if byte_count != 2:
                    bad_line("线性地址记录长度非 2", line)
                    continue
                base = ((payload[0] << 8) | payload[1]) << 16
            elif rtype == 0x03:
                if byte_count != 4:
                    bad_line("入口段地址记录长度非 4", line)
                    continue
                cs = (payload[0] << 8) | payload[1]
                ip = (payload[2] << 8) | payload[3]
                entries.append(("入口 0x03 (SSA)", (cs << 4) + ip,
                                "%04X:%04X" % (cs, ip)))
            elif rtype == 0x05:
                if byte_count != 4:
                    bad_line("入口线性地址记录长度非 4", line)
                    continue
                entries.append(("入口 0x05 (SLA)",
                                int.from_bytes(payload, "big"), None))
            elif rtype == 0x00:
                if byte_count == 0:
                    # 空 record 跳过, 防地址下溢
                    continue
                img.add(base + offset, payload)

    if strict and bad_count:
        raise Fatal("strict 模式: %d 条坏行, 首个坏行: %s (%s)"
                    % (bad_count, first_bad[1], first_bad[0]))
    return {
        "image": img,
        "type_counts": type_counts,
        "bad_count": bad_count,
        "first_bad": first_bad,
        "entries": entries,
    }


SREC_ADDR_WIDTH = {1: 2, 2: 3, 3: 4, 7: 4, 8: 3, 9: 2}


def parse_srec(path, strict):
    img = Image()
    type_counts = collections.Counter()
    bad_count = 0
    first_bad = None
    entries = []

    def bad_line(reason, text):
        nonlocal bad_count, first_bad
        bad_count += 1
        if first_bad is None:
            first_bad = (reason, text)

    with open(path, "r", encoding="ascii", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if len(line) < 4 or line[0] != "S" or not line[1].isdigit():
                bad_line("行首非 'S'+类型数字", line)
                continue
            t = int(line[1])
            try:
                rec = bytes.fromhex(line[2:])
            except ValueError:
                bad_line("含非法 hex 字符", line)
                continue
            # SREC 计数字段 = 计数字节之后的字节数 (地址+数据+校验)
            if len(rec) < 3 or rec[0] != len(rec) - 1:
                bad_line("长度域与数据不符", line)
                continue
            if (sum(rec) & 0xFF) != 0xFF:
                bad_line("校验和不符", line)
                continue
            type_counts["S%d" % t] += 1
            if t in (1, 2, 3):
                aw = SREC_ADDR_WIDTH[t]
                addr = int.from_bytes(rec[1:1 + aw], "big")
                img.add(addr, rec[1 + aw:-1])
            elif t in (7, 8, 9):
                aw = SREC_ADDR_WIDTH[t]
                entries.append(("入口 S%d" % t,
                                int.from_bytes(rec[1:1 + aw], "big"), None))
                break
            # S0/S4/S5/S6 不落数据

    if strict and bad_count:
        raise Fatal("strict 模式: %d 条坏行, 首个坏行: %s (%s)"
                    % (bad_count, first_bad[1], first_bad[0]))
    return {
        "image": img,
        "type_counts": type_counts,
        "bad_count": bad_count,
        "first_bad": first_bad,
        "entries": entries,
    }


def parse_elf32(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise Fatal("非 ELF 文件: %s" % path)
    if data[4] != 1:
        raise Fatal("仅支持 ELF32 (EI_CLASS=%d)" % data[4])
    if data[5] != 1:
        raise Fatal("仅支持小端 ELF (EI_DATA=%d)" % data[5])
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    e_phoff, = struct.unpack_from("<I", data, 28)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
    img = Image()
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 32 > len(data):
            break
        p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_flags = \
            struct.unpack_from("<IIIIIII", data, off)
        if p_type == 1 and p_filesz > 0:
            img.add(p_vaddr, data[p_offset:p_offset + p_filesz])
            loads.append((i, p_offset, p_vaddr, p_filesz, p_memsz))
    return {
        "image": img,
        "e_type": e_type,
        "e_machine": e_machine,
        "loads": loads,
        "bad_count": 0,
        "first_bad": None,
        "entries": [],
    }


def load_bin(path, base):
    with open(path, "rb") as f:
        data = f.read()
    img = Image()
    img.add(base, data)
    return {
        "image": img,
        "bad_count": 0,
        "first_bad": None,
        "entries": [],
    }


def load_any(path, format_opt, base_opt, strict):
    if not os.path.isfile(path):
        raise Fatal("文件不存在: %s" % path)
    fmt = format_opt if format_opt != "auto" else detect_format(path)
    if fmt == "ihex":
        r = parse_ihex(path, strict)
    elif fmt == "srec":
        r = parse_srec(path, strict)
    elif fmt == "elf":
        r = parse_elf32(path)
    elif fmt == "bin":
        r = load_bin(path, base_opt if base_opt is not None else 0)
    else:
        raise Fatal("未知格式: %s" % fmt)
    r["image"].finalize()
    r["fmt"] = fmt
    if base_opt is not None and fmt != "bin" and base_opt != r["image"].min_addr:
        # 非 bin 格式地址内含, -b 仅作基址确认, 矛盾即报错防歧义
        raise Fatal("-b %s 与镜像内含最低地址 %s 不一致, 地址已内含不接受重定基址"
                    % (hx(base_opt), hx(r["image"].min_addr)))
    if r["image"].data_bytes == 0:
        raise Fatal("空镜像 (无有效数据): %s" % path)
    if r.get("bad_count"):
        reason, text = r["first_bad"]
        print("[警告] 已跳过坏行 %d 条, 首个坏行 (%s): %s"
              % (r["bad_count"], reason, text))
    return r


# ----------------------------------------------------------------
# 输出辅助
# ----------------------------------------------------------------
def backup_if_exists(path):
    if os.path.exists(path):
        bak = path + ".bak"
        with open(path, "rb") as f:
            old = f.read()
        with open(bak, "wb") as f:
            f.write(old)
        print("[备份] 既有输出已备份: %s --> %s" % (path, bak))


def write_text_crlf(path, text):
    backup_if_exists(path)
    with open(path, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(text)


def hx(val, width=8):
    return ("0x%%0%dX" % width) % val


def side_bytes(img, addr, limit=8):
    d = img.read_partial(addr, limit)
    if d is None:
        return "--"
    return " ".join("%02X" % b for b in d)


# ----------------------------------------------------------------
# info
# ----------------------------------------------------------------
def cmd_info(args):
    r = load_any(args.file, getattr(args, "format", "auto"),
                 getattr(args, "b", None), getattr(args, "strict", False))
    img = r["image"]
    segs = img.segments
    gaps = img.gaps()
    print("=" * 68)
    print("IceHex info")
    print("文件: %s" % args.file)
    print("格式: %s" % FORMAT_NAMES.get(r["fmt"], r["fmt"]))
    print("-" * 68)
    print("分段表 (%d 段):" % len(segs))
    for i, (s, d) in enumerate(segs):
        print("  段 %2d: %s-%s  %d B" % (i, hx(s), hx(s + len(d) - 1), len(d)))
    if gaps:
        print("gap 表 (%d 个):" % len(gaps))
        for i, (gs, ge, n) in enumerate(gaps):
            print("  gap %2d: %s-%s  %d B" % (i, hx(gs), hx(ge), n))
    print("数据字节总量: %d B" % img.data_bytes)
    print("bbox 跨度    : %s-%s (%d B)"
          % (hx(img.min_addr), hx(img.max_addr), img.bbox_span))
    if gaps:
        print("[警告] bbox 跨度含 gap, 不可当作数据量")
    if r["fmt"] in ("ihex", "srec"):
        parts = ["%s x %d" % (k, v) for k, v in sorted(r["type_counts"].items())]
        print("记录类型统计: %s" % (", ".join(parts) if parts else "无"))
        print("坏行: %d" % r["bad_count"])
        if r["entries"]:
            print("入口记录:")
            for name, val, extra in r["entries"]:
                tail = (" (%s)" % extra) if extra else ""
                print("  %s --> %s%s" % (name, hx(val), tail))
        else:
            print("入口记录: 无")
    if r["fmt"] == "elf":
        mach = r["e_machine"]
        print("e_machine: %d (%s)" % (mach, ELF_MACHINES.get(mach, "未知")))
        print("e_type: %d" % r["e_type"])
        print("PT_LOAD 段表 (%d 个):" % len(r["loads"]))
        for idx, off, vaddr, filesz, memsz in r["loads"]:
            print("  PH %2d: offset %s --> vaddr %s  filesz %d B  memsz %d B"
                  % (idx, hx(off, 6), hx(vaddr), filesz, memsz))
    print("=" * 68)
    return EXIT_WARN if r["bad_count"] else EXIT_OK


# ----------------------------------------------------------------
# diff
# ----------------------------------------------------------------
def diff_images(img_a, img_b):
    sa = img_a.segments
    sb = img_b.segments
    runs = []
    counts = {"Mismatch": 0, "Deletion": 0, "Insertion": 0}
    first_diff = None
    common = 0

    def add_run(kind, start, length):
        nonlocal first_diff
        if length <= 0:
            return
        counts[kind] += length
        if first_diff is None:
            first_diff = start
        if runs and runs[-1][0] == kind and runs[-1][1] + runs[-1][2] == start:
            runs[-1] = (kind, runs[-1][1], runs[-1][2] + length)
        else:
            runs.append((kind, start, length))

    i = j = 0
    ai = bj = 0
    while i < len(sa) or j < len(sb):
        if i >= len(sa):
            s, d = sb[j]
            add_run("Insertion", s + bj, len(d) - bj)
            break
        if j >= len(sb):
            s, d = sa[i]
            add_run("Deletion", s + ai, len(d) - ai)
            break
        a0, ad = sa[i]
        b0, bd = sb[j]
        a1 = a0 + len(ad)
        b1 = b0 + len(bd)
        ca = a0 + ai
        cb = b0 + bj
        if a1 <= cb:
            add_run("Deletion", ca, a1 - ca)
            i += 1
            ai = 0
            continue
        if b1 <= ca:
            add_run("Insertion", cb, b1 - cb)
            j += 1
            bj = 0
            continue
        lo = max(ca, cb)
        hi = min(a1, b1)
        if ca < lo:
            add_run("Deletion", ca, lo - ca)
            ai += lo - ca
        if cb < lo:
            add_run("Insertion", cb, lo - cb)
            bj += lo - cb
        n = hi - lo
        xa = ad[lo - a0:hi - a0]
        xb = bd[lo - b0:hi - b0]
        common += n
        pos = 0
        while pos < n:
            step = min(DIFF_BLK, n - pos)
            if xa[pos:pos + step] == xb[pos:pos + step]:
                pos += step
                continue
            end = pos + step
            while pos < end:
                if xa[pos] != xb[pos]:
                    st = pos
                    while pos < end and xa[pos] != xb[pos]:
                        pos += 1
                    add_run("Mismatch", lo + st, pos - st)
                else:
                    pos += 1
        ai += n
        bj += n
    return runs, counts, first_diff, common


def cmd_diff(args):
    ra = load_any(args.file_a, getattr(args, "format", "auto"), None,
                  getattr(args, "strict", False))
    rb = load_any(args.file_b, getattr(args, "format", "auto"), None,
                  getattr(args, "strict", False))
    ia = ra["image"]
    ib = rb["image"]
    runs, counts, first_diff, common = diff_images(ia, ib)
    print("=" * 68)
    print("IceHex diff (地址空间逐字节语义)")
    print("A: %s" % args.file_a)
    print("   数据 %d B (%d 段), %s-%s"
          % (ia.data_bytes, len(ia.segments), hx(ia.min_addr), hx(ia.max_addr)))
    print("B: %s" % args.file_b)
    print("   数据 %d B (%d 段), %s-%s"
          % (ib.data_bytes, len(ib.segments), hx(ib.min_addr), hx(ib.max_addr)))
    print("-" * 68)
    print("公共地址区字节: %d B" % common)
    print("Mismatch (双侧不等): %d B" % counts["Mismatch"])
    print("Deletion  (仅 A 有): %d B" % counts["Deletion"])
    print("Insertion (仅 B 有): %d B" % counts["Insertion"])
    if common == 0:
        print("[警告] 无公共地址区, 全部内容单侧存在, 不构成相同判定")
    elif first_diff is None:
        print("[完成] 两镜像公共区数据完全一致 (0 差异)")
    else:
        print("首差异地址: %s" % hx(first_diff))
    if runs:
        shown = runs[:args.max_runs]
        print("差异区间 (%d 个, 显示 %d 个):" % (len(runs), len(shown)))
        print("  序   类型       起址       长度     A 侧首 8 字节          B 侧首 8 字节")
        for k, (kind, s, n) in enumerate(shown):
            print("  %3d  %-9s %s  %6d B  %-23s %s"
                  % (k + 1, kind, hx(s), n,
                     side_bytes(ia, s, min(n, 8)),
                     side_bytes(ib, s, min(n, 8))))
        if len(runs) > len(shown):
            print("  ... 其余 %d 个区间未显示, 汇总计数完整" % (len(runs) - len(shown)))
    print("=" * 68)
    return EXIT_OK


# ----------------------------------------------------------------
# to-bin / to-hex
# ----------------------------------------------------------------
def cmd_to_bin(args):
    fill = args.fill
    if not (0 <= fill <= 255):
        raise Fatal("--fill 取值须在 0-255: %s" % args.fill)
    r = load_any(args.file, getattr(args, "format", "auto"),
                 getattr(args, "b", None), getattr(args, "strict", False))
    img = r["image"]
    base = args.b if args.b is not None else img.min_addr
    if base > img.min_addr:
        raise Fatal("基址 %s 高于镜像最低地址 %s, 会静默丢弃数据; "
                    "如需局部导出请改用 dump --mode bin --start/--end"
                    % (hx(base), hx(img.min_addr)))
    size = img.max_addr - base + 1
    buf = bytearray([fill]) * size
    for s, d in img.segments:
        buf[s - base:s - base + len(d)] = d
    if not args.o:
        raise Fatal("to-bin 需 -o 显式指定输出文件")
    backup_if_exists(args.o)
    with open(args.o, "wb") as f:
        f.write(bytes(buf))
    print("=" * 68)
    print("IceHex to-bin")
    print("输入: %s (%s)" % (args.file, FORMAT_NAMES.get(r["fmt"], r["fmt"])))
    print("输出: %s (%d B, 区间 %s-%s, 基址 %s, 填充 0x%02X)"
          % (args.o, size, hx(base), hx(img.max_addr), hx(base), fill))
    print("分段: %d 段落位, gap/前导区按 0x%02X 填充" % (len(img.segments), fill))
    print("输出首 8 字节: %s" % " ".join("%02X" % b for b in bytes(buf[:8])))
    print("[完成] 写出 %d B" % size)
    print("=" * 68)
    return EXIT_WARN if r["bad_count"] else EXIT_OK


def make_record(addr_low, rtype, payload=b""):
    body = bytes([len(payload), (addr_low >> 8) & 0xFF, addr_low & 0xFF,
                  rtype]) + payload
    return ":%02X%04X%02X%s%02X" % (
        len(payload), addr_low, rtype, payload.hex().upper(),
        (-sum(body)) & 0xFF)


def build_ihex_text(img):
    """按地址段生成 Intel HEX 文本, ELA 扩展大写, 数据记录不跨 64KiB 边界"""
    lines = []
    cur_upper = None
    nrec = 0
    for s, d in img.segments:
        pos = 0
        n = len(d)
        while pos < n:
            addr = s + pos
            upper = (addr >> 16) & 0xFFFF
            if upper != cur_upper:
                lines.append(make_record(upper, 0x04,
                                         bytes([upper >> 8, upper & 0xFF])))
                cur_upper = upper
                nrec += 1
            # 数据记录不跨 64KiB 边界
            step = min(16, 0x10000 - (addr & 0xFFFF), n - pos)
            lines.append(make_record(addr & 0xFFFF, 0x00, d[pos:pos + step]))
            nrec += 1
            pos += step
    lines.append(":00000001FF")
    return "\n".join(lines) + "\n", nrec


def cmd_to_hex(args):
    r = load_any(args.file, getattr(args, "format", "auto"),
                 getattr(args, "b", None), getattr(args, "strict", False))
    img = r["image"]
    if not args.o:
        raise Fatal("to-hex 需 -o 显式指定输出文件")
    text, nrec = build_ihex_text(img)
    write_text_crlf(args.o, text)
    print("=" * 68)
    print("IceHex to-hex")
    print("输入: %s (%s, 数据 %d B, %d 段)"
          % (args.file, FORMAT_NAMES.get(r["fmt"], r["fmt"]),
             img.data_bytes, len(img.segments)))
    print("输出: %s (%d 行记录 + 1 EOF, 段间 gap 保留)" % (args.o, nrec))
    print("[完成] Intel HEX 写出 (ELA 扩展, 大写, CRLF)")
    print("=" * 68)
    return EXIT_WARN if r["bad_count"] else EXIT_OK


# ----------------------------------------------------------------
# merge
# ----------------------------------------------------------------
def seg_overlap(img_a, img_b):
    """返回首个实际数据重叠区间 (起, 止), 无重叠返回 None"""
    for sa, da in img_a.segments:
        a1 = sa + len(da)
        for sb, db in img_b.segments:
            b1 = sb + len(db)
            lo = max(sa, sb)
            hi = min(a1, b1)
            if lo < hi:
                return lo, hi - 1
    return None


def cmd_merge(args):
    files = args.files
    if len(files) < 2:
        raise Fatal("merge 至少需要 2 个输入文件")
    strict = getattr(args, "strict", False)
    fmt_opt = getattr(args, "format", "auto")
    loaded = []
    for idx, p in enumerate(files):
        r = load_any(p, fmt_opt, None, strict)
        if r["fmt"] == "bin":
            raise Fatal("输入[%d] %s 为裸 bin, 无内含地址; 请先 to-hex -b <基址> "
                        "转为 Intel HEX 后再 merge" % (idx + 1, os.path.basename(p)))
        loaded.append((p, r))
    # 两两实际数据重叠校验, 拒绝静默覆盖
    n = len(loaded)
    for i in range(n):
        for j in range(i + 1, n):
            ov = seg_overlap(loaded[i][1]["image"], loaded[j][1]["image"])
            if ov is not None:
                raise Fatal("输入[%d] %s 与输入[%d] %s 数据重叠 @ %s-%s, "
                            "拒绝合并; 请检查是否重复指定或分区配置错误"
                            % (i + 1, os.path.basename(loaded[i][0]),
                               j + 1, os.path.basename(loaded[j][0]),
                               hx(ov[0]), hx(ov[1])))
    merged = Image()
    for _p, r in loaded:
        for s, d in r["image"].segments:
            merged.add(s, d)
    merged.finalize()
    out = args.o
    if not out:
        out = os.path.splitext(files[0])[0] + "_merged.hex"
    print("=" * 68)
    print("IceHex merge (地址段级合并, 输出恒为 Intel HEX)")
    for idx, (p, r) in enumerate(loaded):
        img = r["image"]
        print("  输入[%d] %-28s %-9s %s-%s  %6d B / %d 段"
              % (idx + 1, os.path.basename(p),
                 FORMAT_NAMES.get(r["fmt"], r["fmt"]),
                 hx(img.min_addr), hx(img.max_addr),
                 img.data_bytes, len(img.segments)))
    print("-" * 68)
    text, nrec = build_ihex_text(merged)
    # 原子落盘: 先写临时文件, 重解析校验通过后替换目标
    tmp = out + ".merged.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(text)
    check = parse_ihex(tmp, strict=True)
    check["image"].finalize()
    runs, counts, _first, _common = diff_images(merged, check["image"])
    exp_min = min(r["image"].min_addr for _p, r in loaded)
    exp_max = max(r["image"].max_addr for _p, r in loaded)
    if runs or check["image"].min_addr != exp_min \
            or check["image"].max_addr != exp_max:
        os.remove(tmp)
        diff_b = counts["Mismatch"] + counts["Deletion"] + counts["Insertion"]
        raise Fatal("合并后重解析校验失败 (差异 %d B, 范围 %s-%s, 期望 %s-%s), "
                    "已删除临时文件, 终止"
                    % (diff_b, hx(check["image"].min_addr),
                       hx(check["image"].max_addr), hx(exp_min), hx(exp_max)))
    backup_if_exists(out)
    os.replace(tmp, out)
    print("合并: %s-%s (%d 段, %d B 数据, bbox 跨度 %d B)"
          % (hx(merged.min_addr), hx(merged.max_addr), len(merged.segments),
             merged.data_bytes, merged.bbox_span))
    print("校验: 段数据零差异, bbox == 各源并集: 通过")
    print("输出: %s (%d 行记录 + 1 EOF, CRLF)" % (out, nrec))
    print("[完成] 合并写出")
    print("=" * 68)
    warn = any(r["bad_count"] for _p, r in loaded)
    return EXIT_WARN if warn else EXIT_OK


# ----------------------------------------------------------------
# dump
# ----------------------------------------------------------------
def hexdump_lines(img, start, end):
    out = []
    out.append("地址        00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII")
    segs = img.segments
    starts = [s for s, _ in segs]
    cur = start
    while cur <= end:
        seg = None
        for s, d in segs:
            if s <= cur < s + len(d):
                seg = (s, d)
                break
        if seg is None:
            nxt_candidates = [x for x in starts if x > cur]
            nxt = min(nxt_candidates) if nxt_candidates else end + 1
            ge = min(nxt - 1, end)
            out.append("-- GAP %s-%s (%d B) --" % (hx(cur), hx(ge), ge - cur + 1))
            cur = ge + 1
            continue
        s, d = seg
        stop = min(s + len(d) - 1, end)
        while cur <= stop:
            row = d[cur - s:cur - s + 16]
            b0 = " ".join("%02X" % b for b in row[:8])
            b1 = " ".join("%02X" % b for b in row[8:])
            b0 += " " * (23 - len(b0))
            b1 += " " * (23 - len(b1))
            asc = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in row)
            out.append("%s  %s  %s  %s" % (hx(cur), b0, b1, asc))
            cur += 16
    return out


def find_on_path(name):
    for p in os.environ.get("PATH", "").split(os.pathsep):
        cand = os.path.join(p, name)
        if os.path.isfile(cand):
            return cand
        if os.path.isfile(cand + ".exe"):
            return cand + ".exe"
    return None


def find_rv_objdump():
    if os.path.isfile(RISCV_OBJDUMP):
        return RISCV_OBJDUMP
    return find_on_path(RISCV_OBJDUMP_NAME)


def find_arm_fromelf():
    for cand in ARM_FROMELF_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    return find_on_path("fromelf.exe")


def run_tool(cmd):
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    except OSError as e:
        raise Fatal("反汇编工具启动失败: %s (%s)" % (cmd[0], e))
    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        raise Fatal("反汇编工具退出码 %d: %s\n%s"
                    % (proc.returncode, cmd, err[:2000]))
    return out


def cmd_dump(args):
    r = load_any(args.file, getattr(args, "format", "auto"),
                 getattr(args, "b", None), getattr(args, "strict", False))
    img = r["image"]
    fmt = r["fmt"]
    start = args.start if args.start is not None else img.min_addr
    end = args.end if args.end is not None else img.max_addr
    if args.start is not None or args.end is not None:
        start = max(start, img.min_addr)
        end = min(end, img.max_addr)
    if start > end:
        raise Fatal("--start 不得大于 --end")

    if args.mode == "hex":
        lines = hexdump_lines(img, start, end)
        text = "\n".join(lines) + "\n"
        if args.o:
            write_text_crlf(args.o, text)
            print("[完成] hex 转储 %d 行 --> %s (区间 %s-%s)"
                  % (len(lines), args.o, hx(start), hx(end)))
        else:
            print("IceHex dump hex (%s-%s):" % (hx(start), hx(end)))
            sys.stdout.write(text)
        return EXIT_WARN if r["bad_count"] else EXIT_OK

    if args.mode == "bin":
        if not args.o:
            raise Fatal("dump --mode bin 需 -o 显式指定输出文件")
        fill = args.fill
        if not (0 <= fill <= 255):
            raise Fatal("--fill 取值须在 0-255: %s" % args.fill)
        size = end - start + 1
        buf = bytearray([fill]) * size
        for s, d in img.segments:
            lo = max(s, start)
            hi = min(s + len(d) - 1, end)
            if hi >= lo:
                buf[lo - start:hi - start + 1] = d[lo - s:hi - s + 1]
        backup_if_exists(args.o)
        with open(args.o, "wb") as f:
            f.write(bytes(buf))
        print("[完成] bin 导出 %d B --> %s (区间 %s-%s, gap 填充 0x%02X)"
              % (size, args.o, hx(start), hx(end), fill))
        return EXIT_WARN if r["bad_count"] else EXIT_OK

    # disasm: 委托外部工具
    if fmt in ("ihex", "srec"):
        raise Fatal("disasm 不接受 %s 文本输入 (会反汇编文本本身), "
                    "请先 to-bin 再反汇编" % FORMAT_NAMES[fmt])
    if fmt == "elf":
        mach = r["e_machine"]
        if mach == 243:
            tool = find_rv_objdump()
            if not tool:
                raise Fatal("未找到 riscv-none-embed-objdump "
                            "(固定路径与 PATH 均未命中)")
            out = run_tool([tool, "-d", args.file])
        elif mach == 40:
            tool = find_arm_fromelf()
            if not tool:
                raise Fatal("未找到 fromelf (固定路径与 PATH 均未命中)")
            out = run_tool([tool, "--text", "-c", args.file])
        else:
            raise Fatal("ELF e_machine=%d (%s) 无自动反汇编工具; "
                        "raw 镜像请先 to-bin 后用 --arch rv|cm 指定"
                        % (mach, ELF_MACHINES.get(mach, "未知")))
    else:
        if args.arch is None:
            raise Fatal("raw 镜像反汇编需 --arch 指定架构, 可选: rv, cm")
        if args.arch == "rv":
            tool = find_rv_objdump()
            if not tool:
                raise Fatal("未找到 riscv-none-embed-objdump "
                            "(固定路径与 PATH 均未命中)")
            cmd = [tool, "-b", "binary", "-m", "riscv:rv32", "-D",
                   "--adjust-vma=%s" % hx(img.min_addr), args.file]
            out = run_tool(cmd)
        else:
            print("[警告] 本机无 ARM raw bin 反汇编能力 "
                  "(fromelf 仅接受 ELF/axf, 本机无 arm-none-eabi-objdump), "
                  "降级为 hex 转储")
            lines = hexdump_lines(img, start, end)
            out = "\n".join(lines) + "\n"
            if args.o:
                write_text_crlf(args.o, out)
                print("[完成] 降级 hex 转储 %d 行 --> %s" % (len(lines), args.o))
                return EXIT_WARN
            sys.stdout.write(out)
            return EXIT_WARN
    if args.o:
        write_text_crlf(args.o, out)
        print("[完成] 反汇编输出 --> %s (%d 行)" % (args.o, out.count("\n")))
    else:
        sys.stdout.write(out)
    return EXIT_OK


# ----------------------------------------------------------------
# vector
# ----------------------------------------------------------------
def cm_chain(img, table):
    checks = []
    w = img.read(table, 4)
    if w is None:
        checks.append(("SP 项读取失败 @ %s" % hx(table), False))
        return False, checks, None
    sp = int.from_bytes(w, "little")
    sp_ok = True
    for name, ok in (
        ("SP=%s 非 0" % hx(sp), sp != 0),
        ("SP 8 字节对齐", (sp & 7) == 0),
        ("SP 不在镜像数据区内", not img.contains(sp)),
        ("SP < 0x80000000", sp < 0x80000000),
    ):
        checks.append((name, ok))
        sp_ok = sp_ok and ok
    # 项 1-15 入口链逐项推进, 零项 (保留) 跳过, 首个不过项即链断点,
    # 断点之后内容不属表项 (短表/后随代码), 不参与判定
    n_pass = 0
    n_zero = 0
    reset_ok = False
    break_at = None
    for idx in range(1, 16):
        name = CM_SYSTEM_NAMES[idx]
        w = img.read(table + idx * 4, 4)
        if w is None:
            if idx == 1:
                checks.append(("入口 1 (Reset) 数据不可读", False))
            break_at = (idx, name, None, "数据不可读")
            break
        v = int.from_bytes(w, "little")
        if v == 0 and idx != 1:
            n_zero += 1
            continue
        h = v & ~1
        ok = (v & 1) == 1 and img.contains(h)
        checks.append(("入口 %d (%s)=%s bit0==1 且掩码 %s 落镜像数据区内"
                       % (idx, name, hx(v), hx(h)), ok))
        if idx == 1:
            reset_ok = ok
        if ok:
            n_pass += 1
            continue
        why = "bit0=0" if (v & 1) == 0 else "掩码落镜像数据区外"
        break_at = (idx, name, v, why)
        break
    verdict = sp_ok and reset_ok and break_at is None
    info = {"break_at": break_at, "n_pass": n_pass, "n_zero": n_zero}
    return verdict, checks, info


def print_chain(title, checks):
    print("%s:" % title)
    for name, ok in checks:
        print("  [%s] %s" % ("通过" if ok else "不过", name))


def print_chain_summary(info):
    if info is None:
        return
    if info["break_at"] is not None:
        idx, name, v, why = info["break_at"]
        detail = hx(v) if v is not None else "-"
        print("  [失败依据] 入口链在项 %d (%s)=%s 处断裂 (%s), 其后内容不属表项, 不参与判定"
              % (idx, name, detail, why))
    else:
        print("  入口链: 项 1-15 非零 %d 项全部通过 (零项 %d 个跳过)"
              % (info["n_pass"], info["n_zero"]))


def vector_cm(img, table, count):
    ok, checks, info = cm_chain(img, table)
    print_chain("CM 判定链 (表基址 %s)" % hx(table), checks)
    print_chain_summary(info)
    if not ok:
        print("判定: 未通过 --> 非 Cortex-M 向量表 (依据见上), 不输出表项")
        return False
    print("判定: 通过 --> Cortex-M 向量表")
    print("表项 (%d 项):" % count)
    print("  idx  名称         原始值      掩码地址    状态")
    sp_val = None
    for idx in range(count):
        a = table + idx * 4
        name = CM_SYSTEM_NAMES[idx] if idx < 16 else "IRQ%d" % (idx - 16)
        w = img.read(a, 4)
        if w is None:
            print("  %3d  %-10s   数据缺失 (超出镜像数据区)" % (idx, name))
            continue
        v = int.from_bytes(w, "little")
        if idx == 0:
            sp_ok = (v != 0) and ((v & 7) == 0) and \
                (not img.contains(v)) and (v < 0x80000000)
            print("  %3d  %-10s %s  -          %s"
                  % (idx, name, hx(v), "有效" if sp_ok else "可疑(SP 检查未全过)"))
            sp_val = v
            continue
        if v == 0:
            print("  %3d  %-10s %s  -          保留 0" % (idx, name, hx(v)))
            continue
        h = v & ~1
        if (v & 1) == 1 and img.contains(h):
            print("  %3d  %-10s %s  %s  有效" % (idx, name, hx(v), hx(h)))
        else:
            why = "bit0=0" if (v & 1) == 0 else "落镜像数据区外"
            print("  %3d  %-10s %s  %s  可疑(%s)"
                  % (idx, name, hx(v), hx(h), why))
    print("[完成] Cortex-M 向量表解析: %d 项, SP=%s"
          % (count, hx(sp_val) if sp_val is not None else "-"))
    return True


def jal_target(pc, ins):
    imm = (((ins >> 31) & 1) << 20) | (((ins >> 12) & 0xFF) << 12) \
        | (((ins >> 20) & 1) << 11) | (((ins >> 21) & 0x3FF) << 1)
    if imm & (1 << 20):
        imm -= 1 << 21
    return pc + imm


def vector_rv(img, table, count, explicit):
    reasons = []
    table_base = None
    w0raw = img.read(table, 4)
    if w0raw is None:
        reasons.append("表地址首字不可读 @ %s" % hx(table))
    else:
        w0 = int.from_bytes(w0raw, "little")
        if (w0 & 0x7F) == RV_INSN_JAL and ((w0 >> 7) & 0x1F) == 0:
            off = 4
            nops = 0
            while True:
                wn = img.read(table + off, 4)
                if wn is None or int.from_bytes(wn, "little") != RV_INSN_NOP:
                    break
                off += 4
                nops += 1
            web = img.read(table + off, 4)
            if web is not None and \
                    int.from_bytes(web, "little") == RV_INSN_EBREAK:
                table_base = table + off + 4
                jt = jal_target(table, w0)
                print(".init 前导定位: JAL x0 @ %s, nop x %d%s, ebreak @ %s"
                      % (hx(table), nops,
                         " (>=12 佐证)" if nops >= 12 else " (不足 12, 仅提示)",
                         hx(table + off)))
                print("J 目标佐证: %s (%s)"
                      % (hx(jt), "落镜像内" if img.contains(jt) else "落镜像外"))
            else:
                reasons.append("JAL x0 后未检出 ebreak 收尾 (0x00100073)")
        else:
            reasons.append("表地址首字非 JAL x0 (j) 指令 (实际 %s)" % hx(w0))
    if table_base is None:
        if explicit:
            table_base = table
            print("未检出 .init 前导特征 (%s), 按表项 0 地址直接读表" % reasons[0])
        else:
            print("RV 定位失败:")
            for x in reasons:
                print("  - %s" % x)
            return False
    print("表基址: %s" % hx(table_base))
    rows = []
    n_oob = 0
    entry0_in = False
    for idx in range(count):
        a = table_base + idx * 4
        name = RV_SYSTEM_NAMES[idx] if idx < 16 else "IRQ%d" % (idx - 16)
        w = img.read(a, 4)
        if w is None:
            rows.append((idx, name, None))
            continue
        v = int.from_bytes(w, "little")
        rows.append((idx, name, v))
        if idx == 0:
            # 项 0 (_start) 地址 0x0 亦属镜像内 (BL 镜像起点场景)
            entry0_in = img.contains(v)
        elif v != 0 and not img.contains(v):
            n_oob += 1
    print("表项 (%d 项):" % count)
    print("  idx  名称         原始值      状态")
    for idx, name, v in rows:
        if v is None:
            print("  %3d  %-10s   数据缺失" % (idx, name))
        elif idx == 0:
            if img.contains(v):
                print("  %3d  %-10s %s  有效 (落镜像)" % (idx, name, hx(v)))
            else:
                print("  %3d  %-10s %s  可疑 (越界)" % (idx, name, hx(v)))
        elif v == 0:
            print("  %3d  %-10s %s  保留 0" % (idx, name, hx(v)))
        elif img.contains(v):
            print("  %3d  %-10s %s  有效 (落镜像)" % (idx, name, hx(v)))
        else:
            print("  %3d  %-10s %s  可疑 (越界)" % (idx, name, hx(v)))
    ratio = n_oob / count if count else 1.0
    ok = entry0_in and ratio < 0.5
    print("汇总: 项 0 %s, 越界项 %d/%d (%.1f%%, 阈值 <50%%) --> %s"
          % ("落镜像" if entry0_in else "未落镜像",
             n_oob, count, ratio * 100, "识别成功" if ok else "识别失败"))
    if not ok:
        if not entry0_in:
            print("失败依据: 项 0 未落在镜像数据区内")
        if ratio >= 0.5:
            print("失败依据: 表项值大量越界 (占比 >= 50%)")
    return ok


def cmd_vector(args):
    r = load_any(args.file, getattr(args, "format", "auto"),
                 getattr(args, "b", None), getattr(args, "strict", False))
    img = r["image"]
    arch = args.arch
    table = args.table if args.table is not None else img.min_addr
    print("=" * 68)
    print("IceHex vector")
    print("文件: %s (%s)" % (args.file, FORMAT_NAMES.get(r["fmt"], r["fmt"])))
    print("镜像: %s-%s (%d 段), 表参数: %s, 架构: %s"
          % (hx(img.min_addr), hx(img.max_addr), len(img.segments),
             hx(table), arch))
    print("-" * 68)
    if arch in ("cm", "auto"):
        ok_cm, checks, _info = cm_chain(img, table)
        if ok_cm:
            return EXIT_OK if vector_cm(img, table, args.count or 128) \
                else EXIT_WARN
        if arch == "cm":
            print_chain("CM 判定链 (表基址 %s)" % hx(table), checks)
            print_chain_summary(_info)
            print("判定: 未通过 --> 非 Cortex-M 向量表 (依据见上)")
            return EXIT_WARN
        failed = [n for n, p in checks if not p]
        shown = failed[:4]
        tail = (" 等 %d 项不过" % len(failed)) if len(failed) > len(shown) else ""
        print("auto: CM 判定链未通过 (%s%s), 转 RV 路径"
              % ("; ".join(shown), tail))
        print("-" * 68)
    ok_rv = vector_rv(img, table, args.count or 70, args.table is not None)
    if not ok_rv and arch == "auto":
        print("auto 结论: CM 与 RV 两路径均未识别为向量表 (失败依据见上)")
    return EXIT_OK if ok_rv else EXIT_WARN


# ----------------------------------------------------------------
# strings
# ----------------------------------------------------------------
def scan_ascii(data, base, min_len):
    out = []
    n = len(data)
    i = 0
    while i < n:
        j = i
        while j < n and 0x20 <= data[j] <= 0x7E:
            j += 1
        if j - i >= min_len:
            out.append((base + i, "ascii", j - i, data[i:j].decode("ascii")))
        i = j + 1
    return out


def scan_utf16(data, base, min_len, big):
    out = []
    n = len(data)
    i = 0
    while i + 1 < n:
        j = i
        chars = []
        while j + 1 < n:
            lo, hi = (data[j + 1], data[j]) if big else (data[j], data[j + 1])
            if hi == 0 and 0x20 <= lo <= 0x7E:
                chars.append(lo)
                j += 2
            else:
                break
        if len(chars) >= min_len:
            enc = "utf16be" if big else "utf16le"
            out.append((base + i, enc, len(chars) * 2,
                        "".join(chr(c) for c in chars)))
        i = j + 1
    return out


def scan_utf8(data, base, min_len):
    out = []
    n = len(data)
    i = 0
    while i < n:
        j = i
        chars = 0
        while j < n:
            b = data[j]
            if b < 0x80:
                j += 1
                chars += 1
                continue
            if 0xC2 <= b <= 0xDF:
                ln = 2
            elif 0xE0 <= b <= 0xEF:
                ln = 3
            elif 0xF0 <= b <= 0xF4:
                ln = 4
            else:
                break
            if j + ln > n:
                break
            cont = data[j + 1:j + ln]
            if any(not (0x80 <= c <= 0xBF) for c in cont):
                break
            if b == 0xE0 and cont[0] < 0xA0:
                break
            if b == 0xED and cont[0] > 0x9F:
                break
            j += ln
            chars += 1
        if chars >= min_len:
            out.append((base + i, "utf8", j - i,
                        data[i:j].decode("utf-8", errors="replace")))
        i = j + 1
    return out


def cmd_strings(args):
    r = load_any(args.file, getattr(args, "format", "auto"),
                 getattr(args, "b", None), getattr(args, "strict", False))
    img = r["image"]
    results = []
    for s, d in img.segments:
        if args.enc in ("ascii", "all"):
            results.extend(scan_ascii(d, s, args.n))
        if args.enc in ("utf16le", "all"):
            results.extend(scan_utf16(d, s, args.n, big=False))
        if args.enc in ("utf16be", "all"):
            results.extend(scan_utf16(d, s, args.n, big=True))
        if args.enc == "utf8":
            results.extend(scan_utf8(d, s, args.n))
    results.sort(key=lambda x: x[0])
    print("=" * 68)
    print("IceHex strings")
    print("文件: %s, 编码: %s, 最小长度: %d, 数据: %d B"
          % (args.file, args.enc, args.n, img.data_bytes))
    print("-" * 68)
    shown = results[:args.max]
    for addr, enc, blen, text in shown:
        print("%s  %-7s %4d  \"%s\"" % (hx(addr), enc, blen, text))
    if len(results) > len(shown):
        print("  ... 其余 %d 条未显示 (计数完整)" % (len(results) - len(shown)))
    print("[完成] 共 %d 条 (长度按字节计, gap 区不扫描)" % len(results))
    print("=" * 68)
    return EXIT_WARN if r["bad_count"] else EXIT_OK


# ----------------------------------------------------------------
# entropy
# ----------------------------------------------------------------
def shannon(block, total):
    counts = collections.Counter(block)
    if len(counts) <= 1:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def cmd_entropy(args):
    if args.block <= 0:
        raise Fatal("--block 须为正整数")
    r = load_any(args.file, getattr(args, "format", "auto"),
                 getattr(args, "b", None), getattr(args, "strict", False))
    img = r["image"]
    data, marks = img.stream()
    total = len(data)
    blk = args.block
    nfull = total // blk
    tail = total - nfull * blk
    counts = collections.Counter(data)
    h_all = shannon(data, total)
    print("=" * 68)
    print("IceHex entropy")
    print("文件: %s, 数据: %d B (%d 段拼接), 块: %d B (完整 %d 块, 尾部 %d B)"
          % (args.file, total, len(img.segments), blk, nfull, tail))
    print("-" * 68)
    print("整体熵: %.3f (原始 0-8) | %.3f (归一化 0-1)"
          % (h_all, min(1.0, h_all / 8.0)))
    best = (-1.0, None)
    worst = (9.0, None)
    space_sum = 0.0
    graph_sum = 0.0
    for bi in range(nfull):
        b0 = bi * blk
        block = data[b0:b0 + blk]
        h = shannon(block, blk)
        addr = img.offset_addr(marks, b0)
        if h > best[0]:
            best = (h, addr)
        if h < worst[0]:
            worst = (h, addr)
        space_sum += sum(1 for x in block if x in ISSPACE) / blk
        graph_sum += sum(1 for x in block if x in ISGRAPH) / blk
        if args.curve:
            print("  块 %5d  %s  %.3f  %.3f" % (bi, hx(addr), h, min(1.0, h / 8.0)))
    if tail:
        tb = data[nfull * blk:]
        h_tail = shannon(tb, len(tb))
        addr = img.offset_addr(marks, nfull * blk)
        print("  尾部不完整块: %s %d B, 熵 %.3f (不计入最低块)"
              % (hx(addr), len(tb), h_tail))
    if nfull:
        print("最高熵块: %s  熵 %.3f (原始)" % (hx(best[1]), best[0]))
        print("最低熵块: %s  熵 %.3f (原始, 已排除尾部不完整块)"
              % (hx(worst[1]), worst[0]))
        h_norm = min(1.0, h_all / 8.0)
        b_norm = min(1.0, best[0] / 8.0)
        if h_norm > HEUR_ENC_AVG and b_norm > HEUR_ENC_MAX:
            print("启发式: 整体归一 %.3f > %.2f 且最高块归一 %.3f > %.2f "
                  "--> 数据可能被加密或压缩"
                  % (h_norm, HEUR_ENC_AVG, b_norm, HEUR_ENC_MAX))
        else:
            print("启发式: 加密/压缩条件未满足 (整体归一 %.3f, 最高块归一 %.3f)"
                  % (h_norm, b_norm))
        text_rate = (space_sum + graph_sum) / nfull
        if text_rate > HEUR_TEXT_RATE:
            print("启发式: 纯文本率 %.3f > %.2f --> 数据大部分是纯文本"
                  % (text_rate, HEUR_TEXT_RATE))
        else:
            print("启发式: 纯文本率 %.3f <= %.2f" % (text_rate, HEUR_TEXT_RATE))
    top = counts.most_common(10)
    print("直方图 top-10 (值 计数 占比):")
    for v, c in top:
        print("  0x%02X  %10d  %5.2f%%" % (v, c, c * 100.0 / total))
    print("0x00 占比: %.2f%%  0xFF 占比: %.2f%%"
          % (counts.get(0, 0) * 100.0 / total,
             counts.get(0xFF, 0) * 100.0 / total))
    print("[完成] 熵分析结束")
    print("=" * 68)
    return EXIT_WARN if r["bad_count"] else EXIT_OK


# ----------------------------------------------------------------
# fill
# ----------------------------------------------------------------
def cmd_fill(args):
    if args.min_len <= 0:
        raise Fatal("--min-len 须为正整数")
    r = load_any(args.file, getattr(args, "format", "auto"),
                 getattr(args, "b", None), getattr(args, "strict", False))
    img = r["image"]
    runs = []
    for s, d in img.segments:
        n = len(d)
        i = 0
        while i < n:
            j = i + 1
            while j < n and d[j] == d[i]:
                j += 1
            if j - i >= args.min_len:
                runs.append((s + i, s + j - 1, d[i], j - i))
            i = j
    by_val = collections.Counter()
    cnt_val = collections.Counter()
    for _s, _e, v, n in runs:
        by_val[v] += n
        cnt_val[v] += 1
    total_fill = sum(by_val.values())
    data_total = img.data_bytes
    print("=" * 68)
    print("IceHex fill (字节精确连续同值 run, 最小长度 %d)" % args.min_len)
    print("文件: %s, 数据: %d B (%d 段)"
          % (args.file, data_total, len(img.segments)))
    print("-" * 68)
    print("填充区段 (%d 个, 地址序):" % len(runs))
    for s, e, v, n in runs:
        print("  %s-%s  %6d B  值 0x%02X" % (hx(s), hx(e), n, v))
    print("按值汇总:")
    for v in sorted(by_val, key=lambda x: -by_val[x]):
        tag = ""
        if v == 0xFF:
            tag = "  <-- 0xFF 填充"
        elif v == 0x00:
            tag = "  <-- 0x00 填充"
        print("  值 0x%02X: %d 段 / %d B (%.2f%%)%s"
              % (v, cnt_val[v], by_val[v], by_val[v] * 100.0 / data_total, tag))
    print("[完成] 总填充占比: %.2f%% (%d B / %d B 数据字节)"
          % (total_fill * 100.0 / data_total, total_fill, data_total))
    print("=" * 68)
    return EXIT_WARN if r["bad_count"] else EXIT_OK


# ----------------------------------------------------------------
# CLI 装配
# ----------------------------------------------------------------
def int_auto(s):
    try:
        return int(s, 0)
    except ValueError:
        raise argparse.ArgumentTypeError("非法整数: %s" % s)


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["auto", "ihex", "srec", "elf", "bin"],
                        default=argparse.SUPPRESS, help="输入格式 (默认 auto 嗅探)")
    common.add_argument("--strict", action="store_true",
                        default=argparse.SUPPRESS, help="任一坏行即致命错误")
    p = argparse.ArgumentParser(
        prog="icehex",
        description="IceHex 快速 hex 分析工具 "
                    "(info/diff/to-bin/to-hex/merge/dump/vector/strings/entropy/fill)",
        parents=[common])
    sub = p.add_subparsers(dest="cmd", metavar="子命令", required=True)

    sp = sub.add_parser("info", parents=[common], help="分段/gap/记录统计")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("diff", parents=[common], help="双镜像地址空间逐字节比对")
    sp.add_argument("file_a")
    sp.add_argument("file_b")
    sp.add_argument("--max-runs", type=int, default=50,
                    help="差异区间最大显示数 (汇总计数完整)")
    sp.set_defaults(func=cmd_diff)

    sp = sub.add_parser("to-bin", parents=[common], help="任意格式 --> 裸二进制")
    sp.add_argument("file")
    sp.add_argument("-o", required=True, help="输出文件")
    sp.add_argument("-b", type=int_auto, default=None,
                    help="镜像基址 (仅 bin 输入)")
    sp.add_argument("--fill", type=int_auto, default=0xFF, help="gap/前导填充值")
    sp.set_defaults(func=cmd_to_bin)

    sp = sub.add_parser("to-hex", parents=[common], help="任意格式 --> Intel HEX")
    sp.add_argument("file")
    sp.add_argument("-o", required=True, help="输出文件")
    sp.add_argument("-b", type=int_auto, default=None,
                    help="镜像基址 (仅 bin 输入)")
    sp.set_defaults(func=cmd_to_hex)

    sp = sub.add_parser("merge", parents=[common],
                        help="多镜像合并为单一 Intel HEX (段级重叠校验)")
    sp.add_argument("files", nargs="+", metavar="file")
    sp.add_argument("-o", default=None, help="输出 hex (默认 <首输入>_merged.hex)")
    sp.set_defaults(func=cmd_merge)

    sp = sub.add_parser("dump", parents=[common], help="hex 转储/bin 导出/反汇编")
    sp.add_argument("file")
    sp.add_argument("--mode", choices=["hex", "bin", "disasm"], default="hex")
    sp.add_argument("--start", type=int_auto, default=None, help="起始地址")
    sp.add_argument("--end", type=int_auto, default=None, help="结束地址")
    sp.add_argument("-o", default=None, help="输出文件")
    sp.add_argument("-b", type=int_auto, default=None,
                    help="镜像基址 (仅 bin 输入)")
    sp.add_argument("--fill", type=int_auto, default=0xFF,
                    help="bin 模式 gap 填充值")
    sp.add_argument("--arch", choices=["rv", "cm"], default=None,
                    help="raw 镜像反汇编架构")
    sp.set_defaults(func=cmd_dump)

    sp = sub.add_parser("vector", parents=[common], help="向量表解析 (CM/RV)")
    sp.add_argument("file")
    sp.add_argument("-b", type=int_auto, default=None,
                    help="镜像基址 (仅 bin 输入)")
    sp.add_argument("--table", type=int_auto, default=None,
                    help="表地址 (CM=表项 0/SP 地址; RV=.init 起点或表项 0 地址)")
    sp.add_argument("--arch", choices=["auto", "cm", "rv"], default="auto")
    sp.add_argument("--count", type=int, default=None,
                    help="表项数 (cm 默认 128, rv 默认 70)")
    sp.set_defaults(func=cmd_vector)

    sp = sub.add_parser("strings", parents=[common], help="可打印字符串提取")
    sp.add_argument("file")
    sp.add_argument("-n", type=int, default=5, help="最小长度")
    sp.add_argument("--enc", choices=["ascii", "utf16le", "utf16be", "utf8", "all"],
                    default="ascii")
    sp.add_argument("--max", type=int, default=500, help="最大显示条数")
    sp.set_defaults(func=cmd_strings)

    sp = sub.add_parser("entropy", parents=[common], help="熵/直方图分析")
    sp.add_argument("file")
    sp.add_argument("--block", type=int, default=256, help="分块大小")
    sp.add_argument("--curve", action="store_true", help="输出逐块熵行")
    sp.set_defaults(func=cmd_entropy)

    sp = sub.add_parser("fill", parents=[common], help="填充区 (连续同值 run) 分析")
    sp.add_argument("file")
    sp.add_argument("--min-len", type=int, default=16, help="run 最小长度")
    sp.set_defaults(func=cmd_fill)

    return p


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except Fatal as e:
        print("[错误] %s" % e, file=sys.stderr)
        return EXIT_FATAL


if __name__ == "__main__":
    sys.exit(main())
