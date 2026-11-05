# IceHex

固件镜像快速 hex 分析与合并工具。单文件纯标准库 Python CLI，10 个子命令覆盖分析与合并全流程。

- 输入格式：Intel HEX / Motorola SREC / ELF32 / 裸 bin（自动嗅探或显式指定）
- 零第三方依赖：仅 Python 标准库
- 只读输入：不修改任何输入文件；输出显式指定，覆盖既有输出自动备份为 *.bak
- 文本输出统一 CRLF 行尾

## 子命令

| 子命令 | 语法 | 说明 |
|--------|------|------|
| info | `info <file>` | 分段表/gap 表/记录统计/入口记录，elf 附 PT_LOAD 段表 |
| diff | `diff <file_a> <file_b>` | 双镜像地址空间逐字节比对，Mismatch/Deletion/Insertion 区间 |
| to-bin | `to-bin <file> -o <输出> [-b 基址] [--fill 0xFF]` | 任意格式转裸二进制，gap/前导区填充 |
| to-hex | `to-hex <file> -o <输出> [-b 基址]` | 任意格式转 Intel HEX，段间 gap 保留 |
| merge | `merge <file1> <file2> [...] [-o 输出]` | 多镜像段级重叠校验后合并为单一烧录 hex，复验零差异 |
| dump | `dump <file> [--mode hex\|bin\|disasm]` | 十六进制转储/裸字节导出/反汇编（委托 objdump/fromelf） |
| vector | `vector <file> [--arch auto\|cm\|rv]` | Cortex-M / RISC-V 向量表解析与判定链 |
| strings | `strings <file> [-n 5] [--enc ascii\|utf16\|utf8]` | 可打印字符串提取 |
| entropy | `entropy <file> [--block 256]` | 整体与分块熵、直方图、加密/纯文本启发式 |
| fill | `fill <file> [--min-len 16]` | 连续同值填充区段（如 0xFF）起止与占比 |

## 使用示例

```bash
# 固件体检：分段与 gap
python scripts/icehex.py info firmware.hex

# 双版本比对
python scripts/icehex.py diff v1.hex v2.hex

# IAP + APP + ROM 三段合并为单一烧录 hex
python scripts/icehex.py merge iap.hex app.hex rom.hex -o merged.hex

# RISC-V 向量表解析
python scripts/icehex.py vector app.elf --arch rv
```

## 退出码

- 0：成功
- 1：完成但有告警或阴性判定（坏行跳过、向量表判定失败等）
- 2：致命错误（文件不存在/无法解析/参数矛盾/合并数据重叠）

## 版本

v1.1.0

## 许可证

[MIT](LICENSE)
