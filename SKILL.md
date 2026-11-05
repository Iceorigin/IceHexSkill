---
name: IceHex
description: 快速 hex 分析与合并工具。当用户要求"hex 分析"、"分析固件"、"hex 信息"、"分段与 gap"、"固件对比 diff"、"hex 转 bin"、"bin 转 hex"、"十六进制转储"、"反汇编"、"向量表解析"、"Cortex-M"、"RISC-V"、"提取字符串"、"熵分析"、"直方图"、"填充区分析"、"0xFF 填充"、"合并hex"、"merge hex"、"多hex合并"、"固件合并"、"烧录文件合并"、"IAP+APP+ROM合并"、"hex拼接"时触发。支持 Intel HEX / Motorola SREC / ELF32 / 裸 bin 四种格式,提供 info 分段体检、diff 双固件逐字节比对、to-bin/to-hex 格式互转、merge 多镜像合并、dump 转储与反汇编、vector 向量表解析、strings 字符串提取、entropy 熵与直方图、fill 填充区分析共 10 个子命令。适用于嵌入式固件镜像的快速体检、比对、合并与甄别。
---

# Skill: IceHex

固件镜像快速 hex 分析与合并工具,单文件纯标准库 Python CLI,10 个子命令覆盖分析与合并全流程。

## 适用场景

- 固件镜像体检: info 输出分段表/gap 表/记录类型统计/入口地址记录
- 双版本固件比对: diff 按地址空间逐字节比对,输出差异区间列表
- 格式互转: to-bin (任意格式转裸二进制) / to-hex (任意格式转 Intel HEX)
- 多镜像合并: merge 将 bootloader/IAP + APP + BLE ROM 等不连续镜像合并为单一烧录 hex
- 十六进制转储与局部导出: dump hex (hexdump 文本) / dump bin (裸字节)
- 反汇编: 委托本机 objdump (RISC-V) / fromelf (ARM ELF/axf)
- 向量表核对: Cortex-M (SP/Thumb 判定链) 与 RISC-V (前导特征定位) 双架构
- 提取字符串: strings 支持 ASCII / UTF-16LE/BE / UTF-8
- 加密固件甄别: entropy 整体与分块熵、直方图、加密/纯文本启发式
- 填充区分析: fill 报告连续同值填充区段 (0xFF/0x00 等) 起止与占比

## 调用语法

```
python "<skill_dir>/scripts/icehex.py" <子命令> [参数] [--format auto|ihex|srec|elf|bin] [--strict]
```

**子命令参数表**:

| 子命令 | 语法 | 说明 |
|--------|------|------|
| info | `info <file>` | 分段/gap/记录统计/入口记录,elf 附 PT_LOAD 段表与 e_machine |
| diff | `diff <file_a> <file_b> [--max-runs 50]` | Mismatch(双侧不等)/Deletion(仅A)/Insertion(仅B) 区间列表 |
| to-bin | `to-bin <file> -o <输出> [-b 基址] [--fill 0xFF]` | 输出区间 [基址, 最高地址],gap/前导区填 --fill 值 |
| to-hex | `to-hex <file> -o <输出> [-b 基址]` | 按 segments 写 Intel HEX,段间 gap 保留,ELA 扩展,CRLF |
| merge | `merge <file1> <file2> [...] [-o 输出]` | >=2 个镜像段级重叠校验后合并,重编码写 Intel HEX,复验零差异 |
| dump | `dump <file> [--mode hex\|bin\|disasm] [--start 地址] [--end 地址] [-o 输出] [-b 基址] [--fill 0xFF] [--arch rv\|cm]` | hex=hexdump 文本,bin=裸字节导出,disasm=委托外部工具 |
| vector | `vector <file> [-b 基址] [--table 表地址] [--arch auto\|cm\|rv] [--count 项数]` | CM 默认 128 项,RV 默认 70 项,--table 缺省取镜像起始 |
| strings | `strings <file> [-n 5] [--enc ascii\|utf16le\|utf16be\|utf8\|all] [--max 500]` | 只扫真实数据段,长度按字节计 |
| entropy | `entropy <file> [--block 256] [--curve]` | 整体+分块熵双口径,直方图 top-10,加密/纯文本启发式 |
| fill | `fill <file> [--min-len 16]` | 字节精确连续同值 run 区段表+按值汇总+总占比 |

**调用示例** (均为实测):

```
python "<skill_dir>/scripts/icehex.py" info "E:\...\OUT\REL\V3BELBL_MBR_s132_APP_R1_00.hex"
```
(多段镜像分段表 + gap 表 + UICR 高位段,bbox 跨度与数据量分列)

```
python "<skill_dir>/scripts/icehex.py" diff "E:\...\[2026-10-26-005]EELAPP.hex" "E:\...\[2026-10-28-006]EELAPP.hex"
```
(双版本差异区间列表 + 首差异地址 + 差异字节数)

```
python "<skill_dir>/scripts/icehex.py" to-bin "E:\...\V3BELAPP_app.hex" -b 0x40000 -o "E:\temp\app.bin"
```
(hex 转裸 bin,地址内含时 -b 仅作基址确认)

```
python "<skill_dir>/scripts/icehex.py" vector "E:\...\EELAPP_REL_V2.elf" --arch rv
```
(RISC-V 向量表前导定位,报表基址与全部表项)

```
python "<skill_dir>/scripts/icehex.py" merge "E:\...\OnlyUpdateApp_IAP.hex" "E:\...\OnlyUpdateApp_Peripheral.hex" "E:\...\wchble_rom.hex" -o merged.hex
```
(IAP + APP + ROM 三段合并,段级重叠校验,写出后重解析零差异复验)

## 执行流程 (AI 必须按此顺序)

### 第 1 步: 收集输入

- 确认子命令与目标文件;bin 输入必须确认镜像基址 (-b,默认 0)
- hex/srec/elf 输入地址已内含,-b 仅作基址确认 (矛盾即报错)
- 格式嗅探异常时用 --format 显式指定 (auto|ihex|srec|elf|bin)

### 第 2 步: 调用脚本

```bash
python "<skill_dir>/scripts/icehex.py" <子命令> ...
```

其中 `<skill_dir>` 为本 skill 目录 (SKILL.md 所在目录)。

### 第 3 步: 解读报告

- 报告走 stdout,段落前缀: `[完成]` 成功 / `[警告]` 告警 / `[错误]` 失败;致命错误信息走 stderr
- 退出码: 0 = 成功 (含 diff 有差异) / 1 = 完成但有告警或阴性判定 (坏行跳过、向量表判定失败、ARM bin 反汇编降级) / 2 = 致命 (文件不存在、无法解析、空镜像、参数矛盾)

### 第 4 步: 根据结果行动

- 坏行被跳过时如实向用户报告计数与首个坏行内容
- 向量表阴性判定列出逐条依据,不强行下结论
- ARM raw bin 反汇编被降级时向用户说明本机能力边界
- 不擅自修改输入文件;输出文件路径如实告知用户

## 设计要点 (供排查参考)

1. **纯标准库零依赖**: 仅 argparse/math/os/sys/struct/subprocess/collections,单文件 CLI,Python 3.13 实测。
2. **地址空间语义**: segments 按地址升序,相邻 record 合并,start > prev_end + 1 切段为 gap;gap 不吞字节也不伪造数据 (dump 折叠为 `-- GAP 起止 (N B) --` 单行,strings/entropy/fill 只扫真实数据段);info 将数据字节量与 bbox 跨度分列,跨度含 gap 时告警。
3. **熵双口径**: 原始 H (0-8) 主显,归一化 (H/8) 并列;加密启发式 (整体 > 0.83 且最高块 > 0.9) 与纯文本判定 (> 0.95) 均用归一化口径;最低熵块排除尾部不完整块;直方图并入 entropy 报告。
4. **向量表双架构**: Cortex-M 走判定链 (SP 非 0/8 字节对齐/不在镜像内/< 0x80000000;入口链项 1-15 非零项逐项要求 bit0==1 且掩码后落镜像, 零项跳过);判定锚点 = SP + Reset + 入口链 1-15 非零项完整通过, 任一项断裂即阴性;RISC-V 优先前导定位 (JAL x0 --> 连续 nop --> ebreak 之后的字即表基址,.init 变长自适应),显式 --table 时直接读表 (前导特征仅作佐证);auto 先 CM 后 RV,均失败输出双路径依据;汇总判定含"项 0 落镜像 + 越界项占比 < 50%"。
5. **反汇编委托**: RISC-V objdump 优先固定路径 `C:\MounRiver\MounRiver_Studio\toolchain\RISC-V Embedded GCC\bin\riscv-none-embed-objdump.exe`,兜底 PATH;raw bin 命令锁定 `-b binary -m riscv:rv32 -D --adjust-vma=<镜像基址>` (rv32 架构串不影响压缩指令解码);ARM fromelf 依次兜底 `D:\Keil_v5\ARM\ARMCLANG\bin\fromelf.exe` --> `D:\Keil_v5\ARM\ARMCC\bin\fromelf.exe` --> PATH,仅接受 ELF/axf;ELF 输入按 e_machine 自动选工具 (243=RISC-V,40=ARM)。
6. **坏行策略**: 默认跳过 + 计数 + 首个坏行原文展示,--strict 恢复"任一坏行即致命";EOF 记录后内容忽略;空 data record 与缺 EOF 不算错误。
7. **merge 语义**: 输入 ihex/srec/elf (地址内含),两两段级实际数据重叠校验 (段相邻允许);复用 segments 模型重编码为 Intel HEX;写临时文件经重解析 + diff 零差异 + bbox 并集一致三重校验后才原子替换目标。
7. **GPLv2 合规**: 对 ImHex v1.39.0.WIP 仅行为级学习 (解析容错语义、熵公式、strings 字符类、diff 分类),未复制任何源码;bin2hex 与向量表解析为自研域。

## 重要边界

1. **只读输入文件**: 不修改任何输入;输出一律 -o 显式指定,覆盖既有输出自动备份为 `*.bak`。
2. **CRLF 输出**: 文本输出 (to-hex/dump 落盘) 统一 CRLF 行尾。
3. **ARM raw bin 无本机反汇编**: fromelf 仅接受 ELF/axf,本机无 arm-none-eabi-objdump,请求时明确报告并降级 hex 转储 (退出码 1)。
4. **diff 语义**: 仅地址空间逐字节 + 单侧 Deletion/Insertion 分类,不做 Myers/edlib 对齐 diff。
5. **坏行默认跳过**: --strict 恢复严格硬错误语义。
6. **不做烧录、不写回源文件**: 只产出分析报告与显式指定的输出文件。
7. **-b 基址确认**: 仅对 bin 输入设定基址;hex/srec/elf 输入地址内含,传入与内含基址矛盾的 -b 直接报错防歧义。
8. **merge 边界**: 裸 bin 输入拒绝 (无内含地址,先 to-hex -b 转换);输出恒为 Intel HEX 重编码产物 (烧录等价,记录分块与源文件不同);任一数据重叠拒绝合并。

## 已验证场景

| 场景 | 输入 | 结果 |
|------|------|------|
| info 分段/gap | OnlyUpdateApp_merged.hex | 3 主段 + 16 个 2B 微段 + 140B 尾段;gap 0x3C20-0xFFFF (50144B) 与 0x140D0-0x3FFFF (180016B) |
| diff 双版本 | EEL APP [2026-10-28-006] vs [2026-10-26-005] hex | 4 个 Mismatch 区间共 7 B,首差异 0x00017306;同文件自比 0 差异 |
| 格式互转 | V3BELAPP_app.hex -b 0x40000 to-bin --> 126976B (首 8B E8 BF 00 20 19 02 04 00);V3BELAPP.bin to-hex 回转字节一致;gap 填充 0xFF/0x00 双值验证通过 |
| dump 反汇编 | EELAPP_REL_V2.elf / V3BELAPP.axf / Merge.BIN --arch rv | objdump -d 出 _start/handle_reset 符号;fromelf 出 Reset_Handler;raw bin 地址列随 --adjust-vma 起编,压缩指令 c. 助记符可见 |
| vector CM | V3BELAPP.bin -b 0x40000 --arch cm | SP=0x2000BFE8 判定链通过,Reset=0x00040219 掩码后 0x40218,128 项 |
| vector RV | EELAPP_REL_V2.elf / EELBL_REL_V2.elf --arch rv | 前导定位表基址 0xC038 项 0=0xC000 / 0x38 项 0=0x0,各 70 项 |
| strings | V3BELAPP.bin -n 6 | 228 条,与调研实测基线一致;-n 4 时 917 条 |
| entropy/fill | cipher_full.bin / V3BELAPP.bin / Merge.BIN;merged_ff.bin | 整体熵 7.998 / 6.864 / 4.416 (原始口径);fill 报告 0x3C20-0xFFFF 50144B 0xFF 填充 |
| merge 三段合并 | OnlyUpdateApp IAP (0x0-0x3C1F) + Peripheral (0x10000-0x140CF) + wchble_rom (0x40000-0x6ED1F) | 19 段 223728 B;与旧 merge_hex_multi 产物地址空间 0 差异;重叠输入/裸 bin 输入均正确拒绝 (退出码 2) |

## 版本

v1.1.0 | 2026-11-05 (v1.0.0 | 2026-10-29;新增 merge 子命令,收编原 merge-hex 技能)
