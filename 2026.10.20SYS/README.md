# EAC 驱动静态分析存档

没有多余机器做动态调试，内核动态调试 dump 就先到这里吧……纯属无聊时的消遣。综合来看应该是有用但不多，比较麻烦就不折腾了，对我而言意义不大，没什么收益，后期再看吧……

---

## 这里面是什么

`EasyAntiCheat_EOS.sys` v3.2.0.0，The Outlast Trials（Steam appid 1304930）用的 EAC 内核驱动本体。

| 项 | 值 |
|---|---|
| 文件名 | `EasyAntiCheat_EOS.sys` |
| 大小 | 40,474,272 B（38.60 MiB） |
| SHA256 | `26797A1122781CAF12F1A686E33A0883FA1E2895B40C2249932E319B338841C7` |
| MD5 | `2935B628178CECFB69318A336C150093` |
| 版本 | 3.2.0.0 |
| 编译时间 | 2026-10-15 |
| 签名 | Valid — `CN=Epic Games Inc.` |
| PE 架构 | x64，ImageBase `0x140000000`，SizeOfImage `0x26E9000` |

原文件路径：`C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys`

---

## 为什么停止动态调试

三个硬约束叠在一起，绕不过去：

**一、驱动不肯在人工环境初始化。**
手工 `sc create` 建服务加载，`DriverEntry` 跑完后驱动自己退出，返回 `WIN32_EXIT_CODE 2001 (0x7D1)` = `ERROR_DRIVER_FAILED_PRIOR_UNLOAD`。它要真 EAC 的启动上下文，缺了就不干活。

**二、VM 保护免疫硬件断点。**
VM entry/exit 会保存恢复全部 16 个 XMM + 通用寄存器 + FLAGS，把 TF 标志一起搅乱。下 `ba e1` 想断在目标地址，实际命中 `+0x3ef94d`，抛 `Single step exception (0x80000004)`，栈上返回地址是伪造的 `0x0780edc959fd87c1`。

**三、软件断点破坏代码段。**
`bp` 往 `.text` 里写 `0xCC`，跑起来直接 `KERNEL_SECURITY_CHECK_FAILURE (0x139)`。这个是自伤，不是反调试——用纯硬件断点（不改内存）跑同一流程全程没有 bugcheck。

想同时拿到"真实启动上下文 + 能断点"，得另开一台物理机装完整 Steam + 游戏，等于为了看一个驱动再搭一套环境。为这点收益不值。

---

## 静态能拿到的（已全部做完）

### 磁盘字节 == 运行时字节

这一点先证明了，后面所有结论才成立。在 `DriverEntry` 前 dump `seg008` 前 64 KB（运行时 `0xFFFFF8025FD51000`，磁盘偏移 `0x32CA00`）逐字节比对：

```
相同 65,536 字节   不同 0 字节   差异率 0.00%
逐 4KB × 16 块     全部 0 差异
```

**驱动没有运行时解密。** 磁盘文件就是完整运行时代码，不需要串口慢速全量 dump。

### 入口链路

```
0x272978   DriverEntry
  └─ 0x1A223F            thunk
      └─ 0x1403A572E     seg008
          └─ sub_140381041   VM ENTRY       xref = 10211   保存 16 XMM + GP + FLAGS
              └─ 0x14038114F  JUMP SHIM     9 bytes  mov rax,0FFFFFFFFFFC8547Dh，改栈上返回地址
                  └─ 0x14038116C  VM DISPATCHER  xref = 10865   ← 全驱动最热
                      └─ 0x140381A0A  VM EXIT(备用)  xref = 623
```

VM 常数：`0x561C7F4B48E431A5`

### 保护方案判定：VMProtect 2.x

- `.pdata` 只有 `0x11000`，**完全不覆盖 seg008（37 MB）**
- 段熵 seg008 = 6.405 / seg007 = 6.410
- 内嵌字符串 `Kraken` / `Selkie` / `Mermaid` / `Leviathan` / `BitKnit` / `Core.pdb` / `newlz chunk type %d = %s [%d->%d]`

### 监控面：六大方向全占

API 名字表在 `0x1402D8D60`（header `0x1402D8D54`，首记录长度 `0x14`，180 字节前缀共享编码）：

| API 前缀 | 能力 |
|---|---|
| `Clfs*` / `Ntfs*` / `Flt*` | 文件系统 minifilter |
| `Fwpm*` / `Fwps*` | WFP 网络过滤 |
| `Cm*`（回调编号 CM11~CM32） | 注册表监控 |
| `Ps*` / `Ob*` | 进程 / 对象回调 |
| `Mm*` / `Io*` | 内存 / IO |
| `Etw*` | ETW 事件追踪 |

**动态导入只有一条**：`FLTMGR!FltRegisterFilter`，`.idata` 共 16 字节。其余 API 全部哈希解析，没有任何 API 名字符串——所以从文件里搜不到导入清单。

### 运行时内存 dump（都在 `runtime_dumps/`）

| 文件 | 大小 | 内容 |
|---|---|---|
| `speedtest.bin` | 1.00 MB | `.text` 前 1 MB，91.3% 非零 |
| `seg008_head.bin` | 64 KB | seg008 前 64 KB，与磁盘 0 差异（加密否定的证据） |
| `eac_data_rt.bin` | 331,804 B | `.data` 加载前，非零 0.9% |
| `eac_data_ld.bin` | 335,872 B | `.data` 加载后，非零 0.9% |

`.data` 前后对比：**差异 294 字节（0.09%）**。

这 294 字节具体是什么没进一步核实，只能说明加载前后 `.data` 的变化量很小。据此判断不了 API 解析结果存在哪里。

### IDA 数据库

`.i64` 有 171.93 MB，超过 GitHub 单文件 100 MiB 硬上限，没往仓库放。需要的话自己用 IDA 打开原始 sys 让它重新分析，3666 个函数。

---

## 一个反直觉的事实

```
C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.sys   38.60 MB  存在
C:\Windows\System32\drivers\EasyAntiCheat_EOS.sys                缺失
```

**文件在硬盘上，但从来没被加载过。** 服务 `EasyAntiCheat_EOS` 状态 `Stopped`。

本作实际用的是**纯用户态 EOS 反作弊**，不依赖内核驱动就能正常运行、正常联网。

---

## 剩下没做的

驱动侧静态已到顶，业务函数只有 `sub_14006CE22` 一条被代码引用（`gameid=` 在 `0x1402D54C2`，用黄金比例哈希 `0x61C8864680B583EB`，API 地址 = `off_XXXX + K*v6`）。继续翻 3666 个 VM handler 边际收益接近零，除非做 VM 解包，那个以周计。

唯一还有希望的方向是用户态 hook `EOS_AntiCheatClient_*`（走 `EACPayload.dll`），但那属于另一条线，不在这个目录的范围内。

---

## 文件清单

```
2026.10.20SYS/
├── README.md                      ← 本文件
├── EasyAntiCheat_EOS.sys          38.60 MiB  v3.2.0.0
└── runtime_dumps/
    ├── speedtest.bin               1.00 MiB  .text 头部
    ├── seg008_head.bin            64.00 KiB  seg008 头部（0 差异）
    ├── eac_data_rt.bin           324.03 KiB  .data 加载前
    └── eac_data_ld.bin           328.00 KiB  .data 加载后
```

---

2026-10-20：驱动本体 + 静态分析结论存档。动态调试因环境成本暂停，后期有精力再说。
