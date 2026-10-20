# TOT 的 Dump 和 EAC 折腾记录

先说丑话：这是我自己留的分析笔记，起因就是想看看 EAC 到底在干什么。不是外挂，也不教开挂。被踢被封别找我，联机排位别用。二传随意，把这段带上。

> If you can't read Chinese, see the [English README](README_EN.md).

---

游戏是 The Outlast Trials，有的地方叫逃生试炼，代号 TOT。

引擎 UE 5.5，但 RBG 自己 fork 过的，不是原版。进程叫 `TOTClient-Win64-Shipping.exe`，启动器是 `start_protected_game.exe`，反作弊走 EOS 那套 EAC，渲染是 D3D12。

有个坑要提前说：**血量、耐力、位置这些字段是服务器说了算的**。你本地改了，服务器下一帧就盖回去，看起来像"改了没反应"。所以别拿改数值没生效当成代码写错了。

另外这游戏更新挺勤，版本一更偏移就得重看。我这边时间不多，暂时只测到够用为止；这游戏本身玩得也不久，等以后有精力、或者哪天想玩了，再接着往下挖。

---

## 一、Dumper-7 直接上是崩的

报错就一句 `Could not find GNames!`

查过了，是它的特征码跟这游戏对不上：

- 一条是 `48 8D 0D ?? ?? ?? ?? E8`，意思是 `lea` 完紧接着就 `call`。这游戏构造函数里 `lea rcx, stru_146EB2C00` 后面**隔了三条指令**才 call
- 另一条 `FF 15 ?? ?? ?? ??`（call 走 IAT）也不通，因为里面初始化 SRWLock 用的是 `call r14`，寄存器缓存

两条路都死，所以它找不到。

它本来就留了手动指定的口子，只是默认没配而已。改两个地方就活了。

### `C:\Dumper-7\Dumper-7.ini`

```ini
[Settings]
SDKNamespaceName=SDK
SDKGenerationPath=D:/Dump
SleepTimeout=0
DumpKey=0
GNamesOffset=6EB2C00
GameName=TheOutlastTrials
GameVersion=5.5.0
```

`GNamesOffset` 是 FNamePool 的 RVA，十六进制不带 0x。换版本要重新找。

`GameName` / `GameVersion` 填上是为了跳过游戏内的名字查询 —— 那个调用在这游戏上会崩，能跳过就跳过，顺便输出目录名也正常了。

### 改源码

改过的文件都扔在 `dumper7-patch/` 了，就这几个：

`Settings.h` / `Settings.cpp` 里加了个 `GNamesOffset` 配置项。注意解析得用 `strtoul(..., 16)`，`GetPrivateProfileIntA` 不认十六进制，你写 `0x6EB2C00` 它读出来是 0。顺手也把 `GameName`/`GameVersion` 读了。

`Generator.cpp` 的 `InitEngineCore` 里改成：配了 offset 就直接 `FName::Init(offset, GNames, true)`，失败了再退回自动查找。

`main.cpp` 和 `Generator.cpp` 加了 `StageLog()` 写文件，每个阶段用 `__try/__except` 包起来。不加不行，这游戏一崩控制台一起没，什么都不剩，加了才有日志能看。

`NameArray.h/.cpp` 加了个 `IsInitialized()`，用来判断 GNames 到底有没有初始化成功。

> 顺便，**别去动它 `ByIndex` 的寻址**。我一开始以为这池子是"变长紧凑、得按 header 一步步走"的，改完名字全错、内存飙到 9G。老老实实分析数据才确认：它的索引就是**块内字节偏移除以 2**，原版 `chunk + (idx & 0xFFFF) * 2` 本来就是对的。

### 编译

直接拿 cl 编：

```bat
call "D:\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d <Dumper-7 源码目录>
cl /nologo /O2 /std:c++latest /EHsc /MD /DWIN32 /D_WINDOWS /DNDEBUG /D_CONSOLE /DDumper_7_EXPORTS ^
   /IDumper /IDumper\Engine /IDumper\Engine\Private ... ^
   /Fo"out\clbuild\obj/" /c <27 个源文件，一行一个>
link /nologo /DLL /OUT:Dumper-7.dll out\clbuild\obj\*.obj <一堆系统库>
```

`/Fo"路径/"` 结尾必须是正斜杠，写反斜杠的话 `\"` 会把引号吃掉。

### 注入

得先把 EAC 那边处理掉，见下一节。

处理完把编译出来的 DLL 注进去。省事的话用 EACLoader 的 `InjectDll` 配一下，它会在游戏启动早期自动注；手动的话提权之后 `CreateRemoteThread + LoadLibraryW` 也行。

成了的话游戏里会弹个控制台，大概长这样：

```
Initializing [Dumper-7]
GNames override: 0x6eb2c00
Found FChunkedFixedUObjectArray GObjects at offset 0x6f21838
Overwrote offset: 'FNamePool GNames' set as offset 0x6EB2C00
...
NameArray::FNameBlockOffsetBits: 0x10
Generating SDK took (6659.48ms)
```

六秒多出全套。完事按 F6 卸掉。

---

## 二、EAC 那边到底在干什么

游戏是从 `EOS_Platform_GetAntiCheatClientInterface` 拿到反作弊接口的，然后 `BeginSession` 开会话，客户端跟服务器来回通信。检测结果走 `AddNotifyMessageToServer` 那条通道上报。

客户端自己不会封人，它只负责上报。证据到服务器，服务器才决定怎么处理。

这么一搞，动手的地方就在两个方向上：

一个是干脆别让它起来（stub）：8 个 EOS 反作弊出口全换成自己的桩，EAC 就等于不在场。我是联机试的，会被踢，单机我没试过。

另一个是让它照常跑，只把上报那条通道掐掉（filter）：认证正常，也不被踢。但 EAC 是真在干活的，塞进去的东西它看得见 —— 我拿一个带 hook 的 DLL 试过，游戏直接起不来。

我平时用前面那个。

### 具体实现

代码在 `eac-bypass/`。写了个 loader，它干这些事：

把游戏拉起来（`Launch=direct` 直接拉 exe，`Launch=eac` 先起 EAC 服务再拉），然后趁 EAC 还没把回调挂上的时候把 payload 注进去。

payload 在游戏进程里干这几件：

改导入表（IAT、延迟导入、导出表都改），把 8 个反作弊函数全换掉；盯着 `CreateProcessW`，游戏要是想自己去拉 EAC 引导器就直接拒（`BlockRelaunch=1`）；还有 `CrashReportClient.exe` 也要拒 —— 那玩意崩的时候会上传 minidump，里面带模块列表，这个不能让它跑；最后把自己从 PEB 模块链表里摘掉。

配置长这样，`eac-bypass/cfg/` 里有示例：

```ini
Launch=direct      ; direct=直接拉游戏 / eac=先起 EAC 服务
Mode=stub          ; stub=桩掉反作弊出口 / filter=EAC照跑只掐上报
Report=drop        ; drop=丢弃上报 / pass=放行
BlockRelaunch=1    ; 拒绝游戏自己重启到 EAC 引导器
```

编译走 `src\build.ps1`，MinGW 一键出 `EACPayload.dll` 和 `EACLoader.exe`。

---

## 三、这样处理之后会怎样

会被踢，但不会封。我反复被踢，从头到尾没封过。

被踢的时候游戏上写：

```
你已被踢出服务器。
Authentication timed out (1/3)
```

你把 `BeginSession` 桩掉了，游戏以为会话建好了，服务器那边从来没收到过真的 EAC 会话，等不到就踢。

### 还有个隐藏的坑：启动方式

用 `Launch=direct` 的时候游戏自己的日志里会写这些（`%LOCALAPPDATA%\OPP\Saved\Logs\OPP.log`）：

```
LogEOSAntiCheat: [AntiCheatClient] Anti-cheat client not available. ...
LogOnlineRBAntiCheat: Error: OSS: Can't get a handle to the "Anti-Cheat Client Interface".
LogOnline: Warning: OSS: The game was launched with the incorrect executable.
           Launching "Easy Anti-Cheat" Bootstrapper: ...\start_protected_game.exe
```

第三行是说游戏发现启动方式不对，自己去拉 EAC 引导器，被 `BlockRelaunch` 拒了之后就带着残废状态继续跑。

换成 `Launch=eac` 之后这两条 Error 就没了，只剩一条警告。排错必看这日志。

---

## 四、EAC 正常跑的时候，外面读不了内存

本来想走"外部读内存 + 外部画"的路子 —— 完全不进游戏进程，最干净，EAC 也没得查。试了一下，撞墙。

```
ReadProcessMemory            → err=5
NtReadVirtualMemory (ntdll)  → 0xC0000022
裸 syscall（自己拼 stub 绕过 ntdll） → 0xC0000022
NtQueryVirtualMemory         → 放行
EnumProcessModulesEx / Module32 / PEB 查询 → 全被拦
OpenProcess(PROCESS_ALL_ACCESS) → 成功（提权后）
```

连裸 syscall 都被拒，那拦截就在内核里，用户态怎么绕都没用。提权也没用 —— 句柄给你了，读的时候不给。

`tools/read_routes.py` 就是测这个的，你可以自己复现。

现在的局面就是：

- **stub 模式**：什么都能读、能注入，但联机被踢
- **EAC 正常**：不被踢，但外面读不了内存

想两个都要，只能把读的动作挪进游戏进程里（注入一个只读的 DLL），然后别做任何 hook —— 碰渲染、碰窗口都算 hook，那是最容易被抓的地方。模块链表摘掉、PE 头擦一擦。但内核的 VAD 树扫描用户态是绕不过的，这个得认。

---

## 五、这游戏内存长什么样

FNamePool（也就是 GNames）RVA 是 `0x6EB2C00`，GObjects 是 `0x6F21838`，后者是 FChunkedFixedUObjectArray，item 大小 0x18。

池子结构实测是：`pool+0x08` 是 MaxChunkIndex（190），`pool+0x0C` 是 ByteCursor，`pool+0x10` 就是块指针数组本身 —— **注意这里不用再解一层**，我一开始就是多解了一层，白折腾半天。

块大小 0x20000（128KB）。FNameEntry 的 header 是 2 字节，`长度 = header >> 6`，`宽字符标志 = header & 1`，entry 按 2 字节对齐所以会有 1 字节填充。

索引是**块内字节偏移除以 2**，不是第几个 entry，所以 bits = 16。验证办法是看 chunk[0] 开头的序列：`0 → None`、`3 → ByteProperty`、`10 → IntProperty`、`17 → BoolProperty`，跟"偏移÷2"能对上。

常用偏移：

```
UObject::Class / Name                    0x10 / 0x18
AActor::RootComponent                    0x140
USceneComponent::RelativeLocation/Rot    0x124 / 0x130
ARBPawn::Health / bDead / CharLocation   0x5418 / 0x5454 / 0x4B48
ARBPlayer::stamina                       0x7130
ARBNPC::npcName / NPCType                0x5A70 / 0x58C0
AController::Pawn                        0x260
APlayerController::PlayerCameraManager   0x2C8
相机 POV                                 CameraManager + 0x1C30 + 0x10，之后 +0 / +0xC / +0x18
ACharacter::Mesh / CharacterMovement     0x2A0 / 0x2A8
UCharacterMovement::MaxWalkSpeed         0x1AC
```

类名：玩家是 `RBPlayer`，NPC 是 `RBNPC`，玩家控制器是 `RBController`。

还有，`Default__` 前缀那批是类的默认对象（CDO），不在场景里，得滤掉，不然你的列表里全是它们。

完整 SDK 在 `sdk/`，CppSDK 一千四百多个文件，外加 UE 的 usmap 和 IDA 用的 idmap，查东西直接翻。

---

## 六、踩过的坑

Dumper-7 找不到 GNames —— 别想着改特征码，直接配 offset。

FNamePool 索引理解错 —— 一度以为是第几个 entry，改成按 header 步进，结果名字全错、内存涨到 9G。索引是字节偏移÷2。

`GetPrivateProfileIntA` 不认十六进制 —— 配 `0x6EB2C00` 读出来是 0。

`.bat` 里 `/Fo"路径\"` —— 结尾反斜杠吃掉引号，整条命令失效。

MSBuild 编不了 —— 直接 cl，别在 SDK 版本和工程路径上耗。

提权是必须的 —— EAC 驱动会把普通权限进程的读内存权限剥掉（err=5），提权之后才给 ALL_ACCESS。

自己写的注入器 —— 给 FFI 设返回值类型，不然 64 位指针被截断成 0，症状是 `LoadLibraryW @ 0x0`。

游戏一崩什么都不剩 —— 给 Dumper-7 加阶段日志（写文件）加 SEH 才有得查。

崩溃上报要拦 —— `CrashReportClient.exe` 会上传带模块列表的 minidump，在 `CreateProcessW` 那儿拒掉。

---

## 七、其它

想自己复现的话：先让它不碍事（stub），再注入改好的 Dumper-7，dump 出来，F6 卸掉。

改完的文件在 `dumper7-patch/`，EAC 那部分的代码在 `eac-bypass/`，分析脚本在 `tools/`，SDK 在 `sdk/`。

有用就点个 star，没用就算了，主要给自己留档。

QQ 群 1102821216，加群说下从哪看到的，不然不放。

---

2026-10-11：SDK 能 dump 出来了，EAC 的行为也测了一轮。目前就到这，后面看时间。
