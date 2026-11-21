# The Outlast Trials — SDK / 反作弊分析 / 注入链路

本仓库记录对 *The Outlast Trials* 的静态与动态分析结果，包含完整 UE4 SDK、Easy Anti-Cheat 内核驱动的 VM 逆向结论，以及在反作弊未被破坏的前提下完成注入的可复现步骤。

**所有写入本文档的结论均来自实际运行或文件级静态解析。未验证的内容单独标注，不与已验证内容混排。**

---

## 目录

```
SDK/                  UE4 C++ SDK（1424 个文件）
SDK-Dumpspace/        偏移与类型元数据（JSON）
SDK-Mappings/         .usmap / .idmap
SDK-GObjects-Dump.txt 完整 UObject 转储
```

---

## 一、目标环境

| 项 | 值 |
|---|---|
| 主可执行文件 | `OPP/Binaries/Win64/TOTClient-Win64-Shipping.exe` |
| 文件大小 | 119,290,880 字节 |
| 引擎版本 | 4.27.1-272417+release-7-2 |
| 映像基址 | `0x140000000` |
| 映像大小 | `0x762C000` |
| 图形后端 | D3D12 |
| Steam AppId | 1304930 |
| 反作弊 | Easy Anti-Cheat（EOS 变体） |

PE 节表：

| 节 | RVA | 虚拟大小 | 文件偏移 | 原始大小 |
|---|---|---|---|---|
| `.text` | `0x1000` | `0x506BA6D` | `0x400` | `0x506BC00` |
| `.rdata` | `0x506D000` | `0x1AB5C94` | `0x506C000` | `0x1AB5E00` |
| `.data` | `0x6B23000` | `0x61F7B8` | `0x6B21E00` | `0x1BE400` |
| `.pdata` | `0x7143000` | `0x2A9CD8` | `0x6CE0200` | `0x2A9E00` |
| `.reloc` | `0x743B000` | `0x1F0074` | `0x6FD3A00` | `0x1F0200` |

---

## 二、反作弊结构

### 2.1 组成

| 组件 | 位置 | 作用 |
|---|---|---|
| `start_protected_game.exe` | 游戏根目录 | 引导器，负责拉起 EAC 后再拉起游戏 |
| `EasyAntiCheat_EOS.exe` | `EasyAntiCheat_EOS/` | 用户态服务进程 |
| `EOSSDK-Win64-Shipping.dll` | `OPP/Binaries/Win64/` | EOS SDK，含 8 个反作弊客户端导出 |
| `EasyAntiCheat_EOS.sys` | `EasyAntiCheat_EOS/` | 内核驱动，注册文件系统微过滤器 |

驱动 `EasyAntiCheat_EOS.sys` 通过 `FLTMGR!FltRegisterFilter` 注册为微过滤器，这是它拦截跨进程内存访问的来源。

### 2.2 EOS 反作弊入口（共 8 个）

游戏通过延迟导入表调用以下导出：

```
EOS_Platform_GetAntiCheatClientInterface
EOS_AntiCheatClient_BeginSession
EOS_AntiCheatClient_EndSession
EOS_AntiCheatClient_ReceiveMessageFromServer
EOS_AntiCheatClient_AddNotifyMessageToServer
EOS_AntiCheatClient_AddNotifyClientIntegrityViolated
EOS_AntiCheatClient_RemoveNotifyMessageToServer
EOS_AntiCheatClient_RemoveNotifyClientIntegrityViolated
```

实测确认：主模块的**静态导入表中不含 EOSSDK**，全部为延迟导入（延迟导入描述符 `Attributes=1`，字段为 RVA）。

### 2.3 上报路径

`AddNotifyMessageToServer` 与 `AddNotifyClientIntegrityViolated` 注册的回调，是 EAC 向游戏回传检测结果的唯一通道。游戏侧再把结果转发给服务器。

---

## 三、注入链路（已实测）

### 3.1 有效顺序

```
1. CreateProcessW(game_exe, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT)
   环境变量 SteamAppId / SteamGameId = 1304930
2. 主线程冻结期间，远程 LoadLibraryW 注入自包含 payload
3. payload 在进程内完成 8 个 EOS 入口打桩
4. payload 从 PEB 加载器链表摘除自身
5. ResumeThread
6. payload 延迟指定毫秒后，从进程内部 LoadLibraryW 加载目标 DLL
```

**关键点：不经过 `start_protected_game.exe`。** 直接启动游戏本体可以跳过 EAC 引导阶段，此时 EAC 驱动尚未附着到该进程，跨进程注入不被拦截。

### 3.2 三步打桩

payload 内对反作弊入口做三处改写，确保无论调用方走哪条路径都命中桩函数：

| 位置 | 处理 | 实测数量 |
|---|---|---|
| 静态导入表（IAT） | 逐个匹配导出名改写槽 | 0（本构建无静态导入） |
| 延迟导入表 | 匹配 `INT` 名称改写 `IAT` 槽 | 8 |
| EOSSDK 导出地址表（EAT） | 改写 `AddressOfFunctions[ordinal]` | 8 |

实测日志：

```
[*] anti-cheat entry points hooked: 8 / 8 (iat=0 delay=8 eat=8)
[+] self unlinked from PEB loader lists
```

### 3.3 桩函数语义

```
EOS_Platform_GetAntiCheatClientInterface  → 返回 NULL
EOS_AntiCheatClient_AddNotifyMessageToServer          → 返回有效通知 id
EOS_AntiCheatClient_AddNotifyClientIntegrityViolated  → 返回有效通知 id
其余 6 个                                 → 返回 0（EOS_Success）
```

`GetAntiCheatClientInterface` 返回 NULL 时，EOS 走「无反作弊客户端」分支。游戏日志实测：

```
LogEOSAntiCheat: [AntiCheatClient] Anti-cheat client not available, using null client
```

游戏主循环、渲染管线、资源加载全部正常，进程稳定。

### 3.4 延迟加载的必要性

payload 完成打桩后，若从外部进程再注入 DLL，`LoadLibraryW` 会被 EAC 驱动拒绝（返回 0）。通过环境变量把目标 DLL 路径交给 payload，由 payload 在**进程内部**调用 `LoadLibraryW`，可正常加载。

实测：

```
[+] internal load ok   : base=0x7FF8XXXXXXXXXX
```

---

## 四、SDK 导出（已实测）

### 4.1 产物

| 统计项 | 数值 |
|---|---|
| 总文件数 | 1,440 |
| 总大小 | 94.36 MB |
| C++ 头文件 | 1,025 |
| `*_classes.hpp` | 483 |
| `*_functions.cpp` | 402 |
| `*_parameters.hpp` | 401 |
| `*_structs.hpp` | 136 |

生成器状态：`CppGenerator` / `MappingGenerator` / `IDAMappingGenerator` / `DumpspaceGenerator` **全部成功，无崩溃**。

### 4.2 关键偏移

| 符号 | RVA | 文件内校验值 |
|---|---|---|
| `OFFSET_GOBJECTS` | `0x6F83CF8` | `0x4FB53D704FB5390` |
| `OFFSET_GNAMES` | `0x6F27F00` | `0x4523F6006A748D0` |
| `OFFSET_GWORLD` | `0x70FBD60` | `0xA758A750A748A740` |

`OFFSET_APPENDSTRING`、`OFFSET_PROCESSEVENT`、`INDEX_PROCESSEVENT` 为 0：本构建使用内联 `FName::ToString` 与直接 `ProcessEvent` 调用，不存在可定位的独立符号。

### 4.3 GNames 定位（自动探测失败后的替代方案）

该构建的 `FName::StaticInit` 中 `ByteProperty` 字符串回溯逻辑不成立，自动探测返回 `FAILED FNameInit (no GNames)`。改用运行期结构扫描：

1. 在 `.data` 与 `.rdata` 段内按 4 字节步进
2. `+0x08` 为 `int32 CurrentBlock`，取值 `(0, 0x2000]`
3. `+0x0C` 为 `uint16 CurrentByteCursor`，取值 `(0, 0x20000]`
4. `+0x10` 的 `Blocks[0]` 指向可读内存
5. `Blocks[0]` 起始 `0x40` 字节内含 `None`，且 `0x400` 字节内含 `/Script/CoreUObject`

命中 `RVA 0x6F27F00`，`CurrentBlock = 0xC0`，`ByteCursor = 0x7648`。

`Blocks[0]` 解码验证：

```
None
ByteProperty
IntProperty
BoolProperty
FloatProperty
ObjectProperty
NameProperty
DelegateProperty
DoubleProperty
ArrayProperty
StructProperty
VectorProperty
RotatorProperty
StrProperty
TextProperty
InterfaceProperty
MulticastDelegateProperty
LazyObjectProperty
SoftObjectProperty
Int64Property
```

全部属性名语义正确，确认为 `FNamePool`。该值与 SDK 输出的 `OFFSET_GNAMES` 完全一致，构成独立双验证。

### 4.4 复现导出

配置（相对路径，跟随导出器所在目录）：

```ini
[Settings]
SDKNamespaceName=SDK
SDKGenerationPath=../sdk
SleepTimeout=0
DumpKey=0
GNamesOffset=6F27F00
GameName=TheOutlastTrials
GameVersion=4.27.1
```

`GNamesOffset` 为十六进制 RVA，`0` 表示自动探测。本构建必须手动指定，否则 `FNameInit` 失败，后续所有生成器输出为空。

---

## 五、ESP 所需偏移链（全部出自 SDK，逐行核对）

### 5.1 全局

```
GWorld   0x140000000 + 0x70FBD60
GObjects 0x140000000 + 0x6F83CF8
GNames   0x140000000 + 0x6F27F00
```

### 5.2 对象层级

```
GWorld
 ├─ +0x030  PersistentLevel      (ULevel*)
 ├─ +0x128  GameState            (AGameStateBase*)
 ├─ +0x140  Levels               (TArray<ULevel*>)
 └─ +0x188  OwningGameInstance   (UGameInstance*)

ULevel
 └─ +0x098  Actors               (TArray<AActor*>)

UGameInstance
 └─ +0x038  LocalPlayers         (TArray<ULocalPlayer*>)

ULocalPlayer
 └─ +0x070  ViewportClient       (UGameViewportClient*)

UPlayer
 └─ +0x030  PlayerController     (APlayerController*)

APlayerController
 ├─ +0x2B0  AcknowledgedPawn     (APawn*)
 ├─ +0x2C8  PlayerCameraManager  (APlayerCameraManager*)
 ├─ +0x2C0  MyHUD                (AHUD*)
 └─ +0x2A8  Player               (UPlayer*)

APlayerCameraManager
 └─ +0x2A0  CameraCache          (FCameraCacheEntry)

FCameraCacheEntry
 ├─ +0x000  Timestamp            (float)
 └─ +0x010  POV                  (FMinimalViewInfo)

FMinimalViewInfo
 ├─ +0x000  Location             (FVector, 3 × float)
 ├─ +0x00C  Rotation             (FRotator, 3 × float)
 ├─ +0x018  FOV                  (float)
 └─ +0x02C  AspectRatio          (float)

AActor
 ├─ +0x0E8  Owner                (AActor*)
 ├─ +0x128  Instigator           (APawn*)
 └─ +0x140  RootComponent        (USceneComponent*)

USceneComponent
 ├─ +0x0C8  AttachParent         (USceneComponent*)
 ├─ +0x124  RelativeLocation     (FVector)
 └─ +0x148  ComponentVelocity    (FVector)
```

### 5.3 结构体尺寸

| 结构 | 布局 |
|---|---|
| `FVector` | `X` +0x00, `Y` +0x04, `Z` +0x08（总 0x0C） |
| `FRotator` | `Pitch` +0x00, `Yaw` +0x04, `Roll` +0x08（总 0x0C） |
| `FTransform` | `Rotation`(FQuat) +0x00, `Translation`(FVector) +0x10, `Scale3D`(FVector) +0x20 |
| `FCameraCacheEntry` | 总 0x650 |
| `FMinimalViewInfo` | 总 0x640 |

### 5.4 世界坐标转屏幕

```
1. 从 APlayerCameraManager + 0x2A0 + 0x10 读取 POV
2. 用 POV.Location 与 POV.Rotation 构造 view matrix
3. 用 POV.FOV（度）与 POV.AspectRatio 构造投影
4. NDC → 像素：x_px = (ndc.x * 0.5 + 0.5) * screen_w
               y_px = (1 - (ndc.y * 0.5 + 0.5)) * screen_h
5. 目标点位于相机后方时（view space z <= 0）丢弃
```

---

## 六、内核驱动 VM 逆向

### 6.1 样本

| 项 | 值 |
|---|---|
| 文件 | `EasyAntiCheat_EOS.sys`（39 MB 构建） |
| 大小 | 39,930,520 字节 |
| SHA-256 | `70B07D9FB1E9D8A1B2B3EBA16A79B317E5A0131A08B923FCA31DD0DFEBF59C9F` |
| 映像基址 | `0x140000000` |
| 入口 RVA | `0x26AEB8` |
| 导出 | 仅 `DriverEntry` |
| 导入 | 仅 `FLTMGR!FltRegisterFilter` |

### 6.2 密钥派生

解释器 `0x140136721` 前 38 条指令完成派生：

```
0x14013673C  mov   rsi, r9              ; 状态指针
0x14013673F  mov   rbx, r8              ; x = 第三参数
0x140136742  mov   rdi, rcx             ; 字节码基址
0x140136745  mov   rax, 0BF58476D1CE4E5B9h
0x14013674F  imul  r8,  rax             ; t = x * K
0x140136753  mov   r13, r8
0x140136756  shr   r13, 20h             ; t >> 32
0x14013675A  mov   rcx, r8
0x14013675D  shr   rcx, 3Ch             ; t >> 60
0x140136761  shr   r13, cl              ; t >> (32 + (t >> 60))
0x140136764  xor   r13, r8              ; t ^ (t >> shift)
0x140136767  imul  r13, rax             ; (...) * K
0x14013676B  xor   r13, rbx             ; ^ x
```

数学形式：

```
K = 0xBF58476D1CE4E5B9
t = x * K
h = ((t ^ (t >> (32 + (t >> 60)))) * K) ^ x
```

自检值：

| 输入 | 输出 |
|---|---|
| `0` | `0x0000000000000000` |
| `1` | `0xA370EF30C96DF2E8` |

### 6.3 操作码编码

```
0x140136772  movzx ecx, word ptr [rdi]     ; 16 位操作码
0x140136775  imul  eax, r13d, 1B4Bh        ; h.low * 0x1B4B
0x14013677C  movzx eax, ax
0x14013677F  xor   eax, 3CCEh
0x140136784  and   eax, ecx
```

```
mask  = (((h & 0xFFFFFFFF) * 0x1B4B) & 0xFFFF) ^ 0x3CCE
index = opcode_word & mask
```

### 6.4 分派表

有符号 4 字节自相对偏移，目标 = 表项地址 + 表项值：

| 表地址 | 项数 | 目标区间 |
|---|---|---|
| `0x140308D34` | 7 | `0x140136B9C`–`0x140139581` |
| `0x140308D50` | 47 | `0x140137235`–`0x140137689` |
| `0x140308E0C` | 60 | `0x14013692F`–`0x140136CD8` |
| `0x140308F40` | 115 | `0x140136E2A`–`0x140137EA2` |

合计 **229 case**，唯一 handler **184 个**，全部落在解释器区间 `0x140136721`–`0x14013A71F`（16,382 字节）内，**越界 0**。默认分支 `0x140139606`。

### 6.5 加密槽

`.rdata` 中两个连续高熵数组：

| 组 | RVA 范围 | qword 数 |
|---|---|---|
| A | `0x3045F8`–`0x304690` | 19 |
| B | `0x308220`–`0x3082A0` | 16 |

被代码引用者集中在两个函数：

| 函数 | 范围 | 引用槽次数 |
|---|---|---|
| `0x1401EB0B9` | `0x1401EB0B9`–`0x1401EC39F` | 43 |
| `0x1401F097D` | `0x1401F097D`–`0x1401F0Bxx` | 6 |

`0x1401EB0B9` 无直接调用点（8 字节指针引用 0），仅 `.pdata` 一条 `RUNTIME_FUNCTION`：`start=0x1EB0B9`，`end=0x1EC39F`，`unwind=0x310428`。该函数只能经 VM 分派间接进入。

### 6.6 槽解密规则

单槽序列（`0x140308220` 为例）：

```
0x1401EB163  mov  rax, 0B36371EB0779D25Bh   ; 槽专属常数
0x1401EB16D  imul rax, rsi                  ; const * h
0x1401EB171  mov  rcx, cs:off_140308220     ; 槽密文
0x1401EB178  sub  rcx, rax                  ; target = slot - const * h
0x1401EB17B  mov  [rsp+var_B8], rcx
```

通用形式：

```
target = slot_cipher - const * h
h      = ((x*K) ^ ((x*K) >> (32 + ((x*K)>>60)))) * K ^ x
```

槽内保存的是**加密后的地址**，不是函数指针。解出的 `target` 被直接 `call` 或按索引访问。

### 6.7 29 个槽完整数据

具备完整 `mov imm64 → imul rsi → mov cs:off → sub` 链的槽：

| # | 槽 VA | 密文 | 常数 |
|---|---|---|---|
| 1 | `0x1403045F8` | `0xB2D29DC18804A3A7` | `0xE602F0701272AC41` |
| 2 | `0x140304600` | `0xF5CE778BD34F8D88` | `0xB8883B36FABBB50A` |
| 3 | `0x140304610` | `0x8F717CBD63217FEE` | `0x83873EA5E2B3A6BF` |
| 4 | `0x140304618` | `0x7DBA877327F747D6` | `0xBFCC70654D3A905D` |
| 5 | `0x140304620` | `0x0968443A85BA5D8B` | `0xED7E622D5193001D` |
| 6 | `0x140304628` | `0x06FA29331E1EB2D3` | `0x33E92C7C1DE3E7DF` |
| 7 | `0x140304630` | `0xC69F67F7F467FBEC` | `0x18077395D3DB28DC` |
| 8 | `0x140304638` | `0x871C4F79ECA0C669` | `0x567246AE3C79957F` |
| 9 | `0x140304640` | `0xBEBA998A72198350` | `0xAF30035B00600532` |
| 10 | `0x140304648` | `0x6DB5D9C062CF0A14` | `0x88DB0F58E909129A` |
| 11 | `0x140304650` | `0x7613F510075F2272` | `0x6A9068EE42B37944` |
| 12 | `0x140304658` | `0x09265C2C1440A132` | `0x32799FEEC2DE7C60` |
| 13 | `0x140304660` | `0xBC2BA046B5CE8CB2` | `0x7C5E1C8325CDA7CA` |
| 14 | `0x140304668` | `0x5EACC9E26984DBF4` | `0x07625D69CE091D8C` |
| 15 | `0x140304670` | `0xFFA6E60F3CC5904F` | `0x269EBAC16D4C38EA` |
| 16 | `0x140304678` | `0xC65A2518CAD790A3` | `0x3AFDD91F569FC198` |
| 17 | `0x140308220` | `0x04ED48B95C3BE78D` | `0xB36371EB0779D25B` |
| 18 | `0x140308228` | `0x687B1CFD97767CD6` | `0xB789E2DBB16EDE02` |
| 19 | `0x140308230` | `0x18D7C74666A54705` | `0x8EC5E76D75707D3D` |
| 20 | `0x140308238` | `0x9BF5699F3A909225` | `0x952E1953F0C00D67` |
| 21 | `0x140308240` | `0x6BB0ED748E8FD88D` | `0x0220C041F83FF687` |
| 22 | `0x140308248` | `0xCCC7A6A1669B1991` | `0x99AE816A38805D3B` |
| 23 | `0x140308250` | `0xC82BD1378EF7712F` | `0xBFCC70654D3A905D` |
| 24 | `0x140308258` | `0xA817F3AB6498EFED` | `0x818C0871F299BADF` |
| 25 | `0x140308260` | `0xF2FBB72176294DBC` | `0x0A22C03659741824` |
| 26 | `0x140308268` | `0x5E13475B849574B7` | `0x9BEBEFC0F542C9AD` |
| 27 | `0x140308270` | `0xC4ECF505581EE9DB` | `0xC595028F224B18C1` |
| 28 | `0x140308278` | `0x55CA555DDCA2C68D` | `0x0E54B0378D157D9F` |
| 29 | `0x140308280` | `0x016D5F48F1A7B6CD` | `0x60465AC94D478DC7` |

另有 5 个槽（`0x140304608`、`0x140304680`、`0x140308288`、`0x140308290`、`0x140308298`）使用 `neg reg` + 索引访问形式，不参与 `const*h` 地址解算。

### 6.8 关于 h 的运行时取值

`h = splitmix(x)`，`x` 是解释器第三参数。该函数静态无调用点，`x` 由运行期 VM 上下文构造，样本文件内不含其静态值。

因此**槽的解密规则（常数表、派生式、减法方向、符号性）已完全确定**，而 `target` 的具体数值需在目标机器上以运行期寄存器值为输入才能得到。这一点如实记录，不作填充。

---

## 七、实测有效 / 实测无效

### 7.1 实测有效

| 路径 | 结果 |
|---|---|
| 挂起态直接启动游戏本体（跳过引导器） | 成功 |
| 挂起态远程 `LoadLibraryW` 注入 payload | 成功 |
| payload 进程内打桩 8 个 EOS 入口 | 8/8 成功 |
| payload 从 PEB 加载器链表摘除自身 | 成功 |
| payload 从进程内部加载目标 DLL | 成功 |
| 打桩后游戏正常运行 | 成功，`OPP.log` 记录 `using null client` |
| 运行期扫描定位 `FNamePool` | 成功，`RVA 0x6F27F00` |
| SDK 全量导出（四生成器） | 成功，1440 文件 / 94.36 MB |
| 驱动 VM 分派表解析 | 229 case 全部落入解释器区间 |

### 7.2 实测无效

| 路径 | 失败现象 |
|---|---|
| 经引导器启动后跨进程注入 | `ERROR_PARTIAL_COPY (299)` |
| 主线程恢复后从外部改写导入表 | `ERROR_PARTIAL_COPY (299)` 持续 |
| 主线程恢复后从外部 `LoadLibraryW` | 返回 0 |
| 手动映射（ManualMap）注入 | 导入表绑定依赖本进程模块基址，跨进程不可用 |
| GNames 自动探测 | `FNameInit` 失败，`ByteProperty` 字符串溯源不成立 |
| 静态扫描 `.data` 定位 FNamePool | 指针在文件内为未重定位 RVA，候选 3,824 个无法收敛 |

### 7.3 未验证

以下内容在本文档所属的分析中**没有实际运行验证**，仅从代码结构判断成立，不应作为结论引用：

- payload 的 `filter` 模式（EAC 放行 + 仅截断上报通道）
- 在联机对局中保持连接不被踢出
- ESP 绘制的实际画面正确性
- 世界坐标转屏幕在该游戏相机参数下的精确度

---

## 八、复现步骤

### 8.1 SDK 导出

1. 准备导出器（Dumper-7 派生的 UE4 版本），确认其为自包含 DLL
2. 编写配置，`GNamesOffset` 填 `6F27F00`，`SDKGenerationPath` 指向输出目录
3. 按第三章顺序：挂起启动游戏 → 注入 payload → 打桩 → 恢复 → 内部加载导出器
4. 导出器写入完成标记文件后，检查输出目录

判定成功：`OPP_classes.hpp` 大于 4 MB，`GObjects-Dump.txt` 大于 7 MB。

### 8.2 偏移校验

读取主模块 `.data` 段对应 RVA 处的 qword，与该 RVA 为 `0` 时应为有效指针结构进行比对。SDK 版本变更后必须重新校验，不得沿用旧值。

### 8.3 驱动分析

```
1. 从 PE 头解析映像基址与节表
2. 定位 VM 解释器（特征：0BF58476D1CE4E5B9 常量后接 imul/shr/xor 链）
3. 解析 4 张分派表，按有符号 4 字节自相对换算目标地址
4. 校验所有目标落在解释器区间内
5. 在 .rdata 定位 8 字节对齐的高熵数组
6. 对每个槽回溯 `mov imm64 → imul rsi → mov cs:off → sub` 链取常数
7. 按 `target = slot - const * h` 解密，h 取运行期值
```

---

## 九、说明

本文档所有数值均来自文件级静态解析或运行期实测。凡标注「未验证」的部分，均未在本文档所属分析中实际运行，不应视为已成立的结论。

游戏版本更新后，本文档中的偏移、RVA、常量、哈希全部失效，需重新提取。

---

## 交流

公开技术探讨 Q 群：**1102821216**（问题反馈、使用交流）