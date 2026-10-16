# TOT Dumping & EAC Tinkering Notes

Straight up first: these are my own analysis notes. It started because I wanted to see what EAC is actually doing. This is not a cheat, and it does not teach you how to cheat. Don't come to me if you get kicked or banned. Don't use it in online ranked. Repost freely — just keep this paragraph.

> 中文版见 [README.md](README.md).

---

The game is The Outlast Trials, sometimes called 逃生试炼 (Escape Trial) in Chinese, codenamed TOT.

The engine is UE 5.5, but RBG forked it themselves — it is not stock. The process is `TOTClient-Win64-Shipping.exe`, the launcher is `start_protected_game.exe`, anti-cheat is EAC via the EOS stack, and rendering is D3D12.

One pitfall up front: **health, stamina and position are server-authoritative**. Change them locally and the server overwrites them the next frame — it looks like "I changed it and nothing happened". So don't mistake "value edits don't stick" for a bug in your code.

Also, this game updates often, so every version bump means re-checking offsets. I don't have much time, so I only tested as far as I needed; I didn't play the game much either. I'll dig further when I have the energy — or when I feel like playing again.

---

## 1. Dumper-7 crashes on launch

The only error is `Could not find GNames!`

I looked into it: its signatures don't match this game.

- One is `48 8D 0D ?? ?? ?? ?? E8`, meaning `lea` immediately followed by `call`. In this game's constructor, `lea rcx, stru_146EB2C00` is followed by **three instructions** before the call
- The other, `FF 15 ?? ?? ?? ??` (call through IAT), also fails — the SRWLock init inside uses `call r14`, register-cached

Both paths are dead, so it can't find it.

It already has a hook for specifying things manually, it's just not configured by default. Two changes and it works.

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

`GNamesOffset` is the RVA of the FNamePool, in hex without the `0x`. You'll have to find it again after a version change.

`GameName` / `GameVersion` are filled in to skip the in-game name lookup — that call crashes on this game, so skip it when you can. Bonus: the output directory name comes out right too.

### Source changes

All the modified files are in `dumper7-patch/`. Just these few:

`Settings.h` / `Settings.cpp`: added a `GNamesOffset` config entry. Note you have to parse it with `strtoul(..., 16)` — `GetPrivateProfileIntA` doesn't understand hex, so `0x6EB2C00` reads back as 0. Also read `GameName`/`GameVersion` while I was in there.

`Generator.cpp`, in `InitEngineCore`: if an offset is configured, call `FName::Init(offset, GNames, true)` directly; fall back to auto-detection on failure.

`main.cpp` and `Generator.cpp`: added `StageLog()` writing to file, and wrapped each stage in `__try/__except`. You can't skip this — when this game crashes the console goes with it and you're left with nothing. With it, at least you have logs.

`NameArray.h/.cpp`: added `IsInitialized()`, to tell whether GNames actually initialized successfully.

> By the way, **don't touch its `ByIndex` addressing**. I initially assumed the pool was "variable-length compact, so you have to walk it header by header". After that change every name was wrong and memory ballooned to 9 GB. Careful data analysis confirmed it: the index is simply **byte offset within the chunk divided by 2**, and the stock `chunk + (idx & 0xFFFF) * 2` was correct all along.

### Building

Just build it with cl:

```bat
call "D:\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d <Dumper-7 source dir>
cl /nologo /O2 /std:c++latest /EHsc /MD /DWIN32 /D_WINDOWS /DNDEBUG /D_CONSOLE /DDumper_7_EXPORTS ^
   /IDumper /IDumper\Engine /IDumper\Engine\Private ... ^
   /Fo"out\clbuild\obj/" /c <27 source files, one per line>
link /nologo /DLL /OUT:Dumper-7.dll out\clbuild\obj\*.obj <a pile of system libs>
```

`/Fo"path/"` must end with a forward slash — with a backslash the `\"` swallows the quote.

### Injecting

You have to deal with EAC first — see the next section.

Once that's done, inject the compiled DLL. The easy way is to configure EACLoader's `InjectDll`, which injects automatically early in the launch; manually, `CreateRemoteThread + LoadLibraryW` after elevating works too.

If it worked, a console pops up in-game, roughly like this:

```
Initializing [Dumper-7]
GNames override: 0x6eb2c00
Found FChunkedFixedUObjectArray GObjects at offset 0x6f21838
Overwrote offset: 'FNamePool GNames' set as offset 0x6EB2C00
...
NameArray::FNameBlockOffsetBits: 0x10
Generating SDK took (6659.48ms)
```

The full SDK in about six seconds. Press F6 to unload when you're done.

---

## 2. What EAC is actually doing

The game gets the anti-cheat interface from `EOS_Platform_GetAntiCheatClientInterface`, then opens a session with `BeginSession`, and the client talks back and forth with the server. Detection results are reported through the `AddNotifyMessageToServer` channel.

The client never bans anyone itself — it only reports. The evidence goes to the server, and the server decides what to do.

That leaves two places to work on:

One is to simply not let it come up (stub): replace all 8 EOS anti-cheat exports with your own stubs, and EAC is effectively absent. I tested this online and got kicked; single-player I never tried.

The other is to let it run normally and only cut the reporting channel (filter): authentication works, no kick. But EAC really is doing its job, and it can see what you put in — I tried a DLL with hooks and the game wouldn't even start.

I normally use the first one.

### Implementation

The code is in `eac-bypass/`. I wrote a loader that does this:

Launch the game (`Launch=direct` starts the exe directly; `Launch=eac` starts the EAC service first, then the game), then inject the payload before EAC has its callbacks in place.

Inside the game process, the payload:

Patches the import tables (IAT, delay imports and export table) to replace all 8 anti-cheat functions; watches `CreateProcessW` and blocks the game from relaunching into the EAC bootstrapper itself (`BlockRelaunch=1`); also blocks `CrashReportClient.exe` — on a crash it uploads a minidump containing the module list, and that must not run; finally it unlinks itself from the PEB module list.

The config looks like this; examples are in `eac-bypass/cfg/`:

```ini
Launch=direct      ; direct=launch the game directly / eac=start the EAC service first
Mode=stub          ; stub=stub out the anti-cheat exports / filter=let EAC run, cut reporting only
Report=drop        ; drop=discard reports / pass=let them through
BlockRelaunch=1    ; refuse the game relaunching itself into the EAC bootstrapper
```

Build with `src\build.ps1` — one command with MinGW produces `EACPayload.dll` and `EACLoader.exe`.

---

## 3. What happens after all this

You get kicked, but not banned. I was kicked over and over and never banned.

On a kick, the game shows:

```
你已被踢出服务器。
Authentication timed out (1/3)
```

You stubbed out `BeginSession`, so the game thinks the session is established, while the server never received a real EAC session. It waits, gives up, and kicks.

### A hidden pitfall: how you launch

With `Launch=direct`, the game's own log (`%LOCALAPPDATA%\OPP\Saved\Logs\OPP.log`) shows this:

```
LogEOSAntiCheat: [AntiCheatClient] Anti-cheat client not available. ...
LogOnlineRBAntiCheat: Error: OSS: Can't get a handle to the "Anti-Cheat Client Interface".
LogOnline: Warning: OSS: The game was launched with the incorrect executable.
           Launching "Easy Anti-Cheat" Bootstrapper: ...\start_protected_game.exe
```

The third line means the game noticed the launch method was wrong and tried to bring up the EAC bootstrapper itself; after `BlockRelaunch` denied it, it keeps running in a crippled state.

Switch to `Launch=eac` and those two errors disappear, leaving only a warning. Always check this log when debugging.

---

## 4. With EAC running, you can't read memory from outside

I originally wanted the "read memory externally + draw externally" route — never entering the game process at all, the cleanest option, and EAC has nothing to inspect. I tried it and hit a wall.

```
ReadProcessMemory            → err=5
NtReadVirtualMemory (ntdll)  → 0xC0000022
raw syscall (hand-rolled stub to bypass ntdll) → 0xC0000022
NtQueryVirtualMemory         → allowed
EnumProcessModulesEx / Module32 / PEB queries → all blocked
OpenProcess(PROCESS_ALL_ACCESS) → succeeds (after elevating)
```

Even a raw syscall is denied, so the block is in the kernel — no amount of user-mode trickery helps. Elevation doesn't help either: you get the handle, but not the read.

`tools/read_routes.py` is what tests this; reproduce it yourself.

So the situation is:

- **stub mode**: you can read anything, inject anything — but you get kicked online
- **EAC running normally**: no kick, but you can't read memory from outside

To have both, you'd have to move the reading into the game process (inject a read-only DLL) and then do no hooks at all — touching rendering or windows counts as hooking, and that's the most detectable thing you can do. Unlink from the module list, wipe the PE header. But a kernel VAD-tree scan of user mode can't be dodged. Accept it.

---

## 5. What this game's memory looks like

FNamePool (a.k.a. GNames) RVA is `0x6EB2C00`; GObjects is `0x6F21838`, a FChunkedFixedUObjectArray with item size 0x18.

The measured pool layout: `pool+0x08` is MaxChunkIndex (190), `pool+0x0C` is ByteCursor, and `pool+0x10` *is* the chunk-pointer array itself — **note that there is no extra dereference here**. I dereferenced one level too many at first and wasted half a day.

Chunk size is 0x20000 (128 KB). The FNameEntry header is 2 bytes: `length = header >> 6`, `wide flag = header & 1`. Entries are 2-byte aligned, so there's 1 byte of padding.

The index is **byte offset within the chunk divided by 2**, not the nth entry, hence bits = 16. To verify, look at the start of chunk[0]: `0 → None`, `3 → ByteProperty`, `10 → IntProperty`, `17 → BoolProperty` — which matches "offset ÷ 2".

Common offsets:

```
UObject::Class / Name                    0x10 / 0x18
AActor::RootComponent                    0x140
USceneComponent::RelativeLocation/Rot    0x124 / 0x130
ARBPawn::Health / bDead / CharLocation   0x5418 / 0x5454 / 0x4B48
ARBPlayer::stamina                       0x7130
ARBNPC::npcName / NPCType                0x5A70 / 0x58C0
AController::Pawn                        0x260
APlayerController::PlayerCameraManager   0x2C8
Camera POV                               CameraManager + 0x1C30 + 0x10, then +0 / +0xC / +0x18
ACharacter::Mesh / CharacterMovement     0x2A0 / 0x2A8
UCharacterMovement::MaxWalkSpeed         0x1AC
```

Class names: the player is `RBPlayer`, NPCs are `RBNPC`, the player controller is `RBController`.

Also, entries with the `Default__` prefix are class default objects (CDOs) — they're not in the scene, so filter them out, otherwise your list is nothing but those.

The full SDK is in `sdk/` — 1,400+ CppSDK files, plus the UE usmap and an idmap for IDA. Just search it directly.

---

## 6. Pitfalls I hit

Dumper-7 can't find GNames — don't bother rewriting signatures, just configure the offset.

Misreading the FNamePool index — I thought it was the nth entry and switched to walking by header, which made every name wrong and pushed memory to 9 GB. The index is byte offset ÷ 2.

`GetPrivateProfileIntA` doesn't do hex — `0x6EB2C00` reads back as 0.

`/Fo"path\"` in a `.bat` — the trailing backslash eats the quote and the whole command fails.

MSBuild won't build it — use cl directly; don't burn time on SDK versions and project paths.

Elevation is required — the EAC driver strips read-memory rights from normal-privilege processes (`err=5`); only after elevating do you get ALL_ACCESS.

Hand-written injector — set the FFI return type, otherwise 64-bit pointers truncate to 0 and you get `LoadLibraryW @ 0x0`.

A crash leaves nothing behind — add stage logging (to file) and SEH to Dumper-7, or you have nothing to debug with.

Block crash reporting — `CrashReportClient.exe` uploads a minidump with the module list; deny it at `CreateProcessW`.

---

## 7. Misc

To reproduce it yourself: neutralize the anti-cheat first (stub), inject the patched Dumper-7, dump, then F6 to unload.

The patched files are in `dumper7-patch/`, the EAC code is in `eac-bypass/`, the analysis scripts are in `tools/`, and the SDK is in `sdk/`.

Star it if it's useful, skip it if not — it's mainly a record for myself.

QQ group 1102821216 — say where you saw it when you join, otherwise you won't get in.

---

2026-10-11: The SDK dumps fine and I've done one round of testing on EAC's behavior. That's where it stands for now — more when I have the time.
