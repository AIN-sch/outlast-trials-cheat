// EACPayload.dll - instruments and controls the EOS anti-cheat inside the host game.
//
// Every anti-cheat entry point the game uses is intercepted, so the debug console
// shows a live trace of what EAC is asked to do and what it tries to report:
//
//   [api]    EOS_Platform_GetAntiCheatClientInterface / BeginSession / EndSession
//            AddNotify* / RemoveNotify* / ReceiveMessageFromServer, with arguments
//            and the real or stubbed return value
//   [rpt]    every message EAC produces for the server, with size and hex preview,
//            and the drop / forward decision
//   [viol]   every integrity violation EAC tries to hand to the game
//   [mod]    every DLL loaded into or unloaded from the game process, which is how
//            the EAC user-mode module attaching is observed
//
// Modes, selected by EACBYPASS_MODE:
//   stub   (default) none of it reaches EAC; calls are answered locally
//   filter           calls pass through to real EAC, only its reporting is cut
//
// Build: g++ -O2 -s -shared -static -o EACPayload.dll EACPayload.cpp

#include <windows.h>
#include <winnt.h>
#include <cstdarg>
#include <string>
#include <vector>

#define MAX_PATH_LONG 4096

static HANDLE g_log = INVALID_HANDLE_VALUE;
static HANDLE g_con = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_log_lock;
static int g_log_lock_ready = 0;
static int g_con_muted = 0;
static int g_is_filter = 0;
static int g_report_drop = 1;
static unsigned int g_report_count = 0;
static unsigned int g_violation_count = 0;
static int g_hook_count = 0;
static wchar_t g_log_path[MAX_PATH_LONG] = { 0 };

// ------------------------------------------------------------------ logging

static void ts_prefix(char* buf, int size)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wsprintfA(buf, "[%02u:%02u:%02u.%03u] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    (void)size;
}

// The DLL notification callback runs on whichever thread loads a module, so several
// threads can log at once. Build the whole line including CRLF and write it in one
// call under a lock, otherwise lines interleave into unreadable text.
static void log_line(const char* text)
{
    char line[1200];
    ts_prefix(line, sizeof(line));

    int used = lstrlenA(line);
    int room = (int)sizeof(line) - used - 3;
    if (room > 0)
    {
        lstrcpynA(line + used, text, room);
    }
    lstrcatA(line, "\r\n");

    int len = lstrlenA(line);
    DWORD written = 0;

    if (g_log_lock_ready)
        EnterCriticalSection(&g_log_lock);
    if (g_log != INVALID_HANDLE_VALUE)
        WriteFile(g_log, line, (DWORD)len, &written, NULL);
    if (g_con != INVALID_HANDLE_VALUE && !g_con_muted)
        WriteFile(g_con, line, (DWORD)len, &written, NULL);
    if (g_log_lock_ready)
        LeaveCriticalSection(&g_log_lock);
}

static void log_fmt(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    wvsprintfA(buf, fmt, ap);
    va_end(ap);
    log_line(buf);
}

// Paths can contain non-ASCII characters, so encode them as UTF-8 and keep the
// console on code page 65001.
static void log_wide(const char* tag, const wchar_t* text)
{
    char buf[MAX_PATH_LONG * 2];
    buf[0] = '\0';
    if (text)
        WideCharToMultiByte(CP_UTF8, 0, text, -1, buf, (int)sizeof(buf) - 1, NULL, NULL);
    log_fmt("%s%s", tag, buf);
}

static void log_hex(const char* tag, const void* data, unsigned int size, unsigned int max_bytes)
{
    if (!data || !size)
    {
        log_fmt("%s <empty>", tag);
        return;
    }

    unsigned char* p = (unsigned char*)data;
    unsigned int n = (size < max_bytes) ? size : max_bytes;
    char buf[512];
    char* w = buf;
    *w = '\0';
    for (unsigned int i = 0; i < n; ++i)
    {
        wsprintfA(w, "%02X ", p[i]);
        w += 3;
    }
    if (size > n)
        lstrcatA(buf, "...");
    log_fmt("%s size=%u hex=%s", tag, size, buf);
}

// -------------------------------------------------------------- EOS surface

typedef UINT64 EOS_NotificationId;

struct msg_info
{
    void* client_data;
    const void* message_data;
    unsigned int message_size;
};

struct integrity_info
{
    void* client_data;
    int violation_type;
    const char* violation_message;
};

typedef void(__cdecl* msg_callback)(const msg_info*);
typedef void(__cdecl* integrity_callback)(const integrity_info*);

// real function pointers captured from the untouched import slots
static void* (__cdecl* g_real_get_iface)(void*) = NULL;
static int(__cdecl* g_real_begin)(void*, const void*) = NULL;
static int(__cdecl* g_real_end)(void*) = NULL;
static int(__cdecl* g_real_receive)(void*, const void*) = NULL;
static int(__cdecl* g_real_remove_msg)(void*, EOS_NotificationId) = NULL;
static int(__cdecl* g_real_remove_viol)(void*, EOS_NotificationId) = NULL;
static EOS_NotificationId(__cdecl* g_real_add_msg)(void*, const void*, void*, void*) = NULL;
static EOS_NotificationId(__cdecl* g_real_add_viol)(void*, const void*, void*, void*) = NULL;

static msg_callback g_game_msg_cb = NULL;
static integrity_callback g_game_viol_cb = NULL;
static int g_session_active = 0;

// ------------------------------------------------------------ report path

static void __cdecl our_msg_callback(const msg_info* info)
{
    if (!info)
        return;
    ++g_report_count;
    log_fmt("[rpt] #%u EAC -> server message (%s)", g_report_count,
        g_report_drop ? "dropped" : "forwarded");
    log_hex("[rpt]   payload", info->message_data, info->message_size, 48);
    if (!g_report_drop && g_game_msg_cb)
        g_game_msg_cb(info);
}

static void __cdecl our_violation_callback(const integrity_info* info)
{
    if (!info)
        return;
    ++g_violation_count;
    log_fmt("[viol] #%u integrity violation type=%d msg=%s (swallowed)",
        g_violation_count, info->violation_type,
        info->violation_message ? info->violation_message : "(null)");
    if (!g_report_drop && g_game_viol_cb)
        g_game_viol_cb(info);
}

// ------------------------------------------------------------ api wrappers

static void log_api_call(const char* name, const char* extra)
{
    log_fmt("[api] %s%s", name, extra ? extra : "");
}

// --- pass-through (filter mode): call real EAC, then log.

static void* __cdecl pass_get_iface(void* handle)
{
    void* r = g_real_get_iface ? g_real_get_iface(handle) : NULL;
    log_fmt("[api] GetAntiCheatClientInterface -> %p", r);
    return r;
}

static int __cdecl pass_begin(void* handle, const void* options)
{
    log_api_call("BeginSession requested (EAC running)", "");
    int r = g_real_begin ? g_real_begin(handle, options) : -1;
    g_session_active = (r == 0);
    log_fmt("[api] BeginSession -> %d (%s)", r, r == 0 ? "EOS_Success" : "error");
    return r;
}

static int __cdecl pass_end(void* handle)
{
    log_api_call("EndSession requested", "");
    int r = g_real_end ? g_real_end(handle) : -1;
    g_session_active = 0;
    log_fmt("[api] EndSession -> %d", r);
    return r;
}

static int __cdecl pass_receive(void* handle, const void* options)
{
    log_api_call("ReceiveMessageFromServer (server -> EAC)", "");
    int r = g_real_receive ? g_real_receive(handle, options) : -1;
    log_fmt("[api] ReceiveMessageFromServer -> %d", r);
    return r;
}

static int __cdecl pass_remove_msg(void* handle, EOS_NotificationId id)
{
    log_fmt("[api] RemoveNotifyMessageToServer id=%llu", (unsigned long long)id);
    return g_real_remove_msg ? g_real_remove_msg(handle, id) : -1;
}

static int __cdecl pass_remove_viol(void* handle, EOS_NotificationId id)
{
    log_fmt("[api] RemoveNotifyClientIntegrityViolated id=%llu", (unsigned long long)id);
    return g_real_remove_viol ? g_real_remove_viol(handle, id) : -1;
}

static EOS_NotificationId __cdecl pass_add_msg(void* handle, const void* options, void* client_data, void* callback)
{
    g_game_msg_cb = (msg_callback)callback;
    log_api_call("AddNotifyMessageToServer (callback hijacked)", "");
    if (!g_real_add_msg)
        return 0;
    return g_real_add_msg(handle, options, client_data, (void*)our_msg_callback);
}

static EOS_NotificationId __cdecl pass_add_viol(void* handle, const void* options, void* client_data, void* callback)
{
    g_game_viol_cb = (integrity_callback)callback;
    log_api_call("AddNotifyClientIntegrityViolated (callback hijacked)", "");
    if (!g_real_add_viol)
        return 0;
    return g_real_add_viol(handle, options, client_data, (void*)our_violation_callback);
}

// --- stubs (stub mode): answer locally, log what EAC was asked to do.

static uintptr_t g_dummy_handle = 0x45414300u;

static void* __cdecl stub_get_iface(void*)
{
    log_api_call("GetAntiCheatClientInterface (stubbed)", " -> dummy handle");
    return &g_dummy_handle;
}

static int __cdecl stub_begin(void*, const void*)
{
    g_session_active = 1;
    log_api_call("BeginSession (stubbed)", " -> EOS_Success, EAC never starts");
    return 0;
}

static int __cdecl stub_end(void*, const void*)
{
    g_session_active = 0;
    log_api_call("EndSession (stubbed) -> EOS_Success", "");
    return 0;
}

static int __cdecl stub_receive(void*, const void*)
{
    log_api_call("ReceiveMessageFromServer (stubbed)", " -> EOS_Success, not given to EAC");
    return 0;
}

static int __cdecl stub_remove_msg(void*, EOS_NotificationId)
{
    log_api_call("RemoveNotifyMessageToServer (stubbed) -> EOS_Success", "");
    return 0;
}

static int __cdecl stub_remove_viol(void*, EOS_NotificationId)
{
    log_api_call("RemoveNotifyClientIntegrityViolated (stubbed) -> EOS_Success", "");
    return 0;
}

static EOS_NotificationId __cdecl stub_add_msg(void*, const void*, void* client_data, void* callback)
{
    g_game_msg_cb = (msg_callback)callback;
    log_api_call("AddNotifyMessageToServer (stubbed)", " -> dummy id, reports will never exist");
    (void)client_data;
    return (EOS_NotificationId)(uintptr_t)&g_dummy_handle;
}

static EOS_NotificationId __cdecl stub_add_viol(void*, const void*, void* client_data, void* callback)
{
    g_game_viol_cb = (integrity_callback)callback;
    log_api_call("AddNotifyClientIntegrityViolated (stubbed)", " -> dummy id, no violations possible");
    (void)client_data;
    return (EOS_NotificationId)(uintptr_t)&g_dummy_handle;
}

// ------------------------------------------------------------------ binding

struct binding
{
    const char* name;
    void* target;       // replacement for the import slot
    void** real_slot;   // where to store the original pointer
};

static binding kBindings[] =
{
    { "EOS_Platform_GetAntiCheatClientInterface",           NULL, (void**)&g_real_get_iface },
    { "EOS_AntiCheatClient_BeginSession",                   NULL, (void**)&g_real_begin },
    { "EOS_AntiCheatClient_EndSession",                     NULL, (void**)&g_real_end },
    { "EOS_AntiCheatClient_ReceiveMessageFromServer",       NULL, (void**)&g_real_receive },
    { "EOS_AntiCheatClient_AddNotifyMessageToServer",       NULL, (void**)&g_real_add_msg },
    { "EOS_AntiCheatClient_AddNotifyClientIntegrityViolated", NULL, (void**)&g_real_add_viol },
    { "EOS_AntiCheatClient_RemoveNotifyMessageToServer",    NULL, (void**)&g_real_remove_msg },
    { "EOS_AntiCheatClient_RemoveNotifyClientIntegrityViolated", NULL, (void**)&g_real_remove_viol },
};

static const int kBindingCount = (int)(sizeof(kBindings) / sizeof(kBindings[0]));

static void resolve_bindings(int is_filter)
{
    for (int i = 0; i < kBindingCount; ++i)
    {
        const char* n = kBindings[i].name;
        if (is_filter)
        {
            if (lstrcmpA(n, "EOS_Platform_GetAntiCheatClientInterface") == 0)
                kBindings[i].target = (void*)pass_get_iface;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_BeginSession") == 0)
                kBindings[i].target = (void*)pass_begin;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_EndSession") == 0)
                kBindings[i].target = (void*)pass_end;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_ReceiveMessageFromServer") == 0)
                kBindings[i].target = (void*)pass_receive;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_AddNotifyMessageToServer") == 0)
                kBindings[i].target = (void*)pass_add_msg;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_AddNotifyClientIntegrityViolated") == 0)
                kBindings[i].target = (void*)pass_add_viol;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_RemoveNotifyMessageToServer") == 0)
                kBindings[i].target = (void*)pass_remove_msg;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_RemoveNotifyClientIntegrityViolated") == 0)
                kBindings[i].target = (void*)pass_remove_viol;
        }
        else
        {
            if (lstrcmpA(n, "EOS_Platform_GetAntiCheatClientInterface") == 0)
                kBindings[i].target = (void*)stub_get_iface;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_BeginSession") == 0)
                kBindings[i].target = (void*)stub_begin;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_EndSession") == 0)
                kBindings[i].target = (void*)stub_end;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_ReceiveMessageFromServer") == 0)
                kBindings[i].target = (void*)stub_receive;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_AddNotifyMessageToServer") == 0)
                kBindings[i].target = (void*)stub_add_msg;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_AddNotifyClientIntegrityViolated") == 0)
                kBindings[i].target = (void*)stub_add_viol;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_RemoveNotifyMessageToServer") == 0)
                kBindings[i].target = (void*)stub_remove_msg;
            else if (lstrcmpA(n, "EOS_AntiCheatClient_RemoveNotifyClientIntegrityViolated") == 0)
                kBindings[i].target = (void*)stub_remove_viol;
        }
    }
}

static binding* find_binding(const char* name)
{
    for (int i = 0; i < kBindingCount; ++i)
    {
        if (lstrcmpA(name, kBindings[i].name) == 0)
            return &kBindings[i];
    }
    return NULL;
}

// IDA trims the extension when it prints an import module name, the PE descriptor
// normally keeps it, so match on the stem.
static int is_eosdk_module(const char* name)
{
    return _strnicmp(name, "EOSSDK-Win64-Shipping", 21) == 0;
}

// Resolve the real entry points up front so pass-through works even when the import
// declaration lives in a table this code does not walk.
static void capture_real_pointers(HMODULE eosdk)
{
    if (!eosdk)
        return;
    for (int i = 0; i < kBindingCount; ++i)
    {
        if (kBindings[i].real_slot && !*kBindings[i].real_slot)
        {
            void* p = (void*)GetProcAddress(eosdk, kBindings[i].name);
            if (p)
                *kBindings[i].real_slot = p;
        }
    }
}

static int patch_slot(void** slot, binding* b)
{
    if (!slot || !b || !b->target)
        return 0;

    ULONG_PTR original = (ULONG_PTR)*slot;
    if (original == (ULONG_PTR)b->target)
        return 0;

    DWORD old_prot = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old_prot))
        return 0;
    *slot = b->target;
    VirtualProtect(slot, sizeof(void*), old_prot, &old_prot);

    // Keep the genuine address for pass-through; never overwrite it with a wrapper.
    if (b->real_slot && !*b->real_slot && original)
        *b->real_slot = (void*)original;

    ++g_hook_count;
    log_fmt("[+] hooked %-52s original=%p", b->name, (void*)original);
    return 1;
}

static int patch_import_table(HMODULE module)
{
    BYTE* base = (BYTE*)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return -1;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return -1;

    DWORD imp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!imp_rva)
        return -1;

    int modules = 0;
    int saw_eosdk = 0;
    int patched = 0;

    IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + imp_rva);
    for (; desc->Name; ++desc)
    {
        const char* mod_name = (const char*)(base + desc->Name);
        ++modules;
        if (!is_eosdk_module(mod_name))
            continue;

        saw_eosdk = 1;
        IMAGE_THUNK_DATA* first = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
        IMAGE_THUNK_DATA* orig = desc->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA*)(base + desc->OriginalFirstThunk)
            : first;

        for (; orig->u1.AddressOfData; ++orig, ++first)
        {
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                continue;

            IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData);
            patched += patch_slot((void**)&first->u1.Function, find_binding((const char*)ibn->Name));
        }
    }

    log_fmt("[*] import table: %d modules, EOSSDK present=%s",
        modules, saw_eosdk ? "yes" : "no");
    return patched;
}

// Delay-loaded imports sit in their own directory and their IAT slots initially point
// at the delay helper, so replacing the slot means the helper never runs.
struct img_delay_descr
{
    DWORD attributes;
    DWORD rva_dll_name;
    DWORD rva_module_handle;
    DWORD rva_iat;
    DWORD rva_int;
    DWORD rva_bound_iat;
    DWORD rva_unload_iat;
    DWORD timestamp;
};

static int patch_delay_import_table(HMODULE module)
{
    BYTE* base = (BYTE*)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return -1;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return -1;

    DWORD dir_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    if (!dir_rva)
        return -1;

    int patched = 0;
    int entries = 0;
    img_delay_descr* dd = (img_delay_descr*)(base + dir_rva);

    for (; dd->attributes || dd->rva_dll_name || dd->rva_iat; ++dd)
    {
        if (!dd->rva_dll_name)
            continue;

        DWORD attrs_rva = dd->attributes & 1;
        const char* name = (const char*)(attrs_rva
            ? base + dd->rva_dll_name
            : base + (dd->rva_dll_name - (DWORD)(ULONG_PTR)module));
        ++entries;

        if (!is_eosdk_module(name))
            continue;

        DWORD iat_rva = attrs_rva ? dd->rva_iat : (dd->rva_iat - (DWORD)(ULONG_PTR)module);
        DWORD int_rva = attrs_rva ? dd->rva_int : (dd->rva_int - (DWORD)(ULONG_PTR)module);

        IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)(base + iat_rva);
        IMAGE_THUNK_DATA* names = int_rva ? (IMAGE_THUNK_DATA*)(base + int_rva) : iat;

        for (; names->u1.AddressOfData; ++names, ++iat)
        {
            if (names->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                continue;
            IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + names->u1.AddressOfData);
            patched += patch_slot((void**)&iat->u1.Function, find_binding((const char*)ibn->Name));
        }
    }

    log_fmt("[*] delay import table: %d entries, patched=%d", entries, patched);
    return patched;
}

// Redirecting the EOSSDK exports covers callers that resolve by name, including a
// delay helper that runs after this point.
static int patch_export_table(HMODULE module)
{
    BYTE* base = (BYTE*)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return -1;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return -1;

    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress)
        return -1;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    int patched = 0;
    for (DWORD i = 0; i < exp->NumberOfNames; ++i)
    {
        const char* nm = (const char*)(base + names[i]);
        binding* b = find_binding(nm);
        if (!b || !b->target)
            continue;

        DWORD* slot = &funcs[ordinals[i]];
        DWORD rva = (DWORD)((ULONG_PTR)b->target - (ULONG_PTR)module);
        if (*slot == rva)
            continue;

        DWORD old_prot = 0;
        if (!VirtualProtect(slot, sizeof(DWORD), PAGE_READWRITE, &old_prot))
            continue;
        *slot = rva;
        VirtualProtect(slot, sizeof(DWORD), old_prot, &old_prot);
        ++patched;
    }

    log_fmt("[*] export table: %d exported names, redirected=%d", exp->NumberOfNames, patched);
    return patched;
}

// ------------------------------------------------------- child process watch

static int contains_ci(const wchar_t* haystack, const wchar_t* needle)
{
    if (!haystack || !needle || !*needle)
        return 0;

    size_t nlen = lstrlenW(needle);
    for (const wchar_t* p = haystack; *p; ++p)
    {
        size_t i = 0;
        while (i < nlen && p[i] && (p[i] == needle[i]
            || (p[i] >= L'A' && p[i] <= L'Z' && p[i] + 32 == needle[i])
            || (needle[i] >= L'A' && needle[i] <= L'Z' && needle[i] + 32 == p[i])))
        {
            ++i;
        }
        if (i == nlen)
            return 1;
    }
    return 0;
}

typedef BOOL(__cdecl* create_process_fn)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static create_process_fn g_real_create_process = NULL;
static int g_block_relaunch = 1;
static int g_relaunch_seen = 0;

// The game leaves the direct-launch path by re-spawning through the EAC bootstrapper.
// Watching CreateProcessW shows who does it and lets it be refused.
static BOOL __cdecl hook_create_process(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES proc_attr,
    LPSECURITY_ATTRIBUTES thread_attr, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR cwd,
    LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    const wchar_t* shown = app ? app : cmd;
    if (shown)
        log_wide("[proc] CreateProcessW: ", shown);
    else
        log_line("[proc] CreateProcessW (no name)");

    if (shown && (contains_ci(shown, L"start_protected_game") || contains_ci(shown, L"EasyAntiCheat")))
    {
        ++g_relaunch_seen;
        log_fmt("[!] #%d EAC bootstrapper relaunch attempt detected", g_relaunch_seen);
        if (g_block_relaunch)
        {
            log_line("[!] refused (BlockRelaunch=1)");
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        log_line("[!] allowed through (BlockRelaunch=0)");
    }

    // The UE crash handler spawns CrashReportClient to upload a minidump whose
    // module list would show the injected payload. Never let it start.
    if (shown && contains_ci(shown, L"CrashReportClient"))
    {
        log_line("[!] crash reporter launch refused (no minidump upload)");
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    if (!g_real_create_process)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return g_real_create_process(app, cmd, proc_attr, thread_attr, inherit, flags, env, cwd, si, pi);
}

// Patch one named kernel32 import of the main module.
static int patch_host_imports(HMODULE module)
{
    BYTE* base = (BYTE*)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return -1;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return -1;

    DWORD imp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!imp_rva)
        return -1;

    int patched = 0;
    IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + imp_rva);
    for (; desc->Name; ++desc)
    {
        const char* mod_name = (const char*)(base + desc->Name);
        if (_strnicmp(mod_name, "KERNEL32", 8) != 0 && _strnicmp(mod_name, "kernelbase", 10) != 0)
            continue;

        IMAGE_THUNK_DATA* first = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
        IMAGE_THUNK_DATA* orig = desc->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA*)(base + desc->OriginalFirstThunk)
            : first;

        for (; orig->u1.AddressOfData; ++orig, ++first)
        {
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                continue;

            IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData);
            if (lstrcmpA((const char*)ibn->Name, "CreateProcessW") != 0)
                continue;

            ULONG_PTR original = first->u1.Function;
            DWORD old_prot = 0;
            if (!VirtualProtect(&first->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &old_prot))
                continue;
            first->u1.Function = (ULONG_PTR)hook_create_process;
            VirtualProtect(&first->u1.Function, sizeof(ULONG_PTR), old_prot, &old_prot);

            if (!g_real_create_process)
                g_real_create_process = (create_process_fn)original;

            log_fmt("[+] CreateProcessW watched (original=%p, block=%d)",
                (void*)original, g_block_relaunch);
            ++patched;
        }
    }
    return patched;
}

// --------------------------------------------------------- internal user DLL

// Loading from inside the process still works after the anti-cheat hardens the
// process, where an external VirtualAllocEx is refused.
static void load_user_dlls_internal(void)
{
    wchar_t list[4096] = { 0 };
    DWORD n = GetEnvironmentVariableW(L"EACBYPASS_INJECT_DLL", list, 4096);
    if (n == 0 || !list[0])
        return;

    wchar_t delay_buf[32] = { 0 };
    int delay = 0;
    if (GetEnvironmentVariableW(L"EACBYPASS_INJECT_DELAY", delay_buf, 32) > 0)
        delay = _wtoi(delay_buf);

    if (delay > 0)
    {
        log_fmt("[*] internal inject: waiting %d ms before loading user DLLs", delay);
        Sleep((DWORD)delay);
    }

    log_line("[*] internal user DLL load starting");
    wchar_t* cursor = list;
    while (cursor && *cursor)
    {
        wchar_t* sep = cursor;
        while (*sep && *sep != L';' && *sep != L'|')
            ++sep;

        wchar_t saved = *sep;
        *sep = L'\0';

        // trim
        wchar_t* start = cursor;
        while (*start == L' ' || *start == L'\t')
            ++start;
        wchar_t* end = start + lstrlenW(start);
        while (end > start && (end[-1] == L' ' || end[-1] == L'\t'))
            --end;
        *end = L'\0';

        if (*start)
        {
            HMODULE h = LoadLibraryW(start);
            if (h)
                log_fmt("[+] internal load ok   : base=%p  ", (void*)h), log_wide("", start);
            else
                log_fmt("[-] internal load FAIL : GetLastError=%lu  ", GetLastError()), log_wide("", start);
        }

        if (!saved)
            break;
        cursor = sep + 1;
    }
}

// ------------------------------------------------------------- Steam DRM

static int g_steam_patched = 0;

// Returning 0 means "no restart needed". Without this the game asks Steam to relaunch
// it through the official path, which brings the EAC bootstrapper straight back.
static int __cdecl steam_no_restart(void)
{
    return 0;
}

static int patch_steam_exports(HMODULE module)
{
    if (!module || g_steam_patched)
        return 0;

    BYTE* base = (BYTE*)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return -1;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return -1;

    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress)
        return -1;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i)
    {
        const char* nm = (const char*)(base + names[i]);
        if (lstrcmpA(nm, "SteamAPI_RestartAppIfNecessary") != 0)
            continue;

        DWORD* slot = &funcs[ordinals[i]];
        DWORD rva = (DWORD)((ULONG_PTR)steam_no_restart - (ULONG_PTR)module);
        if (*slot == rva)
            return 1;

        DWORD old_prot = 0;
        if (!VirtualProtect(slot, sizeof(DWORD), PAGE_READWRITE, &old_prot))
            return -1;
        *slot = rva;
        VirtualProtect(slot, sizeof(DWORD), old_prot, &old_prot);

        g_steam_patched = 1;
        log_fmt("[steam] SteamAPI_RestartAppIfNecessary neutralised (export ordinal %u)",
            exp->Base + ordinals[i]);
        return 1;
    }

    log_line("[steam] SteamAPI_RestartAppIfNecessary not found in export table");
    return 0;
}

// --------------------------------------------------------- console mirroring

// The injected DLL writes its diagnostics to the console with stderr. That window
// disappears with the process, so new console lines are copied into our log.
// Opt-in via EACBYPASS_MIRROR=1: while active our own console output is muted, which
// both keeps the screen readable and stops the mirror from echoing itself.
static DWORD WINAPI console_mirror(LPVOID)
{
    HANDLE con = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (con == INVALID_HANDLE_VALUE)
    {
        log_line("[-] console mirror: CONOUT$ unavailable");
        return 0;
    }

    CONSOLE_SCREEN_BUFFER_INFO info;
    if (!GetConsoleScreenBufferInfo(con, &info))
    {
        CloseHandle(con);
        return 0;
    }

    g_con_muted = 1;
    log_line("[*] console mirror active (our own console output is muted)");

    std::vector<std::wstring> prev;
    wchar_t text[512];
    int idle = 0;

    while (idle < 2000)
    {
        Sleep(120);

        CONSOLE_SCREEN_BUFFER_INFO cur;
        if (!GetConsoleScreenBufferInfo(con, &cur))
            break;

        std::vector<std::wstring> now;
        SHORT last = cur.dwCursorPosition.Y;
        for (SHORT row = 0; row <= last; ++row)
        {
            DWORD read = 0;
            COORD pos;
            pos.X = 0;
            pos.Y = row;
            if (!ReadConsoleOutputCharacterW(con, text, 500, pos, &read))
                continue;
            if (read >= 500)
                read = 499;
            text[read] = L'\0';

            int len = 0;
            while (text[len])
                ++len;
            while (len > 0 && (text[len - 1] == L' ' || text[len - 1] == L'\t'))
                text[--len] = L'\0';
            now.push_back(std::wstring(text, (size_t)len));
        }

        // Emit only what is past the common prefix with the previous snapshot.
        size_t same = 0;
        while (same < prev.size() && same < now.size() && prev[same] == now[same])
            ++same;

        for (size_t i = same; i < now.size(); ++i)
        {
            if (now[i].empty())
                continue;
            log_wide("[con] ", now[i].c_str());
            idle = 0;
        }

        prev.swap(now);
        ++idle;
    }

    log_line("[*] console mirror ended");
    CloseHandle(con);
    return 0;
}

static void start_console_mirror(void)
{
    wchar_t flag[8] = { 0 };
    // Off by default: the mirror is a diagnostic aid, not part of normal operation.
    if (GetEnvironmentVariableW(L"EACBYPASS_MIRROR", flag, 8) == 0 || lstrcmpW(flag, L"0") == 0)
        return;

    HANDLE th = CreateThread(NULL, 0, console_mirror, NULL, 0, NULL);
    if (th)
        CloseHandle(th);
}

// ------------------------------------------------- DLL activity notification

struct my_unicode_string
{
    USHORT length;
    USHORT maximum_length;
    PWSTR buffer;
};

typedef struct _LDR_DLL_NOTIFICATION_DATA
{
    ULONG flags;
    const my_unicode_string* full_dll_name;
    const my_unicode_string* base_dll_name;
    PVOID dll_base;
    ULONG size_of_image;
} LDR_DLL_NOTIFICATION_DATA;

typedef VOID(__cdecl* PLDR_DLL_NOTIFICATION_FUNCTION)(ULONG, const LDR_DLL_NOTIFICATION_DATA*, PVOID);
typedef LONG(__cdecl* pLdrRegisterDllNotification)(ULONG, PLDR_DLL_NOTIFICATION_FUNCTION, PVOID, PVOID*);

#define MY_DLL_NOTIFICATION_LOADED   1
#define MY_DLL_NOTIFICATION_UNLOADED 2

static VOID __cdecl dll_notification(ULONG reason, const LDR_DLL_NOTIFICATION_DATA* data, PVOID)
{
    if (!data || !data->base_dll_name || !data->base_dll_name->buffer)
        return;

    char name[MAX_PATH_LONG];
    name[0] = '\0';
    WideCharToMultiByte(CP_UTF8, 0, data->base_dll_name->buffer,
        data->base_dll_name->length / sizeof(wchar_t), name, sizeof(name) - 1, NULL, NULL);

    if (reason == MY_DLL_NOTIFICATION_LOADED)
    {
        log_fmt("[mod] loaded   %-40s base=%p size=0x%X", name, data->dll_base, data->size_of_image);
        if (_strnicmp(name, "steam_api64.dll", 15) == 0)
            patch_steam_exports((HMODULE)data->dll_base);
    }
    else if (reason == MY_DLL_NOTIFICATION_UNLOADED)
    {
        log_fmt("[mod] unloaded %-40s base=%p", name, data->dll_base);
    }
}

static void start_dll_notification(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return;
    pLdrRegisterDllNotification reg =
        (pLdrRegisterDllNotification)GetProcAddress(ntdll, "LdrRegisterDllNotification");
    if (!reg)
    {
        log_line("[-] LdrRegisterDllNotification unavailable");
        return;
    }
    PVOID cookie = NULL;
    if (reg(0, dll_notification, NULL, &cookie) == 0)
        log_line("[+] DLL load notification registered (module activity is traced)");
    else
        log_line("[-] LdrRegisterDllNotification failed");
}

// ------------------------------------------------------------- module hiding

struct my_ldr_entry
{
    LIST_ENTRY in_load_order;
    LIST_ENTRY in_memory_order;
    LIST_ENTRY in_init_order;
    PVOID dll_base;
    PVOID entry_point;
    ULONG size_of_image;
    my_unicode_string full_dll_name;
    my_unicode_string base_dll_name;
};

struct my_peb_ldr
{
    ULONG length;
    BOOLEAN initialized;
    PVOID ss_handle;
    LIST_ENTRY in_load_order;
    LIST_ENTRY in_memory_order;
    LIST_ENTRY in_init_order;
};

struct my_peb
{
    BYTE reserved1[2];
    BYTE being_debugged;
    BYTE reserved2[1];
    PVOID reserved3[2];
    my_peb_ldr* ldr;
};

static void* get_peb(void)
{
    void* peb = NULL;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

static int hide_module(HMODULE module)
{
    my_peb* peb = (my_peb*)get_peb();
    if (!peb || !peb->ldr)
        return -1;

    LIST_ENTRY* head = &peb->ldr->in_memory_order;
    for (LIST_ENTRY* e = head->Flink; e && e != head; e = e->Flink)
    {
        my_ldr_entry* entry = CONTAINING_RECORD(e, my_ldr_entry, in_memory_order);
        if (entry->dll_base != module)
            continue;

        entry->in_load_order.Blink->Flink = entry->in_load_order.Flink;
        entry->in_load_order.Flink->Blink = entry->in_load_order.Blink;
        entry->in_memory_order.Blink->Flink = entry->in_memory_order.Flink;
        entry->in_memory_order.Flink->Blink = entry->in_memory_order.Blink;
        entry->in_init_order.Blink->Flink = entry->in_init_order.Flink;
        entry->in_init_order.Flink->Blink = entry->in_init_order.Blink;
        return 0;
    }
    return -1;
}

// --------------------------------------------------------------------- worker

static DWORD WINAPI worker(LPVOID param)
{
    HMODULE self = (HMODULE)param;

    wchar_t console_flag[8] = { 0 };
    if (GetEnvironmentVariableW(L"EACBYPASS_CONSOLE", console_flag, 8) == 0
        || lstrcmpW(console_flag, L"0") != 0)
    {
        if (!GetConsoleWindow() && AllocConsole())
        {
            SetConsoleTitleW(L"EACPayload debug console");
            SetConsoleOutputCP(CP_UTF8);
            g_con = CreateFileA("CONOUT$", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, 0, NULL);
            if (g_con == INVALID_HANDLE_VALUE)
                g_con = INVALID_HANDLE_VALUE;
        }
    }

    wchar_t mode_buf[16] = { 0 };
    GetEnvironmentVariableW(L"EACBYPASS_MODE", mode_buf, 16);
    g_is_filter = (lstrcmpiW(mode_buf, L"filter") == 0);

    wchar_t report_buf[16] = { 0 };
    if (GetEnvironmentVariableW(L"EACBYPASS_REPORT", report_buf, 16) > 0)
        g_report_drop = (lstrcmpiW(report_buf, L"pass") != 0);

    wchar_t block_buf[8] = { 0 };
    if (GetEnvironmentVariableW(L"EACBYPASS_BLOCK_RELAUNCH", block_buf, 8) > 0)
        g_block_relaunch = (lstrcmpW(block_buf, L"0") != 0);

    log_line("================================================");
    log_fmt("[*] EACPayload attached, pid=%lu", GetCurrentProcessId());
    log_wide("[*] log file      : ", g_log_path);
    log_fmt("[*] mode=%s  report=%s", g_is_filter ? "filter" : "stub",
        g_report_drop ? "drop" : "pass");
    log_line("================================================");

    // Register module tracing first so nothing that loads afterwards is missed.
    start_dll_notification();

    log_fmt("[*] main module = %p", (void*)self);
    HMODULE eosdk = NULL;
    for (int i = 0; i < 100 && !eosdk; ++i)
    {
        eosdk = GetModuleHandleW(L"EOSSDK-Win64-Shipping.dll");
        if (!eosdk)
            Sleep(20);
    }
    if (eosdk)
        log_fmt("[*] EOSSDK loaded at %p", (void*)eosdk);
    else
        log_line("[!] EOSSDK-Win64-Shipping.dll not present in this process");

    resolve_bindings(g_is_filter);

    HMODULE main_mod = GetModuleHandleW(NULL);
    wchar_t main_path[MAX_PATH_LONG] = { 0 };
    GetModuleFileNameW(main_mod, main_path, MAX_PATH_LONG);
    log_wide("[*] main module path : ", main_path);
    log_fmt("[*] main module base : %p", (void*)main_mod);

    capture_real_pointers(eosdk);

    int iat = patch_import_table(main_mod);
    int delay = patch_delay_import_table(main_mod);
    int eat = patch_export_table(eosdk);
    int host = patch_host_imports(main_mod);

    log_fmt("[*] anti-cheat entry points hooked: %d / %d (iat=%d delay=%d eat=%d)",
        g_hook_count, kBindingCount, iat, delay, eat);
    if (g_hook_count < kBindingCount)
        log_line("[!] not every entry point was reachable, review the table report above");
    log_fmt("[*] host API watched: %d (CreateProcessW)", host);

    // steam_api64 may already be present; otherwise the load notification handles it.
    HMODULE steam = GetModuleHandleW(L"steam_api64.dll");
    if (steam)
        patch_steam_exports(steam);
    else
        log_line("[*] steam_api64 not loaded yet, watching for it");

    if (hide_module(self) == 0)
        log_line("[+] self unlinked from PEB loader lists");
    else
        log_line("[-] module hiding failed");

    log_line("------------------------------------------------");
    log_line(" watching EAC activity, see [api] [rpt] [viol] [mod] [proc]");
    log_line("------------------------------------------------");

    start_console_mirror();
    load_user_dlls_internal();
    return 0;
}
// --------------------------------------------------------------- entry point

static void open_log(void)
{
    if (!GetTempPathW(MAX_PATH_LONG, g_log_path))
        lstrcpyW(g_log_path, L".\\");
    lstrcatW(g_log_path, L"EACPayload.log");

    // Rewrite on every session: the file stays small and always describes the
    // current process rather than accumulating stale runs.
    g_log = CreateFileW(g_log_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(inst);
        InitializeCriticalSection(&g_log_lock);
        g_log_lock_ready = 1;
        open_log();
        HANDLE th = CreateThread(NULL, 0, worker, (LPVOID)inst, 0, NULL);
        if (th)
            CloseHandle(th);
    }
    return TRUE;
}
