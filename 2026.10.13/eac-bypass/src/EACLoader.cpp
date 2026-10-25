// EACLoader.exe - single-file launcher / injector for The Outlast Trials.
//
// Two independent DLL injections:
//   1. EACPayload.dll  (embedded resource 101) - handles EAC, injected the moment
//      the game process exists, before its main thread runs.
//   2. the user DLL list from InjectDll - injected separately, after an optional
//      delay, so a failure on either side never blocks the other.
//
// Launch=direct : launch the game suspended, bypassing the EAC bootstrapper.
// Launch=eac    : start the EasyAntiCheat_EOS service first, then inject.
// Launch=watch  : stay resident, wait for the game process to appear, then inject.
//
// Build: g++ -O2 -s -o EACLoader.exe EACLoader.cpp payload_res.o -static

#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>
#include <utility>
#include <map>

#define IDR_PAYLOAD   101
#define MAX_PATH_LONG 4096

typedef std::pair<std::wstring, std::wstring> env_pair;

static HANDLE g_out_log = INVALID_HANDLE_VALUE;

// Mirror everything to a file: an elevated process cannot have its stdout
// redirected by the caller, and the log is what gets checked after a run.
static void out(const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    wvsprintfA(buf, fmt, ap);
    va_end(ap);

    fputs(buf, stdout);
    fflush(stdout);

    if (g_out_log != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(g_out_log, buf, (DWORD)lstrlenA(buf), &written, NULL);
    }
}

static void open_out_log(void)
{
    wchar_t path[MAX_PATH_LONG] = { 0 };
    if (!GetTempPathW(MAX_PATH_LONG, path))
        lstrcpyW(path, L".\\");
    lstrcatW(path, L"EACLoader.log");
    g_out_log = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

// wsprintfA has no %ls support, so wide values are converted explicitly. Doing it
// here rather than relying on the CRT locale keeps non-ASCII paths intact.
static std::string u8(const std::wstring& text)
{
    if (text.empty())
        return std::string();

    int need = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), NULL, 0, NULL, NULL);
    if (need <= 0)
        return std::string();

    std::string result;
    result.resize((size_t)need);
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), &result[0], need, NULL, NULL);
    return result;
}

static void pause_if_configured(int pause)
{
    if (!pause)
        return;
    out("\npress Enter to close this window...\n");
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
    {
    }
}

// The manifest requests elevation, so this should always report yes when launched
// through explorer. It is reported anyway so a missing manifest is obvious.
static int is_elevated(void)
{
    BOOL admin = FALSE;
    PSID group = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &group))
    {
        CheckTokenMembership(NULL, group, &admin);
        FreeSid(group);
    }
    return admin != FALSE;
}

static std::wstring to_lower_w(const std::wstring& s)
{
    std::wstring r = s;
    for (size_t i = 0; i < r.size(); ++i)
    {
        if (r[i] >= L'A' && r[i] <= L'Z')
            r[i] = (wchar_t)(r[i] - L'A' + L'a');
    }
    return r;
}

static void trim_inplace(std::wstring& s)
{
    size_t b = s.find_first_not_of(L" \t\r\n");
    size_t e = s.find_last_not_of(L" \t\r\n");
    s = (b == std::wstring::npos) ? std::wstring() : s.substr(b, e - b + 1);
}

static bool read_whole_file(const std::wstring& path, std::vector<unsigned char>& bytes)
{
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER size;
    if (!GetFileSizeEx(f, &size) || size.QuadPart <= 0 || size.QuadPart > (16 << 20))
    {
        CloseHandle(f);
        return false;
    }

    bytes.resize((size_t)size.QuadPart);
    DWORD read = 0;
    BOOL ok = ReadFile(f, bytes.data(), (DWORD)bytes.size(), &read, NULL);
    CloseHandle(f);
    if (!ok)
        return false;
    bytes.resize(read);
    return true;
}

// The profile API only understands ANSI and UTF-16, so non-ASCII paths get mangled
// when the file is UTF-8. Decode explicitly instead.
static std::wstring decode_text(const std::vector<unsigned char>& b)
{
    if (b.size() >= 2 && b[0] == 0xFF && b[1] == 0xFE)
        return std::wstring((const wchar_t*)(b.data() + 2), (b.size() - 2) / sizeof(wchar_t));

    const char* p = (const char*)b.data();
    size_t n = b.size();
    if (n >= 3 && (unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF)
    {
        p += 3;
        n -= 3;
    }

    UINT cp = CP_UTF8;
    int need = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p, (int)n, NULL, 0);
    if (need <= 0)
    {
        cp = CP_ACP;
        need = MultiByteToWideChar(cp, 0, p, (int)n, NULL, 0);
        if (need <= 0)
            return std::wstring();
    }

    std::wstring text;
    text.resize((size_t)need);
    MultiByteToWideChar(cp, (cp == CP_UTF8) ? MB_ERR_INVALID_CHARS : 0, p, (int)n, &text[0], need);
    return text;
}

// Parse the [EACBypass] section, encoding agnostic and case insensitive.
static void load_ini(const std::wstring& path, std::map<std::wstring, std::wstring>& kv)
{
    std::vector<unsigned char> bytes;
    if (!read_whole_file(path, bytes))
        return;

    std::wstring text = decode_text(bytes);
    bool in_section = false;
    size_t pos = 0;

    while (pos <= text.size())
    {
        size_t nl = text.find(L'\n', pos);
        std::wstring line = (nl == std::wstring::npos) ? text.substr(pos) : text.substr(pos, nl - pos);
        pos = (nl == std::wstring::npos) ? text.size() + 1 : nl + 1;

        trim_inplace(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#')
            continue;

        if (line[0] == L'[')
        {
            size_t close = line.find(L']');
            std::wstring name = (close == std::wstring::npos) ? line.substr(1) : line.substr(1, close - 1);
            trim_inplace(name);
            in_section = (to_lower_w(name) == L"eacbypass");
            continue;
        }

        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos || !in_section)
            continue;

        std::wstring key = line.substr(0, eq);
        std::wstring value = line.substr(eq + 1);
        trim_inplace(key);
        trim_inplace(value);
        if (!key.empty())
            kv[to_lower_w(key)] = value;
    }
}

static std::wstring ini_value(const std::wstring& ini, const wchar_t* key, const wchar_t* def)
{
    static std::map<std::wstring, std::wstring> cache;
    static std::wstring loaded_path;

    if (loaded_path != ini)
    {
        cache.clear();
        load_ini(ini, cache);
        loaded_path = ini;
    }

    std::map<std::wstring, std::wstring>::iterator it = cache.find(to_lower_w(key));
    return (it == cache.end()) ? std::wstring(def) : it->second;
}

// Write a usable configuration so the tool works when shipped as a bare exe.
static void write_default_ini(const std::wstring& ini)
{
    std::wstring text =
        L"; EACLoader configuration - edit the values, keep the [EACBypass] section.\r\n"
        L"; GameDir=game root, GameExe=path relative to GameDir, InjectDll=your DLLs (';' separated)\r\n"
        L"; Launch=direct|eac|watch   Mode=stub|filter   Report=drop|pass\r\n"
        L"\r\n"
        L"[EACBypass]\r\n"
        L"GameDir=E:\\Steam\\steamapps\\common\\The Outlast Trials\r\n"
        L"GameExe=OPP\\Binaries\\Win64\\TOTClient-Win64-Shipping.exe\r\n"
        L"InjectDll=\r\n"
        L"Launch=direct\r\n"
        L"Mode=stub\r\n"
        L"Report=drop\r\n"
        L"InjectDelay=3000\r\n"
        L"ProcessName=TOTClient-Win64-Shipping.exe\r\n"
        L"WatchTimeout=300\r\n"
        L"PauseOnExit=1\r\n"
        L"Args=\r\n";

    int need = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), NULL, 0, NULL, NULL);
    if (need <= 0)
        return;
    std::string utf8;
    utf8.resize((size_t)need);
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), &utf8[0], need, NULL, NULL);

    HANDLE f = CreateFileW(ini.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return;

    const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
    DWORD written = 0;
    WriteFile(f, bom, 3, &written, NULL);
    WriteFile(f, utf8.data(), (DWORD)utf8.size(), &written, NULL);
    CloseHandle(f);
}

// Look for the configuration beside the exe, then in cfg\ next to it.
static std::wstring resolve_ini(const std::wstring& exe_dir)
{
    static const wchar_t* candidates[] =
    {
        L"\\EACLoader.ini",
        L"\\cfg\\EACLoader.ini",
        L"\\..\\cfg\\EACLoader.ini",
    };
    for (int i = 0; i < (int)(sizeof(candidates) / sizeof(candidates[0])); ++i)
    {
        std::wstring p = exe_dir + candidates[i];
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES)
            return p;
    }

    std::wstring p = exe_dir + L"\\EACLoader.ini";
    write_default_ini(p);
    return p;
}

// Split a semicolon separated list, dropping empty entries and surrounding spaces.
static std::vector<std::wstring> split_list(const std::wstring& text)
{
    std::vector<std::wstring> items;
    std::wstring current;
    for (size_t i = 0; i <= text.size(); ++i)
    {
        wchar_t ch = (i < text.size()) ? text[i] : L';';
        if (ch == L';' || ch == L'|')
        {
            size_t b = current.find_first_not_of(L" \t");
            size_t e = current.find_last_not_of(L" \t");
            if (b != std::wstring::npos)
                items.push_back(current.substr(b, e - b + 1));
            current.clear();
        }
        else
        {
            current.push_back(ch);
        }
    }
    return items;
}

static bool extract_payload(const std::wstring& target)
{
    HRSRC res = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_PAYLOAD), MAKEINTRESOURCEW(10));
    if (!res)
        return false;

    DWORD size = SizeofResource(NULL, res);
    HGLOBAL gl = LoadResource(NULL, res);
    if (!gl || !size)
        return false;

    void* data = LockResource(gl);
    if (!data)
        return false;

    HANDLE f = CreateFileW(target.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return false;

    DWORD written = 0;
    BOOL ok = WriteFile(f, data, size, &written, NULL);
    CloseHandle(f);
    return ok && written == size;
}

// Copy the current environment block and append the payload switches.
static std::wstring build_env(const std::vector<env_pair>& extra)
{
    std::wstring block;
    LPWCH env = GetEnvironmentStringsW();
    if (env)
    {
        for (LPWCH p = env; *p; p += lstrlenW(p) + 1)
        {
            std::wstring entry(p);
            bool replaced = false;
            for (size_t i = 0; i < extra.size(); ++i)
            {
                const std::wstring& key = extra[i].first;
                if (entry.size() > key.size()
                    && _wcsnicmp(entry.c_str(), key.c_str(), key.size()) == 0
                    && entry[key.size()] == L'=')
                {
                    replaced = true;
                    break;
                }
            }
            if (replaced)
                continue;
            block += entry;
            block.push_back(L'\0');
        }
        FreeEnvironmentStringsW(env);
    }

    for (size_t i = 0; i < extra.size(); ++i)
    {
        block += extra[i].first;
        block.push_back(L'=');
        block += extra[i].second;
        block.push_back(L'\0');
    }
    block.push_back(L'\0');
    return block;
}

// One injection = one remote LoadLibraryW. Returns the module handle the target got.
static bool inject_dll(HANDLE proc, const std::wstring& dll_path, const char* label)
{
    if (GetFileAttributesW(dll_path.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        out("[-] %s: file not found: %s\n", label, u8(dll_path).c_str());
        return false;
    }

    SIZE_T bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(proc, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote)
    {
        out("[-] %s: VirtualAllocEx failed: %lu\n", label, GetLastError());
        return false;
    }

    if (!WriteProcessMemory(proc, remote, dll_path.c_str(), bytes, NULL))
    {
        out("[-] %s: WriteProcessMemory failed: %lu\n", label, GetLastError());
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        return false;
    }

    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE load_lib =
        (LPTHREAD_START_ROUTINE)GetProcAddress(kernel, "LoadLibraryW");
    if (!load_lib)
    {
        out("[-] %s: LoadLibraryW not found\n", label);
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        return false;
    }

    HANDLE th = CreateRemoteThread(proc, NULL, 0, load_lib, remote, 0, NULL);
    if (!th)
    {
        out("[-] %s: CreateRemoteThread failed: %lu\n", label, GetLastError());
        VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
        return false;
    }

    DWORD wait = WaitForSingleObject(th, 60000);
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);

    if (wait != WAIT_OBJECT_0)
    {
        out("[-] %s: remote thread timed out\n", label);
        return false;
    }
    if (code == 0)
    {
        out("[-] %s: LoadLibraryW returned NULL inside target\n", label);
        return false;
    }
    out("[+] %s injected: %s\n", label, u8(dll_path).c_str());
    return true;
}

// Launch=eac path: bring the EasyAntiCheat_EOS service up before the game starts.
static void start_eac_service(void)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
    {
        out("[!] OpenSCManager failed: %lu (run as administrator to enable EAC)\n", GetLastError());
        return;
    }

    SC_HANDLE svc = OpenServiceW(scm, L"EasyAntiCheat_EOS", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc)
    {
        out("[!] OpenService(EasyAntiCheat_EOS) failed: %lu\n", GetLastError());
        CloseServiceHandle(scm);
        return;
    }

    if (StartServiceW(svc, 0, NULL))
        out("[+] EasyAntiCheat_EOS service started\n");
    else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
        out("[*] EasyAntiCheat_EOS service already running\n");
    else
        out("[!] StartService failed: %lu\n", GetLastError());

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

static DWORD find_process_id(const std::wstring& exe_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, exe_name.c_str()) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// A terminated target makes VirtualAllocEx report ERROR_ACCESS_DENIED, which reads
// like a permission problem. Check liveness first so the real cause is visible.
static bool target_alive(HANDLE proc, const char* stage)
{
    DWORD code = 0;
    if (!GetExitCodeProcess(proc, &code))
    {
        out("[!] %s: GetExitCodeProcess failed: %lu\n", stage, GetLastError());
        return false;
    }
    if (code == STILL_ACTIVE)
        return true;

    out("[!] %s: target ALREADY EXITED, exit code = 0x%08lX (%lu)\n", stage, code, code);
    return false;
}

// Watch the target for its whole life and report the moment it dies.
// Inject the payload, then every user DLL after the configured delay.
static int run_injections(HANDLE proc, const std::wstring& payload_path,
    const std::vector<std::wstring>& user_dlls, int delay_ms)
{
    int failures = 0;

    out("--- injection 1/2: EAC payload ---\n");
    if (!inject_dll(proc, payload_path, "payload"))
    {
        out("[-] EAC payload injection failed\n");
        ++failures;
    }

    if (user_dlls.empty())
    {
        out("--- injection 2/2: skipped (InjectDll empty) ---\n");
        return failures;
    }

    if (delay_ms > 0)
    {
        out("[*] waiting %d ms before injecting user DLLs\n", delay_ms);
        Sleep((DWORD)delay_ms);
    }

    if (!target_alive(proc, "before user DLL injection"))
    {
        out("[-] external injection aborted, the target is gone\n");
        return failures + 1;
    }

    out("--- injection 2/2: user DLLs (%d) ---\n", (int)user_dlls.size());
    for (size_t i = 0; i < user_dlls.size(); ++i)
    {
        if (!inject_dll(proc, user_dlls[i], "user"))
            ++failures;
    }
    return failures;
}

int main(void)
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleW(L"EACLoader");
    open_out_log();

    wchar_t self_path[MAX_PATH_LONG] = { 0 };
    GetModuleFileNameW(NULL, self_path, MAX_PATH_LONG);
    std::wstring self(self_path);
    size_t slash = self.find_last_of(L"\\/");
    std::wstring dir = (slash == std::wstring::npos) ? L"." : self.substr(0, slash);
    std::wstring ini = resolve_ini(dir);

    std::wstring game_dir = ini_value(ini, L"GameDir",
        L"E:\\Steam\\steamapps\\common\\The Outlast Trials");
    std::wstring game_rel = ini_value(ini, L"GameExe",
        L"OPP\\Binaries\\Win64\\TOTClient-Win64-Shipping.exe");
    std::wstring user_list = ini_value(ini, L"InjectDll", L"");
    std::wstring extra_args = ini_value(ini, L"Args", L"");
    std::wstring launch = ini_value(ini, L"Launch", L"direct");
    std::wstring mode = ini_value(ini, L"Mode", L"stub");
    std::wstring report = ini_value(ini, L"Report", L"drop");
    std::wstring delay_txt = ini_value(ini, L"InjectDelay", L"3000");
    std::wstring pause_txt = ini_value(ini, L"PauseOnExit", L"1");
    std::wstring watch_name = ini_value(ini, L"ProcessName",
        L"TOTClient-Win64-Shipping.exe");
    std::wstring watch_timeout_txt = ini_value(ini, L"WatchTimeout", L"300");
    std::wstring inject_mode = ini_value(ini, L"InjectMode", L"internal");
    std::wstring block_relaunch = ini_value(ini, L"BlockRelaunch", L"1");
    std::wstring steam_appid = ini_value(ini, L"SteamAppId", L"1304930");
    std::wstring mirror = ini_value(ini, L"Mirror", L"0");

    int delay_ms = _wtoi(delay_txt.c_str());
    int pause = _wtoi(pause_txt.c_str());
    int watch_timeout = _wtoi(watch_timeout_txt.c_str());
    std::vector<std::wstring> user_dlls = split_list(user_list);

    std::wstring game_exe = game_dir + L"\\" + game_rel;

    out("================================================\n");
    out(" EACLoader\n");
    out("================================================\n");
    out("config     : %s\n", u8(ini).c_str());
    out("elevated   : %s\n", is_elevated() ? "yes (administrator)" : "no");
    out("launch     : %s\n", u8(launch).c_str());
    out("mode       : %s (report=%s)\n", u8(mode).c_str(), u8(report).c_str());
    out("game exe   : %s\n", u8(game_exe).c_str());
    out("inject dll : %d configured\n", (int)user_dlls.size());
    for (size_t i = 0; i < user_dlls.size(); ++i)
        out("             [%d] %s\n", (int)i, u8(user_dlls[i]).c_str());
    out("inject delay: %d ms\n", delay_ms);
    out("------------------------------------------------\n");

    wchar_t temp[MAX_PATH_LONG] = { 0 };
    GetTempPathW(MAX_PATH_LONG, temp);
    std::wstring payload_path = std::wstring(temp) + L"EACPayload.dll";

    if (!extract_payload(payload_path))
    {
        out("[-] failed to extract embedded payload\n");
        pause_if_configured(pause);
        return 1;
    }
    out("[*] payload extracted to %s\n", u8(payload_path).c_str());

    std::vector<env_pair> env;
    env.push_back(env_pair(L"EACBYPASS_MODE", mode));
    env.push_back(env_pair(L"EACBYPASS_REPORT", report));
    env.push_back(env_pair(L"EACBYPASS_BLOCK_RELAUNCH", block_relaunch));

    // The payload loads the user DLLs from inside the process; an external
    // VirtualAllocEx is refused once the anti-cheat hardens the process.
    std::wstring joined;
    for (size_t i = 0; i < user_dlls.size(); ++i)
    {
        if (i)
            joined += L";";
        joined += user_dlls[i];
    }
    env.push_back(env_pair(L"EACBYPASS_INJECT_DLL", joined));
    env.push_back(env_pair(L"EACBYPASS_INJECT_DELAY", delay_txt));
    env.push_back(env_pair(L"EACBYPASS_MIRROR", mirror));

    // Steam DRM refuses a process that Steam did not start and asks Steam to relaunch
    // it, which restores the EAC bootstrapper. Present the app identity Steam would.
    env.push_back(env_pair(L"SteamAppId", steam_appid));
    env.push_back(env_pair(L"SteamGameId", steam_appid));
    std::wstring env_block = build_env(env);

    int failures = 0;

    if (launch == L"watch")
    {
        out("[*] watch mode: waiting for %s (timeout %d s)\n",
            u8(watch_name).c_str(), watch_timeout);
        out("[*] start the game yourself now\n");

        DWORD pid = 0;
        DWORD waited = 0;
        while (waited < (DWORD)watch_timeout * 1000)
        {
            pid = find_process_id(watch_name);
            if (pid)
                break;
            Sleep(100);
            waited += 100;
        }

        if (!pid)
        {
            out("[-] process %s not found within timeout\n", u8(watch_name).c_str());
            pause_if_configured(pause);
            return 1;
        }

        out("[+] found %s pid=%lu after %lu ms\n", u8(watch_name).c_str(), pid, waited);

        HANDLE proc = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            FALSE, pid);
        if (!proc)
        {
            out("[-] OpenProcess failed: %lu\n", GetLastError());
            pause_if_configured(pause);
            return 1;
        }

        failures = run_injections(proc, payload_path, user_dlls, delay_ms);
        CloseHandle(proc);
    }
    else
    {
        if (GetFileAttributesW(game_exe.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            out("[-] game executable not found, check GameDir/GameExe in EACLoader.ini\n");
            pause_if_configured(pause);
            return 1;
        }

        if (launch == L"eac")
            start_eac_service();

        std::wstring cmd = L"\"" + game_exe + L"\"";
        if (!extra_args.empty())
            cmd += L" " + extra_args;

        STARTUPINFOW si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));

        out("[*] creating suspended game process (EAC bootstrapper bypassed)\n");
        BOOL ok = CreateProcessW(
            game_exe.c_str(),
            &cmd[0],
            NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            (LPVOID)env_block.c_str(),
            game_dir.c_str(),
            &si, &pi);

        if (!ok)
        {
            out("[-] CreateProcessW failed: %lu\n", GetLastError());
            pause_if_configured(pause);
            return 1;
        }
        out("[+] game pid = %lu\n", pi.dwProcessId);
        out("------------------------------------------------\n");

        // Payload first, while the game main thread is still frozen.
        out("--- injection 1/2: EAC payload ---\n");
        if (!inject_dll(pi.hProcess, payload_path, "payload"))
        {
            out("[-] EAC payload injection failed\n");
            ++failures;
        }

        ResumeThread(pi.hThread);
        out("[+] game resumed\n");
        out("------------------------------------------------\n");

        if (user_dlls.empty())
        {
            out("--- injection 2/2: skipped (InjectDll empty) ---\n");
        }
        else if (inject_mode == L"internal")
        {
            out("--- injection 2/2: %d DLL(s) loaded from inside by the payload ---\n",
                (int)user_dlls.size());
            out("[*] result appears in %%TEMP%%\\EACPayload.log as 'internal load'\n");
        }
        else
        {
            if (delay_ms > 0)
            {
                out("[*] waiting %d ms before injecting user DLLs\n", delay_ms);
                Sleep((DWORD)delay_ms);
            }
            if (target_alive(pi.hProcess, "before user DLL injection"))
            {
                out("--- injection 2/2: user DLLs (%d) ---\n", (int)user_dlls.size());
                for (size_t i = 0; i < user_dlls.size(); ++i)
                {
                    if (!inject_dll(pi.hProcess, user_dlls[i], "user"))
                        ++failures;
                }
            }
            else
            {
                out("[-] external injection aborted, the target is gone\n");
                out("[*] set InjectMode=internal so the payload loads them instead\n");
                ++failures;
            }
        }

        // Observe briefly so an early exit is reported with its exit code.
        if (WaitForSingleObject(pi.hProcess, 5000) == WAIT_OBJECT_0)
        {
            DWORD code = 0;
            GetExitCodeProcess(pi.hProcess, &code);
            out("[!] process ended within 5 s, exit code = 0x%08lX (%lu)\n", code, code);
        }
        else
        {
            out("[+] process still running after 5 s\n");
        }

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    out("------------------------------------------------\n");
    if (failures == 0)
        out("[+] all injections done, no failures\n");
    else
        out("[!] finished with %d failure(s)\n", failures);
    out("[*] payload log: %%TEMP%%\\EACPayload.log\n");

    pause_if_configured(pause);
    return failures ? 1 : 0;
}
