// Mayak update guard (Windows, 5.1.0.27; owner's decision 20.11.2026: no traffic outside the VPN
// while the app updates itself).
//
// The Mayak service verifies a signed update, copies the package and this program into
// %ProgramData%\MayakVPN\update (SYSTEM/Administrators only) and starts this copy as SYSTEM. It
// outlives the service (the installer stops and replaces the service):
//  1. --block: while the update runs, all traffic of other programs is blocked (own dynamic WFP
//     session; only loopback, DHCP, DNS and the Mayak programs of --target may connect, so the new
//     Mayak can reconnect). Windows removes the filters when this process ends, whatever happens.
//  2. Runs the full Mayak installer without a window ("--platform minimal MayakSilent=1").
//  3. Starts the Mayak app in the console user's session ("--mayak-after-update", with
//     "--mayak-reconnect" when the VPN was on).
//  4. --block: ends (and so lifts the block) when the new Mayak reports "connected" through the
//     service (event Global\MayakUpdateConnected), or after --timeout-ms, or at once when the
//     installation failed (the rolled back old version does not reconnect by itself).
// Plain Win32 without Qt: one file, copied next to the package. No secrets are logged.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <rpc.h>
#include <sddl.h>
#include <userenv.h>
#include <wtsapi32.h>

#include <cstdarg>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")

namespace {

FILE* g_log = nullptr;

void logLine(const wchar_t* format, ...) {
    if (!g_log) return;
    SYSTEMTIME t;
    GetSystemTime(&t);
    fwprintf(g_log, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond,
             t.wMilliseconds);
    va_list args;
    va_start(args, format);
    vfwprintf(g_log, format, args);
    va_end(args);
    fwprintf(g_log, L"\n");
    fflush(g_log);
}

std::wstring dirOf(const std::wstring& path) {
    const auto slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
}

std::wstring quote(const std::wstring& value) { return L"\"" + value + L"\""; }

// ---------- traffic block (own dynamic WFP session) ----------
struct Block {
    HANDLE engine = nullptr;
    GUID sublayer{};
    bool active = false;
};

bool addFilter(HANDLE engine, const GUID& sublayer, const GUID& layer, FWP_ACTION_TYPE action, UINT8 weight,
               FWPM_FILTER_CONDITION0* conditions, UINT32 count, const wchar_t* name) {
    FWPM_FILTER0 filter{};
    filter.displayData.name = const_cast<wchar_t*>(name);
    filter.layerKey = layer;
    filter.subLayerKey = sublayer;
    filter.action.type = action;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.filterCondition = conditions;
    filter.numFilterConditions = count;
    const DWORD result = FwpmFilterAdd0(engine, &filter, nullptr, nullptr);
    if (result != ERROR_SUCCESS) logLine(L"filter %s failed %lu", name, result);
    return result == ERROR_SUCCESS;
}

bool startBlock(Block& block, const std::wstring& target) {
    FWPM_SESSION0 session{};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC; // removed by Windows when this process ends
    session.displayData.name = const_cast<wchar_t*>(L"Mayak update guard");
    DWORD result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &block.engine);
    if (result != ERROR_SUCCESS) { logLine(L"engine open failed %lu", result); return false; }
    if (FwpmTransactionBegin0(block.engine, 0) != ERROR_SUCCESS) return false;
    UuidCreate(&block.sublayer);
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = block.sublayer;
    sublayer.displayData.name = const_cast<wchar_t*>(L"Mayak update guard");
    sublayer.weight = 0xFFFF;
    bool ok = FwpmSubLayerAdd0(block.engine, &sublayer, nullptr) == ERROR_SUCCESS;

    const GUID layers[] = {FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                           FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
    // Mayak's own programs (by path: the same paths after the update).
    std::vector<FWP_BYTE_BLOB*> appIds;
    for (const wchar_t* exe : {L"MayakVPN.exe", L"MayakVPN-service.exe", L"tun2socks.exe"}) {
        const std::wstring path = target + L"\\" + exe;
        FWP_BYTE_BLOB* appId = nullptr;
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES &&
            FwpmGetAppIdFromFileName0(path.c_str(), &appId) == ERROR_SUCCESS)
            appIds.push_back(appId);
    }
    // The Windows DNS client service (svchost) resolves names for the new Mayak.
    FWP_BYTE_BLOB* dnsClient = nullptr;
    {
        wchar_t system[MAX_PATH] = {};
        if (GetSystemDirectoryW(system, MAX_PATH)) {
            const std::wstring svchost = std::wstring(system) + L"\\svchost.exe";
            if (FwpmGetAppIdFromFileName0(svchost.c_str(), &dnsClient) != ERROR_SUCCESS) dnsClient = nullptr;
        }
    }
    for (const GUID& layer : layers) {
        const bool connect = IsEqualGUID(layer, FWPM_LAYER_ALE_AUTH_CONNECT_V4) || IsEqualGUID(layer, FWPM_LAYER_ALE_AUTH_CONNECT_V6);
        ok = addFilter(block.engine, block.sublayer, layer, FWP_ACTION_BLOCK, 0, nullptr, 0, L"Mayak update: block") && ok;
        FWPM_FILTER_CONDITION0 loopback{};
        loopback.fieldKey = FWPM_CONDITION_FLAGS;
        loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
        loopback.conditionValue.type = FWP_UINT32;
        loopback.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        ok = addFilter(block.engine, block.sublayer, layer, FWP_ACTION_PERMIT, 15, &loopback, 1, L"Mayak update: loopback") && ok;
        for (FWP_BYTE_BLOB* appId : appIds) {
            FWPM_FILTER_CONDITION0 app{};
            app.fieldKey = FWPM_CONDITION_ALE_APP_ID;
            app.matchType = FWP_MATCH_EQUAL;
            app.conditionValue.type = FWP_BYTE_BLOB_TYPE;
            app.conditionValue.byteBlob = appId;
            ok = addFilter(block.engine, block.sublayer, layer, FWP_ACTION_PERMIT, 15, &app, 1, L"Mayak update: Mayak") && ok;
        }
        if (connect && dnsClient) {
            // Name resolution of the new Mayak runs in the Windows DNS client (svchost), not in the
            // Mayak process: port 53 is permitted for that service only (never any program on 53).
            FWPM_FILTER_CONDITION0 dns[2]{};
            dns[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
            dns[0].matchType = FWP_MATCH_EQUAL;
            dns[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
            dns[0].conditionValue.byteBlob = dnsClient;
            dns[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            dns[1].matchType = FWP_MATCH_EQUAL;
            dns[1].conditionValue.type = FWP_UINT16;
            dns[1].conditionValue.uint16 = 53;
            ok = addFilter(block.engine, block.sublayer, layer, FWP_ACTION_PERMIT, 15, dns, 2, L"Mayak update: dns client") && ok;
        }
        // DHCP keeps the address (both directions), ICMPv6 keeps IPv6 neighbour discovery.
        for (UINT16 port : {static_cast<UINT16>(67), static_cast<UINT16>(68), static_cast<UINT16>(546), static_cast<UINT16>(547)}) {
            FWPM_FILTER_CONDITION0 dhcp[2]{};
            dhcp[0].fieldKey = connect ? FWPM_CONDITION_IP_REMOTE_PORT : FWPM_CONDITION_IP_LOCAL_PORT;
            dhcp[0].matchType = FWP_MATCH_EQUAL;
            dhcp[0].conditionValue.type = FWP_UINT16;
            dhcp[0].conditionValue.uint16 = port;
            dhcp[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            dhcp[1].matchType = FWP_MATCH_EQUAL;
            dhcp[1].conditionValue.type = FWP_UINT8;
            dhcp[1].conditionValue.uint8 = 17; // UDP
            ok = addFilter(block.engine, block.sublayer, layer, FWP_ACTION_PERMIT, 15, dhcp, 2, L"Mayak update: dhcp") && ok;
        }
        if (IsEqualGUID(layer, FWPM_LAYER_ALE_AUTH_CONNECT_V6) || IsEqualGUID(layer, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6)) {
            FWPM_FILTER_CONDITION0 icmp{};
            icmp.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            icmp.matchType = FWP_MATCH_EQUAL;
            icmp.conditionValue.type = FWP_UINT8;
            icmp.conditionValue.uint8 = 58; // ICMPv6
            ok = addFilter(block.engine, block.sublayer, layer, FWP_ACTION_PERMIT, 15, &icmp, 1, L"Mayak update: icmpv6") && ok;
        }
    }
    for (FWP_BYTE_BLOB* appId : appIds) FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
    if (dnsClient) FwpmFreeMemory0(reinterpret_cast<void**>(&dnsClient));
    if (!ok || FwpmTransactionCommit0(block.engine) != ERROR_SUCCESS) {
        FwpmTransactionAbort0(block.engine);
        FwpmEngineClose0(block.engine);
        block.engine = nullptr;
        logLine(L"block failed");
        return false;
    }
    block.active = true;
    logLine(L"block on (apps permitted: %u)", static_cast<unsigned>(appIds.size()));
    return true;
}

void stopBlock(Block& block) {
    if (!block.engine) return;
    FwpmEngineClose0(block.engine); // dynamic session: every filter goes with it
    block.engine = nullptr;
    if (block.active) logLine(L"block off");
    block.active = false;
}

// ---------- installer and app ----------
DWORD runInstaller(const std::wstring& installer) {
    // As SYSTEM the wizard runs in session 0: invisible to the user. MayakSilent=1 makes its pages
    // advance and answers (or rejects) every message box by itself.
    std::wstring command = quote(installer) + L" MayakSilent=1";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(installer.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                        dirOf(installer).c_str(), &startup, &process)) {
        logLine(L"installer start failed %lu", GetLastError());
        return static_cast<DWORD>(-1);
    }
    CloseHandle(process.hThread);
    const DWORD waited = WaitForSingleObject(process.hProcess, 20 * 60 * 1000);
    DWORD code = static_cast<DWORD>(-2);
    if (waited == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &code);
    else logLine(L"installer still running after 20 min: not killed (an installation or rollback cut midway is worse)");
    CloseHandle(process.hProcess);
    logLine(L"installer exit %ld", static_cast<long>(code));
    return code;
}

bool startAppAsUser(const std::wstring& target, bool reconnect) {
    const DWORD sessionId = WTSGetActiveConsoleSessionId();
    if (sessionId == 0xFFFFFFFF) { logLine(L"no console session"); return false; }
    HANDLE token = nullptr;
    if (!WTSQueryUserToken(sessionId, &token)) { logLine(L"no user token %lu", GetLastError()); return false; }
    void* environment = nullptr;
    CreateEnvironmentBlock(&environment, token, FALSE);
    const std::wstring app = target + L"\\MayakVPN.exe";
    std::wstring command = quote(app) + L" --mayak-after-update" + (reconnect ? L" --mayak-reconnect" : L"");
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");
    PROCESS_INFORMATION process{};
    const BOOL started = CreateProcessAsUserW(token, app.c_str(), command.data(), nullptr, nullptr, FALSE,
                                              CREATE_UNICODE_ENVIRONMENT, environment, target.c_str(), &startup, &process);
    const DWORD error = GetLastError();
    if (environment) DestroyEnvironmentBlock(environment);
    CloseHandle(token);
    if (!started) { logLine(L"app start failed %lu", error); return false; }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    logLine(L"app started (reconnect=%d)", reconnect ? 1 : 0);
    return true;
}

HANDLE createConnectedEvent() {
    // Only SYSTEM and Administrators may signal it (the service does, for the new app).
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1,
                                                              &descriptor, nullptr))
        return nullptr;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    HANDLE event = CreateEventW(&attributes, TRUE, FALSE, L"Global\\MayakUpdateConnected");
    LocalFree(descriptor);
    return event;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::wstring installer, target;
    bool block = false, reconnect = false;
    DWORD timeoutMs = 180000;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--installer" && i + 1 < argc) installer = argv[++i];
        else if (arg == L"--target" && i + 1 < argc) target = argv[++i];
        else if (arg == L"--block") block = true;
        else if (arg == L"--reconnect") reconnect = true;
        else if (arg == L"--timeout-ms" && i + 1 < argc) timeoutMs = static_cast<DWORD>(_wtoi(argv[++i]));
    }
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    const std::wstring logPath = dirOf(self) + L"\\guard.log";
    _wfopen_s(&g_log, logPath.c_str(), L"a, ccs=UTF-8");
    if (installer.empty() || target.empty()) { logLine(L"bad arguments"); return 2; }
    HANDLE single = CreateMutexW(nullptr, TRUE, L"Global\\MayakUpdateGuard");
    if (!single || GetLastError() == ERROR_ALREADY_EXISTS) { logLine(L"already running"); return 3; }
    logLine(L"start block=%d reconnect=%d", block ? 1 : 0, reconnect ? 1 : 0);

    HANDLE connected = block ? createConnectedEvent() : nullptr;
    Block guard;
    if (block && !startBlock(guard, target)) {
        // No update without the block: the owner's rule is "no traffic outside the VPN".
        logLine(L"update skipped: the block could not be set");
        if (connected) CloseHandle(connected);
        startAppAsUser(target, reconnect);
        return 4;
    }
    const DWORD code = runInstaller(installer);
    startAppAsUser(target, reconnect);
    if (guard.active) {
        if (code == 0 && connected) {
            const DWORD waited = WaitForSingleObject(connected, timeoutMs);
            logLine(waited == WAIT_OBJECT_0 ? L"new Mayak connected" : L"no connect in time");
        } else logLine(L"installation failed: no wait");
        stopBlock(guard);
    }
    if (connected) CloseHandle(connected);
    if (code == 0) DeleteFileW(installer.c_str()); // the verified package is not needed any more
    logLine(L"done");
    if (g_log) fclose(g_log);
    return code == 0 ? 0 : 1;
}
