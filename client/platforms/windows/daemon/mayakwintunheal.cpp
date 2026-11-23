#include "mayakwintunheal.h"

#include <QCoreApplication>
#include <QDir>

#include <windows.h>

#include "logger.h"
#include "windowsdaemon.h"

namespace {
Logger logger("MayakWintunHeal");
constexpr DWORD kTunnelStopWaitMs = 3000;

// wintun.dll 0.14 API.
using WintunCreateAdapterFn = void*(WINAPI*)(LPCWSTR name, LPCWSTR tunnelType, const GUID* requestedGuid);
using WintunCloseAdapterFn = void(WINAPI*)(void* adapter);

// True while Mayak's tunnel service exists and is not stopped (waits a little for a stopping one).
bool tunnelServiceRunning() {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!scm) return true;  // unknown: never heal next to a possibly running tunnel
  SC_HANDLE service = OpenServiceW(scm, TUNNEL_SERVICE_NAME, SERVICE_QUERY_STATUS);
  if (!service) {
    const DWORD error = GetLastError();
    CloseServiceHandle(scm);
    return error != ERROR_SERVICE_DOES_NOT_EXIST;
  }
  bool running = true;
  for (DWORD waited = 0;; waited += 250) {
    SERVICE_STATUS status{};
    if (!QueryServiceStatus(service, &status)) break;
    if (status.dwCurrentState == SERVICE_STOPPED) { running = false; break; }
    if (waited >= kTunnelStopWaitMs) break;
    Sleep(250);
  }
  CloseServiceHandle(service);
  CloseServiceHandle(scm);
  return running;
}
}  // namespace

namespace MayakWintunHeal {
QString run() {
  if (tunnelServiceRunning()) {
    logger.warning() << "Mayak tunnel service is running; WinTun repair skipped";
    return QStringLiteral("busy");
  }
  // Only this installation's wintun.dll (next to the service), never a search path.
  const QString path = QDir::toNativeSeparators(QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("wintun.dll")));
  HMODULE library = LoadLibraryExW(reinterpret_cast<LPCWSTR>(path.utf16()), nullptr,
                                   LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!library) {
    logger.error() << "wintun.dll could not be loaded:" << GetLastError();
    return QStringLiteral("no_wintun");
  }
  const auto create = reinterpret_cast<WintunCreateAdapterFn>(GetProcAddress(library, "WintunCreateAdapter"));
  const auto close = reinterpret_cast<WintunCloseAdapterFn>(GetProcAddress(library, "WintunCloseAdapter"));
  if (!create || !close) {
    FreeLibrary(library);
    logger.error() << "wintun.dll has no adapter API";
    return QStringLiteral("no_wintun");
  }
  // A random GUID (nullptr): never Mayak's own fixed adapter identity.
  void* adapter = create(L"MayakRepair", L"Mayak", nullptr);
  if (!adapter) {
    const DWORD error = GetLastError();
    FreeLibrary(library);
    logger.error() << "Temporary WinTun adapter could not be created:" << error;
    return QStringLiteral("create_failed");
  }
  close(adapter);  // wintun 0.14: closing an adapter created by this handle removes it
  FreeLibrary(library);
  logger.debug() << "Temporary WinTun adapter created and removed";
  return QStringLiteral("healed");
}
}  // namespace MayakWintunHeal
