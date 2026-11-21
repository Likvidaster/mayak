#include "mayakupdateapply.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <vector>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QUrl>

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include "core/utils/signedUpdateManifest.h"
#include "logger.h"
#include "version.h"

namespace {
Logger logger("MayakUpdateApply");

const QUrl kManifestUrl(QStringLiteral("https://mayaklight.ru") + mayak::signedupdate::feedPath() + QStringLiteral("windows-x64.json"));

QString programDataDir() {
    wchar_t buffer[MAX_PATH] = {};
    const DWORD size = GetEnvironmentVariableW(L"ProgramData", buffer, MAX_PATH);
    return size > 0 && size < MAX_PATH ? QString::fromWCharArray(buffer) : QStringLiteral("C:\\ProgramData");
}

// A real directory (no junction/symlink) owned by SYSTEM or Administrators: users can create folders
// in ProgramData, and a folder they own they can always open up again (review 20.11, B-1).
bool trustedDirectory(const QString& dir) {
    const std::wstring path = dir.toStdWString();
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return false;
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr,
                              nullptr, &descriptor) != ERROR_SUCCESS)
        return false;
    const bool trusted = owner && (IsWellKnownSid(owner, WinLocalSystemSid) || IsWellKnownSid(owner, WinBuiltinAdministratorsSid));
    LocalFree(descriptor);
    return trusted;
}

// Created with its owner and protected rights at once (SYSTEM and Administrators only).
bool createProtectedDirectory(const QString& dir) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1,
                                                              &descriptor, nullptr))
        return false;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    const std::wstring path = dir.toStdWString();
    const BOOL created = CreateDirectoryW(path.c_str(), &attributes);
    LocalFree(descriptor);
    return created || GetLastError() == ERROR_ALREADY_EXISTS;
}

// %ProgramData%\MayakVPN\update, checked at every level; empty when it cannot be trusted.
QString updateDir() {
    const QString base = QDir::toNativeSeparators(programDataDir() + QStringLiteral("\\MayakVPN"));
    const QString update = base + QStringLiteral("\\update");
    if (!createProtectedDirectory(base) || !trustedDirectory(base)) return {};
    if (!createProtectedDirectory(update) || !trustedDirectory(update)) return {};
    // Trusted owner, but an administrator may have created it with inherited rights: reset them.
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1,
                                                              &descriptor, nullptr))
        return {};
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted);
    std::wstring path = update.toStdWString();
    const DWORD set = SetNamedSecurityInfoW(path.data(), SE_FILE_OBJECT,
                                            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                            nullptr, nullptr, dacl, nullptr);
    LocalFree(descriptor);
    return set == ERROR_SUCCESS ? update : QString();
}

// A local absolute path as text (no UNC, device or relative path). The file itself is only ever
// opened as the pipe client (see openAsClient), never by SYSTEM.
bool acceptablePackagePath(const QString& path) {
    const QString native = QDir::toNativeSeparators(path);
    static const QRegularExpression local(QStringLiteral("^[A-Za-z]:\\\\"));
    return local.match(native).hasMatch() && !native.contains(QStringLiteral("..")) && !native.startsWith(QStringLiteral("\\\\"));
}

// Opens the package with the rights of the process that asked (a normal user cannot make SYSTEM read
// another file or authenticate to another host through links), then reverts at once.
HANDLE openAsClient(void* clientPipe, const QString& path) {
    if (!clientPipe || !ImpersonateNamedPipeClient(static_cast<HANDLE>(clientPipe))) return INVALID_HANDLE_VALUE;
    const std::wstring native = QDir::toNativeSeparators(path).toStdWString();
    HANDLE file = CreateFileW(native.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (!RevertToSelf()) {
        // Never continue with the client's identity.
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        TerminateProcess(GetCurrentProcess(), 1);
    }
    if (file != INVALID_HANDLE_VALUE && GetFileType(file) != FILE_TYPE_DISK) { CloseHandle(file); return INVALID_HANDLE_VALUE; }
    return file;
}

// Copies exactly `size` bytes from the handle into `destination` (protected folder) and returns the
// SHA-256 (hex) of what was written.
QByteArray copyFromHandle(HANDLE file, const QString& destination, quint64 size) {
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file, &length) || quint64(length.QuadPart) != size) return {};
    QFile out(destination);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) return {};
    QCryptographicHash hash(QCryptographicHash::Sha256);
    std::vector<char> buffer(1 << 20);
    quint64 total = 0;
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), DWORD(buffer.size()), &read, nullptr)) return {};
        if (read == 0) break;
        total += read;
        if (total > size || out.write(buffer.data(), read) != qint64(read)) return {};
        hash.addData(QByteArrayView(buffer.data(), read));
    }
    out.close();
    return total == size ? hash.result().toHex() : QByteArray();
}

bool guardRunning() {
    HANDLE mutex = OpenMutexW(SYNCHRONIZE, FALSE, L"Global\\MayakUpdateGuard");
    if (!mutex) return false;
    CloseHandle(mutex);
    return true;
}

QByteArray sha256Hex(const QString& path, qint64* size) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!hash.addData(&file)) return {};
    *size = file.size();
    return hash.result().toHex();
}

bool startGuard(const QString& guard, const QString& installer, bool vpnWasOn) {
    const QString target = QDir::toNativeSeparators(QCoreApplication::applicationDirPath());
    QString command = QStringLiteral("\"%1\" --installer \"%2\" --target \"%3\"").arg(guard, installer, target);
    if (vpnWasOn) command += QStringLiteral(" --block --reconnect");
    std::wstring cmd = command.toStdWString();
    const std::wstring exe = guard.toStdWString();
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    // It must outlive this service (the installer stops and replaces it).
    DWORD flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB;
    BOOL started = CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE, flags, nullptr, nullptr, &startup, &process);
    if (!started && GetLastError() == ERROR_ACCESS_DENIED) {
        flags &= ~CREATE_BREAKAWAY_FROM_JOB;
        started = CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE, flags, nullptr, nullptr, &startup, &process);
    }
    if (!started) {
        logger.error() << "Update guard could not be started:" << GetLastError();
        return false;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return true;
}
}  // namespace

namespace MayakUpdateApply {
QString apply(const QByteArray& signedEnvelope, const QString& packagePath, bool vpnWasOn, void* clientPipe) {
    if (guardRunning()) return QStringLiteral("busy");
    QFile keyFile(QStringLiteral(":/mayak/update_signing_public.pem"));
    if (!keyFile.open(QIODevice::ReadOnly)) {
        logger.error() << "Update signing key resource is missing";
        return QStringLiteral("failed");
    }
    SignedUpdateManifest manifest;
    QString error;
    SignedUpdateManifestDisposition disposition = SignedUpdateManifestDisposition::NoNewer;
    if (!mayak::signedupdate::verifySignedManifest(signedEnvelope, keyFile.readAll(), QStringLiteral("windows-x64"),
                                                   QStringLiteral(APP_VERSION), 0, kManifestUrl,
                                                   QDateTime::currentDateTimeUtc(), &manifest, &error, &disposition) ||
        disposition != SignedUpdateManifestDisposition::Newer) {
        logger.warning() << "Update rejected:" << error;
        return QStringLiteral("rejected");
    }
    if (!acceptablePackagePath(packagePath)) {
        logger.warning() << "Update package path is not a local absolute path";
        return QStringLiteral("rejected");
    }
    const QString dir = updateDir();
    if (dir.isEmpty()) {
        logger.error() << "Update folder is missing or not owned by SYSTEM/Administrators";
        return QStringLiteral("failed");
    }
    const QString package = dir + QStringLiteral("\\MayakVPN-update.exe");
    const QString guard = dir + QStringLiteral("\\MayakUpdateGuard.exe");
    QFile::remove(package);
    QFile::remove(guard);
    // Opened as the client, copied through that handle; the protected copy is what gets checked.
    HANDLE source = openAsClient(clientPipe, packagePath);
    if (source == INVALID_HANDLE_VALUE) {
        logger.warning() << "Update package could not be opened for the requesting user";
        return QStringLiteral("rejected");
    }
    const QByteArray copied = copyFromHandle(source, package, manifest.size);
    CloseHandle(source);
    qint64 size = 0;
    if (copied.isEmpty() || copied != manifest.sha256 || sha256Hex(package, &size) != manifest.sha256 ||
        quint64(size) != manifest.size) {
        QFile::remove(package);
        logger.warning() << "Update package does not match the signed feed";
        return QStringLiteral("rejected");
    }
    if (!QFile::copy(QCoreApplication::applicationDirPath() + QStringLiteral("/MayakUpdateGuard.exe"), guard)) {
        QFile::remove(package);
        logger.error() << "Update guard is missing";
        return QStringLiteral("failed");
    }
    logger.info() << "Installing update" << manifest.version << "vpn" << vpnWasOn;
    if (!startGuard(guard, package, vpnWasOn)) return QStringLiteral("failed");
    return QStringLiteral("started");
}

bool signalConnected() {
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Global\\MayakUpdateConnected");
    if (!event) return false;
    const BOOL ok = SetEvent(event);
    CloseHandle(event);
    return ok;
}
}  // namespace MayakUpdateApply
