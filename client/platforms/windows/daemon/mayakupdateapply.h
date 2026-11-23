#pragma once

#include <QByteArray>
#include <QString>

// Mayak service (Windows): installs a Mayak update in the background (owner's decision 20.11.2026).
// The app only asks; the service trusts nothing from it: it verifies the signed feed envelope with
// its own embedded key (signature, validity, platform, strictly newer version), copies the package
// into %ProgramData%\MayakVPN\update (SYSTEM/Administrators only) and checks size and SHA-256 of
// that copy, then starts the update guard (MayakUpdateGuard.exe, copied next to it) as SYSTEM.
// The guard blocks other traffic while the update runs when the VPN was on (--block), runs the
// installer without a window and starts the new app, which reconnects and reports "connected".
namespace MayakUpdateApply {
// "started", "rejected" (not a verified newer Mayak update), "busy" (an update is running) or "failed".
// The package is opened as the pipe client (impersonation), never as SYSTEM, and copied through
// that same handle: no path tricks can make SYSTEM touch another file or host.
QString apply(const QByteArray& signedEnvelope, const QString& packagePath, bool vpnWasOn, void* clientPipe);
// The new app reconnected after the update: the guard lifts its block.
bool signalConnected();
}
