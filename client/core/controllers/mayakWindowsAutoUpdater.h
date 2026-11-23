#pragma once

#include <QByteArray>
#include <functional>
#include <QObject>
#include <QString>
#include <QTimer>

#include "core/protocols/vpnProtocol.h"

class UpdateController;
class ConnectionController;

// Mayak automatic update on Windows (owner's decision 20.11.2026). A verified package waits for a
// quiet moment: nobody used the computer for 5 minutes, no full-screen app or presentation, mains
// power or battery above 50 %, the VPN not in the middle of connecting. Then a notice ("Mayak will
// update in a minute"); any use of the computer during that minute postpones it. Then the Mayak
// service installs it (it verifies everything itself); with the VPN on, its update guard blocks
// other traffic until the new Mayak has reconnected.
class MayakWindowsAutoUpdater : public QObject {
    Q_OBJECT
public:
    MayakWindowsAutoUpdater(UpdateController* updates, ConnectionController* connection, QObject* parent = nullptr);

    // The app was restarted by the update guard: reconnect (when the VPN was on) and report it.
    static void afterUpdate(ConnectionController* connection, bool reconnect, std::function<void()> connect);

private:
    void onReady(const QString& path, const QByteArray& envelope, const QString& version);
    void tick();
    bool quietMoment() const;
    void apply();

    UpdateController* m_updates;
    ConnectionController* m_connection;
    Vpn::ConnectionState m_state = Vpn::ConnectionState::Disconnected;
    QString m_path, m_version;
    QByteArray m_envelope;
    QTimer m_timer;
    qint64 m_announcedAt = 0;
    bool m_applying = false;
};
