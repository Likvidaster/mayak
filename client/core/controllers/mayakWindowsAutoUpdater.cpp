#include "mayakWindowsAutoUpdater.h"

#include <QDateTime>
#include <QFileInfo>

#include "core/controllers/connectionController.h"
#include "core/controllers/mayakForeignVpn.h"
#include "core/controllers/updateController.h"
#include "logger.h"
#include "ui/utils/notificationHandler.h"

#ifdef Q_OS_WIN
#include <windows.h>
#include <shellapi.h>
#endif

namespace {
Logger logger("MayakWindowsAutoUpdater");
constexpr int kTickMs = 30 * 1000;
constexpr qint64 kIdleMs = 5 * 60 * 1000;
constexpr qint64 kNoticeMs = 60 * 1000;
}  // namespace

MayakWindowsAutoUpdater::MayakWindowsAutoUpdater(UpdateController* updates, ConnectionController* connection, QObject* parent)
    : QObject(parent), m_updates(updates), m_connection(connection) {
#ifdef Q_OS_WIN
    if (m_updates) connect(m_updates, &UpdateController::backgroundInstallReady, this, &MayakWindowsAutoUpdater::onReady);
    if (m_connection)
        connect(m_connection, &ConnectionController::connectionStateChanged, this, [this](Vpn::ConnectionState state) { m_state = state; });
    m_timer.setInterval(kTickMs);
    connect(&m_timer, &QTimer::timeout, this, &MayakWindowsAutoUpdater::tick);
#endif
}

void MayakWindowsAutoUpdater::onReady(const QString& path, const QByteArray& envelope, const QString& version) {
    m_path = path; m_envelope = envelope; m_version = version; m_announcedAt = 0;
    logger.info() << "Update" << version << "waits for a quiet moment";
    if (!m_timer.isActive()) m_timer.start();
}

bool MayakWindowsAutoUpdater::quietMoment() const {
#ifdef Q_OS_WIN
    LASTINPUTINFO input{sizeof(LASTINPUTINFO), 0};
    if (!GetLastInputInfo(&input) || qint64(GetTickCount() - input.dwTime) < kIdleMs) return false;
    QUERY_USER_NOTIFICATION_STATE notifications{};
    if (SHQueryUserNotificationState(&notifications) == S_OK &&
        notifications != QUNS_ACCEPTS_NOTIFICATIONS && notifications != QUNS_QUIET_TIME && notifications != QUNS_NOT_PRESENT)
        return false; // full screen, presentation, busy
    SYSTEM_POWER_STATUS power{};
    if (GetSystemPowerStatus(&power) && power.ACLineStatus == 0 && power.BatteryFlag != 128 &&
        power.BatteryLifePercent != 255 && power.BatteryLifePercent <= 50)
        return false;
    return m_state == Vpn::ConnectionState::Connected || m_state == Vpn::ConnectionState::Disconnected ||
           m_state == Vpn::ConnectionState::Error;
#else
    return false;
#endif
}

void MayakWindowsAutoUpdater::tick() {
    if (m_path.isEmpty() || m_applying) return;
    if (!QFileInfo::exists(m_path) || (m_updates && !m_updates->isAutoUpdateEnabled())) {
        m_path.clear(); m_timer.stop(); return;
    }
    if (!quietMoment()) { m_announcedAt = 0; return; }
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (!m_announcedAt) {
        m_announcedAt = now;
        if (auto* notifications = NotificationHandler::instance())
            notifications->mayakInfo(QStringLiteral("Маяк скоро обновится"),
                QStringLiteral("Версия %1 установится через минуту, пока компьютер не используется. Чтобы отложить, просто продолжите работу.")
                    .arg(m_version));
        return;
    }
    if (now - m_announcedAt >= kNoticeMs) apply();
}

void MayakWindowsAutoUpdater::apply() {
    m_applying = true;
    const bool vpnWasOn = m_state == Vpn::ConnectionState::Connected;
    logger.info() << "Asking the service to install" << m_version << "vpn" << vpnWasOn;
    mayak::foreignvpn::requestApplyUpdate(this, m_envelope, m_path, vpnWasOn, [this](bool replied, QString result) {
        m_applying = false;
        logger.info() << "Service answer" << replied << result;
        if (replied && result == QLatin1String("started")) {
            m_path.clear(); m_timer.stop(); // the installer closes this app and starts the new one
            return;
        }
        if (replied && result == QLatin1String("busy")) { m_announcedAt = 0; return; } // try later
        // Rejected or failed: no repeats for this package; the manual "Install" button stays.
        m_path.clear(); m_timer.stop();
    });
}

void MayakWindowsAutoUpdater::afterUpdate(ConnectionController* connection, bool reconnect, std::function<void()> connectNow) {
#ifdef Q_OS_WIN
    if (!connection) return;
    if (auto* notifications = NotificationHandler::instance())
        notifications->mayakInfo(QStringLiteral("Маяк обновлён"), reconnect ? QStringLiteral("Подключаем VPN…") : QString());
    if (!reconnect) { mayak::foreignvpn::notifyUpdateConnected(); return; }
    auto* guard = new QObject(connection);
    QObject::connect(connection, &ConnectionController::connectionStateChanged, guard, [guard](Vpn::ConnectionState state) {
        if (state != Vpn::ConnectionState::Connected) return;
        mayak::foreignvpn::notifyUpdateConnected();
        guard->deleteLater();
    });
    QTimer::singleShot(3000, guard, [connectNow] { if (connectNow) connectNow(); });
    QTimer::singleShot(5 * 60 * 1000, guard, [guard] { guard->deleteLater(); });
#else
    Q_UNUSED(connection); Q_UNUSED(reconnect); Q_UNUSED(connectNow);
#endif
}
