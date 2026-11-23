#pragma once

#include <QObject>
#include <QPointer>
#include <QVariantMap>
#include <memory>
#include "core/controllers/mayakBackendBridge.h"
#include "core/controllers/api/mayakAdmissionClient.h"
#include "core/protocols/vpnProtocol.h"

class SecureQSettings;
class SecureServersRepository;
class SecureAppSettingsRepository;
class SubscriptionController;
class ConnectionController;

// Application-thread owner. No platform getter is read across thread boundaries.
class MayakAutoConnectRuntime final : public QObject {
    Q_OBJECT
public:
    MayakAutoConnectRuntime(SecureQSettings*, SecureServersRepository*, SecureAppSettingsRepository*,
                           SubscriptionController*, ConnectionController*, MayakBackendBridge::Port,
                           QObject* parent = nullptr, mayak::admission::Transport transport = {});
    ~MayakAutoConnectRuntime() override;
    bool manages(const QString& serverId) const;
    void begin(const QString& serverId);
    void cancel();
    bool cleanupPending() const;
    void retryCleanup();
    void shutdown();
    bool busy() const;
    QString message() const { return m_message; }
    QString connectionPhase() const { return m_connectionPhase; }
    QVariantMap exitLocation() const { return m_exitLocation; }
    // The exit and method of the attempt being started/verified or connected (status line under the
    // button): {cityId, city (server card), method: "AmneziaWG"|"Xray"}; empty when not known yet.
    QVariantMap route() const { return m_route; }
    // Connected-state monitoring and Android soft recovery timing (milliseconds).
    struct RecoveryTiming {
        qint64 monitorMs = 10000;        // healthy tunnel probe interval
        qint64 retryProbeMs = 3000;      // after a failed probe
        qint64 probeDeadlineMs = 5000;
        qint64 networkSettleMs = 2000;   // probe this long after a new validated network
        qint64 noNetworkUiMs = 1500;     // OS reports no network: show it after this debounce
        qint64 networkLostExpiryMs = 60000; // loss with no later network event stops blocking recovery
        qint64 stuckRxMs = 8000;         // no RX this long + failed probe = stuck transport
        qint64 stuckRxAfterNetworkMs = 4000;
        qint64 networkRecentMs = 20000;
        qint64 recoverDeadlineMs = 6000;
        QList<qint64> recoverBackoffMs { 0, 10000, 30000 };
        // Connect-time network failure (gateway unreachable, DNS, timeout): retry instead of
        // an immediate error; one delay per retry, then the error is shown.
        QList<qint64> connectRetryMs { 3000, 6000, 12000, 20000, 30000 };
        // Windows daemon: tunnel health is reported as soon as the tunnel interface exists,
        // with or without a handshake. A started attempt with no health at all therefore means
        // the local adapter never came up (e.g. WinTun creation failed right after an update),
        // not a silent exit. Such failures are retried with these delays, then reported.
#ifdef Q_OS_WINDOWS
        bool noHealthMeansLocalFailure = true;
#else
        bool noHealthMeansLocalFailure = false;
#endif
        // The first retry repairs WinTun in the service first (see healWintunFirst), so it comes sooner.
        // 5.1.0.28: three short retries, then «перезагрузите компьютер» (a field device waited up to
        // 5 min between 13 attempts on the same exit while its adapter could not come up).
        QList<qint64> localStartRetryMs { 10000, 30000, 60000 };
        // The "proven" report after a passing tunnel probe. The first try keeps its short budget
        // (it never delays «Подключено»); a try that got no answer from the server (timeout,
        // network) is repeated in the background with these delays while the same attempt stays
        // connected. Any server answer ends the retries.
        qint64 provenReportMs = 2500;
        qint64 provenRetryBudgetMs = 8000;
        QList<qint64> provenRetryMs { 3000, 8000, 15000 };
        // AWG quick give-up: no handshake this long after the path started ends the path before
        // the full proof time. Android reports tunnel health only after a handshake; in the owner's
        // logs (19-20.11.2026) the first health came 0.5-3.2 s after the start, and a dead exit
        // used the full 6 s. Windows reports health as soon as its interface exists, and a new
        // tunnel there passed TCP only 2.5-3.1 s after that: no short safe bound yet (0 = off).
#ifdef Q_OS_ANDROID
        qint64 awgNoHandshakeMs = 4000;
#else
        qint64 awgNoHandshakeMs = 0;
#endif
        // Parallel TCP check of every exit's Xray port before the exits are tried (no data sent).
        qint64 portPrecheckMs = 1500;
        // Connect without the gateway (review 01, item 2): the stored exits are used when v1/config
        // has no signed answer at all, or none this long after the request (the request goes on;
        // a later answer only refreshes the memory or ends a revoked session).
        qint64 offlineEarlyMs = 4500; // review: a slow but live gateway at peak should mostly still answer
        // The late acquire (+ proven) of a session started from the stored exits: first try right
        // after «Подключено», then these delays while it stays connected (the last one repeats).
        qint64 lateAcquireBudgetMs = 8000;
        QList<qint64> lateAcquireRetryMs { 5000, 30000, 120000, 300000 };
    };
    static RecoveryTiming recoveryTiming();
    static void setRecoveryTimingForTests(const RecoveryTiming& timing);
    static void resetFailoverMemoryForTests();
    // Replaces the service's app-exclusion preparation (Windows) in tests; empty restores the default.
    static void setSplitPrepareForTests(std::function<void(QObject*, std::function<void(bool, QString)>)> hook);
    // Replaces the service's WinTun repair (Windows) in tests (never the real service there).
    static void setWintunHealForTests(std::function<void(QObject*, std::function<void(bool, QString)>)> hook);
    // Replaces the Android shutdown of the app's own HTTPS sockets in tests; empty restores the default.
    // startStale: whether connections may already be tied to a tunnel (a fresh process: true).
    static void setHttpsSocketResetForTests(std::function<int()> hook, bool startStale = false);
    // Replaces the TCP check of the exits' Xray port in tests (never real addresses there);
    // empty restores the real check. done(answered) lists one flag per host, in host order.
    using PortPrecheck = std::function<void(QObject* context, const QStringList& hosts, quint16 port, int timeoutMs,
                                            std::function<void(QList<bool>)> done)>;
    static void setPortPrecheckForTests(PortPrecheck hook);
    static PortPrecheck realPortPrecheckForTests(); // the real check, for loopback-only tests
    // The exit memory's "same local network" check ("interface/subnet/prefix" entries; the tunnel by address).
    static bool sameLocalNetworkForTests(const QStringList& before, const QStringList& now, const QString& tunnelAddress);
signals:
    void stateChanged(Vpn::ConnectionState state, const QString& message);
private:
    struct Session;
    void publish(Vpn::ConnectionState state, const QString& message, const QString& phase,
                 const QVariantMap& exitLocation = {}, const QVariantMap& route = {});
    SecureQSettings* m_settings;
    QPointer<SecureServersRepository> m_servers;
    QPointer<SecureAppSettingsRepository> m_app;
    SubscriptionController* m_subscription;
    QPointer<ConnectionController> m_connection;
    MayakBackendBridge::Port m_port;
    mayak::admission::Transport m_transport;
    std::shared_ptr<Session> m_session;
    QString m_message;
    QString m_connectionPhase = QStringLiteral("idle");
    QVariantMap m_exitLocation;
    QVariantMap m_route;
};
