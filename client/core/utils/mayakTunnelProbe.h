#pragma once

#include <QJsonObject>
#include <QHostAddress>
#include <QNetworkInterface>
#include <QObject>
#include <QPointer>
#include <QStringList>

#include "core/utils/mayakSplitTunneling.h"

// 5.1.0.27 (owner's decision, variant В): no third-party sites. The probe asks the exit agent
// inside the Xray tunnel: plain HTTP to a reserved address that only our exit's Xray routes to
// its local agent; the answer carries the nonce and the exit's id. Nothing leaves the exit.
struct MayakTunnelProbeRequest {
    QString attemptTag;
    QHostAddress localAddress;
    QString interfaceName;
    // Id of the exit (gateway candidate id) that must answer inside this tunnel.
    QString expectedExitId;
    QString nonce;
    int deadlineMs = 8000;
    // Xray path race (no tunnel exists yet): connect through this local SOCKS5 entry of the
    // race engine instead of binding to a tunnel interface. Never a tunnel proof by itself:
    // the proof of a started path always binds to its tunnel interface.
    quint16 socksPort = 0;
    QString socksUser;
    QString socksPassword;
    bool viaSocks() const { return socksPort != 0; }
#ifdef MAYAK_TUNNEL_PROBE_TESTING
    QString testHost;
    quint16 testPort = 0;
    int testConnectDelayMs = 0;
    int testSourceBindFailures = 0;
    int testSourceBindError = 9;
    int testBindRetryIntervalMs = 25;
    bool testIdentityDriftDuringBindWait = false;
#endif
};

struct MayakTunnelProbeProof {
    QString attemptTag;
    QString nonce;
    QString observedExitId;
    QString interfaceName;
    QString localAddress;
};

class MayakTunnelProbe final : public QObject {
    Q_OBJECT
public:
    explicit MayakTunnelProbe(QObject *parent = nullptr);
    quint64 start(const MayakTunnelProbeRequest &request);
    void cancel();

    // Strict agent answer validator also used by deterministic tests:
    // exactly {"v":1,"exit":"<expected>","nonce":"<nonce>"}.
    static bool validateAgentResponse(const QByteArray &body, const QString &nonce,
                                      const QString &expectedExitId, QString *observedExitId, QString *error);
    static bool parseHttpResponse(const QByteArray &wire, QByteArray *body, QString *error);
    // Reserved IPv4 of the exit agent (always routed through the tunnel, also in split mode).
    static QString agentAddress();
    static quint16 agentPort();

signals:
    void finished(quint64 generation, bool success, const MayakTunnelProbeProof &proof,
                  const QString &error);

private:
    quint64 m_generation = 0;
    QPointer<QObject> m_run;
};
