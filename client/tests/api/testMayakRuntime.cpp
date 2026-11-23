#include <algorithm>
#include <QApplication>
#include <QJsonArray>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QPromise>
#include <QSet>
#include <QSignalSpy>
#include <QBuffer>
#include <QFileInfo>
#include <QImage>
#include <QTcpServer>
#include <QTcpSocket>
#include <QPointer>
#include <QTemporaryDir>
#include <QTest>
#include <QTimer>
#include <QUuid>
#include "core/utils/mayakTunnelProbe.h"
#include "core/controllers/mayakAutoConnectRuntime.h"
#include "logger.h"
#include "version.h"
#include "core/controllers/mayakAutoConnectCoordinator.h"
#include "core/controllers/mayakAttemptStore.h"
#include "core/controllers/connectionController.h"
#include "core/controllers/api/subscriptionController.h"
#include "core/controllers/api/mayakAdmissionClient.h"
#include "core/models/api/apiV2ServerConfig.h"
#include "core/utils/constants/apiKeys.h"
#include "core/utils/constants/configKeys.h"
#include "ui/controllers/connectionUiController.h"
#include "ui/controllers/mayakCityPhotoUiController.h"

using namespace amnezia;
using B=MayakBackendBridge;
namespace mayak::diagnostics {
QStringList openSslErrorCodeTokens(const QString &errorString);
}
namespace {
QStringList capturedProbeOutput;
void collectAllProbeOutput(QtMsgType, const QMessageLogContext &, const QString &message) {
    capturedProbeOutput.append(message);
}
struct ProbeMessageCapture {
    QtMessageHandler previous = qInstallMessageHandler(collectAllProbeOutput);
    ProbeMessageCapture() { capturedProbeOutput.clear(); }
    ~ProbeMessageCapture() { qInstallMessageHandler(previous); }
    ProbeMessageCapture(const ProbeMessageCapture &) = delete;
    ProbeMessageCapture &operator=(const ProbeMessageCapture &) = delete;
};
QString guid() { return QUuid::createUuid().toString(QUuid::WithoutBraces); }
// Admin city card as the server sends it (exit_location schema 2).
QJsonObject validCard() {
    return QJsonObject{{"city","Вена"},{"country","Австрия"},{"country_code","at"},
        {"fact","Город кофеен и вальсов."},
        {"photo","media/servers/0123456789abcdef0123456789abcdef.jpg?v=0123456789ab"},{"version","a1b2c3d4e5f6"}};
}
QByteArray pngBytes(int w=64, int h=36) {
    QImage image(w,h,QImage::Format_RGB32); image.fill(Qt::darkBlue);
    QByteArray bytes; QBuffer buffer(&bytes); buffer.open(QIODevice::WriteOnly); image.save(&buffer,"PNG");
    return bytes;
}
// Minimal local HTTP server for the city photo loader (never the real network).
struct TinyHttp : QObject {
    QTcpServer server;
    QByteArray status="200 OK", body, contentLength;
    bool silent=false;
    int hits=0;
    TinyHttp() {
        server.listen(QHostAddress::LocalHost,0);
        connect(&server,&QTcpServer::newConnection,this,[this] {
            while (QTcpSocket* socket=server.nextPendingConnection()) {
                ++hits;
                connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
                connect(socket,&QTcpSocket::readyRead,socket,[this,socket] {
                    QByteArray seen=socket->property("seen").toByteArray()+socket->readAll();
                    socket->setProperty("seen",seen);
                    if (silent || !seen.contains("\r\n\r\n") || socket->property("answered").toBool()) return;
                    socket->setProperty("answered",true);
                    socket->write("HTTP/1.1 "+status+"\r\nContent-Type: application/octet-stream\r\nContent-Length: "
                        +(contentLength.isEmpty()?QByteArray::number(body.size()):contentLength)+"\r\nConnection: close\r\n\r\n"+body);
                    socket->disconnectFromHost();
                });
            }
        });
    }
    QString base() const { return QStringLiteral("http://127.0.0.1:%1/gw/").arg(server.serverPort()); }
};
// Minimal local SOCKS5 entry (user/password) that answers as the exit agent itself and closes,
// like Xray + agent in the path race (device test 21.11, 5.1.0.37 crash). Never the real network.
struct TinySocksAgent : QObject {
    QTcpServer server;
    QString exitId;
    bool holdOpen=false; // like Xray's uplinkOnly: the client side stays open after the answer
    QByteArray trailing;  // bytes after the declared body (must never become a proof)
    int splitDelayMs=0;   // > 0: headers+half body first, the rest after this delay
    QByteArray lengthHeader="Content-Length"; // spelling of the length header ("" = no length)
    bool wrongNonce=false;
    explicit TinySocksAgent(QString exit) : exitId(std::move(exit)) {
        server.listen(QHostAddress::LocalHost,0);
        connect(&server,&QTcpServer::newConnection,this,[this] {
            while (QTcpSocket* socket=server.nextPendingConnection()) {
                connect(socket,&QTcpSocket::disconnected,socket,&QObject::deleteLater);
                connect(socket,&QTcpSocket::readyRead,socket,[this,socket] { serve(socket); });
            }
        });
    }
    void serve(QTcpSocket* socket) {
        QByteArray in=socket->property("in").toByteArray()+socket->readAll();
        int stage=socket->property("stage").toInt();
        for (;;) {
            if (stage==0) { // greeting: 05 n methods...
                if (in.size()<2 || in.size()<2+quint8(in[1])) break;
                in.remove(0,2+quint8(in[1])); socket->write(QByteArray("\x05\x02",2)); stage=1; continue;
            }
            if (stage==1) { // RFC 1929: 01 ulen user plen pass
                if (in.size()<2) break;
                const int ulen=quint8(in[1]); if (in.size()<3+ulen) break;
                const int plen=quint8(in[2+ulen]); if (in.size()<3+ulen+plen) break;
                in.remove(0,3+ulen+plen); socket->write(QByteArray("\x01\x00",2)); stage=2; continue;
            }
            if (stage==2) { // 05 01 00 atyp addr port
                if (in.size()<5) break;
                const int atyp=quint8(in[3]);
                const int need=atyp==1?10:atyp==4?22:atyp==3?7+quint8(in[4]):-1;
                if (need<0) { socket->abort(); return; }
                if (in.size()<need) break;
                in.remove(0,need); socket->write(QByteArray("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",10)); stage=3; continue;
            }
            if (stage==3) { // GET /mayak-proof?n=<nonce> HTTP/1.1 ... \r\n\r\n
                const int end=in.indexOf("\r\n\r\n"); if (end<0) break;
                const QByteArray line=in.left(in.indexOf("\r\n"));
                const int at=line.indexOf("?n="); const int sp=line.indexOf(' ',at);
                const QByteArray nonce=at<0||sp<0?QByteArray():line.mid(at+3,sp-at-3);
                const QByteArray answered=wrongNonce?QByteArray("0123456789abcdef0123456789abcdef"):nonce;
                const QByteArray body="{\"v\":1,\"exit\":\""+exitId.toUtf8()+"\",\"nonce\":\""+answered+"\"}";
                const QByteArray head="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    +(lengthHeader.isEmpty()?QByteArray():lengthHeader+": "+QByteArray::number(body.size())+"\r\n")
                    +"Connection: close\r\n\r\n";
                const QByteArray all=head+body+trailing;
                if (splitDelayMs>0) {
                    const qsizetype cut=head.size()+body.size()/2;
                    socket->write(all.left(cut)); socket->flush();
                    QPointer<QTcpSocket> guard(socket);
                    QTimer::singleShot(splitDelayMs,socket,[this,guard,rest=all.mid(cut)] {
                        if (!guard) return;
                        guard->write(rest); guard->flush();
                        if (!holdOpen) guard->disconnectFromHost();
                    });
                } else {
                    socket->write(all);
                    if (!holdOpen) socket->disconnectFromHost();
                }
                stage=4;
            }
            break;
        }
        socket->setProperty("in",in); socket->setProperty("stage",stage);
    }
};
QString photoPath(const QString& ext=QStringLiteral("png")) {
    return QStringLiteral("media/servers/0123456789abcdef0123456789abcdef.")+ext+QStringLiteral("?v=0123456789ab");
}
struct World : QObject {
    SecureQSettings settings{QStringLiteral("MayakRuntime-")+guid(),QStringLiteral("test"),nullptr,true};
    SecureServersRepository servers{&settings};
    SecureAppSettingsRepository app{&settings};
    SubscriptionController subscription{&servers,&app};
    ConnectionController connection{&servers,&app,nullptr};
    QString id, first=guid(), second=guid(), allocation=guid();
    QStringList events;
    int acquires=0, starts=0, releases=0, reconciles=0, stops=0;
    bool fullFirst=false, deadFirst=false, lostAcquire=false, badProof=false, holdStart=false;
    bool holdPermission=false;
    int exitLocationMode=0; // 0 valid, 1 absent, 2 bad schema, 3 candidate mismatch, 4 unknown city
    QJsonValue exitCard=QJsonValue::Null; // exit_location.card (schema 2); Undefined = field absent
    bool backendRunning=false, missingStop=false, failRelease=false, failStopOnce=false, holdNextStop=false;
    bool holdReleaseForever=false;
    bool holdReconcileForever=false, holdProvenForever=false, synchronousCleanup=false;
    bool holdInspection=false, activeInspection=false;
    B::Inspected heldInspection; QString inspectionNonce;
    int reconcileDelay=0;
    int releaseDelay=0;
    int acquireDelay=0;
    QString publicKey, selectedHost = "81.29.149.103";
    B::Ticket current;
    QList<B::Ticket> stopTickets;
    QList<QJsonObject> requestPayloads;
    QList<std::shared_ptr<QPromise<GatewayPostResult>>> heldTransportPromises, allTransportPromises;
    AwgTunnelHealth health;
    QTimer traffic; B::Ticket awgTicket; bool xrayActive=false; bool stallRx=false; bool idle=false; bool healthGone=false;
    std::function<void(B::Ticket,AwgTunnelHealth)> observeHealth;
    B::Done startDone;
    QString permissionRequestId;
    B::PermissionDone heldPermissionDone;
    B::Done heldStopDone;
    QString heldStopNonce;
    std::function<void(B::Result)> observeDown;
    // Connected-state recovery fixture: a stuck transport answers no probe and no RX.
    bool tunnelDown=false, recoverHeals=true, recoverOk=true;
    int failNextProbes=0, recovers=0;
    int bindFailNextProbes=0; // Android: the next probes fail the strict VPN socket bind (network not visible yet)
    std::function<void(B::Ticket,bool)> observeNetwork;
    std::function<void(B::Ticket,bool,bool)> observeResume;
    std::function<void(B::Ticket)> observeUserStop;
    // Cold-start adoption fixture.
    QString inspectionIdentity; // non-empty: the active inspection reports this control identity
    bool adoptOk=true; int adopts=0; QString adoptedTicket;
    qint64 adoptHandshakeAgeMs=60000; // the adopted live session's last handshake (no replacement)
    bool adoptDeadline=false;         // the service never confirms the transfer in time
    std::function<void(bool)> observeVisibility;
    std::function<void(B::Ticket)> observeFailover;
    bool silentFirst=false, singleCandidate=false;
    QString silentHost;      // AWG on this exit host never answers a handshake (no valid health)
    QString xrayDeadHost;    // Xray on this exit host never comes up
    // Port precheck fixture (never real addresses): hosts listed here do not answer.
    QSet<QString> tcpDeadHosts; int prechecks=0; quint16 precheckPort=0;
    QStringList startHosts;  // "<host>/<protocol>" per backend start
    // WinTun repair fixture (never the real service): counts requests; holdHeal keeps the reply.
    int heals=0; bool holdHeal=false; std::function<void(bool,QString)> heldHeal;
    QString healResult=QStringLiteral("healed");
    // Xray paths (5.1.0.21): acquire offers them when asked; the fixture backend runs either path.
    bool offerXray=false, awgSilent=false, xrayDead=false;
    int awgStarts=0, xrayStarts=0;
    QStringList startedProtocols;
    QJsonObject lastXrayConfig;
    // Race engine fixture: started engines get loopback SOCKS entries nobody serves.
    bool withRace=false, raceEngineOk=true;
    bool appExclusionFails=false; // the Windows service reports that app exclusions cannot be applied
    int raceStarts=0, raceStops=0; bool raceRunning=false;
    QJsonObject raceConfig;
    int localFailStarts=0; // Windows: the next N starts never bring the tunnel interface up (no health)
    // Windows: the service is still busy failing the adapter, so the first stop of such an
    // attempt is not confirmed in time (a later stop is).
    bool localFailStopUnconfirmed=false;
    QSet<QString> localFailTickets, localFailStopsSeen;
    // Candidate of the n-th acquire (0-based) of this World.
    QString acquireCandidate(int n) const {
        for (const auto& p:requestPayloads) if (p.value("action").toString()=="acquire" && n--==0) return p.value("candidate_id").toString();
        return {};
    }
    QString lastAcquireCandidate() const {
        QString id;
        for (const auto& p:requestPayloads) if (p.value("action").toString()=="acquire") id=p.value("candidate_id").toString();
        return id;
    }
    std::unique_ptr<MayakAutoConnectRuntime> runtime;
    Vpn::ConnectionState state=Vpn::ConnectionState::Disconnected;
    explicit World(bool withRecover=false, bool withAdopt=true) {
        MayakAutoConnectRuntime::resetFailoverMemoryForTests(); // process-wide failover memory
        MayakAutoConnectRuntime::setPortPrecheckForTests([this](QObject*,const QStringList& hosts,quint16 port,int,
                                                               std::function<void(QList<bool>)> done) {
            ++prechecks; precheckPort=port;
            QList<bool> answered; for (const auto& host:hosts) answered<<!tcpDeadHosts.contains(host);
            done(answered);
        });
        MayakAutoConnectRuntime::setWintunHealForTests([this](QObject* ctx,std::function<void(bool,QString)> done) {
            ++heals; events<<"heal";
            if (holdHeal) { heldHeal=done; return; }
            const QString result=healResult;
            QTimer::singleShot(0,ctx,[done,result] { done(true,result); });
        });
        // This app version already ran here: no "first connect of a new version" repair in tests.
        settings.setValue("Mayak/wintunHealVersion",QStringLiteral(APP_VERSION));
        ApiV2ServerConfig cfg;
        cfg.configVersion=serverConfigUtils::ConfigSource::AmneziaGateway;
        cfg.name="Mayak test"; cfg.defaultContainer=DockerContainer::Awg;
        cfg.apiConfig.serviceType="amnezia-premium"; cfg.apiConfig.serviceProtocol="awg";
        cfg.apiConfig.userCountryCode="ru"; cfg.authData.apiKey="synthetic-device-credential";
        id=servers.addServer(guid(),cfg.toJson(),serverConfigUtils::configTypeFromJson(cfg.toJson()));
        app.setMayakSessionToken("synthetic-email-session"); app.markMayakManagedServer(id);
        B::Port port; port.owner=this;
        port.observe=[this](QObject*,auto healthCallback,auto downCallback){observeHealth=healthCallback;observeDown=downCallback;};
        port.inspect=[this](QString nonce,qint64,B::Inspected done) {
            events<<"inspect";
            if (holdInspection) { inspectionNonce=nonce; heldInspection=done; return; }
            if (activeInspection) {
                current={inspectionIdentity.isEmpty() ? guid() : QStringLiteral("recovery:")+inspectionIdentity,std::make_shared<B::StartGate>()};
                current.gate->commit(); backendRunning=true; done({B::OwnState::Active,nonce,inspectionIdentity,current}); return;
            }
            done({backendRunning?B::OwnState::Unknown:B::OwnState::Off,nonce,{},{}});
        };
        port.preparePermissions=[this](QString requestId,B::PermissionDone done) {
            permissionRequestId=requestId;
            if (holdPermission) heldPermissionDone=std::move(done);
            else done(requestId,B::PermissionResult::Ready);
        };
        port.cancelPermissionPreparation=[this](QString requestId) {
            if (requestId==permissionRequestId) heldPermissionDone={};
        };
        port.start=[this](B::Ticket ticket,QString,QJsonObject config,qint64,B::Done done) {
            ++starts; events<<"start"; current=ticket;
            const QString protocol=config.value("protocol").toString();
            startedProtocols<<protocol; startHosts<<selectedHost+"/"+protocol;
            if (protocol=="xray") {
                ++xrayStarts; lastXrayConfig=config; ticket.gate->commit(); backendRunning=true;
                xrayActive=true; awgTicket={};
                AwgHealthContext expected{"xray:"+ticket.opaqueAttempt,"78726179",selectedHost+":443"};
                done({ticket,B::Outcome::Started,expected});
                health={expected.id,1,expected.peerPublicKey,expected.endpoint,"10.33.0.2/32","MayakXrayFixture",0,10,10,
                        !xrayDead && selectedHost!=xrayDeadHost};
                QTimer::singleShot(10,this,[this,ticket] {if(observeHealth)observeHealth(ticket,health);});
                return;
            }
            ++awgStarts;
            xrayActive=false;
            if (appExclusionFails) mayak::split::markAppExclusionFailure();
            if(holdStart) { startDone=done; return; }
            ticket.gate->commit(); backendRunning=true;
            AwgHealthContext expected{guid(),QString(64,'a'),selectedHost+":49963"};
            done({ticket,deadFirst && starts==1?B::Outcome::Failed:B::Outcome::Started,expected});
            // localFailStarts: started, but the tunnel interface never comes up (no health at all).
            if (localFailStarts>0) { --localFailStarts; events<<"local_fail"; localFailTickets.insert(ticket.opaqueAttempt); return; }
            // silentFirst: the first exit never answers a handshake (no valid health ever).
            const bool silent=(silentFirst && selectedHost=="81.29.149.103") || awgSilent || selectedHost==silentHost;
            // badProof (5.1.0.27, AWG proof = handshake + RX): the exit never answers a handshake.
            health={expected.id,1,expected.peerPublicKey,expected.endpoint,"10.8.0.2","MayakFixture",
                    badProof ? 0 : quint64(QDateTime::currentMSecsSinceEpoch()),10,10,!silent};
            awgTicket=ticket;
            QTimer::singleShot(10,this,[this,ticket] {if(observeHealth)observeHealth(ticket,health);});
        };
        port.cancel=[](B::Ticket t){t.gate->cancel();};
        port.stop=[this](B::Ticket t,QString nonce,qint64,B::Done done) {
            ++stops; events<<"down"; stopTickets.append(t);
            if(localFailStopUnconfirmed && localFailTickets.contains(t.opaqueAttempt) && !localFailStopsSeen.contains(t.opaqueAttempt)) {
                localFailStopsSeen.insert(t.opaqueAttempt); events<<"down_unconfirmed"; done({t,B::Outcome::Unknown,{},nonce}); return;
            }
            if(holdNextStop) {holdNextStop=false;heldStopNonce=nonce;heldStopDone=done;return;}
            if(failStopOnce) {failStopOnce=false;done({t,B::Outcome::Unknown,{},nonce});return;}
            if(missingStop) {done({t,B::Outcome::Unknown,{},nonce});return;}
            backendRunning=false; done({t,B::Outcome::ConfirmedDown,{},nonce});
        };
        port.probe=[this](B::Ticket ticket,MayakTunnelProbeRequest request,qint64,B::Probed done) {
            events<<"probe";
            if (bindFailNextProbes>0) { --bindFailNextProbes; done(ticket,false,{},QStringLiteral("strict Android VPN socket binding failed")); return; }
            bool ok=!badProof && !tunnelDown;
            if (ok && failNextProbes>0) { --failNextProbes; ok=false; }
            // The fixture's exit agent answers with the exit the request expects (5.1.0.27).
            done(ticket,ok,{ticket.opaqueAttempt,request.nonce,request.expectedExitId,request.interfaceName,request.localAddress.toString()},{});
            if (!tunnelDown) health.rxTotal+=500; // a live tunnel still carries RX on a random probe miss
            health.txTotal+=500;
            QTimer::singleShot(10,this,[this,ticket] {if(observeHealth)observeHealth(ticket,health);});
        };
        port.raceStart=[this](QString,QJsonObject config,qint64,std::function<void(bool)> done) {
            if (!withRace) { done(false); return; }
            ++raceStarts; events<<"race_start"; raceConfig=config;
            if (backendRunning) { done(false); return; } // never with a tunnel up
            raceRunning=raceEngineOk; done(raceEngineOk);
        };
        port.raceStop=[this](QString,qint64,std::function<void(bool)> done) {
            ++raceStops; events<<"race_stop"; raceRunning=false; done(true);
        };
        port.observeResume=[this](QObject*,std::function<void(B::Ticket,bool,bool)> resumed){observeResume=resumed;};
        port.observeUserStop=[this](QObject*,std::function<void(B::Ticket)> stopped){observeUserStop=stopped;};
        port.observeVisibility=[this](QObject*,std::function<void(bool)> changed){observeVisibility=changed;};
        port.observeFailover=[this](QObject*,std::function<void(B::Ticket)> requested){observeFailover=requested;};
        if (withAdopt) port.adopt=[this](B::Ticket recovery,B::Ticket fresh,QString identity,QJsonObject,QString nonce,qint64,B::Done done) {
            ++adopts; events<<"adopt"; adoptedTicket=fresh.opaqueAttempt;
            B::Result r{fresh,adoptOk && recovery.same(current) ? B::Outcome::Started : B::Outcome::Failed}; r.requestId=nonce;
            if (adoptDeadline) r.outcome=B::Outcome::Deadline;
            if (r.outcome==B::Outcome::Started) {
                // Handover without replacement: the same running backend and session continue
                // under the attempt ticket; its last handshake predates the adoption.
                AwgHealthContext expected{identity,QString(64,'a'),selectedHost+":49963"};
                r.expected=expected; current=fresh; awgTicket=fresh;
                health={expected.id,7,expected.peerPublicKey,expected.endpoint,"10.8.0.2","MayakFixture",
                        quint64(QDateTime::currentMSecsSinceEpoch()-adoptHandshakeAgeMs),10,10,true};
                QTimer::singleShot(10,this,[this,fresh] { if (observeHealth) observeHealth(fresh,health); });
            }
            done(r);
        };
        if (withRecover) {
            port.observeNetwork=[this](QObject*,std::function<void(B::Ticket,bool)> changed){observeNetwork=changed;};
            port.recover=[this](B::Ticket ticket,QString nonce,qint64,B::Done done) {
                ++recovers; events<<"recover";
                B::Result result{ticket,recoverOk?B::Outcome::Started:B::Outcome::Failed}; result.requestId=nonce;
                if (recoverOk) {
                    if (recoverHeals) tunnelDown=false;
                    // New backend: new generation, counters restart, same proof context.
                    health.generation+=1; health.rxTotal=0; health.txTotal=0;
                    QTimer::singleShot(10,this,[this,ticket] {if(observeHealth)observeHealth(ticket,health);});
                }
                done(result);
            };
        }
        runtime=std::make_unique<MayakAutoConnectRuntime>(&settings,&servers,&app,&subscription,&connection,port,nullptr,
            [this](const QString& path,const QJsonObject& payload,int){return transport(path,payload);});
        connection.setMayakRuntime(runtime.get());
        connect(runtime.get(),&MayakAutoConnectRuntime::stateChanged,this,[this](auto value,QString){state=value;});
        // AWG connected check by counters (5.1.0.27): the device keeps sending; a live tunnel also
        // receives, a stuck one (tunnelDown) does not. Xray keeps its probe-driven counters.
        traffic.setInterval(100);
        connect(&traffic,&QTimer::timeout,this,[this] {
            if (!backendRunning || !observeHealth || !awgTicket.valid() || !health.valid || xrayActive || healthGone) return;
            // idle: reports keep coming with unchanged counters (nobody uses the network).
            if (!idle) {
                health.txTotal+=500;
                if (!tunnelDown && !stallRx) health.rxTotal+=500;
            }
            observeHealth(awgTicket,health);
        });
        traffic.start();
    }
    ~World() {
        traffic.stop();
        if (runtime) disconnect(runtime.get(),nullptr,this,nullptr); // test-local captures may already be gone
        // A later session must never reach this World nor a real address: every host answers.
        MayakAutoConnectRuntime::setPortPrecheckForTests([](QObject*,const QStringList& hosts,quint16,int,std::function<void(QList<bool>)> done) {
            done(QList<bool>(hosts.size(),true)); });
        MayakAutoConnectRuntime::setWintunHealForTests([](QObject* ctx,std::function<void(bool,QString)> done) {
            QTimer::singleShot(0,ctx,[done] { done(false,QString()); }); });
        // A cancelled fixture timer must not destroy an unfinished promise and
        // dispatch a result-less QFuture into the following test's event loop.
        // Drain synthetic transport work while this World's repositories live.
        for (int round=0;round<2;++round) {
            for (const auto& p:allTransportPromises) if (!p->future().isFinished()) {
                p->addResult({ErrorCode::NoError,QByteArrayLiteral("{}"),false}); p->finish();
            }
            QCoreApplication::processEvents();
            if (!round) runtime.reset();
        }
        settings.clearSettings();
    }
    QString config() {
        const QString serverPub=QString::fromLatin1(QByteArray(32,'p').toBase64());
        const QString psk=QString::fromLatin1(QByteArray(32,'s').toBase64());
        const QString native=QStringLiteral("[Interface]\nAddress = 10.8.0.2/32\nPrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\n\n[Peer]\nPublicKey = %1\nPresharedKey = %2\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %3:49963\nPersistentKeepalive = 25\n").arg(serverPub,psk,selectedHost);
        // Keep the gateway's raw allocation shape: admission validates this JSON
        // before the model import substitutes the stable client private key.
        QJsonObject last{{configKey::hostName,selectedHost},{configKey::port,49963},
                         {configKey::clientPrivKey,"$WIREGUARD_CLIENT_PRIVATE_KEY"},
                         {configKey::clientPubKey,publicKey},{configKey::clientId,publicKey},
                         {configKey::serverPubKey,serverPub},{configKey::pskKey,psk},
                         {configKey::clientIp,"10.8.0.2"},{configKey::config,native},
                         {configKey::allowedIps,QJsonArray{"0.0.0.0/0","::/0"}},
                         {configKey::persistentKeepAlive,"25"},{configKey::mtu,"1280"}};
        QJsonObject awg{{configKey::port,"49963"},{"transport_proto","udp"},
                        {configKey::protocolVersion,"2"},{configKey::subnetAddress,"10.8.0.0"},
                        {configKey::subnetCidr,"24"},
                        {configKey::lastConfig,QString::fromUtf8(QJsonDocument(last).toJson(QJsonDocument::Compact))}};
        QJsonObject container{{configKey::container,"amnezia-awg2"},{QString(configKey::awg),awg}};
        QJsonObject api{{apiDefs::key::serviceType,"amnezia-premium"},{apiDefs::key::serviceProtocol,"awg"},
                        {apiDefs::key::userCountryCode,"ru"}};
        QJsonObject cfg{{configKey::configVersion,serverConfigUtils::ConfigSource::AmneziaGateway},
                        {configKey::name,"Mayak test"},{apiDefs::key::apiConfig,api},
                        {apiDefs::key::authData,QJsonObject{{apiDefs::key::apiKey,"synthetic-device-credential"}}},
                        {configKey::hostName,selectedHost},{configKey::defaultContainer,"amnezia-awg2"},
                        {configKey::containers,QJsonArray{container}},
                        {configKey::description,"Mayak runtime fixture"},
                        {configKey::dns1,"1.1.1.1"},{configKey::dns2,"1.0.0.1"}};
        return "vpn://"+QString::fromUtf8(qCompress(QJsonDocument(cfg).toJson(QJsonDocument::Compact)).toBase64(QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals));
    }
    QJsonObject xrayPaths() {
        QJsonArray paths;
        for (const QString fp : {QStringLiteral("firefox"),QStringLiteral("safari"),QStringLiteral("chrome")}) {
            const QJsonObject stream{{"network","xhttp"},{"security","reality"},
                {"realitySettings",QJsonObject{{"fingerprint",fp},{"serverName","example.org"},{"publicKey","pk"},{"shortId","ab"}}},
                {"xhttpSettings",QJsonObject{{"host","example.org"},{"path","/p"},{"mode","auto"}}}};
            const QJsonObject client{{"inbounds",QJsonArray{QJsonObject{{"listen","127.0.0.1"},{"port",10808},{"protocol","socks"},{"settings",QJsonObject{{"udp",true}}}}}},
                {"outbounds",QJsonArray{QJsonObject{{"protocol","vless"},
                    {"settings",QJsonObject{{"vnext",QJsonArray{QJsonObject{{"address",selectedHost},{"port",443},
                        {"users",QJsonArray{QJsonObject{{"id",guid()},{"encryption","none"}}}}}}}}},
                    {"streamSettings",stream}}}}};
            const QJsonObject xray{{"port","443"},{"transport_proto","tcp"},{"xray_fingerprint",fp},{"xray_security","reality"},
                {"xray_sni","example.org"},{"xray_transport","xhttp"},
                {"last_config",QString::fromUtf8(QJsonDocument(client).toJson(QJsonDocument::Compact))}};
            const QJsonObject root{{"config_version",2},{"name","Mayak test"},{"hostName",selectedHost},{"defaultContainer","amnezia-xray"},
                {"containers",QJsonArray{QJsonObject{{"container","amnezia-xray"},{"xray",xray}}}},{"dns1","1.1.1.1"},{"dns2","1.0.0.1"}};
            paths.append(QJsonObject{{"id","xray-"+fp},{"fingerprint",fp},{"config","vpn://"+QString::fromUtf8(
                qCompress(QJsonDocument(root).toJson(QJsonDocument::Compact)).toBase64(QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals))}});
        }
        return {{"schema",1},{"paths",paths}};
    }
    int failConfigCount=0; // gateway unreachable (DNS/timeout) for the next N config fetches
    int failReleaseTransport=0; // the next N releases never reach the server (connection reset)
    int failProvenCount=0; // no server answer for the next N "proven" reports
    bool refuseProven=false; // the server answers "proven": false
    bool errorProven=false;  // the server answers "proven" with an admission error
    int provenCalls=0;
    // Connect without the gateway (review 01, item 2): the gateway never answers anything while
    // `gatewayDown`; v1/config answers after `configDelay` ms; a late acquire answers by `lateMode`
    // (0 place, 1 no answer, 2 REVOKED, 3 NOT_READY, 4 INVALID_REQUEST).
    bool gatewayDown=false; int configDelay=0; int lateMode=0; int lateAcquires=0;
    QJsonObject offlineMemory() const { return QJsonDocument::fromJson(const_cast<SecureQSettings&>(settings).value("Mayak/offlineMemory").toByteArray()).object(); }
    int deferredCleanups() const { return int(QJsonDocument::fromJson(const_cast<SecureQSettings&>(settings).value("Mayak/deferredCleanup").toByteArray()).array().size()); }
    // The pre-23.11 cleanup tests: no stored exits, so an unanswered release/reconcile keeps the
    // manual "retry the disconnect" path (the stored-exit deferral needs a usable memory).
    bool noOfflineMemory=false;
    QJsonObject configError;          // v1/config answers this signed error instead of the capability
    bool invalidNextAcquire=false;    // the next normal acquire: INVALID_REQUEST (an older place is open)
    bool refuseReconcile=false;       // reconcile answers "reconciled": false
    QFuture<GatewayPostResult> transport(QString path,QJsonObject payload) {
        requestPayloads.append(payload);
        if (noOfflineMemory) settings.remove("Mayak/offlineMemory");
        if (gatewayDown) {
            events<<"gateway_down";
            auto promise=std::make_shared<QPromise<GatewayPostResult>>(); promise->start(); auto future=promise->future();
            allTransportPromises.append(promise);
            QTimer::singleShot(5,this,[promise]{ if (promise->future().isFinished()) return;
                promise->addResult({ErrorCode::ApiConfigDownloadError,{},false}); promise->finish(); });
            return future;
        }
        if (payload.value("action").toString()=="acquire" && payload.value("late").isBool() && payload.value("late").toBool()) {
            ++lateAcquires; events<<"late_acquire";
            auto promise=std::make_shared<QPromise<GatewayPostResult>>(); promise->start(); auto future=promise->future();
            allTransportPromises.append(promise);
            if (lateMode==1) {
                QTimer::singleShot(5,this,[promise]{ if (promise->future().isFinished()) return;
                    promise->addResult({ErrorCode::ApiConfigTimeoutError,{},false}); promise->finish(); });
                return future;
            }
            QJsonObject response;
            if (lateMode==2) response={{"http_status",403},{"code","REVOKED"},{"message","REVOKED"}};
            else if (lateMode==3) response={{"http_status",409},{"code","NOT_READY"},{"message","not ready"}};
            else if (lateMode==4) response={{"http_status",400},{"code","INVALID_REQUEST"},{"message","closed"}};
            else response={{"allocation_id",allocation},{"connect_before",QDateTime::currentDateTimeUtc().addSecs(30).toString(Qt::ISODateWithMs)},
                           {"config_revision",14},{"config",config()}};
            QTimer::singleShot(5,this,[promise,response]{ if (promise->future().isFinished()) return;
                promise->addResult({ErrorCode::NoError,QJsonDocument(response).toJson(QJsonDocument::Compact),true}); promise->finish(); });
            return future;
        }
        if(path.endsWith("config") && failConfigCount>0) {
            --failConfigCount; events<<"config_fail";
            auto promise=std::make_shared<QPromise<GatewayPostResult>>(); promise->start(); auto future=promise->future();
            allTransportPromises.append(promise);
            QTimer::singleShot(5,this,[promise]{ if (promise->future().isFinished()) return;
                promise->addResult({ErrorCode::ApiConfigDownloadError,{},false}); promise->finish(); });
            return future;
        }
        if (payload.value("action").toString()=="release" && failReleaseTransport>0) {
            --failReleaseTransport; events<<"release_fail";
            auto promise=std::make_shared<QPromise<GatewayPostResult>>(); promise->start(); auto future=promise->future();
            allTransportPromises.append(promise);
            QTimer::singleShot(5,this,[promise]{ if (promise->future().isFinished()) return;
                promise->addResult({ErrorCode::ApiConfigDownloadError,{},false}); promise->finish(); });
            return future;
        }
        QJsonObject response; int delay=0;bool trusted=true;
        if(path.endsWith("config")) {
            publicKey=payload.value("public_key").toString();events<<"config";
            QJsonArray candidates;
            for(const auto& candidate:{first,second}) {
                if (singleCandidate && candidate==second) continue;
                candidates.append(QJsonObject{{"id",candidate},{"host",candidate==first?"81.29.149.103":"81.29.149.104"},
                {"port",49963},{"preferred",candidate==first},{"expected_egress_ips",QJsonArray{"81.29.149.103"}}});
            }
            response={{"mayak_connection",QJsonObject{{"schema",1},{"revision",14},{"expires_at",QDateTime::currentDateTimeUtc().addSecs(60).toString(Qt::ISODateWithMs)},{"candidates",candidates}}}};
            delay=configDelay;
            if (!configError.isEmpty()) response=configError;
        } else {
            const auto action=payload.value("action").toString();events<<action;
            if(action=="acquire") {
                publicKey=payload.value("public_key").toString();
                selectedHost=payload.value("candidate_id").toString()==first?"81.29.149.103":"81.29.149.104";
                ++acquires; delay=acquireDelay;
                if (invalidNextAcquire) { invalidNextAcquire=false; response={{"http_status",400},{"code","INVALID_REQUEST"},{"message","open place"}}; }
                else if(fullFirst && acquires==1) response={{"http_status",409},{"code","FULL"},{"message","full"}};
                else { response={{"allocation_id",allocation},{"connect_before",QDateTime::currentDateTimeUtc().addSecs(30).toString(Qt::ISODateWithMs)},
                    {"config_revision",14},{"config",config()}}; trusted=!lostAcquire; }
                if (!response.contains("http_status") && offerXray && payload.value("mayak_paths").toInt()==1)
                    response.insert("xray_paths",xrayPaths());
                if (!response.contains("http_status") && payload.value("mayak_exit_location").toInt()==2
                    && exitLocationMode!=1) {
                    const QString candidate=payload.value("candidate_id").toString();
                    QJsonObject location{{"schema",exitLocationMode==2?3:2},
                        {"candidate_id",exitLocationMode==3?guid():candidate},
                        {"city_id",exitLocationMode==4?QStringLiteral("unknown"):candidate==first?QStringLiteral("oslo"):QStringLiteral("helsinki")}};
                    if (!exitCard.isUndefined()) location.insert("card",exitCard);
                    response.insert("exit_location",location);
                }
            } else if(action=="release") {++releases;delay=releaseDelay;response={{"released",!backendRunning && !failRelease}};}
            else if(action=="proven") {
                ++provenCalls;
                if (failProvenCount>0) { // no answer from the server (network/timeout)
                    --failProvenCount; events<<"proven_fail";
                    auto promise=std::make_shared<QPromise<GatewayPostResult>>(); promise->start(); auto future=promise->future();
                    allTransportPromises.append(promise);
                    QTimer::singleShot(5,this,[promise]{ if (promise->future().isFinished()) return;
                        promise->addResult({ErrorCode::ApiConfigTimeoutError,{},false}); promise->finish(); });
                    return future;
                }
                response=errorProven ? QJsonObject{{"http_status",403},{"code","REVOKED"},{"message","REVOKED"}}
                                     : QJsonObject{{"proven",!refuseProven}};
            }
            else if(action=="reconcile") {
                ++reconciles;delay=reconcileDelay;
                // Like the server: a deferred older attempt is reconciled while another tunnel runs.
                bool deferred=false;
                for (const auto& e:QJsonDocument::fromJson(settings.value("Mayak/deferredCleanup").toByteArray()).array())
                    if (e.toObject().value("attempt").toString()==payload.value("attempt_id").toString()) deferred=true;
                response={{"reconciled",(!backendRunning || deferred) && !refuseReconcile}};
            }
        }
        auto promise=std::make_shared<QPromise<GatewayPostResult>>();promise->start();auto future=promise->future();
        allTransportPromises.append(promise);
        if ((payload.value("action").toString()=="release" && holdReleaseForever)
            || (payload.value("action").toString()=="reconcile" && holdReconcileForever)
            || (payload.value("action").toString()=="proven" && holdProvenForever)) {
            heldTransportPromises.append(promise);
            return future;
        }
        if (synchronousCleanup && payload.value("action").toString()!="acquire") {
            promise->addResult({ErrorCode::NoError,QJsonDocument(response).toJson(QJsonDocument::Compact),trusted}); promise->finish(); return future;
        }
        QTimer::singleShot(delay,this,[promise,response,trusted]{if (promise->future().isFinished()) return; promise->addResult({ErrorCode::NoError,QJsonDocument(response).toJson(QJsonDocument::Compact),trusted});promise->finish();});
        return future;
    }
    void seed(int count=1) {
        mayak::attempts::MayakAttemptStore store(&settings);
        for (int i=0;i<count;++i) {
            mayak::attempts::AttemptInput input{{id,guid(),guid(),guid(),first},
                {"https://mayaklight.ru/gw/",guid(),QString::fromLatin1(QByteArray(32,'k').toBase64()),
                 "synthetic-device-credential","amnezia-premium","awg","ru",{}},false,false,{}};
            if (!store.appendBeforeAcquire(input).ok) qFatal("Could not seed isolated test ledger");
        }
    }
    void drainHeld(const QByteArray& body) {
        for (const auto& p:heldTransportPromises) if (!p->future().isFinished()) {
            p->addResult({ErrorCode::NoError,body,true}); p->finish();
        }
        QCoreApplication::processEvents();
    }
    int records() {auto result=mayak::attempts::MayakAttemptStore(&settings).load();return result.ok?result.records.size():-1;}
    // A persisted attempt that started a backend and holds `allocation` (what a cold start finds).
    QString seedStarted(const QString& candidateId=QString()) {
        mayak::attempts::MayakAttemptStore store(&settings);
        mayak::attempts::AttemptIdentity identity{id,guid(),guid(),guid(),candidateId.isEmpty()?first:candidateId};
        mayak::attempts::AttemptInput input{identity,{"https://mayaklight.ru/gw/",guid(),QString::fromLatin1(QByteArray(32,'k').toBase64()),
            "synthetic-device-credential","amnezia-premium","awg","ru",{}},false,false,{}};
        if (!store.appendBeforeAcquire(input).ok || !store.attachAllocation(identity,allocation).ok || !store.markMayHaveStarted(identity).ok)
            qFatal("Could not seed started attempt");
        return identity.attemptId;
    }
};
}
namespace {
// Leave nothing in flight for the next test (sessions may outlive a World's repositories).
void settle(World& w) {
    w.runtime->cancel();
    QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    QTest::qWait(100);
}
// Fast, test-local connected-monitor timing; restored for every other test.
struct FastRecoveryTiming {
    MayakAutoConnectRuntime::RecoveryTiming previous = MayakAutoConnectRuntime::recoveryTiming();
    FastRecoveryTiming() {
        MayakAutoConnectRuntime::RecoveryTiming t;
        t.monitorMs=250; t.retryProbeMs=120; t.probeDeadlineMs=300; t.networkSettleMs=60; t.noNetworkUiMs=60;
        t.stuckRxMs=200; t.stuckRxAfterNetworkMs=100; t.networkRecentMs=1500; t.recoverDeadlineMs=500;
        t.recoverBackoffMs={0,250,500};
        t.connectRetryMs={100,150,200};
        // The fixture's "no valid health" models a silent exit (Android semantics) unless a
        // test opts into the Windows meaning (local adapter never came up).
        t.noHealthMeansLocalFailure=false;
        t.localStartRetryMs={100,150};
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
    }
    ~FastRecoveryTiming() { MayakAutoConnectRuntime::setRecoveryTimingForTests(previous); }
    FastRecoveryTiming(const FastRecoveryTiming&) = delete;
    FastRecoveryTiming& operator=(const FastRecoveryTiming&) = delete;
};
}
// Restores the process-wide coordinator budgets even when a check fails early.
struct CoordinatorTimingGuard {
    mayak::autoconnect::Timing saved = mayak::autoconnect::Coordinator::timing();
    ~CoordinatorTimingGuard() { mayak::autoconnect::Coordinator::timing() = saved; }
};
// Restores the default (service) app-exclusion preparation.
struct SplitPrepareGuard { ~SplitPrepareGuard() { MayakAutoConnectRuntime::setSplitPrepareForTests({}); } };
struct HttpsResetGuard { ~HttpsResetGuard() { MayakAutoConnectRuntime::setHttpsSocketResetForTests({}); } };
// Connect without the gateway: short late-acquire/proven timing; restored after the test.
struct OfflineTiming {
    MayakAutoConnectRuntime::RecoveryTiming previous=MayakAutoConnectRuntime::recoveryTiming();
    explicit OfflineTiming(qint64 earlyMs=3500) {
        auto t=MayakAutoConnectRuntime::recoveryTiming();
        t.offlineEarlyMs=earlyMs; t.lateAcquireBudgetMs=500; t.lateAcquireRetryMs={100,150};
        t.provenRetryBudgetMs=500; t.provenRetryMs={100,150};
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
    }
    ~OfflineTiming() { MayakAutoConnectRuntime::setRecoveryTimingForTests(previous); }
};
class RuntimeTest : public QObject {
    Q_OBJECT
private slots:
    void acquireExitLocationMetadataIsOptionalAndBounded() {
        const auto makeBody=[](QJsonValue location) {
            QJsonObject body{{"allocation_id",guid()},
                {"connect_before",QDateTime::currentDateTimeUtc().addSecs(30).toString(Qt::ISODateWithMs)},
                {"config_revision",14},{"config","fixture"}};
            if (!location.isUndefined()) body.insert("exit_location",location);
            return QJsonDocument(body).toJson(QJsonDocument::Compact);
        };
        mayak::admission::AcquireResponse parsed;
        QVERIFY(mayak::admission::parseAcquireResponse(makeBody(QJsonObject{{"schema",1},
            {"candidate_id",guid()},{"city_id","oslo"}}),&parsed));
        QCOMPARE(parsed.exitLocationCityId,QStringLiteral("oslo"));
        QVERIFY(!parsed.exitLocationHasCard);
        // schema 2 without card (or with card null): the same ids, no card.
        QVERIFY(mayak::admission::parseAcquireResponse(makeBody(QJsonObject{{"schema",2},
            {"candidate_id",guid()},{"city_id","oslo"}}),&parsed));
        QCOMPARE(parsed.exitLocationCityId,QStringLiteral("oslo"));
        QVERIFY(!parsed.exitLocationHasCard);
        QVERIFY(mayak::admission::parseAcquireResponse(makeBody(QJsonObject{{"schema",2},
            {"candidate_id",guid()},{"city_id",""},{"card",QJsonValue::Null}}),&parsed));
        QVERIFY(!parsed.exitLocationCandidateId.isEmpty());
        QVERIFY(!parsed.exitLocationHasCard);
        for (const QJsonValue schema : {QJsonValue(3),QJsonValue(2.5),QJsonValue("2"),QJsonValue(0)}) {
            QVERIFY(mayak::admission::parseAcquireResponse(makeBody(QJsonObject{{"schema",schema},
                {"candidate_id",guid()},{"city_id","oslo"}}),&parsed));
            QVERIFY(parsed.exitLocationCandidateId.isEmpty());
            QVERIFY(parsed.exitLocationCityId.isEmpty());
        }
        QVERIFY(mayak::admission::parseAcquireResponse(makeBody(QJsonObject{{"schema",1},
            {"candidate_id",guid()},{"city_id","other"}}),&parsed));
        QVERIFY(parsed.exitLocationCityId.isEmpty());
        QVERIFY(mayak::admission::parseAcquireResponse(makeBody(QJsonValue{}),&parsed));
        QVERIFY(parsed.exitLocationCityId.isEmpty());
    }

    void selectedExitLocationFollowsTheConnectedFailoverAttemptAndClears() {
        World w;
        w.deadFirst=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.acquires,2);
        QList<QJsonObject> acquireRequests;
        for (const auto& payload : w.requestPayloads) {
            if (payload.value("action").toString()==QStringLiteral("acquire")) acquireRequests.append(payload);
            else QVERIFY(!payload.contains(QStringLiteral("mayak_exit_location")));
        }
        QCOMPARE(acquireRequests.size(),2);
        QCOMPARE(acquireRequests.at(0).value("candidate_id").toString(),w.first);
        QCOMPARE(acquireRequests.at(1).value("candidate_id").toString(),w.second);
        for (const auto& payload : acquireRequests) {
            QVERIFY(payload.value("mayak_exit_location").isDouble());
            QCOMPARE(payload.value("mayak_exit_location").toInt(),2);
        }
        // The config bootstrap is also recorded by World::transport and must
        // not opt in; it has no admission action.
        QVERIFY(!w.requestPayloads.first().contains(QStringLiteral("action")));
        QVERIFY(!w.requestPayloads.first().contains(QStringLiteral("mayak_exit_location")));
        // Construct the read-only facade after the fixture is Connected so a
        // plain QApplication never dispatches its production Connected slot
        // that expects AmneziaApplication's network manager.
        ConnectionUiController ui(&w.connection,nullptr);
        QCOMPARE(ui.exitLocation().value("candidateId").toString(),w.second);
        QCOMPARE(ui.exitLocation().value("cityId").toString(),QStringLiteral("helsinki"));
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QVERIFY(ui.exitLocation().isEmpty());
    }

    void absentOrMismatchedExitLocationNeverBlocksConnection() {
        for (const int mode : {1,3,4}) {
            World w;
            w.exitLocationMode=mode;
            w.runtime->begin(w.id);
            QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
            QCOMPARE(w.runtime->exitLocation().value("cityId").toString(),QString());
            w.runtime->cancel();
            QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        }
    }

    void exitLocationCardIsStrict() {
        namespace ad=mayak::admission;
        ad::ExitLocationCard card;
        QVERIFY(ad::parseExitLocationCard(validCard(),&card));
        QCOMPARE(card.city,QStringLiteral("Вена")); QCOMPARE(card.country,QStringLiteral("Австрия"));
        QCOMPARE(card.countryCode,QStringLiteral("at")); QCOMPARE(card.version,QStringLiteral("a1b2c3d4e5f6"));
        // Optional fields may be empty; city may not.
        QJsonObject minimal=validCard(); minimal["country"]=""; minimal["country_code"]=""; minimal["fact"]=""; minimal["photo"]="";
        QVERIFY(ad::parseExitLocationCard(minimal,&card));
        QJsonObject longest=validCard(); longest["city"]=QString(80,QChar(0x44F)); longest["country"]=QString(80,QChar(0x44F));
        longest["fact"]=QString(240,QChar(0x44F));
        QVERIFY(ad::parseExitLocationCard(longest,&card));
        for (const QString& ext : {QStringLiteral("jpg"),QStringLiteral("png"),QStringLiteral("webp")}) {
            QJsonObject c=validCard(); c["photo"]=photoPath(ext); QVERIFY(ad::parseExitLocationCard(c,&card));
        }
        const QList<QPair<QString,QJsonValue>> bad{
            {"city",""},{"city","   "},{"city",QString(81,QChar(0x44F))},{"city",5},{"city",QJsonValue::Null},
            {"country",QString(81,QChar(0x44F))},{"country",QJsonValue::Null},
            {"country_code","AT"},{"country_code","aut"},{"country_code","a"},{"country_code","a1"},
            {"fact",QString(241,QChar(0x44F))},{"fact",QJsonArray{}},
            {"photo","/media/servers/0123456789abcdef0123456789abcdef.jpg?v=0123456789ab"},
            {"photo","https://evil.example/media/servers/0123456789abcdef0123456789abcdef.jpg?v=0123456789ab"},
            {"photo","media/servers/0123456789ABCDEF0123456789abcdef.jpg?v=0123456789ab"},
            {"photo","media/servers/0123456789abcdef0123456789abcdef.gif?v=0123456789ab"},
            {"photo","media/servers/0123456789abcdef0123456789abcdef.jpg"},
            {"photo","media/servers/../0123456789abcdef0123456789abcdef.jpg?v=0123456789ab"},
            {"photo","media/servers/0123456789abcdef0123456789abcdef.jpg?v=0123456789ab\n"},
            {"country_code","at\n"},
            {"version",""},{"version","A1B2C3D4E5F6"},{"version","a1b2c3d4e5f"},{"version",12},{"version","a1b2c3d4e5f6\n"}};
        for (const auto& item : bad) {
            QJsonObject c=validCard(); c[item.first]=item.second;
            QVERIFY2(!ad::parseExitLocationCard(c,&card),qPrintable(item.first));
            QVERIFY(card.city.isEmpty());
        }
        QJsonObject extra=validCard(); extra["link"]="https://example.com";
        QVERIFY(!ad::parseExitLocationCard(extra,&card));
        QJsonObject missing=validCard(); missing.remove("version");
        QVERIFY(!ad::parseExitLocationCard(missing,&card));
        QVERIFY(!ad::parseExitLocationCard(QJsonValue("Вена"),&card));
        QVERIFY(!ad::parseExitLocationCard(QJsonArray{validCard()},&card));

        // In the acquire response: a malformed card is dropped, the ids stay; schema 1 ignores card.
        const auto body=[](int schema, const QJsonValue& cardValue, const QString& city) {
            return QJsonDocument(QJsonObject{{"allocation_id",guid()},
                {"connect_before",QDateTime::currentDateTimeUtc().addSecs(30).toString(Qt::ISODateWithMs)},
                {"config_revision",14},{"config","fixture"},
                {"exit_location",QJsonObject{{"schema",schema},{"candidate_id",guid()},{"city_id",city},{"card",cardValue}}}})
                .toJson(QJsonDocument::Compact);
        };
        ad::AcquireResponse parsed;
        QVERIFY(ad::parseAcquireResponse(body(2,validCard(),""),&parsed));
        QVERIFY(parsed.exitLocationHasCard);
        QCOMPARE(parsed.exitLocationCard.city,QStringLiteral("Вена"));
        QVERIFY(!parsed.exitLocationCandidateId.isEmpty());
        QVERIFY(parsed.exitLocationCityId.isEmpty());
        QJsonObject broken=validCard(); broken["photo"]="http://evil.example/x.jpg";
        QVERIFY(ad::parseAcquireResponse(body(2,broken,"oslo"),&parsed));
        QVERIFY(!parsed.exitLocationHasCard);
        QCOMPARE(parsed.exitLocationCityId,QStringLiteral("oslo"));
        QVERIFY(!parsed.exitLocationCandidateId.isEmpty());
        QVERIFY(ad::parseAcquireResponse(body(1,validCard(),"oslo"),&parsed));
        QVERIFY(!parsed.exitLocationHasCard);
        QCOMPARE(parsed.exitLocationCityId,QStringLiteral("oslo"));
        // A card never rescues an invalid location (unknown city id).
        QVERIFY(ad::parseAcquireResponse(body(2,validCard(),"vienna"),&parsed));
        QVERIFY(!parsed.exitLocationHasCard);
        QVERIFY(parsed.exitLocationCandidateId.isEmpty());
    }

    void serverCityCardReachesTheUiWithTheGatewayPhotoAddress() {
        World w;
        w.exitCard=validCard();
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        ConnectionUiController ui(&w.connection,nullptr);
        const QVariantMap location=ui.exitLocation();
        QCOMPARE(location.value("cityId").toString(),QStringLiteral("oslo"));
        const QVariantMap card=location.value("card").toMap();
        QCOMPARE(card.value("city").toString(),QStringLiteral("Вена"));
        QCOMPARE(card.value("country").toString(),QStringLiteral("Австрия"));
        QCOMPARE(card.value("countryCode").toString(),QStringLiteral("at"));
        QCOMPARE(card.value("fact").toString(),QStringLiteral("Город кофеен и вальсов."));
        QCOMPARE(card.value("version").toString(),QStringLiteral("a1b2c3d4e5f6"));
        QCOMPARE(card.value("photoUrl").toString(),
                 QStringLiteral("https://mayaklight.ru/gw/media/servers/0123456789abcdef0123456789abcdef.jpg?v=0123456789ab"));
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QVERIFY(ui.exitLocation().isEmpty());
    }

    void cardWithoutPhotoMalformedOrAbsentKeepsTheCityId() {
        QJsonObject noPhoto=validCard(); noPhoto["photo"]="";
        QJsonObject broken=validCard(); broken.insert("extra","x");
        for (const QJsonValue& value : {QJsonValue(noPhoto),QJsonValue(broken),QJsonValue(QJsonValue::Null),QJsonValue(QJsonValue::Undefined)}) {
            World w;
            w.exitCard=value;
            w.runtime->begin(w.id);
            QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
            QCOMPARE(w.runtime->exitLocation().value("cityId").toString(),QStringLiteral("oslo"));
            if (value.isObject() && value.toObject().size()==6) {
                const QVariantMap card=w.runtime->exitLocation().value("card").toMap();
                QCOMPARE(card.value("city").toString(),QStringLiteral("Вена"));
                QVERIFY(card.value("photoUrl").toString().isEmpty());
            } else {
                QVERIFY(!w.runtime->exitLocation().contains("card"));
            }
            w.runtime->cancel();
            QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        }
    }

    void cityPhotoLoadsOnlyOurGatewayMediaAndIsCached() {
        QTemporaryDir cache; QVERIFY(cache.isValid());
        TinyHttp http; QVERIFY(http.server.isListening());
        http.body=pngBytes();
        const QString url=http.base()+photoPath();
        {
            MayakCityPhotoUiController photo(nullptr,cache.path());
            photo.setGatewayBaseForTests(http.base());
            QSignalSpy done(&photo,&MayakCityPhotoUiController::finished);
            // Foreign or malformed addresses are refused without any request.
            for (const QString& bad : {QStringLiteral("https://evil.example/gw/")+photoPath(),
                                       http.base()+QStringLiteral("media/servers/x.png?v=0123456789ab"),
                                       http.base()+QStringLiteral("admin/")+photoPath(),
                                       http.base()+photoPath()+QStringLiteral("\n")}) {
                photo.request(bad);
                QCOMPARE(done.size(),1); QCOMPARE(done.takeFirst().at(1).toBool(),false);
                QVERIFY(photo.source().isEmpty());
            }
            QCOMPARE(http.hits,0);
            photo.request(url);
            QTRY_COMPARE_WITH_TIMEOUT(done.size(),1,5000);
            QCOMPARE(done.takeFirst().at(1).toBool(),true);
            QCOMPARE(http.hits,1);
            const QString file=QUrl(photo.source()).toLocalFile();
            QVERIFY(QFileInfo(file).isFile());
            QCOMPARE(QFileInfo(file).absoluteFilePath(),QFileInfo(photo.cachePathFor(url)).absoluteFilePath());
            photo.request(QString());
            QVERIFY(photo.source().isEmpty());
        }
        // A new start (same cache dir) shows the cached file without the network.
        const QString base=http.base(); // serverPort() is 0 once closed
        http.server.close();
        MayakCityPhotoUiController again(nullptr,cache.path());
        again.setGatewayBaseForTests(base);
        QSignalSpy done(&again,&MayakCityPhotoUiController::finished);
        again.request(url);
        QCOMPARE(done.size(),1); QCOMPARE(done.first().at(1).toBool(),true);
        QVERIFY(!again.source().isEmpty());
        QCOMPARE(http.hits,1);
    }

    void cityPhotoFailuresLeaveNoServerPhoto() {
        struct Case { QByteArray status, body, contentLength; bool silent; };
        const QByteArray huge(int(MayakCityPhotoUiController::maxBytes)+1,'x');
        const QList<Case> cases{
            {"404 Not Found",pngBytes(),{},false},
            {"302 Found",{},{},false},
            {"200 OK","<html>not an image</html>",{},false},
            {"200 OK",{},{},false},
            {"200 OK",huge,{},false},
            {"200 OK",pngBytes(),QByteArray::number(MayakCityPhotoUiController::maxBytes+10),false},
            {"200 OK",{},{},true}};
        int index=0;
        for (const auto& c : cases) {
            QTemporaryDir cache; QVERIFY(cache.isValid());
            TinyHttp http; http.status=c.status; http.body=c.body; http.contentLength=c.contentLength; http.silent=c.silent;
            MayakCityPhotoUiController photo(nullptr,cache.path());
            photo.setGatewayBaseForTests(http.base());
            photo.setTimeoutForTests(400);
            QSignalSpy done(&photo,&MayakCityPhotoUiController::finished);
            const QString url=http.base()+photoPath();
            photo.request(url);
            QTRY_COMPARE_WITH_TIMEOUT(done.size(),1,5000);
            QVERIFY2(!done.first().at(1).toBool(),qPrintable(QString::number(index)));
            QVERIFY(photo.source().isEmpty());
            QVERIFY(!QFileInfo::exists(photo.cachePathFor(url)));
            ++index;
        }
    }

    void cityPhotoIgnoresAStaleReply() {
        QTemporaryDir cache; QVERIFY(cache.isValid());
        TinyHttp slow; slow.silent=true;
        MayakCityPhotoUiController photo(nullptr,cache.path());
        photo.setGatewayBaseForTests(slow.base());
        QSignalSpy done(&photo,&MayakCityPhotoUiController::finished);
        photo.request(slow.base()+photoPath());
        QTRY_VERIFY_WITH_TIMEOUT(slow.hits>0,3000);
        photo.request(QString()); // disconnected before the photo arrived
        QTest::qWait(200);
        QCOMPARE(done.size(),0);
        QVERIFY(photo.source().isEmpty());
    }

    void phaseSnapshotReportsEveryCoordinatorState() {
        World w;
        QStringList phases;
        QList<Vpn::ConnectionState> coarseStates;
        connect(w.runtime.get(), &MayakAutoConnectRuntime::stateChanged, &w,
                [&w, &phases, &coarseStates](Vpn::ConnectionState state, const QString&) {
            phases.append(w.runtime->connectionPhase());
            coarseStates.append(state);
        });

        w.runtime->begin(w.id);
        QCOMPARE(w.runtime->connectionPhase(), QStringLiteral("preparing"));
        QTRY_COMPARE_WITH_TIMEOUT(w.state, Vpn::ConnectionState::Connected, 5000);
        for (const auto& phase : {QStringLiteral("fetching"), QStringLiteral("admitting"),
                                  QStringLiteral("starting"), QStringLiteral("verifying"),
                                  QStringLiteral("connected")})
            QVERIFY2(phases.contains(phase), qPrintable(QStringLiteral("missing phase: ") + phase));

        const int fetching = phases.indexOf(QStringLiteral("fetching"));
        const int admitting = phases.indexOf(QStringLiteral("admitting"));
        const int starting = phases.indexOf(QStringLiteral("starting"));
        const int verifying = phases.indexOf(QStringLiteral("verifying"));
        QVERIFY(fetching >= 0 && admitting > fetching);
        QVERIFY(starting > admitting && verifying > starting);
        QCOMPARE(coarseStates.at(fetching), Vpn::ConnectionState::Preparing);
        QCOMPARE(coarseStates.at(admitting), Vpn::ConnectionState::Preparing);
        QCOMPARE(coarseStates.at(starting), Vpn::ConnectionState::Connecting);
        QCOMPARE(coarseStates.at(verifying), Vpn::ConnectionState::Connecting);

        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.runtime->connectionPhase(), QStringLiteral("cancelled"), 2000);
    }

    void heldPreflightAndIdentityDriftPreserveDisconnectedBehavior() {
        World w;
        w.holdPermission=true;
        QSignalSpy states(w.runtime.get(), &MayakAutoConnectRuntime::stateChanged);
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.heldPermissionDone), 2000);
        QCOMPARE(w.runtime->connectionPhase(), QStringLiteral("preparing"));
        QVERIFY(!w.events.contains(QStringLiteral("config")));
        QTest::qWait(50);
        QCOMPARE(w.runtime->connectionPhase(), QStringLiteral("preparing"));
        QVERIFY(!w.events.contains(QStringLiteral("config")));

        // Remove the active identity without emitting mayakSessionChanging so
        // Ready reaches the existing identity-drift branch uncancelled.
        w.settings.clearSettings();
        auto ready=std::move(w.heldPermissionDone);
        ready(w.permissionRequestId,B::PermissionResult::Ready);
        QTRY_COMPARE_WITH_TIMEOUT(w.runtime->connectionPhase(), QStringLiteral("idle"), 2000);
        QCOMPARE(w.state, Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->message(), QString());
        QCOMPARE(w.runtime->connectionPhase(), QStringLiteral("idle"));
        QVERIFY(!w.events.contains(QStringLiteral("config")));
        const auto last=states.last();
        QCOMPARE(last.at(0).value<Vpn::ConnectionState>(), Vpn::ConnectionState::Disconnected);
        QCOMPARE(last.at(1).toString(), QString());
    }

    void newSessionResetsFailurePhaseBeforeHeldPermission() {
        World w;
        w.badProof=true;
        w.runtime->begin(w.id);
        // AWG proof without a handshake waits for its proof time (6 s per exit) before failing.
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,25000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000);

        w.badProof=false;
        w.holdPermission=true;
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.heldPermissionDone),2000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("preparing"));
        w.runtime->cancel();
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
    }

    void uiPhasePropertyNotifiesAcrossSameCoarseStates() {
        World w;
        w.badProof = true; // Exercise Verifying and terminal failure without Connected UI side effects.
        ConnectionUiController ui(&w.connection, nullptr);
        QStringList phases;
        QList<bool> inProgress;
        connect(&ui, &ConnectionUiController::connectionStateChanged, &w, [&] {
            phases.append(ui.connectionPhase());
            inProgress.append(ui.isConnectionInProgress());
        });

        QCOMPARE(w.connection.openConnection(w.id), ErrorCode::NoError);
        QCOMPARE(ui.connectionPhase(), QStringLiteral("preparing"));
        QTRY_COMPARE_WITH_TIMEOUT(w.state, Vpn::ConnectionState::Error, 25000);
        for (const auto& phase : {QStringLiteral("fetching"), QStringLiteral("admitting"),
                                  QStringLiteral("starting"), QStringLiteral("verifying")})
            QVERIFY2(phases.contains(phase), qPrintable(QStringLiteral("UI missed phase: ") + phase));

        const int fetching = phases.indexOf(QStringLiteral("fetching"));
        const int admitting = phases.indexOf(QStringLiteral("admitting"));
        const int starting = phases.indexOf(QStringLiteral("starting"));
        const int verifying = phases.indexOf(QStringLiteral("verifying"));
        QCOMPARE(inProgress.at(fetching), true);
        QCOMPARE(inProgress.at(admitting), true);
        QCOMPARE(inProgress.at(starting), true);
        QCOMPARE(inProgress.at(verifying), true);
        QVERIFY(admitting > fetching && starting > admitting && verifying > starting);
        QVERIFY(phases.contains(QStringLiteral("failed")));
    }

    void acquiredConfigMatchesFactoryContract() {
        World w;
        SubscriptionController::ProtocolData keys;
        QCOMPARE(w.subscription.getOrCreateMayakAwgProtocolData(w.id,&keys),ErrorCode::NoError);
        QVERIFY(!keys.wireGuardClientPrivKey.isEmpty());
        QVERIFY(!keys.wireGuardClientPubKey.isEmpty());
        w.publicKey=keys.wireGuardClientPubKey;
        const QString encoded=w.config();
        const QByteArray decoded=qUncompress(QByteArray::fromBase64(encoded.mid(6).toUtf8(),
                QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals));
        QJsonParseError error;
        const auto root=QJsonDocument::fromJson(decoded,&error).object();
        QCOMPARE(error.error,QJsonParseError::NoError);
        QCOMPARE(root.value(configKey::configVersion).toInt(),int(serverConfigUtils::ConfigSource::AmneziaGateway));
        QCOMPARE(root.value(configKey::hostName).toString(),w.selectedHost);
        QCOMPARE(root.value(configKey::defaultContainer).toString(),QString("amnezia-awg2"));
        const auto containers=root.value(configKey::containers).toArray();
        QCOMPARE(containers.size(),1);
        QCOMPARE(containers.first().toObject().value(configKey::container).toString(),QString("amnezia-awg2"));
        const auto awg=containers.first().toObject().value(configKey::awg).toObject();
        QVERIFY(awg.value(configKey::port).isString());
        QCOMPARE(awg.value(configKey::port).toString(),QString("49963"));
        const auto last=QJsonDocument::fromJson(awg.value(configKey::lastConfig).toString().toUtf8(),&error).object();
        QCOMPARE(error.error,QJsonParseError::NoError);
        QCOMPARE(last.value(configKey::hostName).toString(),w.selectedHost);
        QVERIFY(last.value(configKey::port).isDouble());
        QCOMPARE(last.value(configKey::port).toInt(),49963);
        QCOMPARE(last.value(configKey::clientPrivKey).toString(),QString("$WIREGUARD_CLIENT_PRIVATE_KEY"));
        QCOMPARE(last.value(configKey::clientPubKey).toString(),keys.wireGuardClientPubKey);
        QCOMPARE(last.value(configKey::clientId).toString(),keys.wireGuardClientPubKey);
        const QString native=last.value(configKey::config).toString();
        QVERIFY(native.contains("PrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY\n"));
        QVERIFY(native.contains(QString("Endpoint = %1:49963\n").arg(w.selectedHost)));
        QVERIFY(native.contains(QString("PublicKey = %1\n").arg(last.value(configKey::serverPubKey).toString())));
        QVERIFY(native.contains(QString("PresharedKey = %1\n").arg(last.value(configKey::pskKey).toString())));
        QCOMPARE(w.subscription.applyMayakAcquireConfig(w.id,keys,encoded,w.selectedHost,49963),ErrorCode::NoError);
        const auto applied=w.servers.apiV2Config(w.id);
        QVERIFY(applied.has_value());
        QCOMPARE(applied->defaultContainer,DockerContainer::Awg2);
        QVERIFY(applied->containers.contains(DockerContainer::Awg2));
        const auto container=applied->containers.value(DockerContainer::Awg2);
        const auto *protocol=container.getAwgProtocolConfig();
        QVERIFY(protocol && protocol->clientConfig.has_value());
        QCOMPARE(protocol->clientConfig->clientPublicKey,keys.wireGuardClientPubKey);
        QCOMPARE(protocol->clientConfig->clientPrivateKey,keys.wireGuardClientPrivKey);
        QVERIFY(protocol->clientConfig->nativeConfig.contains(QString("PrivateKey = %1\n").arg(keys.wireGuardClientPrivKey)));
    }
    void probeCloseFramingRemainsStrict() {
        const QByteArray body = R"({"v":1,"exit":"exit-a","nonce":"n"})";
        const QByteArray headers = "HTTP/1.1 200 OK\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\n\r\n";
        QByteArray parsed; QString error;
        QVERIFY(MayakTunnelProbe::parseHttpResponse(headers + body, &parsed, &error));
        QCOMPARE(parsed, body);
        QVERIFY(!MayakTunnelProbe::parseHttpResponse(headers + body.chopped(1), &parsed, &error));
        QVERIFY(!MayakTunnelProbe::parseHttpResponse(headers + body + 'x', &parsed, &error));
        QVERIFY(!MayakTunnelProbe::parseHttpResponse("HTTP/1.1 402 Payment Required\r\n\r\n" + body, &parsed, &error));
        QVERIFY(!MayakTunnelProbe::parseHttpResponse("HTTP/1.1 200 OK\r\nContent-Length:", &parsed, &error));
        QVERIFY(!MayakTunnelProbe::parseHttpResponse({}, &parsed, &error));
        QVERIFY(MayakTunnelProbe::parseHttpResponse("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body, &parsed, &error));
        QCOMPARE(parsed, body);
        // 5.1.0.27: the exit agent's answer (no third-party site): nonce and this exit's id.
        QString exitId;
        QVERIFY(MayakTunnelProbe::validateAgentResponse(parsed, "n", "exit-a", &exitId, &error));
        QCOMPARE(exitId, QStringLiteral("exit-a"));
        QVERIFY(!MayakTunnelProbe::validateAgentResponse(parsed, "another nonce", "exit-a", nullptr, &error));
        QVERIFY(!MayakTunnelProbe::validateAgentResponse(parsed, "n", "exit-b", nullptr, &error));
        QVERIFY(!MayakTunnelProbe::validateAgentResponse(parsed, "n", "", nullptr, &error));
        QVERIFY(!MayakTunnelProbe::validateAgentResponse(R"({"v":2,"exit":"exit-a","nonce":"n"})", "n", "exit-a", nullptr, &error));
        QVERIFY(!MayakTunnelProbe::validateAgentResponse(R"({"v":1,"exit":"exit-a","nonce":"n","x":1})", "n", "exit-a", nullptr, &error));
        QVERIFY(!MayakTunnelProbe::validateAgentResponse(R"({"v":1,"exit":"exit-a","nonce":"n","nonce":"n"})", "n", "exit-a", nullptr, &error));
        QVERIFY(!MayakTunnelProbe::validateAgentResponse(R"({"args":{"mayak_nonce":"n"},"origin":"203.0.113.9"})", "n", "exit-a", nullptr, &error));
        QCOMPARE(MayakTunnelProbe::agentAddress(), QStringLiteral("198.51.100.1"));
        QCOMPARE(MayakTunnelProbe::agentPort(), quint16(80));
    }
    // Device test 21.11 (5.1.0.37): the agent answered through the race SOCKS entry and closed;
    // the race deleted the probe inside QSslSocket's disconnected handling -> SIGSEGV in Qt.
    // The owner deleting the probe from its finished signal must be safe, several times over.
    void probeDeletedFromItsFinishedSignalAfterAgentClose() {
        TinySocksAgent agent(QStringLiteral("2ac3fd72-a655-4f3c-b006-a3717a69b8b5"));
        QVERIFY(agent.server.isListening());
        for (int round=0; round<6; ++round) {
            // Review R20 V-1: odd rounds have no Content-Length -> accepted on close, i.e. inside
            // QSslSocket's disconnected handling, exactly where 5.1.0.37 crashed.
            agent.lengthHeader=round%2 ? QByteArray() : QByteArray("Content-Length");
            ProbeMessageCapture capture;
            auto* probe=new MayakTunnelProbe;
            bool done=false, ok=false; QString observed, error;
            connect(probe,&MayakTunnelProbe::finished,this,
                    [&](quint64, bool success, const MayakTunnelProbeProof& proof, const QString& why) {
                done=true; ok=success; observed=proof.observedExitId; error=why;
                delete probe; // synchronous, exactly like the race tearing down its probes
            });
            MayakTunnelProbeRequest request;
            request.attemptTag=QStringLiteral("race-%1").arg(round);
            request.nonce=QStringLiteral("nonce_%1_abcdef").arg(round);
            request.expectedExitId=QStringLiteral("2AC3FD72-A655-4F3C-B006-A3717A69B8B5");
            request.socksPort=agent.server.serverPort();
            request.socksUser=QStringLiteral("u"); request.socksPassword=QStringLiteral("p");
            request.deadlineMs=4000;
            probe->start(request);
            QTRY_VERIFY_WITH_TIMEOUT(done,5000);
            QVERIFY2(ok,qPrintable(error));
            QCOMPARE(observed,request.expectedExitId);
            const QString seen=capturedProbeOutput.join(QLatin1Char('\n'));
            QVERIFY(seen.contains(round%2 ? QStringLiteral("event=disconnected ") : QStringLiteral("event=content_complete ")));
            QTest::qWait(50); // let the detached socket finish its close and its deferred delete
        }
    }
    // Owner 21.11, variant 1: Xray on the exit keeps the connection open ~2 s after the agent
    // answered. A complete Content-Length answer is accepted at once; trailing bytes never are.
    void probeAcceptsCompleteAnswerWithoutWaitingForClose() {
        TinySocksAgent agent(QStringLiteral("7818dff5-0ee3-4cce-acec-74f27e1ad842"));
        agent.holdOpen=true;
        auto run=[&](int deadline, bool* ok, QString* error, qint64* elapsed) {
            MayakTunnelProbe probe;
            bool done=false;
            connect(&probe,&MayakTunnelProbe::finished,this,
                    [&](quint64, bool success, const MayakTunnelProbeProof&, const QString& why) { done=true; *ok=success; *error=why; });
            MayakTunnelProbeRequest request;
            request.attemptTag=QStringLiteral("hold"); request.nonce=QStringLiteral("hold_nonce_1");
            request.expectedExitId=QStringLiteral("7818dff5-0ee3-4cce-acec-74f27e1ad842");
            request.socksPort=agent.server.serverPort();
            request.socksUser=QStringLiteral("u"); request.socksPassword=QStringLiteral("p");
            request.deadlineMs=deadline;
            QElapsedTimer timer; timer.start();
            probe.start(request);
            QTRY_VERIFY_WITH_TIMEOUT(done,deadline+1000);
            *elapsed=timer.elapsed();
        };
        bool ok=false; QString error; qint64 elapsed=0;
        run(3000,&ok,&error,&elapsed);
        QVERIFY2(ok,qPrintable(error));
        QVERIFY2(elapsed<1500,qPrintable(QString::number(elapsed)));
        agent.trailing="x"; // a longer answer than declared: no proof, never early
        run(1500,&ok,&error,&elapsed);
        QVERIFY(!ok);
    }
    // Variant 1, more cases (owner 21.11: no device test, more automated checks instead).
    void probeEarlyCompletionEdgeCases() {
        TinySocksAgent agent(QStringLiteral("ae9705a1-ae64-43cb-a106-8f0161ab48d2"));
        agent.holdOpen=true;
        int round=0;
        auto run=[&](int deadline, bool* ok, QString* error, qint64* elapsed, QStringList* stages) {
            ProbeMessageCapture capture;
            MayakTunnelProbe probe;
            bool done=false;
            connect(&probe,&MayakTunnelProbe::finished,this,
                    [&](quint64, bool success, const MayakTunnelProbeProof&, const QString& why) { done=true; *ok=success; *error=why; });
            MayakTunnelProbeRequest request;
            request.attemptTag=QStringLiteral("edge-%1").arg(++round); request.nonce=QStringLiteral("edge_nonce_%1").arg(round);
            request.expectedExitId=QStringLiteral("ae9705a1-ae64-43cb-a106-8f0161ab48d2");
            request.socksPort=agent.server.serverPort();
            request.socksUser=QStringLiteral("u"); request.socksPassword=QStringLiteral("p");
            request.deadlineMs=deadline;
            QElapsedTimer timer; timer.start();
            probe.start(request);
            QTRY_VERIFY_WITH_TIMEOUT(done,deadline+1000);
            *elapsed=timer.elapsed();
            *stages=capturedProbeOutput;
        };
        bool ok=false; QString error; qint64 elapsed=0; QStringList stages;
        auto saw=[&](const char* event) {
            return stages.join(QLatin1Char('\n')).contains(QStringLiteral("event=%1 ").arg(QLatin1String(event)));
        };

        // 1. Body arrives in two parts 300 ms apart: not accepted after the first half, accepted
        //    right after the second (well before the 2 s Xray would hold the connection).
        agent.splitDelayMs=300;
        run(3000,&ok,&error,&elapsed,&stages);
        QVERIFY2(ok,qPrintable(error));
        QVERIFY(saw("content_complete"));
        QVERIFY2(elapsed>=280 && elapsed<1500,qPrintable(QString::number(elapsed)));
        agent.splitDelayMs=0;

        // 2. Header names are case-insensitive.
        agent.lengthHeader="content-LENGTH";
        run(3000,&ok,&error,&elapsed,&stages);
        QVERIFY2(ok,qPrintable(error));
        QVERIFY(elapsed<1500);
        agent.lengthHeader="Content-Length";

        // 3. Wrong nonce with the connection held open: rejected at once, never a proof.
        agent.wrongNonce=true;
        run(3000,&ok,&error,&elapsed,&stages);
        QVERIFY(!ok);
        QVERIFY2(elapsed<1500,qPrintable(QString::number(elapsed)));
        agent.wrongNonce=false;

        // 4. No Content-Length while the connection stays open: never early (the old close
        //    framing applies), so the probe runs into its deadline without a proof.
        agent.lengthHeader.clear();
        run(1200,&ok,&error,&elapsed,&stages);
        QVERIFY(!ok);
        QVERIFY(!saw("content_complete"));
        QVERIFY(elapsed>=1100);

        // 5. No Content-Length, the agent closes: accepted at close as before.
        agent.holdOpen=false;
        run(3000,&ok,&error,&elapsed,&stages);
        QVERIFY2(ok,qPrintable(error));
        QVERIFY(saw("disconnected"));
        QVERIFY(!saw("content_complete"));
    }
    void probeDiagnosticsAreStructuredAndRedacted() {
        ProbeMessageCapture capture;
        MayakTunnelProbe probe;
        MayakTunnelProbeRequest request;
        request.attemptTag = QStringLiteral("SECRET_ATTEMPT_TAG_5108");
        request.nonce = QStringLiteral("SECRET_NONCE_5108");
        request.interfaceName = QStringLiteral("SECRET_INTERFACE_5108");
        request.localAddress = QHostAddress(QStringLiteral("198.51.100.71"));
        request.expectedExitId = QStringLiteral("SECRET_EXIT_5108");
        request.deadlineMs = 1000;
        probe.start(request);

        QVERIFY(!capturedProbeOutput.isEmpty());
        const QString joined = capturedProbeOutput.join(QLatin1Char('\n'));
        QVERIFY(joined.contains(QStringLiteral("MayakTunnelProbe event=start")));
        QVERIFY(joined.contains(QStringLiteral("event=start")));
        QVERIFY(joined.contains(QStringLiteral("endpoint=1")));
        QVERIFY(joined.contains(QStringLiteral("elapsed_ms=")));
        QVERIFY(joined.contains(QStringLiteral("remaining_ms=")));
        QVERIFY(joined.contains(QStringLiteral("socket_state=")));
        QVERIFY(joined.contains(QStringLiteral("socket_error=")));
        QVERIFY(joined.contains(QStringLiteral("platform_bind_ok=")));
        QVERIFY(joined.contains(QStringLiteral("requested_local_binding_match=")));
        QVERIFY(joined.contains(QStringLiteral("fd_valid=")));
        QVERIFY(joined.contains(QStringLiteral("tls_error_count=")));
        QVERIFY(joined.contains(QStringLiteral("ssl_mode=")));
        QVERIFY(joined.contains(QStringLiteral("encrypted_bytes_written=")));
        QVERIFY(joined.contains(QStringLiteral("encrypted_bytes_to_write=")));
        QVERIFY(joined.contains(QStringLiteral("peer_verify_error=")));
        QVERIFY(joined.contains(QStringLiteral("alert_sent_level=")));
        QVERIFY(joined.contains(QStringLiteral("alert_received_type=")));
        QVERIFY(joined.contains(QStringLiteral("wire_bytes=")));
        QVERIFY(!joined.contains(QStringLiteral("SECRET_")));
        QVERIFY(!joined.contains(QStringLiteral("198.51.100.71")));
        QVERIFY(!joined.contains(QStringLiteral("203.0.113.71")));
    }
    void opensslErrorTokensAreNarrowAndRedacted() {
        const QString qtEnglish = QStringLiteral(
            "Error during SSL handshake: error:0A000086:SSL routines::certificate verify failed");
        const QString qtLocalized = QStringLiteral(
            "Ошибка TLS: error:0A00010B:SSL routines::alert handshake failure");
        QCOMPARE(mayak::diagnostics::openSslErrorCodeTokens(qtEnglish), QStringList{QStringLiteral("0A000086")});
        QCOMPARE(mayak::diagnostics::openSslErrorCodeTokens(qtLocalized), QStringList{QStringLiteral("0A00010B")});

        const QString syntheticError = QStringLiteral(
            "SECRET_HOST secret-key TLS routines:ssl3_read_bytes:error:0A00010B:SSL alert number 40; "
            "provider error:ABCDEF012345:SECRET_NONCE");
        const QStringList tokens = mayak::diagnostics::openSslErrorCodeTokens(syntheticError);
        QCOMPARE(tokens, QStringList({QStringLiteral("0A00010B"), QStringLiteral("ABCDEF012345")}));
        const QString diagnostic = tokens.join(QLatin1Char(','));
        QVERIFY(!diagnostic.contains(QStringLiteral("SECRET"), Qt::CaseInsensitive));
        QVERIFY(!diagnostic.contains(QStringLiteral("TLS routines")));
        QVERIFY(!diagnostic.contains(QStringLiteral("alert number")));
        QVERIFY(!diagnostic.contains(QStringLiteral("nonce"), Qt::CaseInsensitive));

        const QStringList invalidTokens = mayak::diagnostics::openSslErrorCodeTokens(
            QStringLiteral("error:1234567: error:0123456789ABCDEF1234: fooerror:0A000086: error:0A00008Z:"));
        QVERIFY(invalidTokens.isEmpty());

        QString manyCodes;
        QStringList expected;
        for (int i = 1; i <= 12; ++i) {
            const QString code = QStringLiteral("%1").arg(i, 8, 16, QLatin1Char('0')).toUpper();
            manyCodes += QStringLiteral("prefix error:%1: ").arg(code);
            if (i <= 8) expected.append(code);
        }
        QCOMPARE(mayak::diagnostics::openSslErrorCodeTokens(manyCodes), expected);
    }
    void ownProofAndExactRelease() {
        World w;QVERIFY(w.app.isMayakManagedServer(w.id));QVERIFY(w.app.mayakSessionToken().size());
        w.connection.openConnection(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QCOMPARE(w.records(),1);QVERIFY(w.connection.isConnected());
        const auto applied=w.servers.apiV2Config(w.id); QVERIFY(applied.has_value());
        QCOMPARE(applied->defaultContainer,DockerContainer::Awg2);
        QVERIFY(applied->containers.contains(DockerContainer::Awg2));
        QVERIFY(!w.connection.canInstallUpdate());
        w.connection.closeConnection();QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QCOMPARE(w.records(),0);QCOMPARE(w.releases,1);QVERIFY(w.events.indexOf("down")<w.events.indexOf("release"));
        QVERIFY(w.connection.canInstallUpdate());
    }
    void fullCandidateFallsBack() {
        World w;w.fullFirst=true;w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QCOMPARE(w.acquires,2);QCOMPARE(w.starts,1);w.runtime->cancel();QTRY_COMPARE(w.records(),0);
    }
    void deadCandidateStopsBeforeFallback() {
        World w;w.deadFirst=true;w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QCOMPARE(w.starts,2);QVERIFY(w.events.indexOf("down")<w.events.indexOf("release"));
        w.runtime->cancel();QTRY_COMPARE(w.records(),0);
    }
    void untrustedAcquireCannotStartOrSkipLedger() {
        World w;w.lostAcquire=true;w.runtime->begin(w.id);QTRY_COMPARE(w.state,Vpn::ConnectionState::Error);
        QCOMPARE(w.starts,0);QCOMPARE(w.acquires,1);QCOMPARE(w.records(),1);
        w.lostAcquire=false;w.runtime->begin(w.id);QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QCOMPARE(w.reconciles,1);w.runtime->cancel();QTRY_COMPARE(w.records(),0);
    }
    void cancellationCleansLateAcquire() {
        World w; ConnectionUiController ui(&w.connection,nullptr); w.acquireDelay=300;
        w.runtime->begin(w.id);QTRY_COMPARE(w.acquires,1);w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);QCOMPARE(w.starts,0);QCOMPARE(w.releases,1);
        QVERIFY(ui.exitLocation().isEmpty());
    }
    void queuedStartCannotActivateAfterCancel() {
        World w;w.holdStart=true;w.runtime->begin(w.id);QTRY_COMPARE(w.starts,1);w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);QVERIFY(!w.current.gate->commit());QVERIFY(!w.backendRunning);
    }
    void noReleaseWithoutDown() {
        World w;w.runtime->begin(w.id);QTRY_COMPARE(w.state,Vpn::ConnectionState::Connected);
        w.missingStop=true;w.runtime->cancel();QTRY_COMPARE(w.state,Vpn::ConnectionState::Error);
        QCOMPARE(w.releases,0);QCOMPARE(w.records(),1);
    }
    void failedNativeStopRetriesSameOwnerAndStaysOff() {
        World w; w.failStopOnce=true;
        QStringList phases;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,
                [&w,&phases](Vpn::ConnectionState,const QString&) { phases.append(w.runtime->connectionPhase()); });
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        QVERIFY(phases.contains(QStringLiteral("failed")));
        const int starts=w.starts, acquires=w.acquires;
        const int stops=w.stops;
        QVERIFY(w.backendRunning);
        w.runtime->retryCleanup(); w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires);
        QCOMPARE(w.stops,stops+1);
        QVERIFY(!w.backendRunning); QCOMPARE(w.records(),0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(phases.contains(QStringLiteral("cancelled")));
    }
    void serverCleanupRetryUsesExistingRecordWithoutReconnect() {
        World w; w.failRelease=true;
        QStringList phases;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,
                [&w,&phases](Vpn::ConnectionState,const QString&) { phases.append(w.runtime->connectionPhase()); });
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1500);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        QVERIFY(phases.contains(QStringLiteral("failed")));
        QVERIFY(!w.backendRunning); QCOMPARE(w.records(),1);
        const int starts=w.starts, acquires=w.acquires;
        w.app.setMayakSessionToken("different-account-session");
        w.failRelease=false;
        w.runtime->retryCleanup(); w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires);
        QCOMPARE(w.records(),0); QVERIFY(w.reconciles>0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(phases.contains(QStringLiteral("cancelled")));
    }
    void neverFinishingReleaseSettlesAndManualRetryReconciles() {
        World w; w.holdReleaseForever=true; w.noOfflineMemory=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        const int starts=w.starts, acquires=w.acquires;
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),4000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        QCOMPARE(w.releases,1); QCOMPARE(w.records(),1); QVERIFY(!w.backendRunning);
        w.holdReleaseForever=false;
        w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),3000);
        QCOMPARE(w.reconciles,1); QCOMPARE(w.records(),0);
        QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        // Let the fake transport deliver a stale negative after the retry won;
        // this also drains its QFutureWatcher before the fixture is destroyed.
        for (const auto& promise:w.heldTransportPromises) {
            promise->addResult({ErrorCode::NoError,QByteArrayLiteral("{\"released\":false}"),true});
            promise->finish();
        }
        QCoreApplication::processEvents();
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
    }
    // 5.1.0.24: the "proven" report is repeated in the background until the server answers.
    void provenReportIsRepeatedUntilTheServerAnswers() {
        FastRecoveryTiming timing;
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.provenRetryMs={100,150,200}; t.provenRetryBudgetMs=500;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w; w.failProvenCount=2;
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        QTRY_COMPARE_WITH_TIMEOUT(w.provenCalls,3,3000);
        QTest::qWait(700);
        QCOMPARE(w.provenCalls,3); // the answer ends the retries
        QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        QCOMPARE(w.acquires,1); QCOMPARE(w.releases,0);
        settle(w);
    }
    void provenReportGivesUpAfterItsRetriesAndStaysConnected() {
        FastRecoveryTiming timing;
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.provenRetryMs={100,150,200}; t.provenRetryBudgetMs=500;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w; w.failProvenCount=100;
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        QTRY_COMPARE_WITH_TIMEOUT(w.provenCalls,4,3000); // first try + 3 retries
        QTest::qWait(700);
        QCOMPARE(w.provenCalls,4);
        QCOMPARE(w.state,Vpn::ConnectionState::Connected); // a lost report never drops the tunnel
        QCOMPARE(w.releases,0);
        settle(w);
    }
    void provenRetriesStopWhenTheUserDisconnects() {
        FastRecoveryTiming timing;
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.provenRetryMs={1000,1000,1000}; t.provenRetryBudgetMs=500;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w; w.failProvenCount=100;
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        QTRY_COMPARE_WITH_TIMEOUT(w.provenCalls,1,2000);
        QTest::qWait(100); // the failed first try has scheduled its retry (1000 ms)
        QVERIFY(w.events.contains("proven_fail"));
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTest::qWait(2500);
        QCOMPARE(w.provenCalls,1);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),3000); QCOMPARE(w.records(),0);
    }
    void refusedProvenIsNotRepeated() {
        FastRecoveryTiming timing;
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.provenRetryMs={100,100,100}; t.provenRetryBudgetMs=500;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w; w.refuseProven=true;
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        QTRY_COMPARE_WITH_TIMEOUT(w.provenCalls,1,2000);
        QTest::qWait(600);
        QCOMPARE(w.provenCalls,1);
        settle(w);
    }
    void admissionErrorOnProvenIsNotRepeated() {
        FastRecoveryTiming timing;
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.provenRetryMs={100,100,100}; t.provenRetryBudgetMs=500;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w; w.errorProven=true;
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        QTRY_COMPARE_WITH_TIMEOUT(w.provenCalls,1,2000);
        QTest::qWait(600);
        QCOMPARE(w.provenCalls,1);
        settle(w);
    }
    void neverProvenSettlesOnceOffAllowsNewOnAndOldReplyCannotChangeIt() {
        World w; w.holdProvenForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        QTRY_COMPARE(w.heldTransportPromises.size(),1);
        w.runtime->cancel(); QTRY_COMPARE(w.records(),0);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),3000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        w.holdProvenForever=false;
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        const auto ticket=w.current;
        w.drainHeld(QByteArrayLiteral("{\"proven\":true}"));
        QTest::qWait(50);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("connected")); QVERIFY(w.current.same(ticket));
        w.runtime->cancel(); QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),3000); QCOMPARE(w.records(),0);
    }
    void latePreflightPositiveCannotResumeFailedOn() {
        World w; w.seed(); w.holdReconcileForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.reconciles,1);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,3000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}"));
        QTRY_COMPARE(w.records(),0); QTest::qWait(100);
        QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0); QVERIFY(w.permissionRequestId.isEmpty());
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed")); QVERIFY(!w.runtime->busy());
        w.holdReconcileForever=false; w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel(); QTRY_COMPARE(w.records(),0);
    }
    void cancelledPreflightLatePositiveOnlySettlesOldObligation() {
        World w; w.seed(); w.holdReconcileForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.reconciles,1); w.runtime->cancel();
        QVERIFY(w.runtime->cleanupPending());
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}"));
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected); QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0);
        w.holdReconcileForever=false; w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}")); QTest::qWait(50);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("connected"));
        w.runtime->cancel(); QTRY_COMPARE(w.records(),0);
    }
    void stalePreflightTimeoutCannotOverwriteEarlySuccessfulCleanupRetry() {
        World w; w.seed(); w.holdReconcileForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.reconciles,1,500);
        QElapsedTimer originalRequest; originalRequest.start(); // old timer already exists
        w.runtime->cancel(); QVERIFY(w.runtime->cleanupPending());
        w.holdReconcileForever=false; w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),1000);
        QVERIFY(originalRequest.elapsed()<2000); // new retry won before the old 2500ms timeout
        QCOMPARE(w.reconciles,2); QCOMPARE(w.records(),0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(w.runtime->busy()); // only the original held request still owns a counter
        QSignalSpy laterStates(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged);
        QTest::qWait(int(qMax<qint64>(0,2700-originalRequest.elapsed())));
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(!w.runtime->cleanupPending()); QVERIFY(!w.runtime->busy());
        mayak::attempts::MayakAttemptStore reopened(&w.settings);
        const auto ledger=reopened.load(); QVERIFY(ledger.ok); QVERIFY(ledger.records.isEmpty());
        QCOMPARE(w.settings.storedValueClass(QStringLiteral("Mayak/pendingAttempts")),
                 SecureQSettings::StoredValueClass::Encrypted);
        QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0);
        for (const auto& row:laterStates) QVERIFY(row.at(0).value<Vpn::ConnectionState>()!=Vpn::ConnectionState::Error);
        // A subsequent authenticated positive can settle only its exact old
        // ledger obligation; the already retired counter must not settle twice.
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}")); QTest::qWait(50);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(!w.runtime->cleanupPending()); QVERIFY(!w.runtime->busy()); QCOMPARE(w.records(),0);
    }
    void cancelledPersistedStartedRecordCanRetryAfterPreflightTimeout() {
        World w; w.seed();
        mayak::attempts::MayakAttemptStore store(&w.settings);
        const auto identity=store.load().records.first().identity();
        QVERIFY(store.markMayHaveStarted(identity).ok);
        w.holdReconcileForever=true; w.runtime->begin(w.id); QTRY_COMPARE(w.reconciles,1);
        w.runtime->cancel(); QTest::qWait(2700);
        QVERIFY(w.runtime->cleanupPending()); QCOMPARE(w.records(),1);
        w.holdReconcileForever=false; w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000); QCOMPARE(w.records(),0);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}")); QTest::qWait(50);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled")); QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0);
    }
    void oldPreflightPositiveCannotReopenAfterNewRetryNegative() {
        World w; w.seed(); w.holdReconcileForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.reconciles,1);
        w.runtime->cancel(); QTest::qWait(2700); w.runtime->retryCleanup();
        QTRY_COMPARE(w.reconciles,2); QCOMPARE(w.heldTransportPromises.size(),2);
        const auto old=w.heldTransportPromises.at(0), current=w.heldTransportPromises.at(1);
        old->addResult({ErrorCode::NoError,QByteArrayLiteral("{\"reconciled\":true}"),true}); old->finish();
        QTRY_COMPARE(w.records(),0);
        current->addResult({ErrorCode::NoError,QByteArrayLiteral("{\"reconciled\":false}"),true}); current->finish();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QVERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0);
    }
    void oldPreflightPositiveCannotResumeOrOverwriteNewCycle() {
        World w; w.seed(); w.holdReconcileForever=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.reconciles,1);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,3000);
        w.holdReconcileForever=false; w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        const auto ticket=w.current;
        w.drainHeld(QByteArrayLiteral("{\"reconciled\":true}")); QTest::qWait(100);
        QCOMPARE(w.state,Vpn::ConnectionState::Connected); QVERIFY(w.current.same(ticket)); QCOMPARE(w.records(),1);
        w.runtime->cancel(); QTRY_COMPARE(w.records(),0);
    }
    void cancelDuringInitialInspectionRequiresPositiveOff() {
        World w; w.holdInspection=true; w.runtime->begin(w.id);
        QTRY_VERIFY(bool(w.heldInspection)); w.runtime->cancel();
        QVERIFY(w.state!=Vpn::ConnectionState::Disconnected); QVERIFY(w.runtime->cleanupPending());
        w.runtime->begin(w.id); QCOMPARE(w.starts,0);
        w.heldInspection({B::OwnState::Off,w.inspectionNonce,{},{}});
        QTRY_VERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.starts,0); QCOMPARE(w.acquires,0); QVERIFY(w.permissionRequestId.isEmpty());
    }
    void cancelDuringRecoveryRequiresExactDown() {
        World w; w.activeInspection=true; w.holdNextStop=true; w.runtime->begin(w.id);
        QTRY_VERIFY(bool(w.heldStopDone)); w.runtime->cancel();
        QVERIFY(w.state!=Vpn::ConnectionState::Disconnected); QVERIFY(w.runtime->cleanupPending());
        const auto ticket=w.current;
        B::Ticket wrong{ticket.opaqueAttempt,std::make_shared<B::StartGate>()};
        w.heldStopDone({wrong,B::Outcome::ConfirmedDown,{},w.heldStopNonce}); QTest::qWait(50);
        QVERIFY(w.runtime->cleanupPending()); QVERIFY(w.state!=Vpn::ConnectionState::Disconnected);
        w.backendRunning=false; w.heldStopDone({ticket,B::Outcome::ConfirmedDown,{},w.heldStopNonce});
        QTRY_VERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0);
    }
    void lateReleasePositiveAfterBothDeadlinesCompletesConsistently() {
        World w; w.releaseDelay=3500; w.noOfflineMemory=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.state,Vpn::ConnectionState::Connected);
        w.runtime->cancel(); QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),3000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("failed"));
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.records(),0); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled")); QVERIFY(!w.runtime->busy());
    }
    void neverStartedLateLeaseReconcileCanCompleteOffAndNewOn() {
        World w; w.acquireDelay=300; w.holdReleaseForever=true; w.noOfflineMemory=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.acquires,1); w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),3500); QCOMPARE(w.starts,0); QCOMPARE(w.records(),1);
        w.holdReleaseForever=false; w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000); QCOMPARE(w.records(),0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected); QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        w.runtime->begin(w.id); QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.drainHeld(QByteArrayLiteral("{\"released\":true}")); QTest::qWait(50);
        QCOMPARE(w.state,Vpn::ConnectionState::Connected); QCOMPARE(w.records(),1);
        w.runtime->cancel(); QTRY_COMPARE(w.records(),0);
    }
    void multiRecordCleanupHasOneTenSecondBudget() {
        World w; w.failRelease=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.state,Vpn::ConnectionState::Connected);
        w.runtime->cancel(); QTRY_VERIFY(w.runtime->cleanupPending());
        w.seed(6); QCOMPARE(w.records(),7); w.reconcileDelay=2250;
        QElapsedTimer elapsed; elapsed.start(); qint64 budgetTerminalAt=-1;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState state,const QString&) {
            // The coordinator may separately finish its original 3s stop
            // deadline. Observe this cleanup attempt's common deadline only.
            if (state==Vpn::ConnectionState::Error && elapsed.elapsed()>=9000 && budgetTerminalAt<0)
                budgetTerminalAt=elapsed.elapsed();
        });
        w.runtime->retryCleanup();
        QTRY_COMPARE_WITH_TIMEOUT(w.reconciles,5,10500);
        QTest::qWait(2600); // last positive arrives at 11.25s, after the shared deadline
        QVERIFY(elapsed.elapsed()<12500); QCOMPARE(w.reconciles,5);
        qInfo() << "cleanup_budget_terminal_ms=" << budgetTerminalAt;
        QVERIFY2(budgetTerminalAt>=9700 && budgetTerminalAt<=10400,qPrintable(QString::number(budgetTerminalAt)));
        QVERIFY(w.runtime->cleanupPending()); QCOMPARE(w.records(),2);
        QCOMPARE(w.acquires,1); QCOMPARE(w.starts,1);
        w.reconcileDelay=0; w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),2000); QCOMPARE(w.records(),0);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QTest::qWait(50);
        QCOMPARE(w.records(),0); QVERIFY(!w.runtime->busy());
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
    }
    void synchronousCleanupSettlesWithoutCounterUnderflow() {
        World w; w.synchronousCleanup=true;
        w.runtime->begin(w.id); QTRY_COMPARE(w.state,Vpn::ConnectionState::Connected);
        w.runtime->cancel(); QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),3000); QCOMPARE(w.records(),0);
        w.runtime->begin(w.id); QTRY_COMPARE(w.state,Vpn::ConnectionState::Connected);
        w.runtime->cancel(); QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),3000); QCOMPARE(w.records(),0);
    }
    void tenSequentialFixtureConnectOffCyclesDrainLedger() {
        World w;
        for (int cycle=0; cycle<10; ++cycle) {
            w.runtime->begin(w.id);
            QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
            QCOMPARE(w.records(),1);
            w.failRelease=(cycle%3==1);
            for (int press=0;press<10;++press) w.runtime->cancel();
            if (w.failRelease) {
                QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1500);
                QCOMPARE(w.records(),1);
                w.failRelease=false;
                for (int press=0;press<10;++press) w.runtime->retryCleanup();
            }
            QTRY_VERIFY_WITH_TIMEOUT(w.runtime->connectionPhase()==QStringLiteral("cancelled"),3000);
            QVERIFY(!w.runtime->busy()); QCOMPARE(w.records(),0);
        }
        QCOMPARE(w.acquires,10); QCOMPARE(w.starts,10); QCOMPARE(w.releases,10);
        QCOMPARE(w.stops,10); QCOMPARE(w.reconciles,3);
    }
    void neverFinishingReconcileSettlesAndManualRetryCompletes() {
        World w; w.failRelease=true; w.noOfflineMemory=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1500);
        w.failRelease=false; w.holdReconcileForever=true;
        w.runtime->retryCleanup();
        QTRY_COMPARE_WITH_TIMEOUT(w.reconciles,1,500);
        QTest::qWait(2700); // The phase was already failed from release; wait past this reconcile's own deadline.
        QCOMPARE(w.records(),1); QVERIFY(w.runtime->cleanupPending());
        w.holdReconcileForever=false;
        w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2500);
        QCOMPARE(w.reconciles,2); QCOMPARE(w.records(),0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        for (const auto& promise:w.heldTransportPromises) {
            promise->addResult({ErrorCode::NoError,QByteArrayLiteral("{\"reconciled\":false}"),true});
            promise->finish();
        }
        QCoreApplication::processEvents();
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
    }
    void directBeginCannotReplacePendingCleanup() {
        World w; w.failRelease=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1500);
        const int configs=w.events.count("config"), acquires=w.acquires, starts=w.starts;
        QCOMPARE(w.connection.openConnection(w.id),ErrorCode::NoError);
        w.runtime->begin(w.id);
        QTest::qWait(100);
        QCOMPARE(w.events.count("config"),configs); QCOMPARE(w.acquires,acquires); QCOMPARE(w.starts,starts);
        QVERIFY(w.runtime->cleanupPending()); QCOMPARE(w.records(),1);
    }
    void exactLateNativePositiveAllowsRetryNegativeToFinishCleanup() {
        World w; w.failStopOnce=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1000);
        w.holdNextStop=true;
        w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.heldStopDone),1000);
        QVERIFY(w.observeDown);
        w.backendRunning=false;
        w.observeDown({w.current,B::Outcome::ConfirmedDown,{},QStringLiteral("late-native-positive")});
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),500);
        auto done=std::move(w.heldStopDone);
        done({w.current,B::Outcome::Unknown,{},w.heldStopNonce});
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.reconciles,1); QCOMPARE(w.records(),0);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QVERIFY(w.stopTickets.first().same(w.stopTickets.last()));
        QCOMPARE(w.starts,1); QCOMPARE(w.acquires,1);
        done({w.current,B::Outcome::Unknown,{},w.heldStopNonce});
        QTest::qWait(50);
        QVERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
    }
    void nativeConfirmationSurvivesOriginalStopCompletion_data() {
        QTest::addColumn<bool>("deadline");
        QTest::newRow("original-unknown-after-native-positive")<<false;
        QTest::newRow("original-deadline-after-native-positive")<<true;
    }
    void nativeConfirmationSurvivesOriginalStopCompletion() {
        QFETCH(bool,deadline);
        World w;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        const auto loaded=mayak::attempts::MayakAttemptStore(&w.settings).load();
        QVERIFY(loaded.ok); QCOMPARE(loaded.records.size(),1);
        const auto original=loaded.records.first();
        QVERIFY(!original.identity().attemptId.isEmpty());
        QVERIFY(!original.identity().cycleToken.isEmpty());
        QVERIFY(!original.deviceApiKey().isEmpty());
        QVERIFY(!original.installationUuid().isEmpty());
        QVERIFY(!original.publicKey().isEmpty());
        const auto ticket=w.current;
        QStringList phases;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,
                [&w,&phases](Vpn::ConnectionState,const QString&) { phases.append(w.runtime->connectionPhase()); });
        const int configs=w.events.count("config"), starts=w.starts, acquires=w.acquires;
        w.holdNextStop=true; w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.heldStopDone),1000);
        auto originalDone=std::move(w.heldStopDone);
        const QString nonce=w.heldStopNonce;
        QVERIFY(w.observeDown);
        w.backendRunning=false;
        w.observeDown({ticket,B::Outcome::ConfirmedDown});
        QTest::qWait(50); // Drain the real bridge observer before stop completion.
        if (!deadline) originalDone({ticket,B::Outcome::Unknown,{},nonce});
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),3500);
        // Neither an expired nor a negative bounded call may release the lease.
        QCOMPARE(w.releases,0); QCOMPARE(w.reconciles,0); QCOMPARE(w.records(),1);
        auto config=*w.servers.apiV2Config(w.id);
        config.authData.apiKey="different-synthetic-device-credential";
        w.servers.editServer(w.id,config.toJson(),serverConfigUtils::configTypeFromJson(config.toJson()));
        w.app.setMayakSessionToken("different-synthetic-account");
        w.missingStop=true; // Native owner has already gone; a restop is Unknown.
        w.runtime->begin(w.id); w.connection.openConnection(w.id);
        w.runtime->retryCleanup(); w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.stops,1); QVERIFY(w.stopTickets.first().same(ticket));
        QCOMPARE(w.reconciles,1); QCOMPARE(w.records(),0);
        QCOMPARE(w.events.count("config"),configs); QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("cancelled"));
        QJsonObject reconcile;
        for (const auto& payload:w.requestPayloads)
            if (payload.value("action")=="reconcile") reconcile=payload;
        QCOMPARE(reconcile.value("attempt_id").toString(),original.identity().attemptId);
        QCOMPARE(reconcile.value("auth_data").toObject().value("api_key").toString(),original.deviceApiKey());
        QCOMPARE(reconcile.value("installation_uuid").toString(),original.installationUuid());
        QCOMPARE(reconcile.value("public_key").toString(),original.publicKey());
        QCOMPARE(reconcile.value("service_type").toString(),original.serviceType());
        QCOMPARE(reconcile.value("service_protocol").toString(),original.serviceProtocol());
        QCOMPARE(reconcile.value("user_country_code").toString(),original.userCountryCode());
        QCOMPARE(reconcile.value("server_country_code").toString(),original.serverCountryCode());
        // Repeated old completions cannot reopen a completed OFF or stop a new ON.
        originalDone({ticket,B::Outcome::Unknown,{},nonce});
        QTest::qWait(50);
        QVERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        config.authData.apiKey=original.deviceApiKey();
        w.servers.editServer(w.id,config.toJson(),serverConfigUtils::configTypeFromJson(config.toJson()));
        w.missingStop=false; w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("connected"));
        QVERIFY(!w.current.same(ticket));
        originalDone({ticket,B::Outcome::ConfirmedDown,{},nonce});
        w.observeDown({ticket,B::Outcome::ConfirmedDown});
        QTest::qWait(50);
        QVERIFY(w.backendRunning); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("connected"));
        QVERIFY(phases.contains(QStringLiteral("cancelled")));
        w.runtime->cancel(); QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,2000);
    }
    void mismatchedNativePositiveCannotConfirmCleanup() {
        World w; w.missingStop=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel(); QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),1000);
        QVERIFY(w.observeDown);
        // Same opaque attempt with a different gate is a different owner.
        B::Ticket wrongGate{w.current.opaqueAttempt,std::make_shared<B::StartGate>()};
        B::Ticket wrongAttempt{guid(),w.current.gate};
        w.observeDown({wrongGate,B::Outcome::ConfirmedDown});
        w.observeDown({wrongAttempt,B::Outcome::ConfirmedDown});
        QTest::qWait(50);
        w.runtime->retryCleanup(); QTest::qWait(100);
        QVERIFY(w.runtime->cleanupPending()); QVERIFY(w.backendRunning);
        QCOMPARE(w.records(),1); QCOMPARE(w.releases,0); QCOMPARE(w.reconciles,0);
        QCOMPARE(w.acquires,1); QCOMPARE(w.starts,1);
        w.backendRunning=false; w.observeDown({w.current,B::Outcome::ConfirmedDown});
        QTest::qWait(50); w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.records(),0); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
    }
    void retryWaitsForOriginalReleaseAndOldNegativeCannotReopenCleanup() {
        World w; w.failRelease=true; w.releaseDelay=5000; w.noOfflineMemory=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,4000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.runtime->cleanupPending(),3500);
        QCOMPARE(w.releases,1);
        w.failRelease=false;
        w.runtime->retryCleanup();
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->cleanupPending(),2000);
        QCOMPARE(w.reconciles,1); QCOMPARE(w.records(),0);
        QTest::qWait(2600); // Original release arrives after its operation token was retired.
        QTest::qWait(100);
        QVERIFY(!w.runtime->cleanupPending()); QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
    }
    void badProofNeverConnected() {
        World w;w.badProof=true;QSignalSpy spy(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged);
        w.runtime->begin(w.id);QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,25000);
        for(const auto& row:spy) QVERIFY(row.at(0).value<Vpn::ConnectionState>()!=Vpn::ConnectionState::Connected);
        // A rejected proof (no handshake answered) stops/releases the first candidate before trying
        // the second. AWG proof sends nothing over the network (5.1.0.27): no probe at all.
        QCOMPARE(w.acquires,2);QCOMPARE(w.starts,2);QVERIFY(!w.events.contains("probe"));
        QCOMPARE(w.events.count("down"),2);QCOMPARE(w.releases,2);
        QStringList lifecycle;
        for(const auto& event:w.events)
            if(event=="start" || event=="probe" || event=="down" || event=="release") lifecycle<<event;
        QCOMPARE(lifecycle,QStringList({"start","down","release","start","down","release"}));
        QCOMPARE(w.records(),0);
    }

    // ---- Connected-state truth and Android soft recovery (5.1.0.17) ----
    void stuckTransportShowsReconnectingAndSoftRecoversWithoutRestart() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int starts=w.starts, stops=w.stops, releases=w.releases, acquires=w.acquires;
        QList<Vpn::ConnectionState> seen;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&seen](Vpn::ConnectionState s,QString){seen<<s;});
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.recovers>=1,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QVERIFY(seen.contains(Vpn::ConnectionState::Reconnecting));
        QCOMPARE(w.runtime->message(),QStringLiteral("Подключено"));
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("connected"));
        QCOMPARE(w.runtime->exitLocation().value("cityId").toString(),QStringLiteral("oslo"));
        QCOMPARE(w.recovers,1);
        // No re-admission, no native stop, no release: the same ticket keeps running.
        QCOMPARE(w.starts,starts); QCOMPARE(w.stops,stops); QCOMPARE(w.releases,releases); QCOMPARE(w.acquires,acquires);
        // The requested replacement (new generation) is not treated as an autonomous reset.
        QTest::qWait(900);
        QCOMPARE(w.state,Vpn::ConnectionState::Connected); QCOMPARE(w.stops,stops); QCOMPARE(w.recovers,1);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QCOMPARE(w.records(),0);
    }

    void osNoNetworkShowsWaitingAndNeverRecovers() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        QVERIFY(bool(w.observeNetwork));
        w.tunnelDown=true; w.observeNetwork(w.current,false);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Reconnecting,3000);
        QCOMPARE(w.runtime->message(),QStringLiteral("Нет сети — ждём…"));
        QTest::qWait(1000);
        QCOMPARE(w.recovers,0); QCOMPARE(w.state,Vpn::ConnectionState::Reconnecting);
        w.tunnelDown=false; w.observeNetwork(w.current,true);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        QCOMPARE(w.recovers,0); QCOMPARE(w.stops,stops);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void networkChangeRecoversOnFirstFailedProbe() {
        FastRecoveryTiming timing;
        auto fast=MayakAutoConnectRuntime::recoveryTiming();
        fast.stuckRxAfterNetworkMs=0; // isolate the rule: after a network change one failure suffices
        MayakAutoConnectRuntime::setRecoveryTimingForTests(fast);
        World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.tunnelDown=true;
        const int mark=w.events.size();
        w.observeNetwork(w.current,true);
        QTRY_VERIFY_WITH_TIMEOUT(w.recovers>=1,3000);
        const QStringList after=w.events.mid(mark);
        QCOMPARE(after.mid(0,after.indexOf("recover")).count("probe"),0); // AWG: counters, no probe
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        QCOMPARE(w.stops,stops);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void networkLossWithoutLaterEventStopsBlockingRecovery() {
        FastRecoveryTiming timing;
        auto fast=MayakAutoConnectRuntime::recoveryTiming();
        fast.networkLostExpiryMs=500;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(fast);
        World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.tunnelDown=true; w.observeNetwork(w.current,false);
        QTRY_COMPARE_WITH_TIMEOUT(w.runtime->message(),QStringLiteral("Нет сети — ждём…"),3000);
        QCOMPARE(w.recovers,0);
        // The same network came back silently: no validated event ever arrives.
        QTRY_VERIFY_WITH_TIMEOUT(w.recovers>=1,4000);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void networkEventsRacingOwnRecoveryNeverResetTheLadder() {
        FastRecoveryTiming timing; World w(true); w.recoverOk=false;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.recovers>=1,5000);
        // e.g. a re-established TUN reported as a "new network" right after each replacement
        for (int i=0;i<12;++i) { w.observeNetwork(w.current,true); QTest::qWait(100); }
        QVERIFY2(w.recovers<=3,qPrintable(QString::number(w.recovers)));
        w.tunnelDown=false;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void singleRandomProbeMissNeverShowsReconnectingOrRecovers() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QList<Vpn::ConnectionState> seen;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&seen](Vpn::ConnectionState s,QString){seen<<s;});
        // AWG (5.1.0.27): exactly one failed check (data sent, nothing back), then data again.
        ProbeMessageCapture capture;
        w.stallRx=true;
        QTRY_VERIFY_WITH_TIMEOUT(capturedProbeOutput.join(QStringLiteral(" | ")).contains(QStringLiteral("event=probe_failed consecutive=1")),3000);
        w.stallRx=false; w.health.rxTotal+=500; w.observeHealth(w.awgTicket,w.health);
        QTest::qWait(1200);
        QVERIFY(!capturedProbeOutput.join(QStringLiteral(" | ")).contains(QStringLiteral("event=probe_failed consecutive=2")));
        QVERIFY(!seen.contains(Vpn::ConnectionState::Reconnecting));
        QCOMPARE(w.recovers,0); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    // Review R17 B-1: after "Reconnecting", an idle tunnel (nothing sent, nothing received) is no
    // proof of life; "Connected" comes back only with data from our peer.
    void idleAfterReconnectingNeverShowsConnectedWithoutData() {
        FastRecoveryTiming timing; World w(true); w.recoverOk=false;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.tunnelDown=true;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Reconnecting,5000);
        w.idle=true; // the person stops using the network: no counters move at all
        QTest::qWait(1500);
        QCOMPARE(w.state,Vpn::ConnectionState::Reconnecting);
        w.tunnelDown=false; w.idle=false; // data flows again: a passed check
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    // Review R17 B-2: the backend died (service/WinTun gone) while the UI is visible: no health
    // report any more. Never "Connected" forever: the connected check fails and the path restarts.
    void deadBackendWithoutHealthReconnects() {
        FastRecoveryTiming timing; World w(false);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.healthGone=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.stops>stops,30000);
        w.healthGone=false;
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.state==Vpn::ConnectionState::Disconnected || w.state==Vpn::ConnectionState::Error,8000);
    }

    void failedSoftRecoveryIsBoundedByBackoff() {
        FastRecoveryTiming timing; World w(true); w.recoverOk=false;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.tunnelDown=true;
        QTRY_COMPARE_WITH_TIMEOUT(w.recovers,3,5000);
        QTest::qWait(1200);
        QCOMPARE(w.recovers,3); QCOMPARE(w.state,Vpn::ConnectionState::Reconnecting); QCOMPARE(w.stops,stops);
        w.tunnelDown=false;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void withoutRecoverPortStatusIsHonestAndNothingRestarts() {
        FastRecoveryTiming timing; World w(false); // Windows/desktop: no soft recovery port
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops, starts=w.starts;
        w.tunnelDown=true;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Reconnecting,3000);
        QCOMPARE(w.runtime->message(),QStringLiteral("Переподключение…"));
        QCOMPARE(w.runtime->connectionPhase(),QStringLiteral("verifying"));
        QVERIFY(w.runtime->exitLocation().isEmpty());
        w.tunnelDown=false;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        QCOMPARE(w.recovers,0); QCOMPARE(w.stops,stops); QCOMPARE(w.starts,starts);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void unrequestedGenerationChangeKeepsExistingRestartPath() {
        FastRecoveryTiming timing; World w(false);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.health.generation+=1; // autonomous backend replacement, never requested by the owner
        w.observeHealth(w.current,w.health);
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.stops>stops,5000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.state==Vpn::ConnectionState::Disconnected || w.state==Vpn::ConnectionState::Error,8000);
    }

    // ---- UI hidden/frozen: service watchdog owns recovery, Qt learns it on resume (r3) ----
    void hiddenServiceReplacementIsAcceptedOnResume() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops, starts=w.starts, acquires=w.acquires, releases=w.releases;
        QVERIFY(bool(w.observeResume));
        // While hidden the service replaced the backend: new generation, same proof context.
        w.observeResume(w.current,true,true);
        QTest::qWait(30);
        w.health.generation+=1; w.health.rxTotal=0; w.health.txTotal=0;
        w.observeHealth(w.current,w.health);
        QTest::qWait(900);
        QCOMPARE(w.state,Vpn::ConnectionState::Connected); QCOMPARE(w.recovers,0);
        QCOMPARE(w.stops,stops); QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires); QCOMPARE(w.releases,releases);
        // The accepted change is not a latent reset: a later stuck transport soft-recovers
        // instead of escalating to a full restart.
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.recovers>=1,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,5000);
        QCOMPARE(w.stops,stops); QCOMPARE(w.starts,starts);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QCOMPARE(w.records(),0);
    }

    void resumeWithoutReplacementStillGuardsGeneration() {
        FastRecoveryTiming timing; World w(false);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.observeResume(w.current,false,true);
        QTest::qWait(30);
        w.health.generation+=1; // not announced: must stay an autonomous reset
        w.observeHealth(w.current,w.health);
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.stops>stops,5000);
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(w.state==Vpn::ConnectionState::Disconnected || w.state==Vpn::ConnectionState::Error,8000);
    }

    void resumeWithoutNetworkShowsWaitingAndNeverRecovers() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.tunnelDown=true;
        w.observeResume(w.current,false,false);
        QTRY_COMPARE_WITH_TIMEOUT(w.runtime->message(),QStringLiteral("Нет сети — ждём…"),3000);
        QTest::qWait(600);
        QCOMPARE(w.recovers,0); QCOMPARE(w.stops,stops);
        w.tunnelDown=false; w.observeNetwork(w.current,true);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,3000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    // ---- Connect-time network failure: retry instead of an immediate error (r5) ----
    void connectNetworkFailureRetriesThenConnects() {
        FastRecoveryTiming timing; World w; w.failConfigCount=2;
        QList<Vpn::ConnectionState> seen; QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState s,QString t){seen<<s;texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.events.count("config_fail"),2);
        QVERIFY(!seen.contains(Vpn::ConnectionState::Error));
        QVERIFY(texts.contains(QStringLiteral("Нет связи с сервером Маяка — повторяем…")));
        QCOMPARE(w.acquires,1); QCOMPARE(w.starts,1);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QCOMPARE(w.records(),0);
    }

    // ---- Connect without the gateway (review 01, item 2; 23.11.2026) ----
    // One normal session: it stores the offered exits and the admitted exit's config, then ends.
    static void connectOnceAndStop(World& w) {
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }
    // ---- Proven again when the app comes back (Android froze the UI process; review 02 item 5) ----
    void provenIsSentAgainWhenTheAppComesBack() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        w.failProvenCount=100; // no answer to any "proven" (frozen / slow network)
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QTRY_COMPARE_WITH_TIMEOUT(w.provenCalls,3,5000); // first try + 2 retries, then given up
        QTest::qWait(400);
        QCOMPARE(w.provenCalls,3);
        QVERIFY(w.observeVisibility);
        w.failProvenCount=0;
        w.observeVisibility(false); w.observeVisibility(true);
        QTRY_COMPARE_WITH_TIMEOUT(w.provenCalls,4,3000);
        w.observeVisibility(false); w.observeVisibility(true); // delivered now: not again
        QTest::qWait(300);
        QCOMPARE(w.provenCalls,4);
        settle(w);
    }
    // ---- Always-on MayakNet journal (5.1.0.28, review 02 item 4) ----
    void mayakNetJournalKeepsOnlyEventsAndRotates() {
        QTemporaryDir dir; QVERIFY(dir.isValid());
        const QString path=dir.filePath("MayakNet-events.log");
        Logger::setMayakNetJournalPathForTests(path);
        Logger::enableMayakNetJournal();
        qInfo().noquote() << "MayakNet event=journal_test value=1";
        qInfo().noquote() << "Unrelated message https://example.org";
        QFile file(path); QVERIFY(file.open(QIODevice::ReadOnly));
        const QByteArray first=file.readAll(); file.close();
        QVERIFY(first.contains("MayakNet event=journal_test value=1"));
        QVERIFY(!first.contains("Unrelated message"));
        // Rotation: never more than ~1 MB in the current file, the previous one kept as ".1".
        const QString filler(120,QLatin1Char('x'));
        for (int i=0;i<10000;++i) qInfo().noquote() << "MayakNet event=fill" << filler;
        Logger::disableMayakNetJournalForTests();
        Logger::setMayakNetJournalPathForTests({});
        QVERIFY(QFile::exists(path+".1"));
        QVERIFY(QFileInfo(path).size()<=1024*1024+4096);
        QVERIFY(QFileInfo(path+".1").size()<=1024*1024+4096);
        const qint64 before=QFileInfo(path).size();
        qInfo().noquote() << "MayakNet event=after_disable";
        QCOMPARE(QFileInfo(path).size(),before);
    }
    void offlineMemoryStoresOfferedExitsAndAdmittedConfig() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        QVERIFY(w.offlineMemory().isEmpty());
        connectOnceAndStop(w);
        const auto memory=w.offlineMemory();
        QVERIFY(!memory.value("owner").toString().isEmpty());
        const qint64 until=qint64(memory.value("until").toDouble());
        const qint64 week=7LL*24*60*60*1000, nowMs=QDateTime::currentMSecsSinceEpoch();
        QVERIFY(until>nowMs+week-60000 && until<=nowMs+week+1000); // no offline_until: the client's 7 days
        const auto exits=memory.value("exits").toArray();
        QCOMPARE(exits.size(),2);
        int withConfig=0;
        for (const auto& e:exits) if (!e.toObject().value("config").toString().isEmpty()) ++withConfig;
        QCOMPARE(withConfig,1); // only the admitted exit has a config
        QCOMPARE(exits.at(0).toObject().value("id").toString(),w.first);
    }
    void offlineStartsFromStoredExitAndReportsPlaceLater() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        connectOnceAndStop(w);
        const int acquiresBefore=w.acquires, startsBefore=w.starts;
        QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState,QString t){texts<<t;});
        w.gatewayDown=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QVERIFY(texts.contains(QStringLiteral("Подключаемся без сервера Маяка…")));
        QCOMPARE(w.acquires,acquiresBefore); // no acquire before the start
        QCOMPARE(w.starts,startsBefore+1);
        QCOMPARE(w.records(),1);
        // The gateway is back: the late acquire records the place, then proven names it.
        const int provenBefore=w.provenCalls;
        w.gatewayDown=false;
        QTRY_VERIFY_WITH_TIMEOUT(w.lateAcquires>=1,5000);
        QTRY_VERIFY_WITH_TIMEOUT(w.provenCalls>provenBefore,5000);
        QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        const auto lateRequest=std::find_if(w.requestPayloads.begin(),w.requestPayloads.end(),[](const QJsonObject& p) {
            return p.value("action").toString()=="acquire" && p.contains("late"); });
        QVERIFY(lateRequest!=w.requestPayloads.end());
        QVERIFY(lateRequest->value("late").isBool() && lateRequest->value("late").toBool());
        settle(w);
        QCOMPARE(w.releases,2); // the normal session's and the late place
    }
    void offlineStartsEarlyWhenGatewayIsSlowAndLateAnswerStartsNothing() {
        FastRecoveryTiming timing; OfflineTiming offline(200); World w;
        connectOnceAndStop(w);
        const int acquiresBefore=w.acquires, startsBefore=w.starts;
        w.configDelay=1500; w.lateMode=1; // the gateway answers v1/config late; the late acquire gets no answer
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,1400); // before the config answer
        QTest::qWait(1600); // the signed config answer arrives during the stored-exit session
        QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        QCOMPARE(w.starts,startsBefore+1);   // no second path
        QCOMPARE(w.acquires,acquiresBefore); // no normal acquire
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        // The late acquire went out without an answer: its possible place waits in the deferred cleanup.
        QCOMPARE(w.records(),0);
        QCOMPARE(w.deferredCleanups(),1);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        // Next connect with the gateway up: the deferred cleanup is reconciled before a new place.
        w.configDelay=0; w.lateMode=0;
        const int reconcilesBefore=w.reconciles;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.reconciles,reconcilesBefore+1);
        QCOMPARE(w.deferredCleanups(),0);
        settle(w);
    }
    void offlineLateRevokedEndsSessionAndWipesMemory() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        connectOnceAndStop(w);
        w.gatewayDown=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.lateMode=2; w.gatewayDown=false;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,5000);
        QCOMPARE(w.runtime->message(),QStringLiteral("Доступ отозван. Войдите в личный кабинет."));
        QVERIFY(w.offlineMemory().isEmpty());
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QCOMPARE(w.deferredCleanups(),0);
        QVERIFY(!w.backendRunning);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }
    void offlineLateNotReadyReconnectsTheNormalWay() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        connectOnceAndStop(w);
        w.gatewayDown=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int acquiresBefore=w.acquires;
        w.lateMode=3; w.gatewayDown=false;
        QTRY_VERIFY_WITH_TIMEOUT(w.acquires>acquiresBefore && w.state==Vpn::ConnectionState::Connected &&
                                 w.lastAcquireCandidate()==w.second,10000); // a normal place, another exit first
        QVERIFY(!w.offlineMemory().isEmpty());
        settle(w);
    }
    void offlineReleaseWithoutGatewayIsDeferredNotAnError() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        QList<Vpn::ConnectionState> seen;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState s,QString){seen<<s;});
        w.gatewayDown=true; // the gateway goes down during a normal session
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,8000);
        QVERIFY(!seen.contains(Vpn::ConnectionState::Error));
        QCOMPARE(w.records(),0);
        QCOMPARE(w.deferredCleanups(),1);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        // Still down: the next connect uses the stored exit (the deferred cleanup does not block it).
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        // Back: the late acquire records the place; the old one is reconciled.
        w.gatewayDown=false;
        QTRY_COMPARE_WITH_TIMEOUT(w.deferredCleanups(),0,5000);
        settle(w);
    }
    void offlineUnansweredReleaseIsDeferredAndLatePositiveSettlesIt() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.holdReleaseForever=true; // the release reaches no answer within its 2.5 s
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,6000);
        QCOMPARE(w.records(),0); QCOMPARE(w.deferredCleanups(),1);
        QVERIFY(!w.runtime->cleanupPending());
        w.drainHeld(QByteArrayLiteral("{\"released\":true}")); // the server's late positive
        QTRY_COMPARE_WITH_TIMEOUT(w.deferredCleanups(),0,3000);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }
    void offlineFailedStoredExitIsMovedBackNeverWiped() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        connectOnceAndStop(w);
        w.gatewayDown=true; w.silentHost="81.29.149.103"; // the only stored exit with a config does not answer
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.state==Vpn::ConnectionState::Error,30000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        const auto exits=w.offlineMemory().value("exits").toArray();
        QVERIFY(!exits.isEmpty());
        int failures=0; bool config=false;
        for (const auto& e:exits) if (e.toObject().value("id").toString()==w.first) {
            failures=e.toObject().value("failures").toInt(); config=!e.toObject().value("config").toString().isEmpty(); }
        QVERIFY(failures>=1); QVERIFY(config); // every failed cycle (with its connect retries) moves it back
        QCOMPARE(w.records(),0);
    }
    void offlineNeverStartsOnSignedRefusal() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        connectOnceAndStop(w);
        const int starts=w.starts;
        // A signed 4xx without a code (older server): no stored exit, no wipe, the old error path.
        w.configError={{"http_status",402},{"message","Access is not active"}};
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QCOMPARE(w.starts,starts); QVERIFY(!w.offlineMemory().isEmpty());
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        // DISABLED: the reason, no retries, the memory stays (the switch-off may be temporary).
        w.configError={{"http_status",402},{"code","DISABLED"},{"message","Device is disabled"}};
        const int configs=w.events.count("config");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QCOMPARE(w.runtime->message(),QStringLiteral("Доступ этого устройства выключен или ещё не одобрен. Откройте личный кабинет."));
        QCOMPARE(w.events.count("config"),configs+1);
        QCOMPARE(w.starts,starts); QVERIFY(!w.offlineMemory().isEmpty());
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        // ACCOUNT_EXPIRED: the memory is wiped and the reason shown.
        w.configError={{"http_status",402},{"code","ACCOUNT_EXPIRED"},{"message","Access is not active"}};
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QCOMPARE(w.runtime->message(),QStringLiteral("Срок доступа закончился. Откройте личный кабинет."));
        QVERIFY(w.offlineMemory().isEmpty()); QCOMPARE(w.starts,starts);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }
    void offlineStartsOnSignedServerFailure() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        connectOnceAndStop(w);
        w.configError={{"http_status",503},{"message","Service unavailable"}};
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QTRY_VERIFY_WITH_TIMEOUT(w.lateAcquires>=1,5000);
        settle(w);
    }
    void invalidRequestOnFreshAcquireIsRepeatedAsLate() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        w.invalidNextAcquire=true; // an older place of this device is still open on the server
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.acquires,1); QCOMPARE(w.lateAcquires,1);
        settle(w);
    }
    void refusedDeferredReconcileIsKeptAndCounted() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.gatewayDown=true; w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,8000);
        QCOMPARE(w.deferredCleanups(),1);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        // The gateway answers again but refuses the reconcile: the entry stays (counted), the
        // connect goes on from the stored exits (the late acquire closes the older place).
        w.gatewayDown=false; w.refuseReconcile=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QVERIFY(w.reconciles>=1);
        QTRY_VERIFY_WITH_TIMEOUT(w.lateAcquires>=1,5000);
        const auto entries=QJsonDocument::fromJson(w.settings.value("Mayak/deferredCleanup").toByteArray()).array();
        QVERIFY(entries.isEmpty() || entries.first().toObject().value("refusals").toInt()>=1);
        w.refuseReconcile=false;
        settle(w);
    }
    void offlineNotUsedForRevokedOrWithoutMemory() {
        FastRecoveryTiming timing; OfflineTiming offline; World w;
        // Without memory a gateway outage behaves as before (retries, then the error).
        w.gatewayDown=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QCOMPARE(w.starts,0);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }

    // ---- Windows: the local tunnel adapter does not come up (WinTun after an update) ----
    static void useWindowsHealthMeaning() {
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.noHealthMeansLocalFailure=true;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
    }
    void localAdapterFailureRetriesLaterWithoutBlamingExit() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.localFailStarts=2; // both exits of the first cycle: no interface
        QList<Vpn::ConnectionState> seen; QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState s,QString t){seen<<s;texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,40000);
        QCOMPARE(w.events.count("local_fail"),2);
        // The retry repaired WinTun first (once), and only then started a tunnel again.
        QCOMPARE(w.heals,1);
        QVERIFY(w.events.indexOf("heal")>w.events.lastIndexOf("local_fail"));
        QVERIFY(w.events.indexOf("start",w.events.indexOf("heal"))>w.events.indexOf("heal"));
        QVERIFY(!seen.contains(Vpn::ConnectionState::Error));
        QVERIFY(std::any_of(texts.cbegin(),texts.cend(),[](const QString& t){
            return t.startsWith(QStringLiteral("VPN-адаптер Windows не запустился — повторим через")); }));
        // No exit was marked as failed: the retry cycle starts with the server's first choice.
        QCOMPARE(w.lastAcquireCandidate(),w.first);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }
    void localAdapterFailureGivesUpWithRebootAdvice() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.localFailStarts=1000;
        QString last;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState,QString t){last=t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,90000);
        QCOMPARE(last,QStringLiteral("VPN-адаптер Windows не запускается. Перезагрузите компьютер и включите Маяк снова."));
        QCOMPARE(w.starts,6); // 2 exits x (first cycle + 2 retries of localStartRetryMs)
        QTest::qWait(500);
        QCOMPARE(w.starts,6); // bounded: no further cycles
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }
    // A connect that succeeds needs no repair later; the user's cancel during a repair starts nothing.
    void wintunRepairIsOnceAndCancellable() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.localFailStarts=2; w.holdHeal=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.heals,1,20000);
        QTRY_COMPARE_WITH_TIMEOUT(w.runtime->message(),QStringLiteral("Восстанавливаем VPN-адаптер Windows…"),3000);
        const int starts=w.starts;
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QVERIFY(w.heldHeal);
        w.heldHeal(true,QStringLiteral("healed")); // a late reply after the cancel
        QTest::qWait(300);
        QCOMPARE(w.starts,starts);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        // The repair was used up by that attempt: the next connect starts at once and connects.
        w.holdHeal=false;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.heals,1);
        settle(w);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.heals,1);
        settle(w);
    }
    // The first connect of a new app version repairs WinTun once in advance (an update over a running
    // VPN may have cut the tunnel); later connects of the same version do not.
    void wintunRepairOnTheFirstConnectOfANewVersion() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.settings.setValue("Mayak/wintunHealVersion",QStringLiteral("5.1.0.26"));
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.heals,1);
        QVERIFY(w.events.indexOf("heal")<w.events.indexOf("start"));
        QCOMPARE(w.settings.value("Mayak/wintunHealVersion").toString(),QStringLiteral(APP_VERSION));
        settle(w);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.heals,1);
        settle(w);
    }
    // The "repair wanted" mark survives an app restart (an update restarts the app) and is used once.
    void wintunRepairWantedSurvivesAnAppRestart() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.settings.setValue("Mayak/wintunHealWanted",true);
        MayakAutoConnectRuntime::resetFailoverMemoryForTests(); // a fresh process: no in-memory mark
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.heals,1);
        QVERIFY(!w.settings.value("Mayak/wintunHealWanted").toBool());
        settle(w);
    }
    // "busy" (a Mayak tunnel still ran in the service): the repair stays wanted for the next start.
    void wintunRepairBusyStaysWanted() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.settings.setValue("Mayak/wintunHealWanted",true); w.healResult=QStringLiteral("busy");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.heals,1);
        settle(w);
        // Connected cleared it (the adapter worked after all): nothing is repeated.
        QVERIFY(!w.settings.value("Mayak/wintunHealWanted").toBool());
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.heals,1);
        settle(w);
    }
    // OFF while the repair runs at the start of a (restarted) session: nothing starts afterwards.
    void wintunRepairInASessionStartIsCancellable() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.settings.setValue("Mayak/wintunHealWanted",true); w.holdHeal=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.heals,1,10000);
        const int starts=w.starts;
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        w.heldHeal(true,QStringLiteral("healed"));
        QTest::qWait(300);
        QCOMPARE(w.starts,starts);
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
    }
    // A repair whose service did not answer (older service, no pipe) still goes on with the retry.
    void wintunRepairWithoutAnswerStillRetries() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.localFailStarts=2;
        MayakAutoConnectRuntime::setWintunHealForTests([&w](QObject* ctx,std::function<void(bool,QString)> done) {
            ++w.heals; QTimer::singleShot(0,ctx,[done] { done(false,QString()); }); });
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,40000);
        QCOMPARE(w.heals,1);
        settle(w);
    }
    void localAdapterFailureOnOneExitStillConnectsInSameCycle() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.localFailStarts=1; // first exit: no interface; second exit connects normally
        QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState,QString t){texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,25000);
        QCOMPARE(w.starts,2);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        QVERIFY(std::none_of(texts.cbegin(),texts.cend(),[](const QString& t){ return t.startsWith(QStringLiteral("VPN-адаптер")); }));
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        // The exit was not blamed: the next connect starts with the server's first choice again
        // (the exit memory of the second exit is cleared: only the failover memory is checked here).
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        w.settings.setValue("Mayak/exitMemory",QByteArray());
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.lastAcquireCandidate(),w.first);
        settle(w);
    }
    // Real 5.1.0.19 case: the service blocks ~16 s failing WinTun, so the 3 s stop is unconfirmed.
    void localAdapterFailureWithUnconfirmedStopRestartsAndConnects() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        World w; w.localFailStarts=1; w.localFailStopUnconfirmed=true;
        QList<Vpn::ConnectionState> seen; QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState s,QString t){seen<<s;texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,40000);
        QCOMPARE(w.events.count("local_fail"),1);
        QCOMPARE(w.events.count("down_unconfirmed"),1);
        QCOMPARE(w.heals,1); // the restarted session repaired WinTun before its first start
        QVERIFY(w.events.indexOf("heal")>w.events.indexOf("local_fail"));
        QVERIFY(!seen.contains(Vpn::ConnectionState::Error));
        QVERIFY(std::any_of(texts.cbegin(),texts.cend(),[](const QString& t){
            return t.startsWith(QStringLiteral("VPN-адаптер Windows не запустился — повторим через")); }));
        QVERIFY(w.reconciles>=1); // the unconfirmed attempt was released exactly before the restart
        QCOMPARE(w.lastAcquireCandidate(),w.first); // the exit was not blamed
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }
    void localAdapterUnconfirmedStopPauseIsCancelledByUser() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.localStartRetryMs={60000};
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w; w.localFailStarts=1000; w.localFailStopUnconfirmed=true;
        QString last;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState,QString t){last=t;});
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(last.startsWith(QStringLiteral("VPN-адаптер Windows не запустился — повторим через 60 с")),40000);
        QVERIFY(w.runtime->busy());
        const int starts=w.starts;
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTest::qWait(300);
        QCOMPARE(w.starts,starts); // no restart after the user's OFF
        QVERIFY(!w.runtime->busy());
    }
    // Review 5120 #1: the UI path of the main button during the pause is retryCleanup(), not cancel().
    void localAdapterUnconfirmedStopPauseUserRetryCleanupDoesNotReconnect() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.localStartRetryMs={60000};
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w; w.localFailStarts=1000; w.localFailStopUnconfirmed=true;
        QString last;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState,QString t){last=t;});
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(last.startsWith(QStringLiteral("VPN-адаптер Windows не запустился — повторим через 60 с")),40000);
        QVERIFY(w.runtime->cleanupPending());
        const int starts=w.starts;
        w.runtime->retryCleanup();            // what ConnectionController::closeConnection() calls
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTest::qWait(300);
        QCOMPARE(w.starts,starts);            // no new session after the user's OFF
        QVERIFY(!w.runtime->busy());
    }
    void localAdapterUnconfirmedStopRestartsAreBoundedAcrossSessions() {
        FastRecoveryTiming timing; useWindowsHealthMeaning(); // localStartRetryMs = {100,150}
        World w; w.localFailStarts=1000; w.localFailStopUnconfirmed=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,60000);
        QCOMPARE(w.events.count("local_fail"),3); // first session + 2 restarts, then the cleanup prompt
        QVERIFY(w.runtime->cleanupPending());
        const int starts=w.starts;
        QTest::qWait(500);
        QCOMPARE(w.starts,starts);
        w.runtime->retryCleanup();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        // A new user connect starts with a fresh retry budget.
        w.localFailStarts=0;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        settle(w);
    }
    void windowsHealthMeaningIsThePlatformDefault() {
        const MayakAutoConnectRuntime::RecoveryTiming defaults;
#ifdef Q_OS_WINDOWS
        QVERIFY(defaults.noHealthMeansLocalFailure);
#else
        QVERIFY(!defaults.noHealthMeansLocalFailure);
#endif
        // The first retry repairs WinTun first, so it comes sooner; the total budget stays.
        QCOMPARE(defaults.localStartRetryMs,(QList<qint64>{10000,30000,60000,120000,240000,300000}));
    }
    void localAdapterRetryIsCancelledByUser() {
        FastRecoveryTiming timing; useWindowsHealthMeaning();
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.localStartRetryMs={60000};
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w; w.localFailStarts=1000;
        QString last;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState,QString t){last=t;});
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(last.startsWith(QStringLiteral("VPN-адаптер Windows не запустился — повторим через 60 с")),40000);
        QCOMPARE(w.state,Vpn::ConnectionState::Preparing);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        const int starts=w.starts;
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTest::qWait(300);
        QCOMPARE(w.starts,starts);
        QVERIFY(!w.runtime->busy());
    }

    void connectNetworkFailureGivesUpAfterBoundedRetries() {
        FastRecoveryTiming timing; World w; w.failConfigCount=100;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QCOMPARE(w.events.count("config_fail"),4); // first try + 3 retries (connectRetryMs size)
        QCOMPARE(w.acquires,0); QCOMPARE(w.starts,0); QCOMPARE(w.records(),0);
        QTest::qWait(500);
        QCOMPARE(w.events.count("config_fail"),4);
        QVERIFY(!w.runtime->busy());
    }

    // ---- Cold-start adoption of the running backend (r6) ----
    void adoptRunningTunnelOnColdStartWithoutStop() {
        FastRecoveryTiming timing; World w(true);
        const QString attempt=w.seedStarted();
        w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&texts](Vpn::ConnectionState,QString t){texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        // Never stopped, never reconciled, no new native start: the same attempt continues.
        QVERIFY(!w.events.contains("down")); QVERIFY(!w.events.contains("reconcile"));
        QCOMPARE(w.adopts,1); QCOMPARE(w.starts,0); QCOMPARE(w.acquires,1);
        QCOMPARE(w.adoptedTicket,attempt);
        bool sameAttempt=false;
        for (const auto& p:w.requestPayloads) if (p.value("action").toString()=="acquire") sameAttempt=p.value("attempt_id").toString()==attempt;
        QVERIFY(sameAttempt);
        QVERIFY(texts.contains(QStringLiteral("Проверяем подключение…")));
        QVERIFY(!texts.contains(QStringLiteral("Выбираем доступный сервер…")));
        QCOMPARE(w.records(),1);
        QCOMPARE(w.runtime->exitLocation().value("cityId").toString(),QStringLiteral("oslo"));
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QVERIFY(w.events.contains("down")); QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    }

    void adoptRefusedStopsWithRecoveryThenConnectsFresh() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.adoptOk=false;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.adopts,1);
        const int adopt=w.events.indexOf("adopt"), down=w.events.indexOf("down");
        QVERIFY(adopt>=0 && down>adopt);               // refused -> stopped with the recovery ticket
        QVERIFY(w.events.indexOf("release",down)>down); // the adopted attempt's allocation is released
        QCOMPARE(w.starts,1);                           // then a normal fresh start
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    }

    void adoptRejectedByServerStopsReconcilesAndContinues() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.fullFirst=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.adopts,0);
        const int down=w.events.indexOf("down");
        QVERIFY(down>0); QVERIFY(w.events.indexOf("reconcile",down)>down);
        QCOMPARE(w.starts,1); QCOMPARE(w.acquires,2);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    }

    void adoptCandidateAbsentFallsBackToFreshConnect() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(guid()); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.adopts,0);
        const int down=w.events.indexOf("down");
        QVERIFY(down>w.events.indexOf("config")); QVERIFY(w.events.indexOf("reconcile",down)>down);
        QCOMPARE(w.starts,1);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void withoutAdoptPortColdStartKeepsStopAndReconcile() {
        FastRecoveryTiming timing; World w(true,false); // Windows: no adoption port
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.adopts,0);
        const int down=w.events.indexOf("down");
        QVERIFY(down>=0 && down<w.events.indexOf("reconcile") && w.events.indexOf("reconcile")<w.events.indexOf("config"));
        QCOMPARE(w.starts,1);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
    }

    void cancelDuringAdoptionStopsBackendAndReleases() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.acquireDelay=800;
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.acquires==1,5000);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_VERIFY_WITH_TIMEOUT(w.events.contains("down"),5000);
        QTRY_VERIFY_WITH_TIMEOUT(w.events.contains("reconcile"),5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QCOMPARE(w.adopts,0); QCOMPARE(w.starts,0);
        QTest::qWait(1200); // the delayed acquire reply arrives after cancel and must change nothing
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected); QCOMPARE(w.adopts,0); QCOMPARE(w.records(),0);
    }

    // ---- r8: independent review fixes ----
    void adoptProvesLiveSessionWithoutReplacement() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        w.adoptHandshakeAgeMs=90000; // older than the attempt, inside the live-session window
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.adopts,1); QCOMPARE(w.starts,0); QVERIFY(!w.events.contains("down"));
        settle(w);
    }

    void adoptRejectsStaleSessionHandshake() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        w.adoptHandshakeAgeMs=200000; // beyond WireGuard's 180 s: not a live session
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.adopts,1); QVERIFY(w.starts>=1);
        QVERIFY(w.events.indexOf("down")>=0 && w.events.indexOf("down")<w.events.lastIndexOf("start"));
        settle(w);
    }

    void adoptTransferUnconfirmedStopsWithRecoveryTicket() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running");
        w.adoptDeadline=true; w.failStopOnce=true; // transfer not confirmed, first recovery stop unconfirmed
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.adopts,1);
        // Until the adopted backend is confirmed down, every stop uses the authority that owns it.
        QVERIFY(w.stopTickets.size()>=2);
        QVERIFY(w.stopTickets.at(0).opaqueAttempt.startsWith(QStringLiteral("recovery:")));
        QVERIFY(w.stopTickets.at(1).opaqueAttempt.startsWith(QStringLiteral("recovery:")));
        settle(w);
    }

    void cancelDuringAdoptionReportsDisconnectedOnlyAfterStop() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.acquireDelay=800;
        bool sawDisconnected=false;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&sawDisconnected](Vpn::ConnectionState s,QString) {
            if (s==Vpn::ConnectionState::Disconnected) sawDisconnected=true;
        });
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.acquires==1,5000);
        w.holdNextStop=true; // the adopted backend's stop is still in flight when the user cancels
        w.runtime->cancel();
        QTRY_VERIFY_WITH_TIMEOUT(!w.heldStopNonce.isEmpty(),5000);
        QTest::qWait(300);
        QVERIFY(!sawDisconnected); QVERIFY(w.runtime->busy());
        w.backendRunning=false;
        w.heldStopDone({w.stopTickets.last(),B::Outcome::ConfirmedDown,{},w.heldStopNonce});
        QTRY_VERIFY_WITH_TIMEOUT(sawDisconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }

    // ---- r9: failover to another exit when the current one stops working ----
    void deadConnectedExitReconnectsToAnotherExitFirst() {
        FastRecoveryTiming timing; World w(false);
        QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&texts](Vpn::ConnectionState,QString t){texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.lastAcquireCandidate(),w.first);
        const int stops=w.stops;
        w.health.generation+=1; // own telemetry reset + failing probes: the exit is dead
        w.observeHealth(w.current,w.health);
        w.tunnelDown=true;
        QTRY_VERIFY_WITH_TIMEOUT(w.stops>stops,8000);
        w.tunnelDown=false; // the other exit works
        QTRY_VERIFY_WITH_TIMEOUT(w.lastAcquireCandidate()==w.second,10000);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        QVERIFY(texts.contains(QStringLiteral("Сервер не отвечает — переподключаемся…")));
        settle(w);
    }

    void serviceFailoverRequestWhileHiddenSwitchesExit() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.lastAcquireCandidate(),w.first);
        QVERIFY(bool(w.observeFailover)); QVERIFY(bool(w.observeVisibility));
        w.observeVisibility(false);
        const int stops=w.stops, acquires=w.acquires;
        w.observeFailover(w.current);
        QTRY_VERIFY_WITH_TIMEOUT(w.stops>stops,5000);
        QTRY_VERIFY_WITH_TIMEOUT(w.acquires>acquires && w.state==Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        settle(w);
    }

    void silentExitIsTriedLastOnNextConnect() {
        FastRecoveryTiming timing; World w(true);
        w.silentFirst=true; // e.g. Vienna unreachable from this network: no handshake answered
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,25000);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        const int acquires=w.acquires;
        w.runtime->begin(w.id); // a new connect (new session) remembers the silent exit
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.acquires,acquires+1);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        settle(w);
    }

    // r10: a release that never reached the server right after the tunnel stop (Android: the dying
    // VPN network reset the new connection) is sent again; the disconnect completes normally.
    void releaseNotReachingTheServerIsSentAgain() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.failReleaseTransport=1;
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QCOMPARE(w.events.count("release_fail"),1);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
    }
    // Bounded: a release that keeps failing ends with the usual cleanup hint after 3 tries.
    void releaseResendIsBounded() {
        FastRecoveryTiming timing; World w(true); w.noOfflineMemory=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.failReleaseTransport=100;
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,6000);
        QCOMPARE(w.events.count("release_fail"),3);
        QTest::qWait(500);
        QCOMPARE(w.events.count("release_fail"),3);
        w.failReleaseTransport=0;
        w.runtime->retryCleanup();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,8000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    }

    // 5.1.0.27 r4, exit memory: the exit that proved on this network is tried first next time,
    // even when the server lists another one first.
    void rememberedExitIsTriedFirstOnTheNextConnect() {
        FastRecoveryTiming timing; World w(true);
        w.silentFirst=true; // the first exit does not answer here: the second one proves
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,25000);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        settle(w);
        w.silentFirst=false; MayakAutoConnectRuntime::resetFailoverMemoryForTests(); // only the exit memory remains
        const int acquires=w.acquires;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.acquires,acquires+1);
        QCOMPARE(w.acquireCandidate(acquires),w.second);
        settle(w);
    }

    // A remembered exit that does not come up is forgotten: the server order applies again.
    void failedRememberedExitIsForgotten() {
        FastRecoveryTiming timing; World w(true);
        w.silentFirst=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,25000);
        settle(w);
        w.silentFirst=false; w.silentHost="81.29.149.104"; // the remembered exit is now silent
        MayakAutoConnectRuntime::resetFailoverMemoryForTests();
        int acquires=w.acquires;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,25000);
        QCOMPARE(w.acquireCandidate(acquires),w.second);   // still tried first once
        QCOMPARE(w.lastAcquireCandidate(),w.first);
        settle(w);
        w.silentHost.clear(); MayakAutoConnectRuntime::resetFailoverMemoryForTests();
        acquires=w.acquires;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.acquireCandidate(acquires),w.first);
        settle(w);
    }

    // Port precheck: one TCP check of every exit's Xray port (443) at once; an exit that does not
    // answer goes last (never dropped).
    void portPrecheckMovesAnUnansweredExitLast() {
        FastRecoveryTiming timing; World w(true);
        w.tcpDeadHosts={"81.29.149.103"};
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.prechecks,1); QCOMPARE(w.precheckPort,quint16(443));
        QCOMPARE(w.acquireCandidate(0),w.second);
        settle(w);
    }

    void portPrecheckWithoutAnyAnswerKeepsTheServerOrder() {
        FastRecoveryTiming timing; World w(true);
        w.tcpDeadHosts={"81.29.149.103","81.29.149.104"};
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.prechecks,1);
        QCOMPARE(w.acquireCandidate(0),w.first);
        settle(w);
    }

    void portPrecheckIsSkippedForASingleExit() {
        FastRecoveryTiming timing; World w(true);
        w.singleCandidate=true; w.tcpDeadHosts={"81.29.149.103"};
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.prechecks,0);
        settle(w);
    }

    // The unanswered exit is still tried with AWG, but its Xray paths on port 443 are skipped.
    void portPrecheckSkipsXrayOfAnUnansweredExit() {
        FastRecoveryTiming timing; CoordinatorTimingGuard guard;
        auto& t=mayak::autoconnect::Coordinator::timing(); t.awgVerifyMs=500; t.xrayVerifyMs=500;
        World w(true);
        w.offerXray=true; w.tcpDeadHosts={"81.29.149.103"};
        w.silentFirst=true;                                          // first exit: AWG silent, Xray would work
        w.silentHost="81.29.149.104"; w.xrayDeadHost="81.29.149.104"; // second exit: nothing works
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.acquires>=2 && w.startHosts.contains("81.29.149.103/awg"),20000);
        QTest::qWait(1500);
        QCOMPARE(w.acquireCandidate(0),w.second);
        QVERIFY(w.startHosts.contains("81.29.149.104/xray"));
        QVERIFY(!w.startHosts.contains("81.29.149.103/xray"));
        settle(w);
    }

    // Exit memory: the network check removes the tunnel by its address, whatever its interface is
    // called (Windows: Qt "ethernet_32777", the service "MayakVPN").
    void sameLocalNetworkIgnoresTheTunnelByAddress() {
        const QStringList before{"wireless_32768/192.168.1.0/24"};
        QVERIFY(MayakAutoConnectRuntime::sameLocalNetworkForTests(before,{"ethernet_32777/10.8.0.2/32","wireless_32768/192.168.1.0/24"},"10.8.0.2"));
        QVERIFY(MayakAutoConnectRuntime::sameLocalNetworkForTests(before,{"tun0/10.8.0.0/24","wireless_32768/192.168.1.0/24"},"10.8.0.2/32"));
        // A lingering adapter of the previous session at start is removed as well.
        QVERIFY(MayakAutoConnectRuntime::sameLocalNetworkForTests({"ethernet_32777/10.8.0.2/32","wireless_32768/192.168.1.0/24"},
            {"ethernet_32777/10.8.0.2/32","wireless_32768/192.168.1.0/24"},"10.8.0.2"));
        QVERIFY(!MayakAutoConnectRuntime::sameLocalNetworkForTests(before,{"ethernet_32777/10.8.0.2/32","rmnet0/100.64.0.0/10"},"10.8.0.2"));
        QVERIFY(!MayakAutoConnectRuntime::sameLocalNetworkForTests(before,before,QString()));   // no address: not compared
        QVERIFY(!MayakAutoConnectRuntime::sameLocalNetworkForTests({},{},"10.8.0.2"));
    }

    // The real port check (loopback only): a listening port answers, a refused one does not, the
    // result comes once, in host order, and no socket is left behind.
    void realPortPrecheckReportsEachHostOnce() {
        QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost,0));
        QObject context; QList<QList<bool>> results; QElapsedTimer clock; clock.start();
        MayakAutoConnectRuntime::realPortPrecheckForTests()(&context,{"127.0.0.1","127.0.0.2","127.0.0.1"},server.serverPort(),3000,
            [&results](QList<bool> answered) { results<<answered; });
        QTRY_COMPARE_WITH_TIMEOUT(results.size(),1,5000);
        QCOMPARE(results.first(),(QList<bool>{true,false,true})); // refused: Windows retries it until the timeout
        QTest::qWait(500);
        QCOMPARE(results.size(),1);
        QTRY_COMPARE_WITH_TIMEOUT(context.findChildren<QTcpSocket*>().size(),0,2000);
        // Every host answered: the result comes before the timeout, and the timeout adds nothing.
        results.clear(); clock.restart();
        MayakAutoConnectRuntime::realPortPrecheckForTests()(&context,{"127.0.0.1","127.0.0.1"},server.serverPort(),3000,
            [&results](QList<bool> answered) { results<<answered; });
        QTRY_COMPARE_WITH_TIMEOUT(results.size(),1,5000);
        QCOMPARE(results.first(),(QList<bool>{true,true}));
        QVERIFY2(clock.elapsed()<2000,qPrintable(QString::number(clock.elapsed())));
        QTest::qWait(3200);
        QCOMPARE(results.size(),1);
        QTRY_COMPARE_WITH_TIMEOUT(context.findChildren<QTcpSocket*>().size(),0,2000);
    }

    // The real port check ends at its timeout when a host never answers (a listener whose backlog
    // is never accepted still completes TCP; so a held, never-finishing host is simulated by a
    // timeout shorter than any answer is possible: 1 ms).
    void realPortPrecheckEndsAtItsTimeout() {
        QTcpServer server; QVERIFY(server.listen(QHostAddress::LocalHost,0));
        QObject context; QList<QList<bool>> results;
        MayakAutoConnectRuntime::realPortPrecheckForTests()(&context,{"127.0.0.1"},server.serverPort(),1,
            [&results](QList<bool> answered) { results<<answered; });
        QTRY_COMPARE_WITH_TIMEOUT(results.size(),1,3000);
        QCOMPARE(results.first().size(),1);
        QTest::qWait(200);
        QCOMPARE(results.size(),1);
        QTRY_COMPARE_WITH_TIMEOUT(context.findChildren<QTcpSocket*>().size(),0,2000);
    }

    // A remembered Xray path (it proved after AWG did not, auto mode) leads the next connect on this
    // network; the race of the Xray paths still runs (a dead remembered path costs no tunnel start).
    void rememberedXrayPathLeadsTheNextConnect() {
        FastRecoveryTiming timing; World w(true);
        w.offerXray=true; w.withRace=true; w.raceEngineOk=false; w.awgSilent=true; // race runs, server order
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,30000);
        QCOMPARE(w.raceStarts,1);
        const QString proved=w.startedProtocols.last();
        QCOMPARE(proved,QStringLiteral("xray"));
        settle(w);
        const int races=w.raceStarts, starts=w.startedProtocols.size();
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.raceStarts,races+1);                          // raced, not skipped
        QCOMPARE(w.startedProtocols.size(),starts+1);            // the first start proved
        QCOMPARE(w.startedProtocols.last(),QStringLiteral("xray"));
        QCOMPARE(w.runtime->exitLocation().value("pathId").toString(),QStringLiteral("xray-firefox"));
        settle(w);
    }

    // An Xray path that proved in a fixed method ("only Xray") is not kept for automatic mode:
    // there AWG is tried first again.
    void xrayPathOfAFixedMethodIsNotRemembered() {
        FastRecoveryTiming timing; World w(true);
        w.offerXray=true; w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,30000);
        QCOMPARE(w.startedProtocols.last(),QStringLiteral("xray"));
        settle(w);
        w.app.setMayakConnectionMethod("auto");
        const int starts=w.startedProtocols.size();
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.startedProtocols.at(starts),QStringLiteral("awg"));
        settle(w);
    }

    // After a failed AWG path the Xray paths of the same exit are raced (no tunnel), not tried one
    // by one: here nobody answers the race, so no Xray tunnel starts and the next exit follows.
    void xrayRaceRunsAfterAFailedAwgPath() {
        FastRecoveryTiming timing;
        World w(true);
        w.offerXray=true; w.withRace=true; w.silentFirst=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,30000);
        QCOMPARE(w.raceStarts,1);
        QVERIFY(!w.startHosts.contains("81.29.149.103/xray"));
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        settle(w);
    }

    // AWG quick give-up: no handshake within awgNoHandshakeMs ends the path before the full proof
    // time; the exit is still tried last on the next connect.
    void awgQuickGiveUpEndsASilentPathEarly() {
        FastRecoveryTiming timing;
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.awgNoHandshakeMs=800;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w(true);
        w.silentFirst=true;
        QElapsedTimer clock; clock.start();
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QVERIFY2(clock.elapsed()<4000,qPrintable(QString::number(clock.elapsed())));
        QCOMPARE(w.acquireCandidate(0),w.first);
        QCOMPARE(w.lastAcquireCandidate(),w.second);
        settle(w);
    }

    // The last option (one exit, AWG only) keeps the full proof time: no quick give-up.
    void awgQuickGiveUpIsNotUsedForTheLastOption() {
        FastRecoveryTiming timing; CoordinatorTimingGuard guard;
        mayak::autoconnect::Coordinator::timing().awgVerifyMs=2000;
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.awgNoHandshakeMs=500;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w(true);
        w.singleCandidate=true; w.awgSilent=true;
        w.offerXray=true; w.xrayDead=true; // Xray paths of the last exit are no reason to give AWG up early
        QElapsedTimer clock; clock.start();
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.stops>=1,10000);
        QVERIFY2(clock.elapsed()>=1800,qPrintable(QString::number(clock.elapsed())));
        settle(w);
    }

    // The quick give-up never ends a path whose handshake came.
    void awgQuickGiveUpKeepsAnAnsweringPath() {
        FastRecoveryTiming timing;
        auto t=MayakAutoConnectRuntime::recoveryTiming(); t.awgNoHandshakeMs=800;
        MayakAutoConnectRuntime::setRecoveryTimingForTests(t);
        World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.acquires,1);
        QTest::qWait(1200);
        QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        settle(w);
    }

    void hiddenFailoverWithSingleExitKeepsTunnel() {
        FastRecoveryTiming timing; World w(true);
        w.singleCandidate=true; // no other exit: taking the dead tunnel down would only leak
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        w.observeVisibility(false);
        const int stops=w.stops, acquires=w.acquires;
        w.observeFailover(w.current);
        QTest::qWait(500);
        QCOMPARE(w.stops,stops); QCOMPARE(w.acquires,acquires); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        settle(w);
    }

    void failoverRequestForAnotherTicketIsIgnored() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int stops=w.stops;
        w.observeFailover({guid(),std::make_shared<B::StartGate>()});
        QTest::qWait(400);
        QCOMPARE(w.stops,stops); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        settle(w);
    }

    // ---- r9: reviewer notes 7 and 8 ----
    void adoptionPermissionDeniedStillStopsAdoptedBackend() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.holdPermission=true;
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(bool(w.heldPermissionDone),5000);
        auto done=w.heldPermissionDone; w.heldPermissionDone={};
        done(w.permissionRequestId,B::PermissionResult::Denied);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,5000);
        QVERIFY(w.events.contains("down")); QVERIFY(w.events.contains("reconcile"));
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        QCOMPARE(w.adopts,0); QCOMPARE(w.starts,0);
    }

    void adoptionGiveUpWithUnconfirmedStopSaysSo() {
        FastRecoveryTiming timing; World w(true);
        w.seedStarted(guid()); w.activeInspection=true; w.inspectionIdentity=QStringLiteral("ctx-running"); w.missingStop=true;
        QStringList texts;
        connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&texts](Vpn::ConnectionState,QString t){texts<<t;});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,8000);
        QCOMPARE(texts.last(),QStringLiteral("Не удалось завершить прежнее подключение. Нажмите «Включить Маяк» ещё раз."));
        QVERIFY(!texts.contains(QStringLiteral("Нет связи с сервером Маяка — повторяем…")));
        QCOMPARE(w.starts,0);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        QTest::qWait(200);
    }

    void hiddenUiProbeFailuresNeverStopTunnel() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QVERIFY(bool(w.observeVisibility));
        const int stops=w.stops, starts=w.starts;
        w.observeVisibility(false);
        w.tunnelDown=true; // e.g. a network switch while the UI is hidden: no health, probes fail
        QTest::qWait(1500);
        QCOMPARE(w.stops,stops); QCOMPARE(w.starts,starts); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        w.tunnelDown=false; // the service watchdog repaired it meanwhile
        w.observeVisibility(true);
        QTest::qWait(700);
        QCOMPARE(w.stops,stops); QCOMPARE(w.starts,starts); QCOMPARE(w.state,Vpn::ConnectionState::Connected);
        settle(w);
    }

    // ---- Stop outside the app (notification/tile "Disconnect") is the user's stop (r7) ----
    void systemUiDisconnectIsHonouredAsUserStop() {
        FastRecoveryTiming timing; World w(true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int starts=w.starts, acquires=w.acquires;
        QVERIFY(bool(w.observeUserStop));
        w.tunnelDown=true; // the service already took the tunnel down
        w.observeUserStop(w.current);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,5000);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTest::qWait(1200);
        // Never recovered, never reconnected, stays off.
        QCOMPARE(w.state,Vpn::ConnectionState::Disconnected);
        QCOMPARE(w.recovers,0); QCOMPARE(w.starts,starts); QCOMPARE(w.acquires,acquires);
        QVERIFY(!w.runtime->busy());
    }

    // ---------- 5.1.0.21 «4 пути» ----------
    void xrayPathConnectsOnTheSameAllocationWhenAwgIsSilent() {
        FastRecoveryTiming timing;
        CoordinatorTimingGuard timingGuard; auto& t=mayak::autoconnect::Coordinator::timing(); t.awgVerifyMs=400;
        World w; w.singleCandidate=true; w.offerXray=true; w.awgSilent=true;
        w.app.setMayakConnectionMethod("auto");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.runtime->exitLocation().value("pathId").toString(),QStringLiteral("xray-firefox"));
        QCOMPARE(w.awgStarts,1); QCOMPARE(w.xrayStarts,1);
        // Rule 5: the started Xray client never logs destinations.
        {
            const auto client=QJsonDocument::fromJson(w.lastXrayConfig.value("xray_config_data").toObject()
                .value("config").toString().toUtf8()).object();
            QCOMPARE(client.value("log").toObject().value("access").toString(),QStringLiteral("none"));
            QCOMPARE(client.value("log").toObject().value("dnsLog").toBool(true),false);
        }
        QCOMPARE(w.acquires,1);           // one place on the exit for every path
        QCOMPARE(w.releases,0);           // switching paths never releases it
        int acquireWithPaths=0, proven=0;
        for (const auto& p:w.requestPayloads) {
            if (p.value("action").toString()=="acquire" && p.value("mayak_paths").isDouble() && p.value("mayak_paths").toInt()==1) ++acquireWithPaths;
            if (p.value("action").toString()=="proven") ++proven;
        }
        QCOMPARE(acquireWithPaths,1); QCOMPARE(proven,1);
        settle(w);
        QCOMPARE(w.releases,1);
        // Path memory: this network now starts with Xray (AWG stays the fallback).
        w.startedProtocols.clear();
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.startedProtocols.value(0),QStringLiteral("xray"));
        settle(w);
    }
    void onlyAwgNeverStartsXray() {
        FastRecoveryTiming timing;
        CoordinatorTimingGuard timingGuard; auto& t=mayak::autoconnect::Coordinator::timing(); t.awgVerifyMs=400;
        World w; w.singleCandidate=true; w.offerXray=true; w.awgSilent=true;
        w.app.setMayakConnectionMethod("awg");
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.state==Vpn::ConnectionState::Error || w.runtime->message().contains(QStringLiteral("повторяем")),10000);
        QCOMPARE(w.xrayStarts,0);
        settle(w);
    }
    void xrayProofRetriesAnAndroidVpnBindFailure() {
        // Android (19.11 log): the probe starts ~10 ms after the Xray tunnel reports Connected and
        // the strict VPN socket bind fails until the VPN network is visible. The same path retries.
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=true; w.bindFailNextProbes=3;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.runtime->exitLocation().value("pathId").toString(),QStringLiteral("xray-firefox"));
        QCOMPARE(w.xrayStarts,1);                  // no path switch for a bind that was not ready
        QVERIFY(w.events.count("probe")>=4);       // three bind failures, then the proof
        QCOMPARE(w.bindFailNextProbes,0);
        settle(w);
    }
    void httpsSocketsAreResetAtConnectAndAfterTheTunnelStops() {
        // Android (19.11 log): a gateway connection opened while the tunnel ran black-holes after it
        // stops. The app drops its own HTTPS sockets when a connect starts and once the tunnel is
        // confirmed down, before the release request (which hung before).
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true;
        HttpsResetGuard resetGuard; // after World: the hook never outlives the world it captures
        MayakAutoConnectRuntime::setHttpsSocketResetForTests([&w] { w.events<<"https_reset"; return 1; });
        // No tunnel ran in this "process" yet: a connect resets nothing (an update download survives).
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.events.count("https_reset"),0);
        // The tunnel ran and is confirmed down: reset once, before the release request.
        settle(w);
        QCOMPARE(w.events.count("https_reset"),1);
        QVERIFY(w.events.lastIndexOf("down")<w.events.lastIndexOf("https_reset"));
        QVERIFY(w.events.lastIndexOf("https_reset")<w.events.lastIndexOf("release"));
        // Already reset after that tunnel: the next connect does not reset again.
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.events.count("https_reset"),1);
        settle(w);
        QCOMPARE(w.events.count("https_reset"),2);
    }
    void httpsSocketsAreResetAtTheFirstConnectOfAFreshProcess() {
        // Android: the app process may restart while a tunnel runs in the service process, so its
        // first gateway connections may go through that tunnel: the first connect resets them.
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true;
        HttpsResetGuard resetGuard;
        MayakAutoConnectRuntime::setHttpsSocketResetForTests([&w] { w.events<<"https_reset"; return 1; }, true);
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.events.count("https_reset"),1);
        QVERIFY(w.events.indexOf("https_reset")<w.events.indexOf("start"));
        settle(w);
    }
    void httpsSocketsAreResetBeforeAConnectRetry() {
        // The gateway did not answer: the retry never waits on the same connection (forced reset).
        FastRecoveryTiming timing;
        World w; w.failConfigCount=1;
        HttpsResetGuard resetGuard;
        MayakAutoConnectRuntime::setHttpsSocketResetForTests([&w] { w.events<<"https_reset"; return 1; });
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.events.count("config_fail"),1);
        QCOMPARE(w.events.count("https_reset"),1);
        QVERIFY(w.events.indexOf("config_fail")<w.events.indexOf("https_reset"));
        settle(w);
    }
    void xrayBindFailureThatPersistsGivesUpAfterItsBudget() {
        // A bind that keeps failing is not a VPN network still coming up: the path gives up after
        // ~3 s (not its whole 8 s proof time) and the next path starts.
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=true; w.bindFailNextProbes=1000;
        w.app.setMayakConnectionMethod("xray");
        QElapsedTimer elapsed; elapsed.start();
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.xrayStarts>=2,6500);
        QVERIFY(elapsed.elapsed()<6500);
        settle(w);
    }
    void routeNamesTheExitAndMethodWhileConnectingAndConnected() {
        FastRecoveryTiming timing;
        {
            World w; w.singleCandidate=true;
            QStringList seen;
            QObject::connect(w.runtime.get(),&MayakAutoConnectRuntime::stateChanged,&w,[&](Vpn::ConnectionState state,const QString&) {
                if (state==Vpn::ConnectionState::Connecting) seen<<w.runtime->route().value("method").toString();
            });
            QVERIFY(w.runtime->route().isEmpty());
            w.runtime->begin(w.id);
            QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
            QVERIFY(seen.contains(QStringLiteral("AmneziaWG")));
            const auto route=w.runtime->route();
            QCOMPARE(route.value("method").toString(),QStringLiteral("AmneziaWG"));
            QCOMPARE(route.value("cityId").toString(),w.runtime->exitLocation().value("cityId").toString());
            settle(w);
            QVERIFY(w.runtime->route().isEmpty());
        }
        {
            World w; w.singleCandidate=true; w.offerXray=true;
            w.app.setMayakConnectionMethod("xray");
            w.runtime->begin(w.id);
            QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
            QCOMPARE(w.runtime->route().value("method").toString(),QStringLiteral("Xray"));
            settle(w);
        }
    }
    void xrayProofOtherFailureStillSwitchesPath() {
        // Any other probe failure (no TLS, wrong egress, ...) is not retried: the next path runs.
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=true; w.failNextProbes=1;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.xrayStarts,2);
        QVERIFY(w.runtime->exitLocation().value("pathId").toString()!=QStringLiteral("xray-firefox"));
        settle(w);
    }
    void onlyXrayNeverStartsAwg() {
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=true;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(w.awgStarts,0); QCOMPARE(w.xrayStarts,1);
        QCOMPARE(w.runtime->exitLocation().value("pathId").toString(),QStringLiteral("xray-firefox"));
        settle(w);
    }
    void appExclusionsArePreparedBeforeAnyTunnelStarts() {
        FastRecoveryTiming timing; SplitPrepareGuard prepareGuard;
        int prepares=0; QString answer=QStringLiteral("amnezia_active");
        MayakAutoConnectRuntime::setSplitPrepareForTests([&](QObject* ctx, std::function<void(bool, QString)> done) {
            ++prepares; QTimer::singleShot(20, ctx, [done, &answer] { done(true, answer); });
        });
        World w; w.singleCandidate=true;
        w.app.setAppsSplitTunnelingEnabled(true);
        w.app.setAppsRouteMode(amnezia::AppsRouteMode::VpnAllExceptApps);
        w.app.setVpnApps(amnezia::AppsRouteMode::VpnAllExceptApps, {InstalledAppInfo{QStringLiteral("Bank"), {}, QStringLiteral("C:/bank.exe")}});
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QVERIFY(w.runtime->message().contains(QStringLiteral("AmneziaVPN")));
        QCOMPARE(prepares,1); QCOMPARE(w.starts,0); QCOMPARE(w.acquires,0);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        answer=QStringLiteral("ok");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(prepares,2);
        settle(w);
    }
    void appExclusionPrepareIsSkippedWithoutExclusions() {
        FastRecoveryTiming timing; SplitPrepareGuard prepareGuard;
        int prepares=0;
        MayakAutoConnectRuntime::setSplitPrepareForTests([&](QObject*, std::function<void(bool, QString)> done) { ++prepares; done(true, QStringLiteral("ok")); });
        World w; w.singleCandidate=true;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        QCOMPARE(prepares,0);
        settle(w);
    }
    void appExclusionFailureEndsWithClearErrorAndNoXrayFallback() {
        FastRecoveryTiming timing;
        CoordinatorTimingGuard timingGuard; auto& t=mayak::autoconnect::Coordinator::timing(); t.awgVerifyMs=2000;
        World w; w.singleCandidate=true; w.offerXray=true; w.awgSilent=true; w.appExclusionFails=true;
        w.app.setMayakConnectionMethod("auto");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QVERIFY(w.runtime->message().contains(QStringLiteral("исключения программ")));
        QCOMPARE(w.xrayStarts,0);          // no silent fallback to a path without app exclusions
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
        QTRY_VERIFY_WITH_TIMEOUT(!w.runtime->busy(),5000);
        // A later connect is a new session: an old failure does not block it.
        w.appExclusionFails=false; w.awgSilent=false; w.app.setMayakConnectionMethod("awg");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        settle(w);
    }
    void connectedXrayEndsOnlyAfterThreeFailedProbes() {
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=true;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,10000);
        const int starts=w.xrayStarts;
        w.failNextProbes=2; // two misses in a row: the same tunnel stays
        QTest::qWait(1500);
        QCOMPARE(w.xrayStarts,starts);
        w.tunnelDown=true;  // a dead path is ended and started again
        QTRY_VERIFY_WITH_TIMEOUT(w.xrayStarts>starts,10000);
        w.tunnelDown=false;
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        settle(w);
    }
    void onlyXrayWithoutPathsIsAClearError() {
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=false;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,10000);
        QVERIFY(w.runtime->message().contains(QStringLiteral("Способ подключения")) || w.runtime->message().contains(QStringLiteral("способ подключения")));
        QCOMPARE(w.starts,0);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    }
    void deadXrayPathsFallBackToTheNextPathThenError() {
        FastRecoveryTiming timing;
        CoordinatorTimingGuard timingGuard; auto& t=mayak::autoconnect::Coordinator::timing(); t.xrayVerifyMs=300;
        World w; w.singleCandidate=true; w.offerXray=true; w.xrayDead=true;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_VERIFY_WITH_TIMEOUT(w.xrayStarts>=3,10000);
        QTRY_VERIFY_WITH_TIMEOUT(w.state!=Vpn::ConnectionState::Connecting,10000);
        QVERIFY(w.state!=Vpn::ConnectionState::Connected);
        QCOMPARE(w.acquires>=1,true);
        settle(w);
    }

    void raceWithoutAnswersDropsXrayAndNeverOverlapsATunnel() {
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=true; w.withRace=true;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Error,15000);
        QCOMPARE(w.raceStarts,1); QCOMPARE(w.raceStops,1);
        QCOMPARE(w.xrayStarts,0); // nobody answered through the race entries: no tunnel was started
        // The engine config: one password-protected loopback entry and one outbound per path.
        const auto inbounds=w.raceConfig.value("inbounds").toArray();
        QCOMPARE(inbounds.size(),3);
        for (const auto& v:inbounds) {
            const auto in=v.toObject();
            QCOMPARE(in.value("listen").toString(),QStringLiteral("127.0.0.1"));
            QCOMPARE(in.value("settings").toObject().value("auth").toString(),QStringLiteral("password"));
        }
        QCOMPARE(w.raceConfig.value("outbounds").toArray().size(),3);
        QCOMPARE(w.raceConfig.value("routing").toObject().value("rules").toArray().size(),3);
        QTRY_COMPARE_WITH_TIMEOUT(w.records(),0,5000);
    }
    void raceEngineFailureFallsBackToServerOrder() {
        FastRecoveryTiming timing;
        World w; w.singleCandidate=true; w.offerXray=true; w.withRace=true; w.raceEngineOk=false;
        w.app.setMayakConnectionMethod("xray");
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Connected,15000);
        QCOMPARE(w.runtime->exitLocation().value("pathId").toString(),QStringLiteral("xray-firefox"));
        QVERIFY(!w.raceRunning);
        settle(w);
    }

    void cancelDuringConnectRetryWaitDisconnects() {
        FastRecoveryTiming timing;
        auto slow=MayakAutoConnectRuntime::recoveryTiming(); slow.connectRetryMs={5000};
        MayakAutoConnectRuntime::setRecoveryTimingForTests(slow);
        World w; w.failConfigCount=100;
        w.runtime->begin(w.id);
        QTRY_COMPARE_WITH_TIMEOUT(w.runtime->message(),QStringLiteral("Нет связи с сервером Маяка — повторяем…"),5000);
        QVERIFY(w.runtime->busy());
        w.runtime->cancel();
        QTRY_COMPARE_WITH_TIMEOUT(w.state,Vpn::ConnectionState::Disconnected,3000);
        QVERIFY(!w.runtime->busy());
        const int fails=w.events.count("config_fail");
        QTest::qWait(400);
        QCOMPARE(w.events.count("config_fail"),fails);
        QCOMPARE(w.acquires,0); QCOMPARE(w.records(),0);
    }
};
int main(int argc,char** argv) {
    QTemporaryDir temp; if(!temp.isValid())return 2;
    QSettings::setDefaultFormat(QSettings::IniFormat);QSettings::setPath(QSettings::IniFormat,QSettings::UserScope,temp.path());
    QSettings::setPath(QSettings::IniFormat,QSettings::SystemScope,temp.path());
    QApplication app(argc,argv);RuntimeTest test;return QTest::qExec(&test,argc,argv);
}
#include "testMayakRuntime.moc"
