#include "mayakAutoConnectRuntime.h"
#include "mayakAutoConnectCoordinator.h"
#include "mayakAttemptStore.h"
#include "api/mayakAdmissionClient.h"
#include "api/subscriptionController.h"
#include "connectionController.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/api/gatewayPayloadBuilder.h"
#include "core/utils/constants/apiKeys.h"
#include <algorithm>
#include <QCryptographicHash>
#include <QCoreApplication>
#include <QDebug>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QThread>
#include <QDateTime>
#include <QFutureWatcher>
#include <QPromise>
#include <QJsonDocument>
#include <QTimer>
#include <QUrl>
#include <QJsonArray>
#include <QJsonObject>
#include <QNetworkInterface>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSet>
#include "core/utils/mayakTunnelProbe.h"
#include "mayakForeignVpn.h"
#include "version.h"
#include "secureQSettings.h"
#include <map>
#include <set>
#include <tuple>
#ifdef Q_OS_ANDROID
#include <cstdlib>
#include <dirent.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace ac = mayak::autoconnect;
namespace ad = mayak::admission;
namespace at = mayak::attempts;
using B = MayakBackendBridge;
using amnezia::ErrorCode;
namespace {
QString randomId() { return B::randomRequestId(); }
MayakAutoConnectRuntime::RecoveryTiming& recoveryTimingStorage() {
    static MayakAutoConnectRuntime::RecoveryTiming timing;
    return timing;
}
// Failover memory for the app process (every connect is a new Session): an exit that stopped
// working, or never answered a handshake while connecting, is tried last for a while.
struct AvoidedExit { QString candidateId; qint64 until = 0; int knownExits = 0; };
AvoidedExit& avoidedExitStorage() { static AvoidedExit avoided; return avoided; }
// Local adapter failure retries survive the automatic session restart below (bounded across
// sessions); a user-started connect or a confirmed connection resets them.
// heal: Windows refused Mayak's tunnel adapter on a start; the next start repairs WinTun first.
struct LocalStartRetries { int count = 0; bool autoRestart = false; bool heal = false; };
LocalStartRetries& localStartRetriesStorage() { static LocalStartRetries retries; return retries; }
constexpr qint64 kAvoidExitMs = 10 * 60 * 1000;
// Path memory: on a network where AWG did not come up and an Xray path did, the next connects
// start with the Xray paths for a while. Stored only on this device as a salted hash of the
// local network (interface names and IPv4 subnets); never sent anywhere, never logged.
constexpr qint64 kXrayFirstMs = 12 * 60 * 60 * 1000;
const char* kPathMemoryKey = "Mayak/pathMemory";
const char* kPathSaltKey = "Mayak/pathMemorySalt";
// Android: a just-started Xray tunnel's VPN network is not visible to ConnectivityManager for a
// moment, so the probe's strict socket bind fails at once (exact text from mayakTunnelProbe.cpp).
// Only this failure is retried, after this delay, within the path's own proof time.
const QLatin1String kAndroidVpnBindFailed("strict Android VPN socket binding failed");
constexpr int kXrayBindRetryMs = 250;
// A bind that still fails this long after the first failure is not a VPN network still coming up:
// the path fails as before instead of using its whole proof time.
constexpr qint64 kXrayBindRetryBudgetMs = 3000;
// Android (19.11 log): gateway requests go through libagw (Go net/http), whose connection pool is
// shared by the whole process. A connection opened while a tunnel ran is tied to that VPN network;
// after the tunnel stops or the network changes it silently black-holes, and every later request
// waits on it until timeout («Нет связи с сервером Маяка», a disconnect that never finishes) until
// the app restarts. libagw has no API to drop it, so the app shuts down its own TCP sockets to
// port 443 (never loopback) at these points: the HTTP client then sees an error and reconnects.
// Only this app process is touched; the VPN services run in their own processes.
int shutdownOwnHttpsSockets() {
#ifdef Q_OS_ANDROID
    DIR* dir=::opendir("/proc/self/fd");
    if (!dir) return -1;
    const int own=::dirfd(dir);
    int closed=0;
    while (dirent* entry=::readdir(dir)) {
        char* end=nullptr;
        const long value=std::strtol(entry->d_name,&end,10);
        if (!end || *end!='\0' || end==entry->d_name || value<0 || value==own) continue;
        const int fd=int(value);
        struct stat st{};
        if (::fstat(fd,&st)!=0 || !S_ISSOCK(st.st_mode)) continue;
        int type=0; socklen_t typeLength=sizeof(type);
        if (::getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&typeLength)!=0 || type!=SOCK_STREAM) continue;
        sockaddr_storage peer{}; socklen_t peerLength=sizeof(peer);
        if (::getpeername(fd,reinterpret_cast<sockaddr*>(&peer),&peerLength)!=0) continue;
        if (peer.ss_family==AF_INET) {
            const auto* v4=reinterpret_cast<const sockaddr_in*>(&peer);
            if (ntohs(v4->sin_port)!=443 || (ntohl(v4->sin_addr.s_addr)>>24)==127) continue;
        } else if (peer.ss_family==AF_INET6) {
            const auto* v6=reinterpret_cast<const sockaddr_in6*>(&peer);
            if (ntohs(v6->sin6_port)!=443 || IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr)) continue;
            if (IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr) && v6->sin6_addr.s6_addr[12]==127) continue;
        } else continue;
        // Only the gateway library's (Go) connections: Go turns TCP_NODELAY on for every TCP conn
        // (net.newTCPConn), Qt and this app never do. A Qt socket (QSslSocket of the network
        // access manager or the probe) shut down under it crashed the app on Android (20.11.2026,
        // SIGSEGV in QSslSocketPrivate::_q_disconnectedSlot); Qt sockets are never stale-pooled.
        int noDelay=0; socklen_t noDelayLength=sizeof(noDelay);
        if (::getsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&noDelay,&noDelayLength)!=0 || noDelay==0) continue;
        if (::shutdown(fd,SHUT_RDWR)==0) ++closed;
    }
    ::closedir(dir);
    return closed;
#else
    return 0;
#endif
}
std::function<int()>& httpsSocketResetStorage() { static std::function<int()> hook=shutdownOwnHttpsSockets; return hook; }
// A tunnel started (or was adopted) since the last reset: only then can the app's HTTPS connections
// be tied to a VPN network that is gone. Without it (e.g. an update download started while no VPN
// ran) nothing is reset at connect, reconnect or release. A fresh app process starts "stale": on
// Android the VPN services run in their own processes, so this process may have been restarted
// while a tunnel ran and its first gateway requests went through it.
bool& httpsSocketsMayBeStale() { static bool stale=true; return stale; }
// The local network as "interface/subnet/prefix" entries (sorted); only kept in memory.
QStringList localNetworkParts() {
    QStringList parts;
    for (const auto& iface : QNetworkInterface::allInterfaces()) {
        const auto flags = iface.flags();
        if (!(flags & QNetworkInterface::IsUp) || !(flags & QNetworkInterface::IsRunning) || (flags & QNetworkInterface::IsLoopBack)) continue;
        for (const auto& entry : iface.addressEntries()) {
            if (entry.ip().protocol() != QAbstractSocket::IPv4Protocol || entry.prefixLength() <= 0) continue;
            const quint32 mask = entry.prefixLength() >= 32 ? 0xffffffffu : ~((1u << (32 - entry.prefixLength())) - 1u);
            parts << iface.name() + '/' + QHostAddress(entry.ip().toIPv4Address() & mask).toString() + '/' + QString::number(entry.prefixLength());
        }
    }
    parts.sort();
    return parts;
}
QString localNetworkKey(SecureQSettings* settings, const QStringList& parts) {
    if (!settings || parts.isEmpty()) return {};
    QString salt = settings->value(kPathSaltKey).toString();
    if (salt.size() != 64) { salt = B::randomRequestId(); settings->setValue(kPathSaltKey, salt); }
    return QString::fromLatin1(QCryptographicHash::hash((salt + '|' + parts.join('|')).toUtf8(), QCryptographicHash::Sha256).toHex());
}
// Same network as `before`, ignoring the tunnel's own interface (it exists only while connected).
// It is found by the tunnel's local IPv4 address: interface names differ between Qt and the service
// on Windows (Qt "ethernet_NNNNN", the service "MayakVPN"). Without the address nothing is compared.
bool sameLocalNetwork(QStringList before, QStringList now, const QString& tunnelAddress) {
    const QHostAddress own(tunnelAddress.section('/', 0, 0));
    if (own.protocol() != QAbstractSocket::IPv4Protocol) return false;
    const auto inTunnel = [&own](const QString& part) {
        const QStringList f = part.split('/');
        return f.size() >= 3 && own.isInSubnet(QHostAddress(f.at(f.size() - 2)), f.last().toInt());
    };
    before.removeIf(inTunnel); now.removeIf(inTunnel);
    return !before.isEmpty() && before == now;
}
bool rememberedXrayFirst(SecureQSettings* settings, const QString& network) {
    if (!settings || network.isEmpty()) return false;
    const auto memory = QJsonDocument::fromJson(settings->value(kPathMemoryKey).toByteArray()).object();
    const auto entry = memory.value(network).toObject();
    return entry.value("xrayFirst").toBool() && entry.value("until").toDouble() > double(QDateTime::currentMSecsSinceEpoch());
}
void rememberPath(SecureQSettings* settings, const QString& network, bool xrayFirst) {
    if (!settings || network.isEmpty()) return;
    auto memory = QJsonDocument::fromJson(settings->value(kPathMemoryKey).toByteArray()).object();
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    for (const auto& key : memory.keys())
        if (memory.value(key).toObject().value("until").toDouble() <= double(now)) memory.remove(key);
    if (xrayFirst) memory.insert(network, QJsonObject{{"xrayFirst", true}, {"until", double(now + kXrayFirstMs)}});
    else memory.remove(network);
    while (memory.size() > 16) memory.remove(memory.keys().first());
    settings->setValue(kPathMemoryKey, QJsonDocument(memory).toJson(QJsonDocument::Compact));
}
// Exit memory: the exit and path that last proved on this local network are tried first next
// time, while the server still offers that exit (else the server order stands). A failure of the
// remembered exit/path forgets it. Same salted network key as the path memory; only on this device,
// never sent, never logged.
constexpr qint64 kExitMemoryMs = 7LL * 24 * 60 * 60 * 1000;
const char* kExitMemoryKey = "Mayak/exitMemory";
// `path` is set only for an Xray path that proved after AWG did not, in automatic mode: it expires
// with the path memory (12 h); otherwise the method's usual order applies on the remembered exit.
struct RememberedExit {
    QString exit, path;
    bool valid() const { return !exit.isEmpty(); }
    bool is(const QString& candidate) const { return valid() && exit.compare(candidate, Qt::CaseInsensitive) == 0; }
};
RememberedExit rememberedExit(SecureQSettings* settings, const QString& network) {
    if (!settings || network.isEmpty()) return {};
    const auto entry = QJsonDocument::fromJson(settings->value(kExitMemoryKey).toByteArray()).object().value(network).toObject();
    const double now = double(QDateTime::currentMSecsSinceEpoch());
    if (entry.value("until").toDouble() <= now) return {};
    return {entry.value("exit").toString(), entry.value("pathUntil").toDouble() > now ? entry.value("path").toString() : QString()};
}
// An empty exit forgets this network's entry.
void rememberExit(SecureQSettings* settings, const QString& network, const QString& exit, const QString& path) {
    if (!settings || network.isEmpty()) return;
    auto memory = QJsonDocument::fromJson(settings->value(kExitMemoryKey).toByteArray()).object();
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    for (const auto& key : memory.keys())
        if (memory.value(key).toObject().value("until").toDouble() <= double(now)) memory.remove(key);
    if (!exit.isEmpty()) {
        QJsonObject entry{{"exit", exit}, {"until", double(now + kExitMemoryMs)}};
        if (!path.isEmpty()) { entry.insert("path", path); entry.insert("pathUntil", double(now + kXrayFirstMs)); }
        memory.insert(network, entry);
    } else memory.remove(network);
    while (memory.size() > 16) { // the entry that expires first goes
        QString oldest; double until = 0;
        for (const auto& key : memory.keys()) {
            const double u = memory.value(key).toObject().value("until").toDouble();
            if (oldest.isEmpty() || u < until) { oldest = key; until = u; }
        }
        memory.remove(oldest);
    }
    settings->setValue(kExitMemoryKey, QJsonDocument(memory).toJson(QJsonDocument::Compact));
}
// Connect without the gateway (review 01, item 2; 23.11.2026). After every signed v1/config and
// acquire the device keeps, encrypted (SecureQSettings, never sent, never logged), the exits it was
// offered (at most 3) and, for each exit it was admitted to, the allocation config exactly as the
// server sent it (its private key is a placeholder; the stable device key is substituted at start,
// as for a fresh acquire), its Xray paths and the city card. When the gateway gives no signed
// answer, a session connects to these exits directly and reports the place later (late acquire).
// The device's peer is on every exit; the place is only accounting. Wiped only by authoritative
// signals (REVOKED / ACCOUNT_EXPIRED) and ignored for another subscription/device key/credential or
// after its bound; a stored exit that fails is moved back, never wiped (the gateway may be down
// while the network is bad, exactly when the memory is needed).
constexpr qint64 kOfflineDefaultMs = 7LL * 24 * 60 * 60 * 1000;
const char* kOfflineMemoryKey = "Mayak/offlineMemory";
struct OfflineExit {
    QString id, host; quint16 port = 0; bool preferred = false; QStringList egress;
    QString encodedConfig; QJsonArray xrayPaths; QString tunnelHash;
    QString cityId; bool hasCard = false; ad::ExitLocationCard card;
    int failures = 0; qint64 okAt = 0;
    bool usable() const { return !id.isEmpty() && !host.isEmpty() && port != 0 && !egress.isEmpty() && !encodedConfig.isEmpty(); }
};
struct OfflineMemory {
    QString owner; qint64 until = 0; QList<OfflineExit> exits;
    bool usable(const QString& who, qint64 nowUtc) const {
        if (owner.isEmpty() || owner != who || until <= nowUtc) return false;
        return std::any_of(exits.begin(), exits.end(), [](const OfflineExit& e) { return e.usable(); });
    }
};
// Binds the memory to this subscription, device key and device credential (hash only).
QString offlineOwner(const QString& serverId, const QString& publicKey, const QString& apiKey) {
    if (serverId.isEmpty() || publicKey.isEmpty() || apiKey.isEmpty()) return {};
    return QString::fromLatin1(QCryptographicHash::hash((serverId + '|' + publicKey + '|' + apiKey).toUtf8(),
                                                        QCryptographicHash::Sha256).toHex());
}
// The tunnel part of an allocation config: host and containers (exit key/PSK, port, AWG parameters,
// client address, DNS), without the per-answer API fields (key expiry, end date, API key).
QString offlineTunnelHash(const QString& encoded) {
    QString body = encoded;
    if (body.startsWith(QLatin1String("vpn://"))) body = body.mid(6);
    const QByteArray raw = qUncompress(QByteArray::fromBase64(body.toLatin1(), QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
    const QJsonObject root = QJsonDocument::fromJson(raw).object();
    if (root.isEmpty()) return {};
    const QByteArray part = QJsonDocument(QJsonObject{{"hostName", root.value("hostName")}, {"containers", root.value("containers")}})
                                .toJson(QJsonDocument::Compact);
    return QString::fromLatin1(QCryptographicHash::hash(part, QCryptographicHash::Sha256).toHex().left(16));
}
OfflineMemory loadOfflineMemory(SecureQSettings* settings) {
    OfflineMemory m;
    if (!settings) return m;
    const QJsonObject root = QJsonDocument::fromJson(settings->value(kOfflineMemoryKey).toByteArray()).object();
    m.owner = root.value("owner").toString(); m.until = qint64(root.value("until").toDouble());
    for (const auto& value : root.value("exits").toArray()) {
        const QJsonObject o = value.toObject(); OfflineExit e;
        e.id = o.value("id").toString(); e.host = o.value("host").toString(); e.port = quint16(o.value("port").toInt());
        e.preferred = o.value("preferred").toBool();
        for (const auto& ip : o.value("egress").toArray()) e.egress << ip.toString();
        e.encodedConfig = o.value("config").toString(); e.xrayPaths = o.value("xray").toArray(); e.tunnelHash = o.value("hash").toString();
        e.cityId = o.value("cityId").toString();
        const QJsonObject card = o.value("card").toObject();
        e.hasCard = !card.isEmpty();
        e.card = {card.value("city").toString(), card.value("country").toString(), card.value("countryCode").toString(),
                  card.value("fact").toString(), card.value("photo").toString(), card.value("version").toString()};
        e.failures = o.value("failures").toInt(); e.okAt = qint64(o.value("okAt").toDouble());
        if (!e.id.isEmpty()) m.exits << e;
    }
    return m;
}
void saveOfflineMemory(SecureQSettings* settings, const OfflineMemory& m) {
    if (!settings) return;
    QJsonArray exits;
    for (const auto& e : m.exits) {
        QJsonObject o{{"id", e.id}, {"host", e.host}, {"port", int(e.port)}, {"preferred", e.preferred},
                      {"egress", QJsonArray::fromStringList(e.egress)}, {"failures", e.failures}, {"okAt", double(e.okAt)}};
        if (!e.encodedConfig.isEmpty()) { o.insert("config", e.encodedConfig); o.insert("hash", e.tunnelHash); }
        if (!e.xrayPaths.isEmpty()) o.insert("xray", e.xrayPaths);
        if (!e.cityId.isEmpty()) o.insert("cityId", e.cityId);
        if (e.hasCard) o.insert("card", QJsonObject{{"city", e.card.city}, {"country", e.card.country}, {"countryCode", e.card.countryCode},
                                                    {"fact", e.card.fact}, {"photo", e.card.photo}, {"version", e.card.version}});
        exits.append(o);
    }
    settings->setValue(kOfflineMemoryKey, QJsonDocument(QJsonObject{{"owner", m.owner}, {"until", double(m.until)}, {"exits", exits}})
                                              .toJson(QJsonDocument::Compact));
}
// Cleanup of a place whose release/reconcile got no answer at all while the gateway was down and the
// tunnel is confirmed down: the exact attempt (with its original device authority) is kept here and
// reconciled at the next signed gateway answer, so the gateway's outage neither blocks the OFF nor
// the next connect. A late acquire also closes an older open place of the device on the server.
const char* kDeferredCleanupKey = "Mayak/deferredCleanup";
struct DeferredCleanup { at::AttemptIdentity identity; at::CleanupAuthorityInput authority; int refusals = 0; };
// Never more entries than this; a full list refuses further deferral (the manual cleanup stays).
constexpr int kDeferredCleanupMax = 32;
// A reconcile the server refuses this often (e.g. another device key since) is given up.
constexpr int kDeferredCleanupRefusals = 3;
QList<DeferredCleanup> loadDeferredCleanup(SecureQSettings* settings) {
    QList<DeferredCleanup> list;
    if (!settings) return list;
    for (const auto& value : QJsonDocument::fromJson(settings->value(kDeferredCleanupKey).toByteArray()).array()) {
        const QJsonObject o = value.toObject(); DeferredCleanup d;
        d.identity = {o.value("subscription").toString(), o.value("epoch").toString(), o.value("cycle").toString(),
                      o.value("attempt").toString(), o.value("candidate").toString()};
        d.authority = {o.value("gateway").toString(), o.value("installation").toString(), o.value("publicKey").toString(),
                       o.value("apiKey").toString(), o.value("serviceType").toString(), o.value("serviceProtocol").toString(),
                       o.value("userCountry").toString(), o.value("serverCountry").toString()};
        d.refusals = o.value("refusals").toInt();
        if (!d.identity.attemptId.isEmpty()) list << d;
    }
    return list;
}
void saveDeferredCleanup(SecureQSettings* settings, const QList<DeferredCleanup>& list) {
    if (!settings) return;
    if (list.isEmpty()) { settings->remove(kDeferredCleanupKey); return; }
    QJsonArray array;
    for (const auto& d : list)
        array.append(QJsonObject{{"subscription", d.identity.localSubscriptionId}, {"epoch", d.identity.accountIdentityEpoch},
            {"cycle", d.identity.cycleToken}, {"attempt", d.identity.attemptId}, {"candidate", d.identity.candidateId},
            {"gateway", d.authority.gatewayEndpoint}, {"installation", d.authority.installationUuid}, {"publicKey", d.authority.publicKey},
            {"apiKey", d.authority.deviceApiKey}, {"serviceType", d.authority.serviceType}, {"serviceProtocol", d.authority.serviceProtocol},
            {"userCountry", d.authority.userCountryCode}, {"serverCountry", d.authority.serverCountryCode},
            {"refusals", d.refusals}});
    settings->setValue(kDeferredCleanupKey, QJsonDocument(array).toJson(QJsonDocument::Compact));
}
QJsonObject payloadForDeferred(const DeferredCleanup& d) {
    return {{"auth_data", QJsonObject{{"api_key", d.authority.deviceApiKey}}}, {"installation_uuid", d.authority.installationUuid},
        {"public_key", d.authority.publicKey}, {"service_type", d.authority.serviceType}, {"service_protocol", d.authority.serviceProtocol},
        {"user_country_code", d.authority.userCountryCode}, {"server_country_code", d.authority.serverCountryCode}};
}
// Port precheck: one plain TCP connect per exit to its Xray port, all at once, before the exits
// are tried. Nothing is sent (no TLS, no SNI). An exit that does not answer goes last, it is never
// dropped (AWG over UDP may still work there). Its Xray paths on this port are skipped in this cycle.
constexpr quint16 kXrayPrecheckPort = 443;
void tcpPortPrecheck(QObject* context, const QStringList& hosts, quint16 port, int timeoutMs, std::function<void(QList<bool>)> done) {
    struct State { QList<bool> answered, settled; int pending = 0; bool finished = false; QList<QPointer<QTcpSocket>> sockets; std::function<void(QList<bool>)> done; };
    auto st = std::make_shared<State>();
    st->answered = QList<bool>(hosts.size(), false); st->settled = st->answered; st->pending = int(hosts.size()); st->done = std::move(done);
    // Never runs inside a socket's own signal: sockets are aborted and deleted afterwards.
    const auto finish = [st] {
        if (st->finished) return;
        st->finished = true;
        for (const auto& socket : st->sockets) if (socket) { QObject::disconnect(socket, nullptr, nullptr, nullptr); socket->abort(); socket->deleteLater(); }
        auto callback = std::move(st->done);
        if (callback) callback(st->answered);
    };
    for (int i = 0; i < hosts.size(); ++i) {
        auto* socket = new QTcpSocket(context);
        st->sockets.append(socket);
        const auto settled = [st, context, finish, i](bool ok) {
            if (st->finished || st->settled.at(i)) return;
            st->settled[i] = true; st->answered[i] = ok; --st->pending;
            if (st->pending == 0) QTimer::singleShot(0, context, finish);
        };
        QObject::connect(socket, &QTcpSocket::connected, context, [settled] { settled(true); });
        QObject::connect(socket, &QAbstractSocket::errorOccurred, context, [settled] { settled(false); });
        socket->connectToHost(QHostAddress(hosts.at(i)), port);
    }
    QTimer::singleShot(qMax(1, timeoutMs), context, finish);
}
MayakAutoConnectRuntime::PortPrecheck& portPrecheckStorage() {
    static MayakAutoConnectRuntime::PortPrecheck hook = tcpPortPrecheck;
    return hook;
}
// The port of an Xray path's single outbound (0 when unknown).
int xrayOutboundPort(const QJsonObject& clientJson) {
    const auto vnext = clientJson.value("outbounds").toArray().first().toObject().value("settings").toObject().value("vnext").toArray();
    return vnext.size() == 1 ? vnext.first().toObject().value("port").toInt(0) : 0;
}
using SplitPrepare = std::function<void(QObject*, std::function<void(bool, QString)>)>;
SplitPrepare& splitPrepareStorage() { static SplitPrepare hook; return hook; }
// WinTun repair in the service (Windows); empty = the real service request. The "repair wanted" mark
// also survives an app restart (an update over a running VPN restarts the app), and the first connect
// of a new app version repairs once in advance (an update may have cut the running tunnel).
const char* kWintunHealWantedKey = "Mayak/wintunHealWanted";
const char* kWintunHealVersionKey = "Mayak/wintunHealVersion";
SplitPrepare& wintunHealStorage() { static SplitPrepare hook; return hook; }
const char* kAppExclusionUnavailable =
    "Не удалось включить исключения программ: драйвер раздельного туннелирования недоступен. "
    "Перезагрузите компьютер или уберите исключения в «Раздельное туннелирование».";
QString splitPrepareText(const QString& result) {
    if (result == QLatin1String("amnezia_active"))
        return QStringLiteral("Исключения программ заняты AmneziaVPN: в ней сейчас включён VPN. Выключите VPN в AmneziaVPN и включите Маяк снова.");
    if (result == QLatin1String("amnezia_busy"))
        return QStringLiteral("AmneziaVPN сейчас запускается или останавливается. Включите Маяк через несколько секунд.");
    if (result == QLatin1String("mullvad"))
        return QStringLiteral("Исключения программ недоступны: их драйвер использует установленный Mullvad VPN. Уберите исключения в «Раздельное туннелирование».");
    if (result == QLatin1String("amnezia_holds"))
        return QStringLiteral("Исключения программ заняты AmneziaVPN. Перезагрузите компьютер или удалите AmneziaVPN, если она не нужна.");
    return QString::fromUtf8(kAppExclusionUnavailable);
}
quint16 freeLoopbackPort() {
    QTcpServer server;
    if (!server.listen(QHostAddress::LocalHost, 0)) return 0;
    const quint16 port = server.serverPort();
    server.close();
    return port;
}
qint64 utcDeadline(qint64 mono) { return QDateTime::currentMSecsSinceEpoch() + qMax<qint64>(0, mono-B::monotonicMillis()); }
QJsonObject payloadFor(const at::AttemptRecord& r) {
    return {{"auth_data", QJsonObject{{"api_key",r.deviceApiKey()}}}, {"installation_uuid",r.installationUuid()},
        {"public_key",r.publicKey()}, {"service_type",r.serviceType()}, {"service_protocol",r.serviceProtocol()},
        {"user_country_code",r.userCountryCode()}, {"server_country_code",r.serverCountryCode()}};
}
ad::GatewayFactory factoryFor(QString endpoint) {
    return [endpoint](int timeout) { return QSharedPointer<GatewayController>::create(endpoint,false,timeout,false,nullptr); };
}
ad::Transport gatewayTransport() {
    return [](const QString& api,const QJsonObject& payload,int timeout) {
        auto gateway=factoryFor(QStringLiteral("https://mayaklight.ru/gw/"))(timeout);
        auto promise=std::make_shared<QPromise<GatewayPostResult>>(); promise->start();
        auto future=promise->future();
        auto* watcher=new QFutureWatcher<GatewayPostResult>();
        QObject::connect(watcher,&QFutureWatcher<GatewayPostResult>::finished,watcher,[gateway,watcher,promise] {
            promise->addResult(watcher->result()); promise->finish(); watcher->deleteLater();
        });
        watcher->setFuture(gateway->postAuthenticatedAsync(api,payload));
        return future;
    };
}
QString errorText(ac::ErrorCategory e) {
    switch(e) {
    case ac::ErrorCategory::Capacity: return QStringLiteral("Серверы заняты. Повторите подключение немного позже.");
    case ac::ErrorCategory::AuthRevoked: return QStringLiteral("Доступ отозван. Войдите в личный кабинет.");
    case ac::ErrorCategory::AccountExpired: return QStringLiteral("Срок доступа закончился. Откройте личный кабинет.");
    case ac::ErrorCategory::NotReady: return QStringLiteral("Сервер готовит доступ. Повторите подключение через несколько секунд.");
    case ac::ErrorCategory::StopUnconfirmed: return QStringLiteral("Не удалось подтвердить отключение. Повторите попытку для безопасного завершения.");
    case ac::ErrorCategory::Unsupported: return QStringLiteral("Выбранный способ подключения недоступен для этого сервера. Выберите «Автоматически» в настройках подключения.");
    default: return QStringLiteral("Не удалось подключиться к доступному серверу. Проверьте интернет и повторите попытку.");
    }
}
QString manualName(const QString& city) {
    return city.isEmpty() ? QStringLiteral("Выбранный сервер") : QStringLiteral("Сервер «%1»").arg(city);
}
QString manualMissingText(const QString& city) {
    return manualName(city)+QStringLiteral(" сейчас недоступен для подключения. Выберите «Авто» или другой сервер.");
}
QString manualFailedText(const QString& city,ac::ErrorCategory e) {
    switch(e) {
    case ac::ErrorCategory::Capacity: return manualName(city)+QStringLiteral(" занят. Выберите «Авто» или другой сервер.");
    case ac::ErrorCategory::NotReady: return manualName(city)+QStringLiteral(" готовит доступ. Повторите подключение через несколько секунд.");
    case ac::ErrorCategory::Unsupported: return errorText(e);
    default: return manualName(city)+QStringLiteral(" не подключился. Выберите «Авто» или другой сервер.");
    }
}
}

// Callbacks retain Session, not UI or repositories. Every remote effect carries
// the immutable original device authority. The encrypted ledger survives exits.
struct MayakAutoConnectRuntime::Session : QObject, ac::Adapter, ac::Clock,
                                        std::enable_shared_from_this<Session> {
    QPointer<MayakAutoConnectRuntime> facade;
    QPointer<SecureServersRepository> servers;
    QPointer<SecureAppSettingsRepository> app;
    QPointer<ConnectionController> connection;
    SubscriptionController* subscription;
    SecureQSettings* settings = nullptr;
    ad::Transport transport;
    // Connection method for this session ("auto", "awg", "xray") and the local network key of
    // the path memory, both fixed when the session starts (before any tunnel exists).
    QString method = QStringLiteral("auto");
    QString networkKey;
    // Exit memory of this network (read at session start) and the exits whose Xray port did not
    // answer the precheck of the current cycle (by candidate id, lower case).
    RememberedExit remembered;
    QStringList networkParts; // the local network at session start (the exit memory is saved only on it)
    QSet<QString> tcpUnanswered;
    ac::State observedState = ac::State::Idle; // the previous coordinator state seen by state()
    bool healPending = false; // a WinTun repair request is in flight (the user's OFF ends the session)
    bool healedThisSession = false; // at most one repair per session (a "busy" answer keeps the mark for later)
    // Exits offered in the current cycle and fresh acquires made in it (the AWG quick give-up
    // is used only while another exit or path is left to try).
    int cycleCandidates = 0, cycleAcquires = 0;
    // Connect without the gateway (see OfflineMemory): the owner key of this session's memory, whether
    // the current cycle's candidates came from the stored exits, and a final refusal of the late
    // acquire (REVOKED / ACCOUNT_EXPIRED) that ends the session with that error.
    QString offlineOwnerKey;
    bool offlineCycle = false;
    bool offlineRevoked = false;
    ac::ErrorCategory lateTerminal = ac::ErrorCategory::None;
    QString fetchRefusalText; // a signed v1/config refusal with its own message (no retries)
    // Owner's manual exit (5.1.0.29), fixed at session start: "" = «Авто». A chosen exit is the only
    // candidate of every cycle (no exit memory, no connect without the gateway, no other exit).
    QString manualExit;
    QString manualCity;
    // Windows: the service could not apply the user's app exclusions (split tunnel driver unavailable).
    // The cycle ends with a clear error instead of retrying or falling back to a path without exclusions.
    qint64 sessionStartMono = mayak::split::monotonicNowMs();
    bool appExclusionBlocked = false;
    bool splitPrepared = false; // app exclusions prepared in the service for this session
    // Xray path race engine (one per session at a time). Starts wait until it is stopped.
    struct Race {
        bool engineActive = false;   // started or starting; a stop is still owed
        bool stopping = false;
        QString requestId;
        std::pair<ac::CycleId,ac::AttemptId> tag{0,0};
        std::vector<QPointer<MayakTunnelProbe>> probes;
        std::function<void()> afterStop; // a path start waiting for the engine to stop
    } race;
    std::unique_ptr<at::MayakAttemptStore> store;
    std::unique_ptr<B> bridge;
    std::unique_ptr<ac::Coordinator> coordinator;
    QTimer timer;
    QString serverId, epoch, cycleToken, endpoint;
    QJsonObject common;
    SubscriptionController::ProtocolData keys;
    at::CleanupAuthorityInput authority;
    int inFlight = 0;
    bool cancelled = false, preparing = true, terminal = false, reconnectWanted = false;
    bool permissionPending = false;
    bool cleanupPending = false, cleanupOperation = false;
    quint64 cleanupGeneration = 0, preflightGeneration = 0;
    qint64 cleanupDeadline = 0;
    bool preflightNativeOff = false;
    QString permissionRequestId;
    qint64 preflightDeadline = 0, lastMonitor = 0;
    bool monitorProbing = false;
    // Connect-time network failures are retried (RecoveryTiming::connectRetryMs) before an error.
    int connectRetries = 0;
    qint64 connectRetryAt = 0;
    // The local tunnel adapter did not come up in this cycle (RecoveryTiming::noHealthMeansLocalFailure).
    bool localStartFailed = false;
    int localStartRetries = 0;
    // Windows was still busy failing the adapter when the 3 s stop expired: confirm the stop
    // later (exact cleanup) and then start a fresh session.
    qint64 localRestartAt = 0;
    bool restartAfterCleanup = false;
    // Connected-state truth for the UI (rule: never "Connected" without a passing
    // tunnel probe) and Android soft recovery of a stuck AWG transport.
    struct Recovery {
        int probeFailures = 0;
        bool shown = false, shownNoNetwork = false;
        bool networkLost = false;
        qint64 networkLostAt = 0, networkChangedAt = 0, forceProbeAt = 0, outageStart = 0, nextAt = 0, lastRecoverAt = 0;
        int attempts = 0;
        bool inFlight = false;
    } rec;
    QVariantMap connectedLocation;
    // Last coordinator attempt/path, for the status line (which exit, which method).
    ac::CycleId routeCycle = 0; ac::AttemptId routeAttempt = 0; std::string routePathId;
    struct XrayEntry { ad::XrayPath path; ad::XrayPathConfig config; };
    struct Attempt {
        at::AttemptIdentity identity;
        ac::Candidate candidate;
        ac::Path path{"awg", ac::PathKind::Awg}; // path of the current/last backend start
        int pathStarts = 0;
        std::vector<XrayEntry> xray;              // validated Xray paths of this allocation
        bool awgFailedHere = false;               // an AWG path of this allocation did not prove
        bool noHandshakeGaveUp = false;           // this AWG path ended early: no handshake in time
        QString rememberedFirst;                  // the remembered path planned first for this exit
        int plannedPaths = 0;                     // paths planned for this allocation
        qint64 probeStartedMono = 0;
        int xrayBindRetries = 0;                  // Xray proof probes repeated after a VPN bind failure
        qint64 xrayBindFirstFailMono = 0;         // first bind failure of this path (bounds the retries)
        QString allocation;
        QString encodedConfig;
        QString exitLocationCityId;
        bool exitLocationHasCard = false;
        ad::ExitLocationCard exitLocationCard;
        qint64 connectBefore = 0;
        B::Ticket ticket;
        AwgHealthContext expected;
        AwgTunnelHealth health;
        qint64 startMono = 0, startUtc = 0, healthAt = 0;
        bool started = false, stopped = false, cancelled = false, probing = false;
        bool adopted = false; // continues the persisted attempt of an adopted running backend
        // Started from the stored exits (no acquire before the start). Until the late acquire
        // answers, the coordinator's allocation handle is `offlineHandle` (no place on the server).
        bool offline = false;
        QString offlineHandle;
        bool lateSent = false;    // a late acquire went out: the server may hold a place for this attempt
        bool lateSettled = false; // the late acquire got its final answer
        bool lateNoPlace = false; // ... and the server holds no place for this attempt
        bool offlineFailCounted = false;
        bool releaseDeferred = false; // its release got no answer and was moved to the deferred cleanup
        bool invalidRetried = false;  // a normal acquire refused with INVALID_REQUEST was repeated as late
        bool provenDelivered = false; // the server answered this attempt's "proven"
        bool provenInFlight = false;  // a "proven" post of this attempt is waiting for its answer
        bool releasePending = false, releaseCallbackHandled = false, releaseLateHandled = false;
        quint64 releaseOperationId = 0;
        bool reset = false;
        qint64 rxChangedAt = 0;          // last time own-peer RX advanced
        qint64 replacementAllowedUntil = 0; // one requested backend replacement may change generation
        quint64 baselineRx = 0, baselineTx = 0;
        ProofDone proofDone;
        QString nonce;
        QStringList egress;
        qint64 proofDeadline = 0;
        bool tlsOk = false;
        MayakTunnelProbeProof proof;
        // Adopted attempt whose ownership transfer was never confirmed: the running backend is
        // still owned by the recovery ticket, so every stop/cleanup of this attempt uses it.
        B::Ticket stopTicket;
        const B::Ticket& ownTicket() const { return stopTicket.valid() ? stopTicket : ticket; }
        bool acceptNativeDown(const B::Result& result) {
            // The Ticket is immutable for this attempt. Native OFF evidence is
            // monotonic across observer, original stop and cleanup retry ingress;
            // a different operation's Unknown/Deadline cannot revoke it.
            if (result.outcome!=B::Outcome::ConfirmedDown || !(ticket.same(result.ticket) ||
                (stopTicket.valid() && stopTicket.same(result.ticket)))) return false;
            stopped=true;
            return true;
        }
    };
    std::map<std::pair<ac::CycleId,ac::AttemptId>, std::shared_ptr<Attempt>> attempts;
    // AWG connected check by counters (5.1.0.27): the previous sample of the same tunnel.
    std::weak_ptr<Attempt> monitorFor;
    quint64 monitorRx = 0, monitorTx = 0, monitorGeneration = 0, monitorHandshake = 0;
    // Cold-start adoption (Android): the inspected running backend continues its persisted
    // attempt instead of being stopped. While `pending`, only the recovery ticket owns it;
    // every path either hands it to an Attempt (fresh ticket) or stops it with that ticket.
    struct Adoption {
        bool pending = false;
        at::AttemptIdentity identity;
        QString allocationId;
        B::Ticket recovery;
        QString controlIdentity;
    } adoption;
    // An adoption is being given up (backend stop + reconcile in flight): the session stays
    // busy and a coordinator cancel must not publish "Disconnected" before it settles.
    bool abandoning = false, abandonHeldDisconnect = false;
    // Android UI hidden (Activity stopped): the service pauses streamed health and runs its own
    // watchdog, so health age and probes say nothing here; connected monitoring pauses.
    bool uiHidden = false;
    // Note 7: giving up an adoption could not confirm the backend stop.
    bool abandonUnconfirmed = false;
    // Device test 21.11: the service refused to hand over a running tunnel (e.g. Xray restarted
    // after an update): that says nothing about the exit, so its memory is kept.
    bool adoptRefused = false;
    // Failover: the exit that just stopped working goes last in the next cycles for a while.
    void avoidCandidate(const QString& id,const char* reason="connected_dead") {
        if (id.isEmpty()) return;
        avoidedExitStorage().candidateId=id; avoidedExitStorage().until=now()+kAvoidExitMs;
        logNet(QStringLiteral("event=failover_avoid reason=%1").arg(QLatin1String(reason)));
        if (remembered.is(id)) forgetRemembered("avoided");
    }
    void forgetRemembered(const char* reason) {
        if (!remembered.valid()) return;
        remembered={}; rememberExit(settings,networkKey,{},{});
        logNet(QStringLiteral("event=exit_memory_forget reason=%1").arg(QLatin1String(reason)));
    }

    explicit Session(MayakAutoConnectRuntime* f, QString id)
        : facade(f), servers(f->m_servers), app(f->m_app), connection(f->m_connection),
          subscription(f->m_subscription), settings(f->m_settings), transport(f->m_transport), store(new at::MayakAttemptStore(f->m_settings)),
          bridge(new B(f->m_port)), serverId(std::move(id)), epoch(randomId()), cycleToken(randomId()) {
        auto& retries=localStartRetriesStorage();
        if (!retries.autoRestart) retries.count=0;
        retries.autoRestart=false;
        localStartRetries=retries.count;
        if (app) connect(app, &SecureAppSettingsRepository::mayakSessionChanging, this, [this] {
            if (permissionPending) stopUser();
        });
        if (servers) {
            connect(servers, &SecureServersRepository::serverEdited, this, [this](const QString &editedId) {
                if (permissionPending && editedId == serverId) stopUser();
            });
            connect(servers, &SecureServersRepository::serverRemoved, this, [this](const QString &removedId, int) {
                if (permissionPending && removedId == serverId) stopUser();
            });
        }
        timer.setInterval(100);
        connect(&timer,&QTimer::timeout,this,[this] {
            if (coordinator && !appExclusionBlocked && !cancelled &&
                mayak::split::appExclusionFailedSince(sessionStartMono)) {
                const auto st=coordinator->status().state;
                if (st!=ac::State::Idle && st!=ac::State::Failed && st!=ac::State::Cancelled) {
                    appExclusionBlocked=true; reconnectWanted=false; connectRetryAt=0; localStartFailed=false;
                    logNet(QStringLiteral("event=app_exclusion_unavailable"));
                    coordinator->cancel();
                }
            }
            if (coordinator) coordinator->tick();
            // Retry starts only after exact release acknowledgement and fresh fetch.
            if (reconnectWanted && coordinator && coordinator->status().state == ac::State::Failed && !inFlight) {
                const auto loaded=store->load();
                if (loaded.ok && loaded.records.isEmpty()) { reconnectWanted=false; terminal=false; resetHttpsSockets("reconnect"); coordinator->begin(); }
            }
            // Scheduled connect retry after a network failure: same release barrier as above.
            if (connectRetryAt && now()>=connectRetryAt && coordinator && !cancelled &&
                coordinator->status().state == ac::State::Failed && !inFlight) {
                const auto loaded=store->load();
                if (loaded.ok && loaded.records.isEmpty()) {
                    connectRetryAt=0; terminal=false;
                    logNet(QStringLiteral("event=connect_retry_start retry=%1 local_retry=%2").arg(connectRetries).arg(localStartRetries));
                    resetHttpsSockets("connect_retry",true); // the gateway did not answer: never wait on the same connection
                    const bool healing=healWintunFirst([weak=weak_from_this()] {
                        auto self=weak.lock();
                        if (self && self->coordinator && self->coordinator->status().state==ac::State::Failed) self->coordinator->begin();
                    });
                    if (!healing) coordinator->begin();
                } else if (now()>=connectRetryAt+10000) {
                    // An unreleased attempt blocks a fresh cycle: never spin in "retrying" forever.
                    connectRetryAt=0; terminal=true; phase=QStringLiteral("failed");
                    logNet(QStringLiteral("event=connect_retry_blocked"));
                    output(Vpn::ConnectionState::Error,errorText(ac::ErrorCategory::Network));
                }
            }
            // Local adapter failure with an unconfirmed stop: confirm and release now, then restart.
            if (localRestartAt && now()>=localRestartAt && cleanupPending && !cleanupOperation && !cancelled) {
                localRestartAt=0;
                logNet(QStringLiteral("event=local_start_cleanup retry=%1").arg(localStartRetries));
                retryCleanup();
            }
            for (auto& [tag,a]:attempts) {
                if (a->proofDone) advanceProof(tag,a);
            }
            monitor();
        });
        connect(bridge.get(),&B::health,this,[this](B::Ticket ticket,AwgTunnelHealth h) {
            for(auto& [tag,a]:attempts) {
                if (!a->ticket.same(ticket) || !a->expected.matches(h) || !h.valid || a->cancelled) continue;
                if (a->health.valid && h.generation!=a->health.generation && now()<a->replacementAllowedUntil) {
                    // Exactly one owner-requested soft recovery: new backend, same proof context.
                    a->replacementAllowedUntil=0; a->rxChangedAt=now();
                    rec.forceProbeAt=now()+300; // the new interface identity is now known
                } else if (a->health.valid && (h.generation!=a->health.generation || h.rxTotal<a->health.rxTotal || h.txTotal<a->health.txTotal)) a->reset=true;
                else if (!a->health.valid || h.rxTotal>a->health.rxTotal) a->rxChangedAt=now();
                a->health=h; a->healthAt=now();
            }
        });
        connect(bridge.get(),&B::networkChanged,this,[this](B::Ticket ticket,bool available) { onNetwork(ticket,available); });
        connect(bridge.get(),&B::resumed,this,[this](B::Ticket ticket,bool replaced,bool available) { onResume(ticket,replaced,available); });
        connect(bridge.get(),&B::visibilityChanged,this,[this](bool visible) { onVisibility(visible); });
        // The service watchdog could not repair the current exit while the UI was hidden:
        // reconnect now, another exit first.
        connect(bridge.get(),&B::failoverRequested,this,[this](B::Ticket ticket) {
            auto a=connectedAttempt();
            if (!a || !a->ticket.same(ticket) || a->cancelled || cancelled || !coordinator) return;
            const auto s=coordinator->status();
            if (s.state!=ac::State::Connected) return;
            // N2: a hidden failover first takes the (dead) tunnel down. With no other exit known
            // that only trades "no traffic" for "traffic outside the VPN": keep the tunnel.
            if (avoidedExitStorage().knownExits<2) { logNet(QStringLiteral("event=failover_skip reason=single_exit")); return; }
            logNet(QStringLiteral("event=failover_start source=service"));
            reconnectWanted=true;
            avoidCandidate(a->identity.candidateId);
            coordinator->onOwnRepairExhausted(s.cycle);
        });
        // Stopped outside the app (notification/tile "Disconnect", VPN revoked): honour it as the
        // user's own disconnect -- never as a fault to recover or reconnect.
        connect(bridge.get(),&B::userStopped,this,[this](B::Ticket ticket) {
            if (cancelled) return;
            for (const auto& [tag,a]:attempts) {
                if (!a->ticket.same(ticket) || a->cancelled) continue;
                logNet(QStringLiteral("event=user_stop"));
                stopUser(); return;
            }
        });
        connect(bridge.get(),&B::error,this,[this](const B::Result& r) {
            if (!coordinator) return;
            if (r.detail==QStringLiteral("permissionDenied")) { cancelled=true; coordinator->cancel(); }
        });
        connect(bridge.get(),&B::backendDown,this,[this](const B::Result& r) {
            for(auto& [tag,a]:attempts) noteNativeDown(a,r);
        });
    }
    ac::Millis now() const override { return B::monotonicMillis(); }
    QString phase = QStringLiteral("preparing");
    void output(Vpn::ConnectionState state,QString text, QVariantMap exitLocation = {}) {
        if (facade) facade->publish(state,text,phase,exitLocation,routeFor(state));
    }
    // The exit (as the acquire answered it) and the method of the current path. Only while a path
    // is being started/verified or is connected; before an exit is admitted nothing is known.
    QVariantMap routeFor(Vpn::ConnectionState state) {
        if (state!=Vpn::ConnectionState::Connecting && state!=Vpn::ConnectionState::Connected) return {};
        const auto a=get(routeCycle,routeAttempt);
        if (!a || routePathId.empty()) return {};
        const QString path=QString::fromStdString(routePathId);
        QVariantMap route{{QStringLiteral("cityId"),a->exitLocationCityId},
            {QStringLiteral("method"),path.startsWith(QStringLiteral("xray")) ? QStringLiteral("Xray") : QStringLiteral("AmneziaWG")}};
        if (a->exitLocationHasCard) route.insert(QStringLiteral("city"),a->exitLocationCard.city);
        return route;
    }
    bool identityCurrent() const {
        if (!facade || !servers || !app || !connection || cancelled || app->mayakSessionToken().isEmpty()) return false;
        const auto cfg=servers->apiV2Config(serverId);
        return facade->manages(serverId) && cfg && cfg->authData.toJson()==common.value("auth_data").toObject() &&
            cfg->serviceType()==common.value("service_type").toString() &&
            cfg->apiConfig.serviceProtocol==common.value("service_protocol").toString() &&
            cfg->apiConfig.userCountryCode==common.value("user_country_code").toString();
    }
    void failure(QString text) { ++preflightGeneration; preparing=false; terminal=true; phase=QStringLiteral("failed"); output(Vpn::ConnectionState::Error,std::move(text)); }
    // Note 8: an early refusal after adoption began still stops the adopted backend first
    // (recovery ticket + reconcile), exactly like every other adoption give-up.
    void failureAfterAdoption(QString text) {
        if (!adoption.pending) { failure(std::move(text)); return; }
        preparing=false; terminal=false; // busy until the give-up settles
        auto self=shared_from_this();
        abandonAdoption([self,text](bool) { self->failure(text); });
    }
    // Windows refused Mayak's tunnel adapter on an earlier start (local_start_failed) and no tunnel of
    // this app runs now: the service repairs the WinTun state once (one temporary adapter, as any
    // other WinTun app does; 20.11.2026 that cured the refusal without a reboot), then `next` runs
    // whatever the result. False: nothing to repair, the caller goes on itself.
    bool healWintunFirst(std::function<void()> next) {
        auto& retries=localStartRetriesStorage();
        if (!retries.heal || adoption.pending || healedThisSession) return false;
        retries.heal=false; healPending=true; healedThisSession=true;
        if (settings) settings->remove(kWintunHealWantedKey);
        output(Vpn::ConnectionState::Preparing,QStringLiteral("Восстанавливаем VPN-адаптер Windows…"));
        auto done=[weak=weak_from_this(),next](bool replied,QString result) {
            auto self=weak.lock();
            if (!self || !self->healPending) return;
            self->healPending=false;
            self->logNet(QStringLiteral("event=wintun_heal replied=%1 result=%2").arg(replied ? 1 : 0).arg(result));
            // A tunnel of Mayak still ran in the service: the repair did not happen, keep it wanted.
            if (replied && result==QLatin1String("busy")) self->markWintunHealWanted();
            if (self->cancelled) return;
            next();
        };
        if (auto& hook=wintunHealStorage()) hook(this,done);
        else mayak::foreignvpn::requestHealWintun(this,done,15000);
        return true;
    }
    void markWintunHealWanted() {
        localStartRetriesStorage().heal=true;
        if (settings) settings->setValue(kWintunHealWantedKey,true);
    }
    void beginCoordinatorAfterPreflight() {
        if (cancelled || !identityCurrent()) {
            if (adoption.pending && !cancelled) { failureAfterAdoption(QStringLiteral("Сеанс Маяка изменился. Войдите снова и повторите попытку.")); return; }
            preparing=false; terminal=true;
            phase=cancelled ? QStringLiteral("cancelled") : QStringLiteral("idle");
            output(Vpn::ConnectionState::Disconnected,{}); return;
        }
        if (healWintunFirst([weak=weak_from_this()] {
                auto self=weak.lock();
                if (self && !self->terminal && !self->coordinator) self->beginCoordinatorAfterPreflight();
            })) { preparing=true; return; }
        if (!splitPrepared && needsSplitPrepare()) {
            // Windows app exclusions need the split tunnel driver; the service prepares it first, with its
            // own time budget (it may release AmneziaVPN's copy), never inside the tunnel start deadline.
            splitPrepared=true; preparing=true;
            output(Vpn::ConnectionState::Preparing,QStringLiteral("Готовим исключения программ…"));
            auto done=[weak=weak_from_this()](bool replied,QString result) {
                auto self=weak.lock();
                if (!self || self->cancelled || self->terminal || self->coordinator) return;
                self->logNet(QStringLiteral("event=split_prepare replied=%1 result=%2").arg(replied ? 1 : 0).arg(result));
                if (replied && result==QLatin1String("ok")) { self->beginCoordinatorAfterPreflight(); return; }
                self->failureAfterAdoption(splitPrepareText(replied ? result : QStringLiteral("unavailable")));
            };
            if (auto& hook=splitPrepareStorage()) hook(this,done);
            else mayak::foreignvpn::requestPrepareSplitTunnel(this,done,25000);
            return;
        }
        coordinator=std::make_unique<ac::Coordinator>(*this,*this,[weak=weak_from_this()](const ac::Status& s) {
            if(auto self=weak.lock()) self->state(s);
        });
        preparing=false;
        coordinator->begin();
    }
    // Windows app exclusions ("all apps except these") are active for this connect.
    bool needsSplitPrepare() const {
#ifdef Q_OS_WINDOWS
        const bool windows=true;
#else
        const bool windows=bool(splitPrepareStorage());
#endif
        // An adopted running tunnel already has its exclusions; never release drivers under it.
        if (!windows || adoption.pending || !app || !app->isAppsSplitTunnelingEnabled()) return false;
        const auto mode=app->appsRouteMode();
        return mode!=amnezia::AppsRouteMode::VpnAllApps && !app->vpnApps(mode).isEmpty();
    }
    void preparePermissionsAndBeginCoordinator() {
        if (cancelled || terminal || !preparing || now()>=preflightDeadline || permissionPending || coordinator) return;
        if (!identityCurrent()) { failureAfterAdoption(QStringLiteral("Сеанс Маяка изменился. Войдите снова и повторите попытку.")); return; }
        permissionPending=true;
        permissionRequestId=randomId();
        const QString requestId=permissionRequestId;
        output(Vpn::ConnectionState::Preparing,QStringLiteral("Подтвердите разрешение VPN…"));
        bridge->preparePermissions(requestId,[weak=weak_from_this(),requestId](QString returnedId,B::PermissionResult result) {
            auto self=weak.lock();
            if (!self || self->cancelled || !self->permissionPending || returnedId!=requestId || self->permissionRequestId!=requestId) return;
            self->permissionPending=false;
            self->permissionRequestId.clear();
            if (result==B::PermissionResult::Denied) {
                self->failureAfterAdoption(QStringLiteral("Разрешение VPN не выдано. Нажмите «Включить Маяк» и разрешите подключение.")); return;
            }
            if (result!=B::PermissionResult::Ready) {
                self->failureAfterAdoption(QStringLiteral("Не удалось подготовить разрешение VPN. Повторите попытку.")); return;
            }
            self->beginCoordinatorAfterPreflight();
        });
    }
    // See shutdownOwnHttpsSockets(): drop gateway connections that may be tied to a stopped tunnel.
    // Only after a tunnel ran since the last reset, unless forced (the gateway did not answer).
    void resetHttpsSockets(const char* reason,bool force=false) {
        if (!force && !httpsSocketsMayBeStale()) return;
        httpsSocketsMayBeStale()=false;
        const auto& hook=httpsSocketResetStorage();
        const int closed=hook ? hook() : 0;
        if (closed!=0) logNet(QStringLiteral("event=https_sockets_reset reason=%1 closed=%2").arg(QLatin1String(reason)).arg(closed));
    }
    void initialize() {
        auto self=shared_from_this();
        resetHttpsSockets("connect");
        output(Vpn::ConnectionState::Preparing,QStringLiteral("Проверяем доступ…"));
        if (!facade || !servers || !app || app->mayakSessionToken().isEmpty()) { failure(QStringLiteral("Войдите в личный кабинет Маяка.")); return; }
        const auto cfg=servers->apiV2Config(serverId);
        if (!cfg || subscription->getOrCreateMayakAwgProtocolData(serverId,&keys)!=ErrorCode::NoError) {
            failure(QStringLiteral("Не удалось сохранить доступ. Повторите настройку в личном кабинете.")); return;
        }
        endpoint=QStringLiteral("https://mayaklight.ru/gw/");
        common=GatewayPayloadBuilder(app).addField(apiDefs::key::authData,cfg->authData.toJson())
            .addField(apiDefs::key::serviceType,cfg->serviceType()).addField(apiDefs::key::serviceProtocol,QStringLiteral("awg"))
            .addField(apiDefs::key::userCountryCode,cfg->apiConfig.userCountryCode)
            .addField(apiDefs::key::publicKey,keys.wireGuardClientPubKey).build();
        authority={endpoint,common.value("installation_uuid").toString(),keys.wireGuardClientPubKey,
            cfg->authData.toJson().value("api_key").toString(),cfg->serviceType(),QStringLiteral("awg"),cfg->apiConfig.userCountryCode,{}};
        method=app->mayakConnectionMethod();
        networkParts=localNetworkParts(); networkKey=localNetworkKey(settings,networkParts);
        if (recoveryTimingStorage().noHealthMeansLocalFailure && settings) {
            auto& retries=localStartRetriesStorage();
            if (settings->value(kWintunHealWantedKey).toBool()) retries.heal=true;
            const QString version=QStringLiteral(APP_VERSION);
            if (settings->value(kWintunHealVersionKey).toString()!=version) {
                settings->setValue(kWintunHealVersionKey,version);
                markWintunHealWanted(); // kept on disk: a first session ended early still repairs later
                logNet(QStringLiteral("event=wintun_heal_planned reason=new_version"));
            }
        }
        remembered=rememberedExit(settings,networkKey);
        offlineOwnerKey=offlineOwner(serverId,keys.wireGuardClientPubKey,authority.deviceApiKey);
        manualExit=app->mayakManualExit(); manualCity=app->mayakManualExitCity();
        logNet(QStringLiteral("event=connection_method method=%1 xray_first=%2 remembered_exit=%3 offline_memory=%4 manual_exit=%5").arg(method)
            .arg(rememberedXrayFirst(settings,networkKey) ? 1 : 0).arg(remembered.valid() ? 1 : 0).arg(offlineUsable() ? 1 : 0)
            .arg(manualExit.isEmpty() ? 0 : 1));
        preflightDeadline=now()+10000;
        inspectPreflight();
        timer.start();
    }
    // A confirmed OFF of an adopted backend through its recovery authority also discharges the
    // cold-start "foreign backend" barrier: that backend was the only one inspection found.
    bool noteNativeDown(const std::shared_ptr<Attempt>& a,const B::Result& r) {
        const bool down=a->acceptNativeDown(r);
        if (down && a->stopTicket.valid() && a->stopTicket.same(r.ticket)) preflightNativeOff=true;
        return down;
    }
    bool nativeDown() const {
        if (!preflightNativeOff) return false;
        for (const auto& [tag,a]:attempts) if (a->started && !a->stopped) return false;
        return true;
    }
    QString cleanupText() const {
        return nativeDown()
            ? QStringLiteral("Туннель остановлен; очистка доступа на сервере ожидает повтора.")
            : QStringLiteral("Не удалось подтвердить отключение. Нажмите «Повторить отключение».");
    }
    bool finishCleanup() {
        const auto loaded=store->load();
        if (!loaded.ok || !loaded.records.isEmpty() || !nativeDown()) return false;
        abandonHeldDisconnect=false;
        cleanupPending=false; cleanupOperation=false; cancelled=true;
        preparing=false; terminal=true; reconnectWanted=false; timer.stop();
        if (restartAfterCleanup && facade) {
            // The local adapter attempt is fully stopped and released: start a fresh session
            // (preflight + reconcile + new cycle) that keeps the bounded retry count.
            restartAfterCleanup=false;
            phase=QStringLiteral("preparing");
            localStartRetriesStorage().count=localStartRetries;
            logNet(QStringLiteral("event=local_start_restart retry=%1").arg(localStartRetries));
            QTimer::singleShot(0,facade.data(),[f=facade,id=serverId] {
                if (!f) return;
                localStartRetriesStorage().autoRestart=true;
                f->begin(id);
                localStartRetriesStorage().autoRestart=false;
            });
            return true;
        }
        phase=QStringLiteral("cancelled"); output(Vpn::ConnectionState::Disconnected,{});
        scheduleDeferredSweep();
        return true;
    }
    void inspectPreflight() {
        auto self=shared_from_this();
        const auto deadline=cleanupOperation ? qMin(now()+3000,cleanupDeadline) : now()+3000;
        bridge->inspectOwnBackend(deadline,[self](B::Inspection i) {
            if (i.state==B::OwnState::Off) {
                self->preflightNativeOff=true;
                if (self->cancelled) {
                    self->cleanupOperation=false;
                    if (!self->finishCleanup()) {
                        self->cleanupPending=true;
                        self->phase=QStringLiteral("failed");
                        self->output(Vpn::ConnectionState::Error,self->cleanupText());
                    }
                } else if (!self->terminal) self->reconcileNext();
            } else if (i.state==B::OwnState::Active && i.recoveryTicket.valid()) {
                if (!self->cancelled && !self->cleanupOperation && self->tryBeginAdoption(i)) return;
                const auto ticket=i.recoveryTicket;
                self->bridge->cancel(ticket);
                self->bridge->stopAndConfirm(ticket,self->cleanupOperation ? qMin(self->now()+3000,self->cleanupDeadline) : self->now()+3000,[self,ticket](B::Result r) {
                    self->cleanupOperation=false;
                    if (r.outcome==B::Outcome::ConfirmedDown && ticket.same(r.ticket)) {
                        self->preflightNativeOff=true;
                        // A running tunnel found at preflight is down now: drop connections made through it.
                        httpsSocketsMayBeStale()=true; self->resetHttpsSockets("preflight_stop");
                        if (self->cancelled) {
                            if (!self->finishCleanup()) self->cleanupPending=true;
                        } else if (!self->terminal) self->reconcileNext();
                    } else {
                        if (self->cancelled) self->cleanupPending=true;
                        self->failure(errorText(ac::ErrorCategory::StopUnconfirmed));
                    }
                });
            } else {
                self->cleanupOperation=false;
                if (self->cancelled) self->cleanupPending=true;
#ifdef Q_OS_ANDROID
                self->failure(QStringLiteral("Служба VPN Android не ответила. Закройте и снова откройте Маяк. Если ошибка повторится, проверьте обновления."));
#else
                self->failure(QStringLiteral("Служба VPN не отвечает. Перезапустите приложение; на Windows проверьте установку Маяка."));
#endif
            }
        });
    }
    // Cold start found our running backend. Adopt it when the ledger holds exactly the attempt
    // that may own it (started, with an allocation, same device credential and gateway).
    // Server-side truth is re-checked by the idempotent acquire; the tunnel by the normal proof.
    bool tryBeginAdoption(const B::Inspection& i) {
        if (!bridge->canAdopt() || i.ownControlIdentity.isEmpty() || terminal || !preparing || now()>=preflightDeadline) return false;
        const auto loaded=store->load();
        if (!loaded.ok || loaded.records.size()!=1) return false;
        const auto& r=loaded.records.first();
        if (!r.mayHaveStarted() || r.tombstoned() || r.allocationId().isEmpty() || r.identity().attemptId.isEmpty() ||
            r.identity().localSubscriptionId!=serverId || r.deviceApiKey()!=authority.deviceApiKey ||
            r.gatewayEndpoint()!=authority.gatewayEndpoint) return false;
        adoption={true,r.identity(),r.allocationId(),i.recoveryTicket,i.ownControlIdentity};
        logNet(QStringLiteral("event=adopt_candidate"));
        output(Vpn::ConnectionState::Preparing,QStringLiteral("Проверяем подключение…"));
        preparePermissionsAndBeginCoordinator();
        return true;
    }
    // Give up adoption: stop the running backend with the recovery ticket, release every server
    // allocation of the persisted attempt (reconcile) and drop its ledger record. then(true) only
    // when all three are confirmed; otherwise the old cleanup/error paths remain responsible.
    void abandonAdoption(std::function<void(bool)> callerThen) {
        if (!adoption.pending) { if (callerThen) callerThen(true); return; }
        adoption.pending=false;
        const auto recovery=adoption.recovery; const auto identity=adoption.identity;
        auto self=shared_from_this();
        // Busy for the whole give-up (stop + reconcile); a cancel meanwhile is finished here.
        abandoning=true; ++inFlight;
        std::weak_ptr<Session> owner=self;
        const std::function<void(bool)> then=[owner,callerThen](bool ok) {
            auto self=owner.lock(); if (!self) return;
            --self->inFlight; self->abandoning=false;
            if (callerThen) callerThen(ok);
            if (!self->abandonHeldDisconnect) return;
            self->abandonHeldDisconnect=false;
            if (!self->finishCleanup()) {
                self->cleanupPending=true; self->terminal=true; self->phase=QStringLiteral("failed");
                self->output(Vpn::ConnectionState::Error,self->cleanupText());
            }
        };
        bridge->stopAndConfirm(recovery,now()+3000,[self,recovery,identity,then](B::Result r) {
            if (r.outcome!=B::Outcome::ConfirmedDown || !recovery.same(r.ticket)) {
                self->logNet(QStringLiteral("event=adopt_abandon_stop_unconfirmed"));
                self->abandonUnconfirmed=true; if (then) then(false); return;
            }
            self->preflightNativeOff=true;
            // The abandoned adopted tunnel is down: drop connections made through it before reconcile.
            httpsSocketsMayBeStale()=true; self->resetHttpsSockets("adopt_abandon");
            const auto loaded=self->store->load();
            if (!loaded.ok) { if (then) then(false); return; }
            const auto it=std::find_if(loaded.records.begin(),loaded.records.end(),[&](const at::AttemptRecord& x){ return x.identity()==identity; });
            if (it==loaded.records.end()) { if (then) then(true); return; }
            ad::Request req; req.action="reconcile"; req.attemptId=identity.attemptId; req.cycleToken=identity.cycleToken;
            req.commonPayload=payloadFor(*it); req.deadlineUtcMs=utcDeadline(self->now()+2500);
            ++self->inFlight;
            auto settled=std::make_shared<bool>(false);
            std::weak_ptr<Session> weak=self;
            auto settle=[weak,settled,identity,then](bool ok) {
                auto self=weak.lock(); if (!self || *settled) return;
                *settled=true; --self->inFlight;
                const bool removed=ok && self->store->removeAfterConfirmedCleanup(identity).ok;
                self->logNet(QStringLiteral("event=adopt_abandoned released=%1").arg(removed ? 1 : 0));
                if (then) then(removed);
            };
            QTimer::singleShot(2500,self.get(),[settle] { settle(false); });
            ad::MayakAdmissionClient::postAsync(req,self->transport,[settle](ad::Response response) {
                settle(response.success && response.authenticatedResponse);
            });
        });
    }
    void reconcileNext() {
        if (cancelled || terminal || !preparing) return;
        if (now()>=preflightDeadline) { failure(QStringLiteral("Завершаем прежнее подключение. Повторите попытку.")); return; }
        auto self=shared_from_this();
        const auto loaded=store->load();
        if (!loaded.ok) { failure(QStringLiteral("Хранилище доступа недоступно. Подключение остановлено.")); return; }
        if (!loaded.records.isEmpty()) {
            if (now()>=preflightDeadline) { failure(QStringLiteral("Завершаем прежнее подключение. Повторите попытку.")); return; }
            const auto r=loaded.records.first();
            ad::Request req; req.action="reconcile"; req.attemptId=r.identity().attemptId; req.cycleToken=r.identity().cycleToken;
            req.commonPayload=payloadFor(r); req.deadlineUtcMs=utcDeadline(preflightDeadline);
            ++inFlight;
            auto settled=std::make_shared<bool>(false);
            auto lateHandled=std::make_shared<bool>(false);
            auto timedOutSeen=std::make_shared<bool>(false);
            std::weak_ptr<Session> weak=self;
            const auto generation=preflightGeneration, cleanupOwner=cleanupGeneration;
            auto settle=[weak,r,generation,cleanupOwner,settled,lateHandled,timedOutSeen](ad::Response response, bool timedOut) {
                auto self=weak.lock(); if (!self) return;
                if (*settled && !(timedOut == false && *timedOutSeen && response.success && response.authenticatedResponse && !*lateHandled)) return;
                const bool first=!(*settled); *settled=true;
                if (timedOut) *timedOutSeen=true;
                if (!first) *lateHandled=true;
                if (first) --self->inFlight;
                // Settlement belongs to this old operation even after cancel;
                // presentation belongs only to the still-current ON intent.
                const auto currentPreflight=[&] {
                    return first && generation==self->preflightGeneration
                        && cleanupOwner==self->cleanupGeneration && self->preparing && !self->terminal
                        && !self->cancelled && !self->cleanupPending && !self->cleanupOperation;
                };
                // The gateway gives no answer at all: with the stored exits the old place is reconciled
                // later (deferred cleanup) and this connect goes on, possibly without the gateway.
                if ((timedOut || !response.authenticatedResponse) && currentPreflight() &&
                    self->deferCleanup(r.identity(),"preflight_no_answer")) {
                    self->reconcileNext(); return;
                }
                if (timedOut) {
                    if (currentPreflight()) self->failure(QStringLiteral("Не удалось завершить прежний сеанс. Проверьте интернет и повторите попытку."));
                    return;
                }
                if (!response.success || !response.authenticatedResponse) {
                    if (currentPreflight()) self->failure(QStringLiteral("Не удалось завершить прежний сеанс. Проверьте интернет и повторите попытку."));
                    return;
                }
                if (!self->store->removeAfterConfirmedCleanup(r.identity()).ok) {
                    if (currentPreflight()) self->failure(QStringLiteral("Не удалось сохранить завершение прежнего сеанса. Повторите попытку."));
                    return;
                }
                // Authenticated late cleanup may discharge only its exact old
                // obligation. It cannot revive a failed/cancelled ON intent.
                if (self->cancelled && !self->cleanupOperation) self->finishCleanup();
                else if (currentPreflight() && self->now()<self->preflightDeadline) self->reconcileNext();
            };
            QTimer::singleShot(2500,this,[settle] { settle({},true); });
            ad::MayakAdmissionClient::postAsync(req,transport,[settle](ad::Response response) { settle(response,false); }); return;
        }
        preparePermissionsAndBeginCoordinator();
    }
    void state(const ac::Status& s) {
        // Copy the typed coordinator state on its owning thread. Consumers see
        // only this immutable value, never the coordinator or its session.
        routeCycle=s.cycle; routeAttempt=s.attempt; routePathId=s.pathId;
        const auto previousState=observedState; observedState=s.state;
        switch(s.state) {
        case ac::State::Idle: phase=QStringLiteral("idle"); break;
        case ac::State::Fetching: phase=QStringLiteral("fetching"); break;
        case ac::State::Admitting: phase=QStringLiteral("admitting"); break;
        case ac::State::Racing: phase=QStringLiteral("starting"); break;
        case ac::State::Starting: phase=QStringLiteral("starting"); break;
        case ac::State::Verifying: phase=QStringLiteral("verifying"); break;
        case ac::State::Connected: phase=QStringLiteral("connected"); break;
        case ac::State::Stopping: phase=s.switchingPath ? QStringLiteral("starting") : QStringLiteral("stopping"); break;
        case ac::State::Failed: phase=QStringLiteral("failed"); break;
        case ac::State::Cancelled: phase=QStringLiteral("cancelled"); break;
        }
        switch(s.state) {
        case ac::State::Fetching: case ac::State::Admitting:
            terminal=false;
            output(Vpn::ConnectionState::Preparing, adoption.pending ? QStringLiteral("Проверяем подключение…")
                                                                     : QStringLiteral("Выбираем доступный сервер…"));
            break;
        case ac::State::Racing:
            logNet(QStringLiteral("event=race_begin"));
            output(Vpn::ConnectionState::Connecting,QStringLiteral("Подбираем способ подключения…")); break;
        case ac::State::Starting:
            logNet(QStringLiteral("event=path_start path=%1").arg(QString::fromStdString(s.pathId)));
            output(Vpn::ConnectionState::Connecting,offlineCycle ? QStringLiteral("Подключаемся без сервера Маяка…")
                                                                 : QStringLiteral("Проверяем VPN-соединение…")); break;
        case ac::State::Verifying:
            output(Vpn::ConnectionState::Connecting,offlineCycle ? QStringLiteral("Подключаемся без сервера Маяка…")
                                                                 : QStringLiteral("Проверяем VPN-соединение…")); break;
        case ac::State::Connected:
            lastMonitor=now(); {
                QVariantMap location;
                const auto selected = get(s.cycle, s.attempt);
                if (selected && !selected->cancelled) {
                    location.insert(QStringLiteral("candidateId"), selected->identity.candidateId);
                    location.insert(QStringLiteral("cityId"), selected->exitLocationCityId);
                    location.insert(QStringLiteral("pathId"), QString::fromStdString(s.pathId));
                    // Admin city card (schema 2). The photo address is built against the gateway this
                    // acquire went to; the UI loads it only in «Подключено» (after the tunnel probe).
                    if (selected->exitLocationHasCard) {
                        const auto& card=selected->exitLocationCard;
                        location.insert(QStringLiteral("card"), QVariantMap{
                            {QStringLiteral("city"), card.city}, {QStringLiteral("country"), card.country},
                            {QStringLiteral("countryCode"), card.countryCode}, {QStringLiteral("fact"), card.fact},
                            {QStringLiteral("photoUrl"), card.photo.isEmpty() ? QString() : endpoint + card.photo},
                            {QStringLiteral("version"), card.version}});
                    }
                    if (avoidedExitStorage().candidateId.compare(selected->identity.candidateId,Qt::CaseInsensitive)==0)
                        avoidedExitStorage()={{},0,avoidedExitStorage().knownExits};
                    selected->rxChangedAt=now();
                    if (!selected->adopted) offlineMarkExit(selected->identity.candidateId,true);
                    if (selected->offline) logNet(QStringLiteral("event=offline_connected"));
                    // Path memory (auto mode only): Xray proved here after AWG did not -> Xray first
                    // for a while on this network; AWG proved -> back to the default order.
                    if (method==QStringLiteral("auto") && !selected->adopted) {
                        const bool viaXray=selected->path.kind==ac::PathKind::Xray;
                        if (!viaXray) rememberPath(settings,networkKey,false);
                        else if (selected->awgFailedHere || rememberedXrayFirst(settings,networkKey)) rememberPath(settings,networkKey,true);
                    }
                    // Exit memory: this exit proved here; the next connects on this network start with it.
                    // Its Xray path is kept only like the path memory above (auto mode, after AWG did not
                    // prove; 12 h). Not saved when the local network changed since the session started
                    // (the key would name the old network).
                    if (!selected->adopted && !s.pathId.empty()) {
                        const bool keepPath=method==QStringLiteral("auto") && selected->path.kind==ac::PathKind::Xray &&
                            rememberedXrayFirst(settings,networkKey);
                        const RememberedExit fresh{selected->identity.candidateId,keepPath ? QString::fromStdString(s.pathId) : QString()};
                        if (!sameLocalNetwork(networkParts,localNetworkParts(),selected->health.localAddress)) {
                            logNet(QStringLiteral("event=exit_memory_skipped reason=network_changed"));
                        } else {
                            if (!remembered.is(fresh.exit) || remembered.path!=fresh.path) logNet(QStringLiteral("event=exit_memory_saved path=%1").arg(keepPath ? 1 : 0));
                            remembered=fresh;
                            rememberExit(settings,networkKey,remembered.exit,remembered.path);
                        }
                    }
                }
                logNet(QStringLiteral("event=connected path=%1").arg(QString::fromStdString(s.pathId)));
                const bool networkLost=rec.networkLost;
                rec={}; rec.networkLost=networkLost; rec.networkLostAt=networkLost ? now() : 0;
                connectRetries=0; connectRetryAt=0; abandonUnconfirmed=false;
                localStartFailed=false; localStartRetries=0; localStartRetriesStorage().count=0; localStartRetriesStorage().heal=false;
                if (settings) settings->remove(kWintunHealWantedKey);
                connectedLocation=location;
                output(Vpn::ConnectionState::Connected,QStringLiteral("Подключено"),location);
                // The gateway revoked this device while the stored exit was starting: end it now.
                if (lateTerminal!=ac::ErrorCategory::None) endOfflineSession(lateTerminal);
            } break;
        case ac::State::Stopping:
            // A path of the remembered exit did not come up (not the user's cancel): forget it (a later
            // path of the same exit that proves saves it again).
            if ((previousState==ac::State::Starting || previousState==ac::State::Verifying) &&
                s.error!=ac::ErrorCategory::None && s.error!=ac::ErrorCategory::Cancelled && !cancelled &&
                !adoptRefused && remembered.is(QString::fromStdString(s.candidateId)))
                forgetRemembered("path_failed");
            // A stored exit that did not come up goes back in the memory (never wiped by failures).
            if ((previousState==ac::State::Starting || previousState==ac::State::Verifying) &&
                s.error!=ac::ErrorCategory::None && s.error!=ac::ErrorCategory::Cancelled && !cancelled) {
                const auto failed=get(s.cycle,s.attempt);
                if (failed && failed->offline && !failed->offlineFailCounted) {
                    failed->offlineFailCounted=true; offlineMarkExit(failed->identity.candidateId,false);
                }
            }
            adoptRefused=false;
            if (s.switchingPath) {
                logNet(QStringLiteral("event=path_failed path=%1 error=%2").arg(QString::fromStdString(s.pathId)).arg(int(s.error)));
                output(Vpn::ConnectionState::Connecting,QStringLiteral("Пробуем другой способ подключения…"));
            } else output(Vpn::ConnectionState::Disconnecting,QStringLiteral("Завершаем подключение…"));
            break;
        case ac::State::Failed:
            terminal=true;
            if (lateTerminal!=ac::ErrorCategory::None && !cancelled && s.error!=ac::ErrorCategory::StopUnconfirmed) {
                // The gateway revoked this device during a session from the stored exits.
                const auto e=lateTerminal; lateTerminal=ac::ErrorCategory::None;
                reconnectWanted=false; connectRetryAt=0;
                output(Vpn::ConnectionState::Error,errorText(e));
            } else if (!fetchRefusalText.isEmpty() && !cancelled && s.error!=ac::ErrorCategory::StopUnconfirmed) {
                const QString text=fetchRefusalText; fetchRefusalText.clear();
                reconnectWanted=false; connectRetryAt=0;
                output(Vpn::ConnectionState::Error,text);
            } else if (appExclusionBlocked && !cancelled) {
                // Stop of the failed attempt was not confirmed: keep the exact cleanup and its retry hint.
                if (s.error==ac::ErrorCategory::StopUnconfirmed) { cleanupPending=true; output(Vpn::ConnectionState::Error,cleanupText()); }
                else output(Vpn::ConnectionState::Error,QString::fromUtf8(kAppExclusionUnavailable));
            } else if (s.error==ac::ErrorCategory::StopUnconfirmed && localStartFailed && !cancelled && !reconnectWanted &&
                localStartRetries<recoveryTimingStorage().localStartRetryMs.size()) {
                // Windows is still failing the adapter (~16 s) so the 3 s stop could not be confirmed.
                // Not a user-facing cleanup error: confirm the stop after a pause, then restart.
                localStartFailed=false; cleanupPending=true; restartAfterCleanup=true; terminal=false;
                const qint64 delay=recoveryTimingStorage().localStartRetryMs.at(localStartRetries++);
                localRestartAt=now()+delay;
                phase=QStringLiteral("preparing");
                output(Vpn::ConnectionState::Preparing,
                       QStringLiteral("VPN-адаптер Windows не запустился — повторим через %1 с. Если не поможет, перезагрузите компьютер.").arg((delay+999)/1000));
                logNet(QStringLiteral("event=local_start_retry_scheduled retry=%1 delay_ms=%2 stop=unconfirmed").arg(localStartRetries).arg(delay));
            } else if (s.error==ac::ErrorCategory::StopUnconfirmed) {
                cleanupPending=true;
                if (localStartFailed && !cancelled) {
                    localStartFailed=false;
                    logNet(QStringLiteral("event=local_start_retry_exhausted stop=unconfirmed"));
                }
                output(Vpn::ConnectionState::Error,cleanupText());
            } else if (abandonUnconfirmed && !cancelled) {
                // Note 7: the adopted backend's stop was not confirmed. Not a network problem and
                // no automatic retry: a new connect re-inspects and stops it first.
                abandonUnconfirmed=false;
                output(Vpn::ConnectionState::Error,QStringLiteral("Не удалось завершить прежнее подключение. Нажмите «Включить Маяк» ещё раз."));
            } else if (localStartFailed && !cancelled && !reconnectWanted &&
                       (s.error==ac::ErrorCategory::Network || s.error==ac::ErrorCategory::Deadline ||
                        s.error==ac::ErrorCategory::ProofFailed)) {
                // The local tunnel adapter never came up (Windows refused to create it): no exit
                // is at fault and an immediate retry fails the same way. Wait, then a fresh cycle.
                localStartFailed=false;
                if (localStartRetries<recoveryTimingStorage().localStartRetryMs.size()) {
                    const qint64 delay=recoveryTimingStorage().localStartRetryMs.at(localStartRetries++);
                    connectRetryAt=now()+delay; terminal=false;
                    phase=QStringLiteral("preparing");
                    output(Vpn::ConnectionState::Preparing,
                           QStringLiteral("VPN-адаптер Windows не запустился — повторим через %1 с. Если не поможет, перезагрузите компьютер.").arg((delay+999)/1000));
                    logNet(QStringLiteral("event=local_start_retry_scheduled retry=%1 delay_ms=%2").arg(localStartRetries).arg(delay));
                } else {
                    logNet(QStringLiteral("event=local_start_retry_exhausted"));
                    output(Vpn::ConnectionState::Error,
                           QStringLiteral("VPN-адаптер Windows не запускается. Перезагрузите компьютер и включите Маяк снова."));
                }
            } else if ((s.error==ac::ErrorCategory::Network || s.error==ac::ErrorCategory::Deadline) && !cancelled &&
                       !reconnectWanted && connectRetries<recoveryTimingStorage().connectRetryMs.size()) {
                // The gateway was unreachable (DNS/timeout, e.g. a mobile network waking up):
                // keep the session busy and start a fresh cycle after a pause, not an error.
                const qint64 delay=recoveryTimingStorage().connectRetryMs.at(connectRetries++);
                connectRetryAt=now()+delay; terminal=false;
                phase=QStringLiteral("preparing");
                output(Vpn::ConnectionState::Preparing,QStringLiteral("Нет связи с сервером Маяка — повторяем…"));
                logNet(QStringLiteral("event=connect_retry_scheduled retry=%1 delay_ms=%2").arg(connectRetries).arg(delay));
            } else if (reconnectWanted && !cancelled) {
                // A dead connected exit is being replaced (another exit first): not an error.
                terminal=false; phase=QStringLiteral("preparing");
                output(Vpn::ConnectionState::Preparing,QStringLiteral("Сервер не отвечает — переподключаемся…"));
            } else if (!manualExit.isEmpty() && !cancelled && s.error!=ac::ErrorCategory::AuthRevoked &&
                       s.error!=ac::ErrorCategory::AccountExpired) {
                // Owner's choice: only that exit was tried; say so instead of "no available server".
                output(Vpn::ConnectionState::Error,manualFailedText(manualCity,s.error));
            } else output(Vpn::ConnectionState::Error,errorText(s.error));
            break;
        case ac::State::Cancelled: case ac::State::Idle:
            terminal=true;
            if (abandoning) {
                // The adopted backend is still being stopped/released: report it when settled.
                abandonHeldDisconnect=true; phase=QStringLiteral("stopping");
                output(Vpn::ConnectionState::Disconnecting,QStringLiteral("Завершаем подключение…"));
            } else if (appExclusionBlocked && !cancelled) {
                phase=QStringLiteral("failed");
                output(Vpn::ConnectionState::Error,QString::fromUtf8(kAppExclusionUnavailable));
            } else output(Vpn::ConnectionState::Disconnected,{});
            break;
        }
    }
    void stopUser() {
        const bool reconnectWaiting=reconnectWanted;
        cancelled=true; reconnectWanted=false; ++preflightGeneration;
        if (!permissionRequestId.isEmpty()) {
            bridge->cancelPermissionPreparation(permissionRequestId);
            permissionRequestId.clear(); permissionPending=false;
        }
        for(auto& [tag,a]:attempts) { a->cancelled=true; if(a->ticket.valid()) bridge->cancel(a->ticket); }
        // A WinTun repair before a connect retry: the coordinator is Failed and ignores cancel().
        const bool retryWaiting=connectRetryAt!=0 || healPending; connectRetryAt=0; healPending=false;
        const bool localRestartWaiting=restartAfterCleanup; localRestartAt=0; restartAfterCleanup=false;
        const bool adopting=adoption.pending;
        if (adopting) {
            // The adopted backend is not yet owned by any attempt: stop it with the recovery
            // ticket and release its attempt, then finish like any cancelled cleanup.
            auto self=shared_from_this();
            abandonAdoption([self](bool ok) {
                if (ok && self->finishCleanup()) return;
                self->abandonHeldDisconnect=false;
                self->cleanupPending=true; self->terminal=true;
                self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,self->cleanupText());
            });
        }
        if(coordinator) {
            coordinator->cancel();
            // A Failed coordinator ignores cancel(); a pending connect retry or failover
            // reconnect is ours to end.
            if ((retryWaiting || reconnectWaiting) && coordinator->status().state==ac::State::Failed) {
                terminal=true; phase=QStringLiteral("cancelled"); output(Vpn::ConnectionState::Disconnected,{});
            } else if (localRestartWaiting && cleanupPending && !cleanupOperation) {
                // The user's OFF during the local-adapter pause: no restart, finish the pending
                // exact cleanup now (Disconnected on success, the cleanup error otherwise).
                terminal=true; phase=QStringLiteral("stopping");
                output(Vpn::ConnectionState::Disconnecting,QStringLiteral("Завершаем подключение…"));
                retryCleanup();
            }
        } else {
            preparing=false; terminal=true;
            if (adopting) {
                // The abandon callback above finishes (or reports) this cleanup.
                phase=QStringLiteral("stopping"); output(Vpn::ConnectionState::Disconnecting,QStringLiteral("Завершаем подключение…"));
            } else if (!finishCleanup()) {
                cleanupPending=true;
                phase=QStringLiteral("failed");
                output(Vpn::ConnectionState::Error,errorText(ac::ErrorCategory::StopUnconfirmed));
            }
        }
    }
    // The user pressed the main button («Повторить отключение») while a local-adapter restart was
    // pending: the user wants OFF, so the cleanup must not end in an automatic new connection.
    void userRetryCleanup() {
        if (restartAfterCleanup || localRestartAt) {
            restartAfterCleanup=false; localRestartAt=0;
            logNet(QStringLiteral("event=local_start_restart_cancelled reason=user"));
        }
        retryCleanup();
    }
    void retryCleanup(bool continuation=false) {
        if (!cleanupPending || cleanupOperation || !facade) return;
        // The coordinator owns its first exact release request. Never race it
        // with reconciliation of the same encrypted attempt.
        for (const auto& [tag,attempt] : attempts)
            if (attempt->releasePending) return;
        for (const auto& [tag,attempt] : attempts) attempt->releaseOperationId=0;
        if (!continuation) cleanupDeadline=now()+10000;
        if (finishCleanup()) return;
        if (now()>=cleanupDeadline) {
            phase=QStringLiteral("failed");
            output(Vpn::ConnectionState::Error,QStringLiteral("Очистка доступа ожидает повтора. Нажмите «Повторить отключение».")); return;
        }
        if (!coordinator && !preflightNativeOff) {
            cleanupOperation=true; inspectPreflight(); return;
        }
        const auto loaded=store->load();
        if (!loaded.ok || loaded.records.isEmpty()) {
            phase=QStringLiteral("failed"); output(Vpn::ConnectionState::Error,QStringLiteral("Не удалось проверить сохранённую очистку. Отключение остаётся неподтверждённым."));
            return;
        }
        const auto record=loaded.records.first();
        // Before coordinator creation a fresh own-backend OFF/recovery-stop
        // barrier covers persisted records from a prior process. Once native
        // starts are possible, each relevant current ticket needs its own down.
        if (record.mayHaveStarted() && (coordinator || !preflightNativeOff)) {
            std::shared_ptr<Attempt> attempt;
            for (const auto& [tag,candidate] : attempts)
                if (candidate->identity==record.identity()) { attempt=candidate; break; }
            if (!attempt) {
                phase=QStringLiteral("failed"); output(Vpn::ConnectionState::Error,QStringLiteral("Сеанс VPN не подтверждён. Отключение остаётся неподтверждённым."));
                return;
            }
            if (!attempt->stopped) {
                cleanupOperation=true;
                const quint64 generation=++cleanupGeneration;
                bridge->cancel(attempt->ticket);
                auto self=shared_from_this();
                bridge->stopAndConfirm(attempt->ownTicket(),qMin(now()+3000,cleanupDeadline),[self,attempt,generation](B::Result result) {
                    self->noteNativeDown(attempt,result);
                    if (generation!=self->cleanupGeneration) {
                        if (attempt->stopped && !self->cleanupOperation) self->retryCleanup(true);
                        return;
                    }
                    if (!attempt->stopped) {
                        self->cleanupOperation=false;
                        self->cleanupPending=true;
                        self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,QStringLiteral("Не удалось подтвердить отключение. Нажмите «Повторить отключение»."));
                        return;
                    }
                    self->cleanupOperation=false;
                    self->retryCleanup(true);
                });
                return;
            }
        }
        // Reconcile the original encrypted record with its stored device authority.
        cleanupOperation=true;
        const quint64 generation=++cleanupGeneration;
        ad::Request request; request.action="reconcile"; request.attemptId=record.identity().attemptId;
        request.cycleToken=record.identity().cycleToken; request.commonPayload=payloadFor(record);
        const auto operationDeadline=qMin(now()+2500,cleanupDeadline);
        request.deadlineUtcMs=utcDeadline(operationDeadline);
        ++inFlight;
        auto self=shared_from_this();
        auto settled=std::make_shared<bool>(false);
        auto lateHandled=std::make_shared<bool>(false);
        auto timedOutSeen=std::make_shared<bool>(false);
        std::weak_ptr<Session> weak=self;
        auto finish=[weak,record,generation,settled,lateHandled,timedOutSeen](ad::Response response, bool timedOut) {
            auto self=weak.lock(); if (!self) return;
            if (*settled && !(timedOut == false && *timedOutSeen && response.success && response.authenticatedResponse && !*lateHandled)) return;
            const bool first=!(*settled); *settled=true;
            if (timedOut) *timedOutSeen=true;
            if (!first) *lateHandled=true;
            if (first) --self->inFlight;
            if (generation!=self->cleanupGeneration) return;
            if (first) self->cleanupOperation=false;
            // Another authenticated operation may already have durably settled
            // this exact record. A later negative/timeout cannot reopen it.
            if (self->finishCleanup()) return;
            // No gateway answer at all, the tunnel confirmed down (checked before this reconcile):
            // with the stored exits the OFF completes and the place is reconciled later.
            if (first && (timedOut || !response.authenticatedResponse) && self->deferCleanup(record.identity(),"cleanup_no_answer")) {
                self->cleanupPending=true; self->retryCleanup(true); return;
            }
            if (timedOut) {
                self->cleanupPending=true;
                self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,self->cleanupText());
                return;
            }
            if (!response.success || !response.authenticatedResponse ||
                !self->store->removeAfterConfirmedCleanup(record.identity()).ok) {
                self->cleanupPending=true;
                self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,self->cleanupText());
                return;
            }
            self->cleanupPending=true;
            self->retryCleanup(true);
        };
        QTimer::singleShot(qMax<qint64>(0,operationDeadline-now()),this,[finish] { finish({},true); });
        ad::MayakAdmissionClient::postAsync(request,transport,[finish](ad::Response response) { finish(response,false); });
    }
    void fetchFresh(ac::CycleId c,ac::AttemptId a,ac::Millis deadline,FetchDone done) override {
        if (!adoption.pending) { fetch(c,a,deadline,0,std::move(done)); return; }
        auto self=shared_from_this();
        fetch(c,a,deadline,0,[self,done](ac::CycleId c,ac::AttemptId a,ac::FetchStatus status,ac::Snapshot s) mutable {
            if (!self->adoption.pending) { done(c,a,status,std::move(s)); return; }
            if (status==ac::FetchStatus::Success) {
                const QString want=self->adoption.identity.candidateId;
                const auto it=std::find_if(s.candidates.begin(),s.candidates.end(),[&](const ac::Candidate& x) {
                    return QString::fromStdString(x.id).compare(want,Qt::CaseInsensitive)==0; });
                // The coordinator preserves order: the adopted exit is admitted first.
                if (it!=s.candidates.end()) { std::rotate(s.candidates.begin(),it,it+1); done(c,a,status,std::move(s)); return; }
                self->logNet(QStringLiteral("event=adopt_abandon reason=candidate_absent"));
            } else self->logNet(QStringLiteral("event=adopt_abandon reason=fetch_failed"));
            self->abandonAdoption([done,c,a,status,s](bool ok) mutable {
                done(c,a,ok?status:ac::FetchStatus::NetworkError,ok?std::move(s):ac::Snapshot{});
            });
        });
    }
    void fetch(ac::CycleId c,ac::AttemptId a,ac::Millis deadline,int retry,FetchDone done) {
        auto self=shared_from_this();
        if(!identityCurrent() || now()>=deadline) { done(c,a,ac::FetchStatus::AuthRevoked,{}); return; }
        if (retry==0) offlineCycle=false;
        const int timeout=int(qMax<qint64>(1,deadline-now()));
        // One owner for this cycle's candidates: the gateway's signed answer or the stored exits,
        // never both. `owned` is taken by whichever decides first; a later gateway answer then only
        // refreshes the memory or ends a session the server revoked (no second path is started).
        auto owned=std::make_shared<bool>(false);
        auto offlineOwned=std::make_shared<bool>(false);
        std::weak_ptr<Session> weakSelf=self;
        const auto deliverOffline=[weakSelf,owned,offlineOwned,c,a,done](const char* reason) -> bool {
            auto self=weakSelf.lock();
            if (!self || *owned || self->cancelled || self->adoption.pending || !self->offlineUsable()) return false;
            *owned=true; *offlineOwned=true; self->offlineCycle=true;
            auto s=self->offlineSnapshot();
            self->logNet(QStringLiteral("event=offline_start reason=%1 exits=%2").arg(QLatin1String(reason)).arg(s.candidates.size()));
            done(c,a,ac::FetchStatus::Success,std::move(s));
            return true;
        };
        if (retry==0 && !adoption.pending && offlineUsable())
            QTimer::singleShot(qMax<qint64>(1,recoveryTimingStorage().offlineEarlyMs),this,[deliverOffline] { deliverOffline("slow"); });
        auto* watcher=new QFutureWatcher<GatewayPostResult>();
        ++inFlight;
        connect(watcher,&QFutureWatcher<GatewayPostResult>::finished,watcher,[self,watcher,c,a,deadline,retry,done,owned,offlineOwned,deliverOffline]() mutable {
            const auto r=watcher->result(); watcher->deleteLater(); --self->inFlight;
            ad::AdmissionError err;
            const bool isError=ad::parseAdmissionError(r.body,r.authenticatedResponse,&err);
            ad::ConnectionCapability cap;
            const bool capOk=!isError && r.authenticatedResponse && ad::parseConnectionCapability(r.body,QDateTime::currentDateTimeUtc(),&cap);
            if (isError && (err.code=="REVOKED" || err.code=="ACCOUNT_EXPIRED")) self->offlineWipe(err.code=="REVOKED" ? "revoked" : "expired");
            if (capOk) { self->offlineRememberCapability(cap); self->rememberManualExits(cap); }
            if (*offlineOwned) {
                // The stored exits own this cycle: a revoked/expired answer ends that session.
                if (isError && (err.code=="REVOKED" || err.code=="ACCOUNT_EXPIRED"))
                    self->endOfflineSession(err.code=="REVOKED" ? ac::ErrorCategory::AuthRevoked : ac::ErrorCategory::AccountExpired);
                self->logNet(QStringLiteral("event=offline_late_config answered=%1").arg(isError || capOk ? 1 : 0));
                return;
            }
            if (*owned) return;
            // The stored exits only without a signed answer, for a signed server failure (5xx) or "no
            // ready exit". A signed refusal (4xx: access ended, device disabled or revoked, another
            // installation, device limit...) never starts them, with or without a known code.
            int httpStatus=0; QString code;
            if (isError) { httpStatus=err.httpStatus; code=err.code; }
            else if (r.authenticatedResponse && !capOk) {
                const QJsonObject body=QJsonDocument::fromJson(r.body).object();
                httpStatus=body.value("http_status").toInt(); code=body.value("code").toString();
            }
            const bool offlineAllowed=!r.authenticatedResponse || (!capOk && (httpStatus>=500 || code=="no_ready_exit"));
            if(isError) {
                if(err.code=="provisioning" && retry<2 && self->now()+1500<deadline && !self->cancelled) {
                    *owned=true; // the server answered: this device is not ready yet (no stored exits)
                    const int delay=qBound(250,err.retryAfterMs,2000);
                    QTimer::singleShot(delay,self.get(),[self,c,a,deadline,retry,done] { self->fetch(c,a,deadline,retry+1,done); }); return;
                }
                if (offlineAllowed && deliverOffline("server_error")) return;
                *owned=true;
                // Disabled (not approved yet or switched off) may be temporary: the memory stays, the
                // reason is shown, no automatic retries.
                if (err.code=="DISABLED")
                    self->fetchRefusalText=QStringLiteral("Доступ этого устройства выключен или ещё не одобрен. Откройте личный кабинет.");
                done(c,a,err.code=="REVOKED"?ac::FetchStatus::AuthRevoked:err.code=="ACCOUNT_EXPIRED"?ac::FetchStatus::AccountExpired:ac::FetchStatus::NetworkError,{}); return;
            }
            if(!capOk) {
                if (offlineAllowed && deliverOffline(r.authenticatedResponse ? "server_error" : "no_answer")) return;
                *owned=true;
                done(c,a,ac::FetchStatus::NetworkError,{}); return;
            }
            *owned=true;
            // A cleanup left by an earlier gateway outage is settled first: the server refuses a new
            // place while an older one of the device is open. Not settled -> the stored exits.
            if (!loadDeferredCleanup(self->settings).isEmpty()) {
                ++self->inFlight;
                self->reconcileDeferred(deadline-1500,[self,c,a,deadline,done,cap,owned,offlineOwned](bool clear) mutable {
                    --self->inFlight;
                    if (!clear && !self->cancelled && !self->adoption.pending && self->offlineUsable()) {
                        *offlineOwned=true; self->offlineCycle=true;
                        auto s=self->offlineSnapshot();
                        self->logNet(QStringLiteral("event=offline_start reason=deferred_cleanup exits=%1").arg(s.candidates.size()));
                        done(c,a,ac::FetchStatus::Success,std::move(s)); return;
                    }
                    self->continueFetch(c,a,deadline,cap,done);
                });
                return;
            }
            self->continueFetch(c,a,deadline,cap,done);
        });
        watcher->setFuture(transport(QStringLiteral("%1v1/config"),ad::buildMayakConfigPayload(common),timeout));
    }
    // The signed v1/config answer of this cycle (the gateway owns its candidates).
    void continueFetch(ac::CycleId c,ac::AttemptId a,ac::Millis deadline,const ad::ConnectionCapability& cap,FetchDone done) {
            auto self=shared_from_this();
            ac::Snapshot s; s.schemaVersion=cap.schema; s.revision=QString::number(cap.revision).toStdString();
            s.expiresAt=self->now()+QDateTime::currentDateTimeUtc().msecsTo(cap.expiresAt);
            // Owner's manual exit: the only candidate. Not offered any more (another role) = «Авто»;
            // offered without the chosen exit = a clear refusal, never another exit.
            QList<ad::Candidate> offered=cap.candidates;
            if (!self->manualExit.isEmpty() && !self->adoption.pending && !cap.manualExits.isEmpty()) {
                const auto it=std::find_if(cap.manualExits.begin(),cap.manualExits.end(),[&self](const ad::ManualExit& x) {
                    return x.candidate.id.compare(self->manualExit,Qt::CaseInsensitive)==0; });
                if (it==cap.manualExits.end()) {
                    self->logNet(QStringLiteral("event=manual_exit_missing"));
                    self->fetchRefusalText=manualMissingText(self->manualCity);
                    done(c,a,ac::FetchStatus::NetworkError,{}); return;
                }
                offered={it->candidate};
                self->logNet(QStringLiteral("event=manual_exit auto=%1").arg(it->autoSelect ? 1 : 0));
            } else if (!self->manualExit.isEmpty() && !self->adoption.pending) {
                self->logNet(QStringLiteral("event=manual_exit_not_offered"));
                self->manualExit.clear(); self->manualCity.clear();
            }
            for(const auto& v:offered) {
                ac::Candidate x{v.id.toStdString(),v.host.toStdString(),v.port,v.preferred,{}};
                for(const auto& ip:v.expectedEgressIps) x.expectedEgressIps.push_back(ip.toStdString());
                s.candidates.push_back(std::move(x));
            }
            avoidedExitStorage().knownExits=int(s.candidates.size());
            // Exit memory: the exit that last proved on this network goes first while it is offered.
            if (!self->adoption.pending && self->remembered.valid()) {
                const auto it=std::find_if(s.candidates.begin(),s.candidates.end(),[&self](const ac::Candidate& x) {
                    return self->remembered.is(QString::fromStdString(x.id)); });
                if (it!=s.candidates.end()) { std::rotate(s.candidates.begin(),it,it+1); self->logNet(QStringLiteral("event=exit_memory_first")); }
            }
            // Failover: an exit that just stopped working is tried last (server order otherwise).
            if (!self->adoption.pending && s.candidates.size()>1 && self->now()<avoidedExitStorage().until) {
                const QString avoid=avoidedExitStorage().candidateId;
                std::stable_partition(s.candidates.begin(),s.candidates.end(),[&avoid](const ac::Candidate& x) {
                    return QString::fromStdString(x.id).compare(avoid,Qt::CaseInsensitive)!=0; });
            }
            // Exits the coordinator will try (its own filter), for the AWG quick give-up.
            self->cycleAcquires=0; self->cycleCandidates=0;
            { std::set<std::string> ids,ips;
              for (const auto& x:s.candidates) {
                  bool ok=!x.id.empty() && x.port!=0 && !x.expectedEgressIps.empty() && ac::Coordinator::isValidPublicIpv4(x.publicIpv4);
                  for (const auto& ip:x.expectedEgressIps) ok=ok && ac::Coordinator::isValidPublicIpv4(ip);
                  if (ok && ids.insert(x.id).second && ips.insert(x.publicIpv4).second) ++self->cycleCandidates;
              }
              if (s.candidates.size()>3) self->cycleCandidates=0; }
            if (self->adoption.pending) { done(c,a,ac::FetchStatus::Success,std::move(s)); return; }
            self->precheckPorts(std::move(s),deadline,[c,a,done](ac::Snapshot checked) mutable {
                done(c,a,ac::FetchStatus::Success,std::move(checked)); });
    }
    // Parallel TCP check of the exits' Xray port (see tcpPortPrecheck). Exits that answered keep the
    // order (server order with the exit memory first); the others follow. Nothing answered at all
    // says nothing about single exits: the order stays and no path is skipped.
    void precheckPorts(ac::Snapshot s,ac::Millis deadline,std::function<void(ac::Snapshot)> next) {
        tcpUnanswered.clear();
        const qint64 budget=qMin<qint64>(recoveryTimingStorage().portPrecheckMs,deadline-now()-1000);
        if (s.candidates.size()<2 || budget<300 || cancelled || method==QStringLiteral("awg")) { next(std::move(s)); return; }
        QStringList hosts; for (const auto& x:s.candidates) hosts<<QString::fromStdString(x.publicIpv4);
        auto self=shared_from_this(); const qint64 started=now();
        auto snapshot=std::make_shared<ac::Snapshot>(std::move(s));
        portPrecheckStorage()(this,hosts,kXrayPrecheckPort,int(budget),[self,snapshot,next,started](QList<bool> answered) {
            auto& list=snapshot->candidates;
            if (answered.size()!=qsizetype(list.size())) { next(std::move(*snapshot)); return; }
            const int ok=int(std::count(answered.begin(),answered.end(),true));
            self->logNet(QStringLiteral("event=port_precheck answered=%1/%2 elapsed_ms=%3").arg(ok).arg(list.size()).arg(self->now()-started));
            if (ok==0) { next(std::move(*snapshot)); return; }
            std::vector<std::pair<ac::Candidate,bool>> marked;
            for (std::size_t i=0;i<list.size();++i) {
                const QString id=QString::fromStdString(list[i].id);
                // The remembered exit without an Xray path proved over AWG: it needs no TCP, it keeps its place.
                const bool keep=answered.at(qsizetype(i)) ||
                    (self->remembered.is(id) && self->remembered.path.isEmpty() && self->method!=QStringLiteral("xray"));
                if (!answered.at(qsizetype(i))) self->tcpUnanswered.insert(id.toLower());
                marked.push_back({list[i],keep});
            }
            std::stable_partition(marked.begin(),marked.end(),[](const auto& m) { return m.second; });
            list.clear(); for (auto& m:marked) list.push_back(std::move(m.first));
            next(std::move(*snapshot));
        });
    }
    void acquire(ac::CycleId c,ac::AttemptId n,const ac::Candidate& candidate,ac::Millis deadline,AdmissionDone done) override {
        auto self=shared_from_this();
        if (adoption.pending) {
            if (QString::fromStdString(candidate.id).compare(adoption.identity.candidateId,Qt::CaseInsensitive)==0) {
                acquireAdopted(c,n,candidate,deadline,std::move(done)); return;
            }
            logNet(QStringLiteral("event=adopt_abandon reason=other_candidate"));
            const auto chosen=candidate;
            abandonAdoption([self,c,n,chosen,deadline,done](bool ok) mutable {
                if (!ok) { done(c,n,{ac::AdmissionStatus::Malformed,{}}); return; }
                self->acquire(c,n,chosen,deadline,std::move(done));
            });
            return;
        }
        if (offlineCycle) { acquireFromMemory(c,n,candidate,std::move(done)); return; }
        const auto loaded=store->load();
        // A lost earlier acquire may still own a slot. Never allocate over it.
        if(!identityCurrent() || !loaded.ok || !loaded.records.isEmpty()) { done(c,n,{ac::AdmissionStatus::Malformed,{}}); return; }
        auto a=std::make_shared<Attempt>(); a->candidate=candidate;
        a->identity={serverId,epoch,cycleToken,randomId(),QString::fromStdString(candidate.id)};
        a->ticket={a->identity.attemptId,std::make_shared<B::StartGate>()};
        if(!store->appendBeforeAcquire({a->identity,authority,false,false,{}}).ok) { done(c,n,{ac::AdmissionStatus::Malformed,{}}); return; }
        attempts[{c,n}]=a; ++cycleAcquires;
        ad::Request request; request.action="acquire"; request.attemptId=a->identity.attemptId; request.cycleToken=cycleToken;
        request.candidateId=a->identity.candidateId; request.commonPayload=common; request.deadlineUtcMs=utcDeadline(deadline);
        request.requestPaths=method!=QStringLiteral("awg");
        ++inFlight;
        // Kept alive by the request in flight; the retry below reuses it (weak self-reference).
        auto handler=std::make_shared<std::function<void(ad::Response)>>();
        std::weak_ptr<std::function<void(ad::Response)>> weakHandler=handler;
        *handler=[self,a,c,n,done,request,weakHandler](ad::Response r) mutable {
            --self->inFlight;
            // INVALID_REQUEST to a fresh attempt: an older place of this device is still open on the
            // server (its cleanup was lost or is still deferred). Once: ask again as a late acquire,
            // which closes the older place (review of item 2).
            if (r.authenticatedResponse && r.isError && r.error.code=="INVALID_REQUEST" && !a->invalidRetried) {
                if (auto again=weakHandler.lock()) {
                    a->invalidRetried=true;
                    self->logNet(QStringLiteral("event=acquire_invalid_retry_late"));
                    ad::Request late=request; late.late=true;
                    ++self->inFlight;
                    ad::MayakAdmissionClient::postAsync(late,self->transport,[again](ad::Response response) { (*again)(response); });
                    return;
                }
            }
            if(r.authenticatedResponse && r.acquireValid && r.success) {
                a->allocation=r.acquire.allocationId; a->encodedConfig=r.acquire.encodedConfig;
                if (r.acquire.exitLocationCandidateId.compare(a->identity.candidateId, Qt::CaseInsensitive) == 0) {
                    a->exitLocationCityId = r.acquire.exitLocationCityId;
                    a->exitLocationHasCard = r.acquire.exitLocationHasCard;
                    a->exitLocationCard = r.acquire.exitLocationCard;
                }
                a->connectBefore=self->now()+QDateTime::currentDateTimeUtc().msecsTo(r.acquire.connectBefore);
                // Pre-send record remains sufficient for exact cleanup if this write fails.
                const bool saved=self->store->attachAllocation(a->identity,a->allocation).ok;
                ac::Allocation allocation{a->allocation.toStdString(), saved?a->encodedConfig.toStdString():std::string{}, {}, false};
                self->planPaths(a,r.acquire,&allocation);
                self->offlineRememberAllocation(a,r.acquire);
                done(c,n,{ac::AdmissionStatus::Admitted,std::move(allocation)}); return;
            }
            ac::AdmissionStatus status=ac::AdmissionStatus::Malformed;
            if(r.authenticatedResponse && r.isError) {
                if(r.error.code=="FULL") status=ac::AdmissionStatus::Full;
                else if(r.error.code=="NOT_READY") status=ac::AdmissionStatus::NotReady;
                else if(r.error.code=="DISABLED") status=ac::AdmissionStatus::Disabled;
                else if(r.error.code=="REVOKED") status=ac::AdmissionStatus::AuthRevoked;
                else if(r.error.code=="ACCOUNT_EXPIRED") status=ac::AdmissionStatus::AccountExpired;
                if (status==ac::AdmissionStatus::AuthRevoked || status==ac::AdmissionStatus::AccountExpired)
                    self->offlineWipe(status==ac::AdmissionStatus::AuthRevoked ? "revoked" : "expired");
                if(status!=ac::AdmissionStatus::Malformed && !self->store->removeAfterConfirmedCleanup(a->identity).ok) status=ac::AdmissionStatus::Malformed;
            }
            // Unknown/lost reply retains record and terminates; next user retry reconciles.
            done(c,n,{status,{}});
        };
        ad::MayakAdmissionClient::postAsync(request,transport,[handler](ad::Response response) { (*handler)(response); });
    }
    // A candidate of the stored exits (see OfflineMemory): no request; the place is reported by the
    // late acquire after «Подключено». The coordinator's handle names no place on the server.
    void acquireFromMemory(ac::CycleId c,ac::AttemptId n,const ac::Candidate& candidate,AdmissionDone done) {
        const auto loaded=store->load();
        if(!identityCurrent() || !loaded.ok || !loaded.records.isEmpty()) { done(c,n,{ac::AdmissionStatus::Malformed,{}}); return; }
        const QString id=QString::fromStdString(candidate.id);
        const auto memory=loadOfflineMemory(settings);
        const auto it=std::find_if(memory.exits.begin(),memory.exits.end(),[&id](const OfflineExit& e) {
            return e.id.compare(id,Qt::CaseInsensitive)==0 && e.usable(); });
        if (memory.owner!=offlineOwnerKey || it==memory.exits.end() || it->host!=QString::fromStdString(candidate.publicIpv4)) {
            done(c,n,{ac::AdmissionStatus::NetworkError,{}}); return;
        }
        auto a=std::make_shared<Attempt>(); a->candidate=candidate; a->offline=true;
        a->identity={serverId,epoch,cycleToken,randomId(),id};
        a->ticket={a->identity.attemptId,std::make_shared<B::StartGate>()};
        a->offlineHandle=QStringLiteral("offline-")+a->identity.attemptId; a->allocation=a->offlineHandle;
        a->encodedConfig=it->encodedConfig;
        a->exitLocationCityId=it->cityId; a->exitLocationHasCard=it->hasCard; a->exitLocationCard=it->card;
        if(!store->appendBeforeAcquire({a->identity,authority,false,false,{}}).ok) { done(c,n,{ac::AdmissionStatus::Malformed,{}}); return; }
        attempts[{c,n}]=a; ++cycleAcquires;
        a->connectBefore=now()+ac::Coordinator::timing().cycleWithXrayMs;
        ad::AcquireResponse stored; stored.encodedConfig=it->encodedConfig;
        for (const auto& value:it->xrayPaths) {
            const QJsonObject p=value.toObject();
            stored.xrayPaths.push_back({p.value("id").toString(),p.value("fingerprint").toString(),p.value("config").toString()});
        }
        stored.xrayPathsOffered=!stored.xrayPaths.isEmpty();
        ac::Allocation allocation{a->allocation.toStdString(),a->encodedConfig.toStdString(),{},false};
        planPaths(a,stored,&allocation);
        logNet(QStringLiteral("event=offline_acquire failures=%1").arg(it->failures));
        done(c,n,{ac::AdmissionStatus::Admitted,std::move(allocation)});
    }
    // Idempotent acquire of the adopted attempt: same attempt id and cycle token, so the server
    // re-validates account/device/exit and must return the SAME allocation (no new slot).
    void acquireAdopted(ac::CycleId c,ac::AttemptId n,const ac::Candidate& candidate,ac::Millis deadline,AdmissionDone done) {
        auto self=shared_from_this();
        if (!identityCurrent()) {
            abandonAdoption([done,c,n](bool) { done(c,n,{ac::AdmissionStatus::Malformed,{}}); }); return;
        }
        auto a=std::make_shared<Attempt>(); a->candidate=candidate; a->identity=adoption.identity; a->adopted=true; ++cycleAcquires;
        a->ticket={a->identity.attemptId,std::make_shared<B::StartGate>()};
        attempts[{c,n}]=a;
        ad::Request request; request.action="acquire"; request.attemptId=a->identity.attemptId; request.cycleToken=a->identity.cycleToken;
        request.candidateId=a->identity.candidateId; request.commonPayload=common; request.deadlineUtcMs=utcDeadline(deadline);
        request.resumeAllocation=true; // the allocation's original connect_before is long past
        ++inFlight;
        logNet(QStringLiteral("event=adopt_acquire"));
        ad::MayakAdmissionClient::postAsync(request,transport,[self,a,c,n,done](ad::Response r) mutable {
            --self->inFlight;
            if (r.authenticatedResponse && r.acquireValid && r.success &&
                r.acquire.allocationId==self->adoption.allocationId && self->adoption.pending) {
                a->allocation=r.acquire.allocationId; a->encodedConfig=r.acquire.encodedConfig;
                if (r.acquire.exitLocationCandidateId.compare(a->identity.candidateId, Qt::CaseInsensitive) == 0) {
                    a->exitLocationCityId = r.acquire.exitLocationCityId;
                    a->exitLocationHasCard = r.acquire.exitLocationHasCard;
                    a->exitLocationCard = r.acquire.exitLocationCard;
                }
                a->connectBefore=self->now()+qMax<qint64>(15000,QDateTime::currentDateTimeUtc().msecsTo(r.acquire.connectBefore));
                self->offlineRememberAllocation(a,r.acquire);
                // The adopted backend is the AWG one that is already running.
                done(c,n,{ac::AdmissionStatus::Admitted,{a->allocation.toStdString(),a->encodedConfig.toStdString(),
                    {{"awg",ac::PathKind::Awg}},true}}); return;
            }
            ac::AdmissionStatus status=ac::AdmissionStatus::NetworkError;
            if (r.authenticatedResponse && r.isError) {
                if (r.error.code=="FULL") status=ac::AdmissionStatus::Full;
                else if (r.error.code=="NOT_READY") status=ac::AdmissionStatus::NotReady;
                else if (r.error.code=="DISABLED") status=ac::AdmissionStatus::Disabled;
                else if (r.error.code=="REVOKED") status=ac::AdmissionStatus::AuthRevoked;
                else if (r.error.code=="ACCOUNT_EXPIRED") status=ac::AdmissionStatus::AccountExpired;
            } else if (r.authenticatedResponse && r.success) status=ac::AdmissionStatus::NotReady; // a different allocation
            self->logNet(QStringLiteral("event=adopt_abandon reason=acquire status=%1").arg(int(status)));
            a->cancelled=true;
            // Stop the backend and release the attempt (reconcile releases every allocation of it).
            self->abandonAdoption([done,c,n,status](bool ok) { done(c,n,{ok?status:ac::AdmissionStatus::Malformed,{}}); });
        });
    }
    std::shared_ptr<Attempt> get(ac::CycleId c,ac::AttemptId a) {
        auto i=attempts.find({c,a}); return i==attempts.end()?nullptr:i->second;
    }
    // Orders the paths of a fresh allocation by the connection method and the path memory.
    void planPaths(const std::shared_ptr<Attempt>& a,const ad::AcquireResponse& acquired,ac::Allocation* allocation) {
        a->xray.clear();
        for (const auto& p:acquired.xrayPaths) {
            XrayEntry entry{p,{}}; QString reason;
            if (ad::decodeXrayPathConfig(p,QString::fromStdString(a->candidate.publicIpv4),&entry.config,&reason)) a->xray.push_back(entry);
            else logNet(QStringLiteral("event=xray_path_rejected path=%1 reason=%2").arg(p.id,reason));
        }
        if (acquired.xrayPathsOffered && !acquired.xrayPathsRejected.isEmpty())
            logNet(QStringLiteral("event=xray_paths_rejected reason=%1").arg(acquired.xrayPathsRejected));
        const QString candidateId=QString::fromStdString(a->candidate.id);
        // This exit's Xray port did not answer the precheck while others did: its Xray paths on that
        // port are skipped in this cycle (AWG is still tried). "Only Xray" keeps them all.
        if (method!=QStringLiteral("xray") && tcpUnanswered.contains(candidateId.toLower())) {
            const auto before=a->xray.size();
            a->xray.erase(std::remove_if(a->xray.begin(),a->xray.end(),[](const XrayEntry& e) {
                return xrayOutboundPort(e.config.clientJson)==kXrayPrecheckPort; }),a->xray.end());
            if (a->xray.size()!=before) logNet(QStringLiteral("event=xray_paths_skipped reason=port_precheck count=%1").arg(before-a->xray.size()));
        }
        std::vector<ac::Path> xray;
        for (const auto& e:a->xray) xray.push_back({e.path.id.toStdString(),ac::PathKind::Xray});
        const ac::Path awg{"awg",ac::PathKind::Awg};
        allocation->pathsExplicit=true;
        if (method==QStringLiteral("awg")) allocation->paths={awg};
        else if (method==QStringLiteral("xray")) allocation->paths=xray;
        else if (rememberedXrayFirst(settings,networkKey)) { allocation->paths=xray; allocation->paths.push_back(awg); }
        else { allocation->paths={awg}; allocation->paths.insert(allocation->paths.end(),xray.begin(),xray.end()); }
        // Exit memory: the path that proved on this exit and network goes first.
        a->rememberedFirst.clear();
        if (remembered.is(candidateId) && !remembered.path.isEmpty()) {
            auto& paths=allocation->paths;
            const auto it=std::find_if(paths.begin(),paths.end(),[this](const ac::Path& p) { return QString::fromStdString(p.id)==remembered.path; });
            if (it!=paths.end()) { std::rotate(paths.begin(),it,it+1); a->rememberedFirst=remembered.path; }
        }
        // The service does not enforce connect_before; a later path of this allocation still
        // belongs to the same admitted place on the exit.
        if (!xray.empty()) a->connectBefore=qMax(a->connectBefore,now()+ac::Coordinator::timing().cycleWithXrayMs);
        a->plannedPaths=int(allocation->paths.size());
        QStringList order; for (const auto& p:allocation->paths) order<<QString::fromStdString(p.id);
        logNet(QStringLiteral("event=paths order=%1 remembered=%2").arg(order.join(',')).arg(a->rememberedFirst.isEmpty() ? 0 : 1));
    }
    // A later path of the same attempt gets a fresh backend ticket and clean per-start state.
    void preparePathStart(const std::shared_ptr<Attempt>& a,const ac::Path& path) {
        if (a->pathStarts>0) {
            a->ticket={a->identity.attemptId+QStringLiteral("-p")+QString::number(a->pathStarts),std::make_shared<B::StartGate>()};
            a->started=false; a->stopped=false; a->cancelled=false; a->stopTicket={};
            a->health={}; a->healthAt=0; a->expected={}; a->reset=false; a->rxChangedAt=0; a->replacementAllowedUntil=0;
            a->proofDone={}; a->probing=false; a->tlsOk=false; a->proof={};
            a->xrayBindRetries=0; a->xrayBindFirstFailMono=0; a->noHandshakeGaveUp=false;
        }
        ++a->pathStarts; a->path=path;
    }
    void start(ac::CycleId c,ac::AttemptId n,const ac::Allocation& allocation,const ac::Path& path,ac::Millis deadline,StartDone done) override {
        auto a=get(c,n);
        if (!a || cancelled) { done(c,n,{ac::StartStatus::MalformedConfig}); return; }
        if (!appExclusionBlocked && mayak::split::appExclusionFailedSince(sessionStartMono)) {
            // The service could not apply app exclusions: no further path (Xray ignores them on Windows).
            appExclusionBlocked=true; reconnectWanted=false; connectRetryAt=0; localStartFailed=false;
            logNet(QStringLiteral("event=app_exclusion_unavailable at=path_start"));
            QTimer::singleShot(0,this,[weak=weak_from_this()] { if (auto self=weak.lock(); self && self->coordinator) self->coordinator->cancel(); });
            return;
        }
        if (a->path.kind==ac::PathKind::Awg && a->pathStarts>0 && !a->adopted) a->awgFailedHere=true;
        preparePathStart(a,path);
        // Never start a tunnel while the race engine still runs: wait for its stop (bounded by the
        // race stop deadline), then start.
        if (race.engineActive) {
            auto self=shared_from_this(); const auto copy=allocation; const auto p=path;
            race.afterStop=[self,c,n,copy,p,deadline,done]() mutable { self->startPath(c,n,copy,p,deadline,std::move(done)); };
            return;
        }
        startPath(c,n,allocation,path,deadline,std::move(done));
    }
    void startPath(ac::CycleId c,ac::AttemptId n,const ac::Allocation& allocation,const ac::Path& path,ac::Millis deadline,StartDone done) {
        auto a=get(c,n);
        if (!a || a->cancelled || cancelled) { done(c,n,{ac::StartStatus::MalformedConfig}); return; }
        if (path.kind==ac::PathKind::Xray) { startXray(c,n,path,deadline,std::move(done)); return; }
        if (a->adopted) { startAdopted(c,n,deadline,std::move(done)); return; }
        startNew(c,n,allocation,deadline,std::move(done));
    }
    void startXray(ac::CycleId c,ac::AttemptId n,const ac::Path& path,ac::Millis deadline,StartDone done) {
        auto self=shared_from_this(); auto a=get(c,n);
        const auto entry=std::find_if(a->xray.begin(),a->xray.end(),[&path](const XrayEntry& e){ return e.path.id.toStdString()==path.id; });
        if (entry==a->xray.end() || !identityCurrent() || a->cancelled) { done(c,n,{ac::StartStatus::MalformedConfig}); return; }
        QJsonObject config;
        if (connection->prepareMayakXrayConnection(serverId,entry->config.root,config)!=ErrorCode::NoError ||
            !identityCurrent() || !store->markMayHaveStarted(a->identity).ok) {
            done(c,n,{ac::StartStatus::MalformedConfig}); return;
        }
        a->started=true; a->startMono=now(); a->startUtc=QDateTime::currentMSecsSinceEpoch(); httpsSocketsMayBeStale()=true;
        bridge->startPrepared(a->ticket,serverId,config,qMin<qint64>(deadline,a->connectBefore),[self,a,c,n,done](B::Result r) {
            a->expected=r.expected;
            done(c,n,{r.outcome==B::Outcome::Started?ac::StartStatus::Started:ac::StartStatus::NetworkError});
        });
    }
    // Hand the running backend to the adopted attempt: the service confirms control identity +
    // ticket and soft-replaces the backend (new socket, same TUN), so the normal proof below
    // sees a handshake newer than startUtc. Refusal: stop it with the recovery ticket.
    void startAdopted(ac::CycleId c,ac::AttemptId n,ac::Millis deadline,StartDone done) {
        auto self=shared_from_this(); auto a=get(c,n);
        // The allocation is already admitted to this attempt: the coordinator's normal release
        // frees it and the ledger record. Here only the backend is stopped (recovery ticket).
        const auto giveUp=[self,a,c,n,done](const QString& reason) {
            self->logNet(QStringLiteral("event=adopt_abandon reason=%1").arg(reason));
            const bool pending=self->adoption.pending; const auto recovery=self->adoption.recovery;
            self->adoption.pending=false;
            if (!pending || !a) { done(c,n,{ac::StartStatus::MalformedConfig}); return; }
            self->bridge->stopAndConfirm(recovery,self->now()+3000,[self,a,c,n,done,recovery](B::Result s) {
                if (s.outcome==B::Outcome::ConfirmedDown && recovery.same(s.ticket)) {
                    // The adopted tunnel ran until now: connections made through it are dead (r3-1).
                    self->preflightNativeOff=true; a->started=false; a->stopped=true; httpsSocketsMayBeStale()=true;
                } else {
                    // Unconfirmed: the coordinator's stop must not claim it is down, and it must
                    // retry with the authority that still owns the backend (the recovery ticket).
                    a->started=true; a->stopTicket=recovery; httpsSocketsMayBeStale()=true;
                }
                done(c,n,{ac::StartStatus::MalformedConfig});
            });
        };
        if (!a || !adoption.pending || !identityCurrent() || a->cancelled || now()>=a->connectBefore) { giveUp(QStringLiteral("start_precondition")); return; }
        const auto err=subscription->applyMayakAcquireConfig(serverId,keys,a->encodedConfig,QString::fromStdString(a->candidate.publicIpv4),a->candidate.port);
        QJsonObject config; DockerContainer container;
        if (err!=ErrorCode::NoError || !identityCurrent() || connection->prepareConnection(serverId,config,container)!=ErrorCode::NoError
            || !ContainerUtils::isAwgContainer(container)) { giveUp(QStringLiteral("config")); return; }
        const auto recovery=adoption.recovery; const auto controlIdentity=adoption.controlIdentity;
        adoption.pending=false; // ownership transfer in flight: this callback owns every outcome
        a->started=true; a->startMono=now(); a->startUtc=QDateTime::currentMSecsSinceEpoch(); httpsSocketsMayBeStale()=true;
        logNet(QStringLiteral("event=adopt_request"));
        bridge->adopt(recovery,a->ticket,controlIdentity,config,qMin<qint64>(deadline,a->connectBefore),[self,a,c,n,done,recovery](B::Result r) {
            if (r.outcome==B::Outcome::Started) {
                a->expected=r.expected; self->preflightNativeOff=true; // no foreign backend remains
                self->logNet(QStringLiteral("event=adopt_ok"));
                done(c,n,{ac::StartStatus::Started}); return;
            }
            self->logNet(QStringLiteral("event=adopt_refused outcome=%1").arg(int(r.outcome)));
            // Review R20 V-2: only a live attempt that the service refused; a late callback of a
            // cancelled attempt or a bridge deadline must not spare the next real path failure.
            if (!a->cancelled && (r.outcome==B::Outcome::Failed || r.outcome==B::Outcome::Busy)) self->adoptRefused=true;
            self->bridge->stopAndConfirm(recovery,self->now()+3000,[self,a,c,n,done,recovery](B::Result s) {
                if (s.outcome==B::Outcome::ConfirmedDown && recovery.same(s.ticket)) {
                    // Down by the recovery authority: the coordinator's stop of this attempt is a no-op,
                    // and its normal release frees the allocation and the ledger record.
                    self->preflightNativeOff=true; a->started=false; a->stopped=true;
                } else a->stopTicket=recovery; // the transfer never completed: recovery still owns it
                done(c,n,{ac::StartStatus::NetworkError});
            });
        });
    }
    void startNew(ac::CycleId c,ac::AttemptId n,const ac::Allocation&,ac::Millis deadline,StartDone done) {
        auto self=shared_from_this(); auto a=get(c,n);
        if(!a || !identityCurrent() || a->cancelled || now()>=a->connectBefore) { done(c,n,{ac::StartStatus::MalformedConfig}); return; }
        const auto err=subscription->applyMayakAcquireConfig(serverId,keys,a->encodedConfig,QString::fromStdString(a->candidate.publicIpv4),a->candidate.port);
        QJsonObject config; DockerContainer container;
        if(err!=ErrorCode::NoError || !identityCurrent() || connection->prepareConnection(serverId,config,container)!=ErrorCode::NoError
           || !ContainerUtils::isAwgContainer(container) || !store->markMayHaveStarted(a->identity).ok) {
            done(c,n,{ac::StartStatus::MalformedConfig}); return;
        }
        a->started=true; a->startMono=now(); a->startUtc=QDateTime::currentMSecsSinceEpoch(); httpsSocketsMayBeStale()=true;
        bridge->startPrepared(a->ticket,serverId,config,qMin<qint64>(deadline,a->connectBefore),[self,a,c,n,done](B::Result r) {
            a->expected=r.expected;
            done(c,n,{r.outcome==B::Outcome::Started?ac::StartStatus::Started:ac::StartStatus::NetworkError});
        });
    }
    void verifyOwnTunnel(ac::CycleId c,ac::AttemptId n,const ac::Path&,const std::string& nonce,const std::vector<std::string>& ips,
                         ac::Millis deadline,ProofDone done) override {
        auto a=get(c,n); if(!a) { done(c,n,{}); return; }
        a->proofDone=std::move(done); a->nonce=QString::fromStdString(nonce); a->proofDeadline=deadline;
        a->egress.clear(); for(const auto& ip:ips) a->egress.append(QString::fromStdString(ip));
        a->tlsOk=false; a->probing=false; advanceProof({c,n},a);
        // AWG proof has no request of its own (5.1.0.27). No fresh handshake shortly before its
        // deadline is a failed proof (as a failed probe was), even when no further health arrives.
        if (a->path.kind==ac::PathKind::Awg && a->proofDone) {
            std::weak_ptr<Session> weak=shared_from_this();
            const std::pair<ac::CycleId,ac::AttemptId> tag{c,n};
            const std::string pathId=a->path.id; const qint64 proofDeadline=a->proofDeadline;
            QTimer::singleShot(int(qMax<qint64>(1,deadline-now()-100)),this,[weak,a,tag,pathId,proofDeadline] {
                auto live=weak.lock();
                if (!live || !a->proofDone || a->cancelled) return;
                // Review R17 V-1: an AWG path that ended early must never end the next path's proof
                // (an Xray path of the same exit runs on the same attempt).
                if (a->path.kind!=ac::PathKind::Awg || a->path.id!=pathId || a->proofDeadline!=proofDeadline) return;
                live->advanceProof(tag,a);
                if (!a->proofDone || a->cancelled) return; // proven by the last sample
                // No health at all keeps its own path (deadline: local start failure or silent exit).
                if (!a->health.valid || !a->expected.matches(a->health)) return;
                live->logNet(QStringLiteral("event=awg_unproven reason=no_handshake"));
                auto done=std::move(a->proofDone); done(tag.first,tag.second,{});
            });
        }
    }
    // Xray: no peer telemetry. Proof = one probe bound to this path's own tunnel interface (as
    // reported for this ticket), started after the path started: the exit agent answers inside
    // the tunnel with the nonce and this exit's id (no third-party site, 5.1.0.27).
    void advanceXrayProof(std::pair<ac::CycleId,ac::AttemptId> tag,const std::shared_ptr<Attempt>& a) {
        if(!a->proofDone || a->cancelled) return;
        if(now()>=a->proofDeadline || a->reset) { auto done=std::move(a->proofDone); done(tag.first,tag.second,{}); return; }
        if(!a->health.valid || !a->expected.matches(a->health)) return;
        if(!a->probing) {
            a->probing=true; a->probeStartedMono=now(); a->baselineRx=a->health.rxTotal; a->baselineTx=a->health.txTotal;
            MayakTunnelProbeRequest req; req.attemptTag=a->ticket.opaqueAttempt; req.localAddress=QHostAddress(a->health.localAddress.section('/',0,0));
            req.interfaceName=a->health.interfaceName; req.expectedExitId=QString::fromStdString(a->candidate.id); req.nonce=a->nonce;
            req.deadlineMs=int(qBound(qint64(1),qint64(a->proofDeadline-now()),qint64(8000)));
            auto self=shared_from_this();
            bridge->probe(a->ticket,req,a->proofDeadline,[self,a,tag](B::Ticket t,bool ok,MayakTunnelProbeProof proof,QString error) {
                if(!a->ticket.same(t) || !a->proofDone || a->cancelled) return;
                if(!ok && error==kAndroidVpnBindFailed && !a->xrayBindFirstFailMono) a->xrayBindFirstFailMono=self->now();
                const bool bindFailed=!ok && error==kAndroidVpnBindFailed;
                const bool bindRetry=bindFailed && self->now()-a->xrayBindFirstFailMono<kXrayBindRetryBudgetMs &&
                    self->now()+kXrayBindRetryMs<a->proofDeadline;
                if(bindFailed && !bindRetry)
                    self->logNet(QStringLiteral("event=xray_probe_bind_gave_up retries=%1").arg(a->xrayBindRetries));
                if(bindRetry) {
                    // Nothing was sent: a fresh probe (new start time, fresh baselines) follows after the
                    // pause. `probing` stays set meanwhile, so health samples cannot start it early.
                    if(++a->xrayBindRetries==1 || a->xrayBindRetries%8==0)
                        self->logNet(QStringLiteral("event=xray_probe_bind_retry retry=%1").arg(a->xrayBindRetries));
                    std::weak_ptr<Session> weak=self;
                    const auto ticket=a->ticket;
                    QTimer::singleShot(kXrayBindRetryMs,self.get(),[weak,a,tag,ticket] {
                        auto s=weak.lock();
                        if(!s || !a->ticket.same(ticket) || !a->proofDone || a->cancelled) return;
                        a->probing=false; s->advanceXrayProof(tag,a);
                    });
                    return;
                }
                if(!ok) { auto done=std::move(a->proofDone); done(tag.first,tag.second,{}); return; }
                a->tlsOk=true; a->proof=proof; self->advanceXrayProof(tag,a);
            });
            return;
        }
        if(!a->tlsOk) return;
        ac::ProofResult result; result.probeSucceeded=true;
        auto& e=result.evidence;
        e.nonceMatched=a->proof.nonce==a->nonce;
        e.nonce=a->nonce.toStdString(); e.observedExitId=a->proof.observedExitId.toStdString();
        e.rxBytesBefore=a->baselineRx; e.rxBytesAfter=a->health.rxTotal; e.counterReset=a->reset;
        e.pathId=a->path.id; e.probeStartedAt=a->probeStartedMono;
        e.interfaceBound=a->proof.attemptTag==a->ticket.opaqueAttempt && a->proof.interfaceName==a->health.interfaceName &&
            a->proof.localAddress==a->health.localAddress.section('/',0,0);
        auto done=std::move(a->proofDone); done(tag.first,tag.second,std::move(result));
    }
    void advanceProof(std::pair<ac::CycleId,ac::AttemptId> tag,const std::shared_ptr<Attempt>& a) {
        if (a->path.kind==ac::PathKind::Xray) { advanceXrayProof(tag,a); return; }
        if(!a->proofDone || a->cancelled) return;
        if(now()>=a->proofDeadline || a->reset) { auto done=std::move(a->proofDone); done(tag.first,tag.second,{}); return; }
        // Quick give-up: no handshake of this start in time (see RecoveryTiming::awgNoHandshakeMs),
        // only while another exit is left to try (Xray paths of this exit may still be dropped by
        // their race). The last exit keeps the full proof time (WireGuard repeats an unanswered
        // handshake after 5 s).
        const qint64 quickMs=recoveryTimingStorage().awgNoHandshakeMs;
        const bool moreToTry=cycleAcquires<cycleCandidates;
        if (quickMs>0 && moreToTry && !a->adopted && a->started && now()-a->startMono>=quickMs &&
            !(a->health.valid && a->expected.matches(a->health) && qint64(a->health.latestHandshakeEpochMs)>=(a->startUtc/1000)*1000)) {
            a->noHandshakeGaveUp=true;
            logNet(QStringLiteral("event=awg_no_handshake waited_ms=%1").arg(now()-a->startMono));
            auto done=std::move(a->proofDone); done(tag.first,tag.second,{}); return;
        }
        if(!a->health.valid || !a->expected.matches(a->health)) return;
        // 5.1.0.27 (no third-party sites): the tunnel proves itself, no network request. The counters
        // of this tunnel start at zero, so RX above zero is data received from our peer; an adopted
        // live session counts from its start too (its handshake bounds freshness below).
        if(!a->probing) { a->probing=true; a->baselineRx=0; a->baselineTx=0; }
        if(a->health.rxTotal<=a->baselineRx) return;
        const auto handshake=qint64(a->health.latestHandshakeEpochMs);
        // An independently established NEW activation context scopes the sample.
        // Backend timestamps may have one-second precision: reject any earlier
        // second, never convert an old handshake by stamping receipt time.
        const qint64 activationSecond=(a->startUtc/1000)*1000;
        const qint64 nowUtc=QDateTime::currentMSecsSinceEpoch();
        const bool clockSane=qAbs((nowUtc-a->startUtc)-(now()-a->startMono))<1500;
        // An adopted backend is not restarted (a new socket loses its first handshake and costs
        // seconds). Its session predates this attempt, so freshness is the live-session bound
        // instead: a handshake no older than WireGuard's reject-after-time (180 s), with data
        // received in this session.
        const bool adoptedLive=a->adopted && handshake>0 && handshake<=nowUtc && nowUtc-handshake<=180000;
        const qint64 handshakeMono=adoptedLive && handshake<a->startUtc ? a->startMono-(a->startUtc-handshake)
                                                                          : a->startMono+qMax<qint64>(0,handshake-a->startUtc);
        const bool fresh=clockSane && ((handshake>=activationSecond && handshake<=nowUtc) || adoptedLive);
        // No handshake of this start yet: wait for the next health sample (until the deadline).
        if(!fresh) return;
        ac::ProofResult result; result.probeSucceeded=true;
        auto& e=result.evidence;
        e.nonce=a->nonce.toStdString(); e.ownPeerId=a->expected.peerPublicKey.toStdString(); e.handshakeAt=handshakeMono;
        e.rxBytesBefore=a->baselineRx; e.rxBytesAfter=a->health.rxTotal; e.counterReset=a->reset; e.peerHandshakeObserved=true;
        e.adoptedLiveSession=adoptedLive;
        if (fresh && !a->adopted) logNet(QStringLiteral("event=awg_handshake after_start_ms=%1").arg(qMax<qint64>(0,handshake-a->startUtc)));
        auto done=std::move(a->proofDone); done(tag.first,tag.second,std::move(result));
    }
    void stopAndConfirm(ac::CycleId c,ac::AttemptId n,ac::Millis deadline,StopDone done) override {
        auto a=get(c,n); if(!a) { done(c,n,{false}); return; }
        if(!a->started) { a->stopped=true; done(c,n,{true}); return; }
        // A started backend that never got a single handshake answered (not the user's cancel):
        // this exit is unreachable from here; the next connects try it last.
        // (a->cancelled is set by the coordinator's own retry stop; the user's cancel is `cancelled`.)
        const bool noHealth=!a->health.valid && now()-a->startMono>=5000;
        if (a->path.kind==ac::PathKind::Awg && !a->adopted && !cancelled && (noHealth || a->noHandshakeGaveUp)) {
            if (noHealth && recoveryTimingStorage().noHealthMeansLocalFailure) {
                // Windows: no health = the tunnel interface never existed. Local, not the exit's fault.
                localStartFailed=true;
                logNet(QStringLiteral("event=local_start_failed waited_ms=%1").arg(now()-a->startMono));
                markWintunHealWanted();
            } else avoidCandidate(a->identity.candidateId,"no_handshake");
        }
        auto self=shared_from_this(); bridge->cancel(a->ticket);
        bridge->stopAndConfirm(a->ownTicket(),deadline,[self,a,c,n,done](B::Result r) {
            // Preserve exact observer evidence, but report this bounded call's
            // own result to the coordinator. A timed-out call must still fail;
            // a later OFF retry can use the retained evidence for reconciliation.
            const bool confirmed=self->noteNativeDown(a,r);
            done(c,n,{confirmed});
        });
    }
    void releaseAllocation(ac::CycleId c,ac::AttemptId n,const std::string& exact,BasicDone done) override {
        auto a=get(c,n);
        if(!a) { qInfo() << "MayakRelease started=false reason=attempt_missing"; return; }
        const bool cleanupConfirmed=!a->started || a->stopped;
        // A session from the stored exits: the coordinator names the offline handle. Once the late
        // acquire answered with a place, that place is released below like any other.
        if (a->offline && QString::fromStdString(exact)==a->offlineHandle && a->allocation==a->offlineHandle) {
            if (!cleanupConfirmed) { qInfo() << "MayakRelease started=false offline=true cleanup_confirmed=false"; return; }
            resetHttpsSockets("tunnel_stopped");
            bool removed=false;
            if (!a->lateSent || a->lateNoPlace || offlineRevoked) {
                // The server never saw this attempt or holds no place for it: nothing to release there.
                removed=store->removeAfterConfirmedCleanup(a->identity).ok;
                logNet(QStringLiteral("event=offline_release local=1 ok=%1").arg(removed ? 1 : 0));
            } else {
                // A late acquire went out without a final answer: the server may hold a place for this
                // attempt. Reconcile it at the next gateway answer (it releases every place of the attempt).
                removed=deferCleanup(a->identity,"offline_release");
            }
            std::weak_ptr<Session> weak=shared_from_this();
            QTimer::singleShot(0,this,[weak,c,n,done,removed] {
                auto self=weak.lock(); if (!self) return;
                if (!removed) {
                    self->cleanupPending=true; self->terminal=true;
                    self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,self->cleanupText());
                    return;
                }
                const auto remaining=self->store->load();
                if (!remaining.ok || !remaining.records.isEmpty()) {
                    self->cleanupPending=true;
                    if (self->cancelled) self->retryCleanup(true);
                    return;
                }
                if (done) done(c,n);
                if (self->cancelled) { self->cleanupPending=true; self->finishCleanup(); }
            });
            return;
        }
        const bool allocationMatches=a->allocation==QString::fromStdString(exact) ||
            (a->offline && QString::fromStdString(exact)==a->offlineHandle && !a->allocation.isEmpty());
        if(!allocationMatches || !cleanupConfirmed) {
            qInfo() << "MayakRelease started=false allocation_match=" << allocationMatches
                    << "cleanup_confirmed=" << cleanupConfirmed;
            return;
        }
        qInfo() << "MayakRelease started=true";
        // The tunnel is confirmed down: its connections are dead. The flag decides (an earlier path of
        // this attempt or an adopted tunnel may have run even when this path never started).
        resetHttpsSockets("tunnel_stopped");
        if (!cleanupDeadline || now()>=cleanupDeadline) cleanupDeadline=now()+10000;
        a->releasePending=true; a->releaseCallbackHandled=false; a->releaseLateHandled=false;
        auto self=shared_from_this(); ad::Request req; req.action="release"; req.attemptId=a->identity.attemptId;
        req.cycleToken=a->identity.cycleToken; req.allocationId=a->allocation; req.commonPayload=common; req.deadlineUtcMs=utcDeadline(now()+2500);
        ++inFlight;
        const quint64 operation=++cleanupGeneration;
        a->releaseOperationId=operation;
        auto settled=std::make_shared<bool>(false);
        auto timedOutSeen=std::make_shared<bool>(false);
        std::weak_ptr<Session> weak=self;
        // Android (20.11.2026, r9 on the owner's phone): the release right after the tunnel stop
        // connected while the dying VPN network was still the default one and was reset at once
        // ("connection reset, in tcp connect"); the disconnect then showed the cleanup error. A
        // release that never reached the server (no server answer at all) is sent again, twice at
        // most, within its own 2.5 s; a release of the same allocation is idempotent on the server.
        const qint64 releaseStarted=now();
        auto resend=std::make_shared<std::function<void()>>();
        auto resends=std::make_shared<int>(0);
        std::weak_ptr<std::function<void()>> weakResend=resend;
        auto finish=[weak,a,c,n,done,settled,timedOutSeen,operation,weakResend,resends,releaseStarted](ad::Response r, bool timedOut) {
            auto self=weak.lock(); if (!self) return;
            if (a->releaseOperationId!=operation) return;
            // Already moved to the deferred cleanup (no answer in time): a late positive settles it there.
            if (a->releaseDeferred) {
                if (!timedOut && r.success && r.authenticatedResponse) self->dropDeferred(a->identity.attemptId);
                return;
            }
            // The tunnel is confirmed down and the gateway gave no answer at all: with the stored exits
            // available, the OFF completes and the place is reconciled at the next gateway answer.
            const auto completeDeferred=[&self,&a,c,n,&done](bool first) {
                a->releaseDeferred=true;
                const auto remaining=self->store->load();
                if (!remaining.ok || !remaining.records.isEmpty()) {
                    self->cleanupPending=true;
                    if (self->cancelled) self->retryCleanup(true);
                    return;
                }
                if (first && done) done(c,n);
                if (self->cancelled || !first) { self->cleanupPending=true; self->finishCleanup(); }
            };
            if (!timedOut && !*settled && !r.authenticatedResponse && r.transportError!=ErrorCode::NoError &&
                *resends<2 && self->now()-releaseStarted<1500) {
                if (auto again=weakResend.lock()) {
                    const int delay=*resends==0 ? 300 : 600;
                    ++*resends;
                    self->logNet(QStringLiteral("event=release_resend try=%1 transport=%2").arg(*resends).arg(int(r.transportError)));
                    QTimer::singleShot(delay,self.get(),[again] { (*again)(); });
                    return;
                }
            }
            const bool first=!(*settled);
            if (!first && (timedOut || !*timedOutSeen || a->releaseLateHandled || !r.success || !r.authenticatedResponse)) return;
            if (first) *settled=true;
            if (timedOut) *timedOutSeen=true;
            else a->releaseLateHandled=true;
            if (first) { a->releaseCallbackHandled=true; a->releasePending=false; --self->inFlight; }
            if (timedOut && first && self->deferCleanup(a->identity,"release_no_answer")) { completeDeferred(first); return; }
            if (timedOut) {
                self->cleanupPending=true; self->terminal=true;
                self->phase=QStringLiteral("failed");
                self->output(Vpn::ConnectionState::Error,self->cleanupText());
                return;
            }
            qInfo() << "MayakRelease result transport_enum=" << int(r.transportError)
                    << "authenticated=" << r.authenticatedResponse
                    << "response_valid=" << r.responseValid << "success=" << r.success;
            if(r.success && r.authenticatedResponse) {
                const auto removal=self->store->removeAfterConfirmedCleanup(a->identity);
                qInfo() << "MayakRelease ledger_remove attempted=true ok=" << removal.ok
                        << "error_enum=" << int(removal.error);
                if(removal.ok) {
                    const auto remaining=self->store->load();
                    if (!remaining.ok || !remaining.records.isEmpty()) {
                        self->cleanupPending=true;
                        if (self->cancelled) self->retryCleanup(true);
                    } else {
                        // Timely completion belongs to the coordinator. A late
                        // positive cannot resume its already terminal cycle.
                        if (first && done) done(c,n);
                        if (self->cancelled || !first) {
                            self->cleanupPending=true;
                            self->finishCleanup();
                        }
                    }
                } else {
                    self->cleanupPending=true; self->terminal=true;
                    self->phase=QStringLiteral("failed");
                    self->output(Vpn::ConnectionState::Error,QStringLiteral("Сервер подтвердил остановку; локальная запись очистки ожидает сохранения. Нажмите «Повторить отключение»."));
                }
            } else if (!r.authenticatedResponse && first && self->deferCleanup(a->identity,"release_no_answer")) {
                completeDeferred(first);
            } else {
                qInfo() << "MayakRelease ledger_remove attempted=false reason=release_not_accepted";
                self->cleanupPending=true; self->terminal=true;
                self->phase=QStringLiteral("failed"); self->output(Vpn::ConnectionState::Error,self->cleanupText());
            }
        };
        // The posted callback keeps `resend` alive while a request is in flight (no ownership cycle).
        *resend=[finish,req,weak,resend=std::weak_ptr<std::function<void()>>(resend)] {
            auto self=weak.lock(); auto keep=resend.lock(); if (!self || !keep) return;
            ad::MayakAdmissionClient::postAsync(req,self->transport,[finish,keep](ad::Response response) { finish(response,false); });
        };
        QTimer::singleShot(2500,this,[finish,resend] { finish({},true); });
        (*resend)();
    }
    void reportProven(ac::CycleId c,ac::AttemptId n,const std::string&,BasicDone done) override {
        auto a=get(c,n); if(!a) return;
        auto self=shared_from_this();
        if (a->offline && a->allocation==a->offlineHandle) {
            // Started from the stored exits: there is no place to name yet. «Подключено» never waits
            // for the gateway; the late acquire (then proven) runs in the background.
            std::weak_ptr<Session> weak=self;
            QTimer::singleShot(0,this,[weak,c,n,done] {
                auto self=weak.lock(); if (self && done && !self->terminal && !self->cancelled) done(c,n);
            });
            sendLate(c,n,a,0);
            return;
        }
        const qint64 budget=recoveryTimingStorage().provenReportMs;
        ++inFlight;
        auto settled=std::make_shared<bool>(false);
        std::weak_ptr<Session> weak=self;
        auto finish=[weak,settled,c,n,done] {
            auto self=weak.lock(); if (!self || *settled) return;
            *settled=true; --self->inFlight;
            if (done && !self->terminal && !self->cancelled) done(c,n);
        };
        QTimer::singleShot(budget,this,finish);
        sendProven(c,n,a,budget,0,std::make_shared<bool>(false),a->allocation,[finish] { finish(); });
    }
    // One "proven" post for the connected attempt. A server answer (proven or refused) ends the
    // report; a try without an answer (timeout, network) is repeated in the background, never
    // holding the session busy, while the same attempt stays connected.
    void sendProven(ac::CycleId c,ac::AttemptId n,const std::shared_ptr<Attempt>& a,qint64 budget,int tryIndex,
                    std::shared_ptr<bool> delivered,const QString& allocation,std::function<void()> first) {
        ad::Request req; req.action="proven"; req.attemptId=a->identity.attemptId;
        req.cycleToken=a->identity.cycleToken; req.allocationId=allocation; req.commonPayload=common;
        req.deadlineUtcMs=utcDeadline(now()+budget);
        std::weak_ptr<Session> weak=shared_from_this();
        a->provenInFlight=true;
        ad::MayakAdmissionClient::postAsync(req,transport,[weak,a,c,n,tryIndex,delivered,allocation,first](ad::Response r) {
            a->provenInFlight=false;
            if (first) first();
            auto self=weak.lock(); if (!self || *delivered) return;
            // Any authenticated server reply means the report arrived; only a missing reply is repeated.
            if (r.responseValid || r.isError || (r.authenticatedResponse && r.transportError==amnezia::ErrorCode::NoError)) {
                *delivered=true; a->provenDelivered=true;
                if (r.isError && (r.error.code=="REVOKED" || r.error.code=="ACCOUNT_EXPIRED"))
                    self->offlineWipe(r.error.code=="REVOKED" ? "revoked" : "expired");
                if (tryIndex>0 || !r.success)
                    self->logNet(QStringLiteral("event=proven_report result=%1 try=%2")
                        .arg(r.success ? QStringLiteral("ok") : QStringLiteral("refused")).arg(tryIndex+1));
                return;
            }
            // A request the client cannot even build will not get better by repeating it.
            if (r.transportError==amnezia::ErrorCode::ApiConfigEmptyError) {
                self->logNet(QStringLiteral("event=proven_report result=invalid_request try=%1").arg(tryIndex+1));
                return;
            }
            self->logNet(QStringLiteral("event=proven_report result=no_answer try=%1 transport_error=%2")
                .arg(tryIndex+1).arg(int(r.transportError)));
            self->scheduleProvenRetry(c,n,a,tryIndex,delivered,allocation);
        });
    }
    void scheduleProvenRetry(ac::CycleId c,ac::AttemptId n,const std::shared_ptr<Attempt>& a,int tryIndex,
                             std::shared_ptr<bool> delivered,const QString& allocation) {
        const auto& delays=recoveryTimingStorage().provenRetryMs;
        if (tryIndex>=delays.size() || !provenStillWanted(c,n,a,allocation)) {
            logNet(QStringLiteral("event=proven_report result=%1 tries=%2")
                .arg(tryIndex>=delays.size() ? QStringLiteral("gave_up") : QStringLiteral("not_needed")).arg(tryIndex+1));
            return;
        }
        logNet(QStringLiteral("event=proven_report result=retry try=%1").arg(tryIndex+1));
        std::weak_ptr<Session> weak=shared_from_this();
        QTimer::singleShot(delays.at(tryIndex),this,[weak,a,c,n,tryIndex,delivered,allocation] {
            auto self=weak.lock(); if (!self || *delivered || !self->provenStillWanted(c,n,a,allocation)) return;
            self->sendProven(c,n,a,recoveryTimingStorage().provenRetryBudgetMs,tryIndex+1,delivered,allocation,{});
        });
    }
    // The report still matters only for the same connected attempt on the same allocation.
    bool provenStillWanted(ac::CycleId c,ac::AttemptId n,const std::shared_ptr<Attempt>& a,const QString& allocation) {
        if (cancelled || terminal || !coordinator || get(c,n)!=a) return false;
        if (a->cancelled || a->stopped || a->releasePending || a->allocation!=allocation) return false;
        const auto& st=coordinator->status();
        return st.state==ac::State::Connected && st.cycle==c && st.attempt==n;
    }
    // ---------- Connect without the gateway (see OfflineMemory) ----------
    static qint64 utcNowMs() { return QDateTime::currentMSecsSinceEpoch(); }
    bool offlineUsable() const { return manualExit.isEmpty() && loadOfflineMemory(settings).usable(offlineOwnerKey,utcNowMs()); }
    void offlineWipe(const char* reason) {
        if (!settings || settings->storedValueClass(kOfflineMemoryKey)==SecureQSettings::StoredValueClass::Missing) return;
        settings->remove(kOfflineMemoryKey);
        logNet(QStringLiteral("event=offline_memory_wiped reason=%1").arg(QLatin1String(reason)));
    }
    // A signed v1/config: the owner's manual exit list for the home screen (empty = not offered).
    void rememberManualExits(const ad::ConnectionCapability& cap) {
        if (!app) return;
        QJsonArray list;
        for (const auto& x:cap.manualExits)
            list.append(QJsonObject{{QStringLiteral("id"),x.candidate.id},{QStringLiteral("city"),x.city},{QStringLiteral("auto"),x.autoSelect}});
        app->setMayakManualExits(list);
    }
    // A signed v1/config: the offered exits (configs of the same exit and address are kept) and the bound.
    void offlineRememberCapability(const ad::ConnectionCapability& cap) {
        if (!settings || offlineOwnerKey.isEmpty()) return;
        auto m=loadOfflineMemory(settings);
        if (m.owner!=offlineOwnerKey) m=OfflineMemory{offlineOwnerKey,0,{}};
        m.until=cap.offlineUntil.isValid() ? cap.offlineUntil.toMSecsSinceEpoch() : utcNowMs()+kOfflineDefaultMs;
        QList<OfflineExit> next;
        for (const auto& c:cap.candidates) {
            OfflineExit e;
            for (const auto& old:m.exits) if (old.id.compare(c.id,Qt::CaseInsensitive)==0) { e=old; break; }
            if (!e.id.isEmpty() && e.host!=c.host) { e.encodedConfig.clear(); e.xrayPaths={}; e.tunnelHash.clear(); e.failures=0; }
            e.id=c.id; e.host=c.host; e.port=c.port; e.preferred=c.preferred; e.egress=c.expectedEgressIps;
            next<<e;
        }
        for (const auto& old:m.exits) {
            if (next.size()>=3) break;
            const bool listed=std::any_of(next.begin(),next.end(),[&old](const OfflineExit& e) { return e.id.compare(old.id,Qt::CaseInsensitive)==0; });
            if (!listed && old.usable()) next<<old;
        }
        m.exits=next;
        saveOfflineMemory(settings,m);
    }
    // A signed acquire (normal or late): this exit's config, Xray paths and card, as the server sent them.
    void offlineRememberAllocation(const std::shared_ptr<Attempt>& a,const ad::AcquireResponse& r) {
        if (!settings || offlineOwnerKey.isEmpty() || r.encodedConfig.isEmpty()) return;
        auto m=loadOfflineMemory(settings);
        if (m.owner!=offlineOwnerKey) m=OfflineMemory{offlineOwnerKey,0,{}};
        const QString id=a->identity.candidateId;
        int index=-1;
        for (int i=0;i<m.exits.size();++i) if (m.exits.at(i).id.compare(id,Qt::CaseInsensitive)==0) { index=i; break; }
        if (index<0) {
            OfflineExit e; e.id=id; e.host=QString::fromStdString(a->candidate.publicIpv4); e.port=a->candidate.port;
            e.preferred=a->candidate.preferred;
            for (const auto& ip:a->candidate.expectedEgressIps) e.egress<<QString::fromStdString(ip);
            m.exits.prepend(e); index=0;
            while (m.exits.size()>3) m.exits.removeLast();
        }
        auto& e=m.exits[index];
        const QString hash=offlineTunnelHash(r.encodedConfig);
        if (!e.tunnelHash.isEmpty() && e.tunnelHash!=hash) logNet(QStringLiteral("event=offline_config_changed"));
        e.encodedConfig=r.encodedConfig; e.tunnelHash=hash;
        if (r.xrayPathsOffered || !r.xrayPaths.isEmpty()) {
            QJsonArray xray;
            for (const auto& p:r.xrayPaths) xray.append(QJsonObject{{"id",p.id},{"fingerprint",p.fingerprint},{"config",p.encodedConfig}});
            e.xrayPaths=xray; // a request without paths (method "awg") keeps the stored ones
        }
        if (a->exitLocationHasCard || !a->exitLocationCityId.isEmpty()) {
            e.cityId=a->exitLocationCityId; e.hasCard=a->exitLocationHasCard; e.card=a->exitLocationCard;
        }
        saveOfflineMemory(settings,m);
    }
    void offlineMarkExit(const QString& id,bool ok) {
        if (!settings || offlineOwnerKey.isEmpty()) return;
        auto m=loadOfflineMemory(settings);
        if (m.owner!=offlineOwnerKey) return;
        for (auto& e:m.exits) {
            if (e.id.compare(id,Qt::CaseInsensitive)!=0) continue;
            if (ok) { if (e.failures==0 && e.okAt>utcNowMs()-60000) return; e.failures=0; e.okAt=utcNowMs(); }
            else ++e.failures;
            saveOfflineMemory(settings,m); return;
        }
    }
    // The stored exits as a candidate snapshot: this network's remembered exit first, then the
    // fewest failures and the latest success; an exit that just stopped working goes last.
    ac::Snapshot offlineSnapshot() {
        const auto m=loadOfflineMemory(settings);
        std::vector<OfflineExit> list;
        for (const auto& e:m.exits) if (e.usable()) list.push_back(e);
        const QString avoid=now()<avoidedExitStorage().until ? avoidedExitStorage().candidateId : QString();
        const auto rank=[this,&avoid](const OfflineExit& e) {
            return std::make_tuple(!avoid.isEmpty() && e.id.compare(avoid,Qt::CaseInsensitive)==0 ? 1 : 0,
                                   remembered.is(e.id) ? 0 : 1, e.failures, -e.okAt);
        };
        std::stable_sort(list.begin(),list.end(),[&rank](const OfflineExit& x,const OfflineExit& y) { return rank(x)<rank(y); });
        ac::Snapshot s; s.schemaVersion=1; s.revision="offline"; s.expiresAt=now()+120000;
        for (const auto& e:list) {
            if (s.candidates.size()>=3) break;
            ac::Candidate c{e.id.toStdString(),e.host.toStdString(),e.port,e.preferred,{}};
            for (const auto& ip:e.egress) c.expectedEgressIps.push_back(ip.toStdString());
            s.candidates.push_back(std::move(c));
        }
        avoidedExitStorage().knownExits=int(s.candidates.size());
        cycleAcquires=0; cycleCandidates=int(s.candidates.size());
        return s;
    }
    // Moves the exact attempt record (with its original device authority) to the deferred cleanup
    // (see DeferredCleanup). Only for a release/reconcile without any gateway answer, the tunnel
    // confirmed down, and only while the stored exits can carry the next connect.
    bool deferCleanup(const at::AttemptIdentity& identity,const char* reason) {
        if (!store || !offlineUsable()) return false;
        const auto loaded=store->load();
        if (!loaded.ok) return false;
        const auto it=std::find_if(loaded.records.begin(),loaded.records.end(),[&identity](const at::AttemptRecord& r) { return r.identity()==identity; });
        if (it==loaded.records.end()) return false;
        auto list=loadDeferredCleanup(settings);
        if (!std::any_of(list.begin(),list.end(),[&identity](const DeferredCleanup& d) { return d.identity.attemptId==identity.attemptId; })) {
            if (list.size()>=kDeferredCleanupMax) return false; // never drop an owed cleanup
            list<<DeferredCleanup{it->identity(),{it->gatewayEndpoint(),it->installationUuid(),it->publicKey(),it->deviceApiKey(),
                                                  it->serviceType(),it->serviceProtocol(),it->userCountryCode(),it->serverCountryCode()},0};
            saveDeferredCleanup(settings,list);
        }
        if (!store->removeAfterConfirmedCleanup(identity).ok) return false;
        logNet(QStringLiteral("event=cleanup_deferred reason=%1 pending=%2").arg(QLatin1String(reason)).arg(list.size()));
        return true;
    }
    void dropDeferred(const QString& attemptId) {
        auto list=loadDeferredCleanup(settings);
        const auto before=list.size();
        list.erase(std::remove_if(list.begin(),list.end(),[&attemptId](const DeferredCleanup& d) { return d.identity.attemptId==attemptId; }),list.end());
        if (list.size()!=before) saveDeferredCleanup(settings,list);
    }
    // Reconciles the deferred cleanups one by one (each tried once per call); then(true) when none is
    // left. An accepted reconcile settles an entry; a refused one counts against it (given up after
    // kDeferredCleanupRefusals); no answer stops with then(false). countBusy=false for background
    // sweeps (they never hold the session busy).
    void reconcileDeferred(qint64 deadline,std::function<void(bool)> then,bool countBusy=true,int index=0) {
        const auto list=loadDeferredCleanup(settings);
        if (index>=list.size()) { if (then) then(list.isEmpty()); return; }
        if (now()+500>=deadline) { if (then) then(false); return; }
        const auto d=list.at(index);
        ad::Request req; req.action="reconcile"; req.attemptId=d.identity.attemptId; req.cycleToken=d.identity.cycleToken;
        req.commonPayload=payloadForDeferred(d);
        const qint64 until=qMin(now()+2500,deadline); req.deadlineUtcMs=utcDeadline(until);
        if (countBusy) ++inFlight;
        auto settled=std::make_shared<bool>(false);
        std::weak_ptr<Session> weak=shared_from_this();
        auto settle=[weak,settled,d,deadline,then,countBusy,index](bool answered,bool ok) {
            auto self=weak.lock(); if (!self || *settled) return;
            *settled=true; if (countBusy) --self->inFlight;
            if (!answered) { if (then) then(false); return; }
            int next=index;
            if (ok) self->dropDeferred(d.identity.attemptId);
            else if (!self->countDeferredRefusal(d.identity.attemptId)) ++next; // kept: try the next entry
            self->logNet(QStringLiteral("event=cleanup_deferred_done reconciled=%1").arg(ok ? 1 : 0));
            self->reconcileDeferred(deadline,then,countBusy,next);
        };
        QTimer::singleShot(qMax<qint64>(1,until-now()),this,[settle] { settle(false,false); });
        ad::MayakAdmissionClient::postAsync(req,transport,[settle](ad::Response r) { settle(r.authenticatedResponse,r.success && r.authenticatedResponse); });
    }
    // One more refusal of this entry; true when it was given up (removed).
    bool countDeferredRefusal(const QString& attemptId) {
        auto list=loadDeferredCleanup(settings);
        for (int i=0;i<list.size();++i) {
            if (list.at(i).identity.attemptId!=attemptId) continue;
            if (++list[i].refusals>=kDeferredCleanupRefusals) {
                list.removeAt(i); saveDeferredCleanup(settings,list);
                logNet(QStringLiteral("event=cleanup_deferred_given_up"));
                return true;
            }
            saveDeferredCleanup(settings,list); return false;
        }
        return true;
    }
    // After an OFF with cleanups still owed: reconcile them in the background (30 s, 2 min, 10 min)
    // while this session is the app's current one, so a place left open does not hold capacity.
    void scheduleDeferredSweep(int step=0) {
        static const qint64 delays[]={30000,120000,600000};
        if (step>=3 || loadDeferredCleanup(settings).isEmpty()) return;
        std::weak_ptr<Session> weak=shared_from_this();
        QTimer::singleShot(delays[step],this,[weak,step] {
            auto self=weak.lock();
            if (!self || !self->facade || self->facade->m_session.get()!=self.get() || loadDeferredCleanup(self->settings).isEmpty()) return;
            self->reconcileDeferred(self->now()+15000,[weak,step](bool) { if (auto s=weak.lock()) s->scheduleDeferredSweep(step+1); },false);
        });
    }
    // The late acquire matters only while the same attempt is connected.
    bool lateStillWanted(ac::CycleId c,ac::AttemptId n,const std::shared_ptr<Attempt>& a) {
        if (!a || cancelled || terminal || !coordinator || get(c,n)!=a || a->cancelled || a->stopped || a->releasePending) return false;
        const auto& st=coordinator->status();
        return st.state==ac::State::Connected && st.cycle==c && st.attempt==n;
    }
    // The gateway revoked this device (or its access ended) during a session from the stored exits:
    // end it with that error (a start in progress ends at «Подключено», see state()).
    void endOfflineSession(ac::ErrorCategory category) {
        offlineRevoked=true; lateTerminal=category; reconnectWanted=false; connectRetryAt=0;
        if (!coordinator || coordinator->status().state!=ac::State::Connected) return;
        const auto cycle=coordinator->status().cycle;
        std::weak_ptr<Session> weak=shared_from_this();
        QTimer::singleShot(0,this,[weak,cycle] {
            auto self=weak.lock(); if (self && self->coordinator) self->coordinator->onOwnRepairExhausted(cycle);
        });
    }
    // Late acquire (late: true) of a session started from the stored exits, then proven. The server
    // records the place even over capacity and closes an older open place of this device; a repeat
    // with the same attempt returns the same place. No answer -> again later while connected.
    void sendLate(ac::CycleId c,ac::AttemptId n,const std::shared_ptr<Attempt>& a,int tryIndex) {
        if (!lateStillWanted(c,n,a) || a->lateSettled) return;
        a->lateSent=true;
        ad::Request req; req.action="acquire"; req.attemptId=a->identity.attemptId; req.cycleToken=a->identity.cycleToken;
        req.candidateId=a->identity.candidateId; req.commonPayload=common; req.late=true; req.requestPaths=method!=QStringLiteral("awg");
        req.deadlineUtcMs=utcDeadline(now()+recoveryTimingStorage().lateAcquireBudgetMs);
        logNet(QStringLiteral("event=late_acquire try=%1").arg(tryIndex+1));
        std::weak_ptr<Session> weak=shared_from_this();
        ad::MayakAdmissionClient::postAsync(req,transport,[weak,a,c,n,tryIndex](ad::Response r) {
            auto self=weak.lock(); if (!self || a->lateSettled) return;
            if (r.authenticatedResponse && r.isError &&
                (r.error.code=="REVOKED" || r.error.code=="ACCOUNT_EXPIRED")) {
                a->lateSettled=true; a->lateNoPlace=true;
                self->offlineWipe(r.error.code=="REVOKED" ? "revoked" : "expired");
                self->logNet(QStringLiteral("event=late_acquire result=%1").arg(r.error.code.toLower()));
                if (self->lateStillWanted(c,n,a))
                    self->endOfflineSession(r.error.code=="REVOKED" ? ac::ErrorCategory::AuthRevoked : ac::ErrorCategory::AccountExpired);
                return;
            }
            if (!self->lateStillWanted(c,n,a)) return; // released meanwhile: the deferred cleanup owns it
            if (r.authenticatedResponse && r.acquireValid && r.success) {
                a->lateSettled=true; a->allocation=r.acquire.allocationId;
                self->store->attachAllocation(a->identity,a->allocation);
                self->offlineRememberAllocation(a,r.acquire);
                self->logNet(QStringLiteral("event=late_acquire result=ok try=%1").arg(tryIndex+1));
                self->reconcileDeferred(self->now()+10000,{},false);
                self->sendProven(c,n,a,recoveryTimingStorage().provenRetryBudgetMs,0,std::make_shared<bool>(false),a->allocation,{});
                return;
            }
            if (r.authenticatedResponse && r.isError) {
                // NOT_READY / DISABLED: this exit is no longer for this device; the gateway answers now,
                // so reconnect the normal way. INVALID_REQUEST: the place is already closed (a later
                // acquire of this device); FULL: an older server without "late". No place is held.
                a->lateSettled=true; a->lateNoPlace=true;
                const QString code=r.error.code;
                self->logNet(QStringLiteral("event=late_acquire result=%1").arg(code.toLower()));
                if (code=="NOT_READY" || code=="DISABLED") {
                    self->reconnectWanted=true;
                    self->avoidCandidate(a->identity.candidateId,"late_not_ready");
                    self->coordinator->onOwnRepairExhausted(c);
                }
                return;
            }
            const auto& delays=recoveryTimingStorage().lateAcquireRetryMs;
            const qint64 delay=delays.isEmpty() ? 300000 : delays.at(qMin<qsizetype>(tryIndex,delays.size()-1));
            self->logNet(QStringLiteral("event=late_acquire result=no_answer try=%1 next_s=%2").arg(tryIndex+1).arg(delay/1000));
            std::weak_ptr<Session> again=self;
            QTimer::singleShot(delay,self.get(),[again,a,c,n,tryIndex] {
                auto self=again.lock(); if (self) self->sendLate(c,n,a,tryIndex+1);
            });
        });
    }
    void cancelOwned(ac::CycleId c,ac::AttemptId n) override {
        if (race.tag==std::make_pair(c,n)) stopRace();
        auto a=get(c,n); if(!a) return; a->cancelled=true; a->proofDone={}; bridge->cancel(a->ticket);
    }
    // ---------- Xray path race ----------
    // One xray engine with one password-protected loopback SOCKS entry per path (no tunnel, no
    // routes). Probes run in parallel through each entry; the first answers lead the order.
    void racePaths(ac::CycleId c,ac::AttemptId n,const std::vector<ac::Path>& paths,const std::vector<std::string>& egress,
                   ac::Millis deadline,RaceDone done) override {
        auto a=get(c,n);
        // a->cancelled is not checked: every stop of the previous path (AWG) sets it, and the race
        // runs between paths, before the next start clears it (it was skipped after every AWG failure).
        if (!a || cancelled || !bridge->canRace() || race.engineActive || paths.size()<2) {
            logNet(QStringLiteral("event=race_skipped paths=%1").arg(paths.size()));
            done(c,n,{false,{}}); return;
        }
        struct Lane { std::string id; quint16 port=0; QString user,pass,nonce; int state=0; }; // 0 running, 1 ok, 2 failed
        auto lanes=std::make_shared<std::vector<Lane>>();
        QJsonArray inbounds,outbounds,rules;
        for (const auto& path:paths) {
            const auto entry=std::find_if(a->xray.begin(),a->xray.end(),[&path](const XrayEntry& e){ return e.path.id.toStdString()==path.id; });
            const quint16 port=freeLoopbackPort();
            if (entry==a->xray.end() || !port) continue;
            Lane lane{path.id,port,B::randomRequestId().left(16),B::randomRequestId().left(32),randomId(),0};
            const QString index=QString::number(lanes->size());
            inbounds.append(QJsonObject{{"tag","in-"+index},{"listen","127.0.0.1"},{"port",port},{"protocol","socks"},
                {"settings",QJsonObject{{"auth","password"},{"udp",false},
                    {"accounts",QJsonArray{QJsonObject{{"user",lane.user},{"pass",lane.pass}}}}}}});
            QJsonObject outbound=entry->config.clientJson.value("outbounds").toArray().first().toObject();
            outbound.insert("tag","out-"+index);
            outbounds.append(outbound);
            rules.append(QJsonObject{{"type","field"},{"inboundTag",QJsonArray{"in-"+index}},{"outboundTag","out-"+index}});
            lanes->push_back(lane);
        }
        if (lanes->size()<2) { done(c,n,{false,{}}); return; }
        // Rule 5: no access/DNS log (an empty "access" would log every destination to stdout).
        const QJsonObject config{{"log",QJsonObject{{"loglevel","warning"},{"access","none"},{"dnsLog",false}}},{"inbounds",inbounds},{"outbounds",outbounds},
            {"routing",QJsonObject{{"domainStrategy","AsIs"},{"rules",rules}}}};
        race={}; race.engineActive=true; race.requestId=randomId(); race.tag={c,n};
        const QString request=race.requestId;
        const qint64 started=now();
        auto self=shared_from_this();
        auto settled=std::make_shared<bool>(false);
        // Order: answered lanes first (answer order), then lanes still running; failed ones dropped.
        auto order=std::make_shared<std::vector<std::string>>();
        const std::string preferred=a->rememberedFirst.toStdString();
        auto finish=[self,c,n,done,settled,lanes,order,request,started,preferred](bool ran) mutable {
            if (*settled) return; *settled=true;
            std::vector<std::string> result=*order;
            // The remembered path (proved on this network) leads when it answered the race.
            const auto it=std::find(result.begin(),result.end(),preferred);
            if (!preferred.empty() && it!=result.end()) std::rotate(result.begin(),it,it+1);
            int failed=0;
            for (const auto& lane:*lanes) { if (lane.state==0) result.push_back(lane.id); if (lane.state==2) ++failed; }
            QStringList shown; for (const auto& id:result) shown<<QString::fromStdString(id);
            self->logNet(QStringLiteral("event=race_done ran=%1 order=%2 failed=%3 elapsed_ms=%4")
                .arg(ran ? 1 : 0).arg(shown.join(',')).arg(failed).arg(self->now()-started));
            if (self->race.requestId==request) self->stopRace();
            done(c,n,{ran,ran ? result : std::vector<std::string>{}});
        };
        const qint64 raceEnd=deadline-300; // leave the engine stop inside the coordinator's budget
        QTimer::singleShot(int(qMax<qint64>(0,raceEnd-now())),this,[finish,lanes]() mutable {
            for (auto& lane:*lanes) if (lane.state==0) lane.state=2; // no answer in time = failed
            finish(true);
        });
        bridge->raceStart(request,config,qMin<qint64>(raceEnd,now()+2500),[self,a,lanes,order,finish,request,raceEnd](bool ok) mutable {
            if (self->race.requestId!=request || !self->race.engineActive) return;
            if (!ok) { self->logNet(QStringLiteral("event=race_engine_failed")); finish(false); return; }
            const QString exitId=QString::fromStdString(a->candidate.id);
            for (std::size_t i=0;i<lanes->size();++i) {
                auto& lane=(*lanes)[i];
                auto* probe=new MayakTunnelProbe(self.get());
                self->race.probes.push_back(probe);
                QObject::connect(probe,&MayakTunnelProbe::finished,self.get(),[self,lanes,order,finish,i,probe,request](quint64,bool success,MayakTunnelProbeProof,QString) mutable {
                    probe->deleteLater();
                    if (self->race.requestId!=request) return;
                    auto& lane=(*lanes)[i];
                    if (lane.state!=0) return;
                    lane.state=success ? 1 : 2;
                    if (success) {
                        order->push_back(lane.id);
                        // The fastest path is known: the others keep their chance only as fallback.
                        if (order->size()==1) QTimer::singleShot(300,self.get(),[finish]() mutable { finish(true); });
                    }
                    if (std::all_of(lanes->begin(),lanes->end(),[](const auto& l){ return l.state!=0; })) finish(true);
                });
                MayakTunnelProbeRequest req; req.attemptTag=request; req.nonce=lane.nonce; req.expectedExitId=exitId;
                req.socksPort=lane.port; req.socksUser=lane.user; req.socksPassword=lane.pass;
                req.deadlineMs=int(qBound(qint64(1),qint64(raceEnd-self->now()),qint64(8000)));
                probe->start(req);
            }
        });
    }
    void stopRace() {
        for (auto& probe:race.probes) if (probe) { probe->cancel(); probe->deleteLater(); }
        race.probes.clear();
        race.requestId.clear(); race.tag={0,0};
        if (!race.engineActive || race.stopping) return;
        race.stopping=true;
        auto self=shared_from_this();
        bridge->raceStop(QStringLiteral("stop"),now()+2000,[self](bool stopped) {
            self->race.stopping=false; self->race.engineActive=false;
            if (!stopped) self->logNet(QStringLiteral("event=race_stop_unconfirmed"));
            if (auto next=std::move(self->race.afterStop)) { self->race.afterStop={}; next(); }
        });
    }
    void logNet(const QString& text) const { qInfo().noquote() << QStringLiteral("MayakNet ") + text; }
    std::shared_ptr<Attempt> connectedAttempt() {
        if(!coordinator || cancelled || coordinator->status().state!=ac::State::Connected) return {};
        const auto s=coordinator->status(); return get(s.cycle,s.attempt);
    }
    void showRecovering() {
        if (rec.shown && rec.shownNoNetwork==rec.networkLost) return;
        rec.shown=true; rec.shownNoNetwork=rec.networkLost;
        // Beacon shows the verification animation; never the Connected city card.
        phase=QStringLiteral("verifying");
        output(Vpn::ConnectionState::Reconnecting, rec.networkLost ? QStringLiteral("Нет сети — ждём…")
                                                                  : QStringLiteral("Переподключение…"));
        logNet(QStringLiteral("event=ui_reconnecting no_network=%1").arg(rec.networkLost ? 1 : 0));
    }
    void onNetwork(const B::Ticket& ticket,bool available) {
        auto a=connectedAttempt();
        if (!a || !a->ticket.same(ticket) || a->cancelled) return;
        const auto& t=recoveryTimingStorage();
        if (!available) {
            if (!rec.networkLost) { rec.networkLost=true; rec.networkLostAt=now(); logNet(QStringLiteral("event=network_lost")); }
            return;
        }
        const bool wasLost=rec.networkLost;
        rec.networkLost=false; rec.networkChangedAt=now();
        // A genuinely new network earns a fresh recovery ladder, but an event caused by
        // (or racing) our own backend replacement never does: no recovery loop.
        if (!rec.lastRecoverAt || now()-rec.lastRecoverAt>=t.networkRecentMs) { rec.attempts=0; rec.nextAt=0; }
        rec.forceProbeAt=now()+t.networkSettleMs;
        monitorFor.reset(); // AWG counters: the first sample after a network change is a new baseline
        if (wasLost && rec.shown) showRecovering(); // "no network" -> "reconnecting"
        logNet(QStringLiteral("event=network_validated after_loss=%1").arg(wasLost ? 1 : 0));
    }
    // The UI was hidden (Android froze this process; health was paused by the service).
    // Health age therefore says nothing about the tunnel, and a backend replaced meanwhile by
    // the service watchdog (same proof context) is one authorized generation change, not a reset.
    void onResume(const B::Ticket& ticket,bool replaced,bool available) {
        auto a=connectedAttempt();
        if (!a || !a->ticket.same(ticket) || a->cancelled) return;
        a->healthAt=now();
        if (replaced) { a->replacementAllowedUntil=now()+8000; a->rxChangedAt=now(); }
        rec.forceProbeAt=now()+(replaced ? 1500 : 500); // verify the tunnel right away
        monitorFor.reset();
        logNet(QStringLiteral("event=ui_resume replaced=%1 no_network=%2").arg(replaced ? 1 : 0).arg(available ? 0 : 1));
        if (!available) onNetwork(ticket,false);
        else if (rec.networkLost) onNetwork(ticket,true);
    }
    void onVisibility(bool visible) {
        if (uiHidden==!visible) return;
        uiHidden=!visible;
        logNet(QStringLiteral("event=ui_%1").arg(visible ? QStringLiteral("visible") : QStringLiteral("hidden")));
        if (!visible) return;
        // Back in front: health resumes now; give it one interval before judging its age.
        if (auto a=connectedAttempt(); a && !a->cancelled) {
            a->healthAt=now(); lastMonitor=now();
            // Android freezes this (UI) process in the background; a "proven" that got no answer
            // before that is sent again now (review 02, item 5). Late proven: the place keeps its
            // first connect time on the server.
            const auto s=coordinator->status();
            if (!a->provenDelivered && !a->provenInFlight && (!a->offline || a->allocation!=a->offlineHandle) &&
                provenStillWanted(s.cycle,s.attempt,a,a->allocation)) {
                logNet(QStringLiteral("event=proven_report result=resend reason=ui_visible"));
                sendProven(s.cycle,s.attempt,a,recoveryTimingStorage().provenRetryBudgetMs,0,std::make_shared<bool>(false),a->allocation,{});
            }
        }
    }
    void startRecover(const std::shared_ptr<Attempt>& a) {
        const auto& t=recoveryTimingStorage();
        rec.inFlight=true; rec.lastRecoverAt=now();
        const int attempt=++rec.attempts;
        a->replacementAllowedUntil=now()+t.recoverDeadlineMs+3000;
        logNet(QStringLiteral("event=recover_request attempt=%1").arg(attempt));
        const qint64 started=now();
        auto self=shared_from_this();
        bridge->recover(a->ticket,now()+t.recoverDeadlineMs,[self,a,attempt,started](B::Result r) {
            const auto& t=recoveryTimingStorage();
            self->rec.inFlight=false;
            const bool ok=r.outcome==B::Outcome::Started;
            if (!ok) a->replacementAllowedUntil=0;
            self->logNet(QStringLiteral("event=%1 attempt=%2 elapsed_ms=%3")
                .arg(ok ? QStringLiteral("recover_backend_ok") : QStringLiteral("recover_failed")).arg(attempt).arg(self->now()-started));
            const auto& backoff=t.recoverBackoffMs;
            self->rec.nextAt=self->now()+(attempt<backoff.size() ? backoff.at(attempt) : backoff.isEmpty() ? 0 : backoff.last());
            // Verify promptly; a new-generation health sample may move this earlier.
            if (ok && !self->rec.forceProbeAt) self->rec.forceProbeAt=self->now()+1500;
            if (ok) self->monitorFor.reset(); // a new backend: its counters start again
        });
    }
    void onMonitorResult(const std::shared_ptr<Attempt>& a,bool ok) {
        const auto& t=recoveryTimingStorage();
        if (ok) {
            if (rec.shown) {
                logNet(QStringLiteral("event=recovered outage_ms=%1 recover_attempts=%2").arg(now()-rec.outageStart).arg(rec.attempts));
                phase=QStringLiteral("connected");
                output(Vpn::ConnectionState::Connected,QStringLiteral("Подключено"),connectedLocation);
            }
            rec={}; return;
        }
        if (++rec.probeFailures==1) rec.outageStart=now();
        logNet(QStringLiteral("event=probe_failed consecutive=%1 no_network=%2").arg(rec.probeFailures).arg(rec.networkLost ? 1 : 0));
        if (rec.probeFailures>=2) showRecovering();
        const bool recentNetwork=rec.networkChangedAt && now()-rec.networkChangedAt<t.networkRecentMs;
        const qint64 rxStale=now()-a->rxChangedAt;
        // A single random failure is not enough unless the underlying network just changed.
        const bool stuck=!rec.networkLost && (recentNetwork || rec.probeFailures>=2) &&
            rxStale>=(recentNetwork ? t.stuckRxAfterNetworkMs : t.stuckRxMs);
        if (stuck && a->path.kind==ac::PathKind::Awg && bridge->canRecover() && !rec.inFlight && rec.attempts<t.recoverBackoffMs.size() && now()>=rec.nextAt) {
            showRecovering();
            startRecover(a);
        }
    }
    void monitor() {
        auto a=connectedAttempt();
        if(!a || !a->health.valid || a->probing && a->proofDone) return;
        // Hidden UI: no health arrives by design and the service watchdog owns stuck-tunnel
        // repair. A probe failure here must never turn into a full stop of a working tunnel.
        if (uiHidden) return;
        const auto& t=recoveryTimingStorage();
        // A loss without any later network event must not block recovery forever.
        if (rec.networkLost && now()-rec.networkLostAt>=t.networkLostExpiryMs) {
            rec.networkLost=false; logNet(QStringLiteral("event=network_lost_expired"));
            if (rec.shown) showRecovering();
        }
        if (rec.networkLost && now()-rec.networkLostAt>=t.noNetworkUiMs) showRecovering();
        if (monitorProbing || rec.inFlight) return;
        const bool forced=rec.forceProbeAt && now()>=rec.forceProbeAt;
        if (!forced && now()-lastMonitor<(rec.probeFailures>0 ? t.retryProbeMs : t.monitorMs)) return;
        rec.forceProbeAt=0;
        const auto s=coordinator->status();
        monitorProbing=true; lastMonitor=now(); auto self=shared_from_this();
        const auto rx=a->health.rxTotal,tx=a->health.txTotal;
        if (a->path.kind==ac::PathKind::Awg) {
            // AWG (5.1.0.27): no network request at all. The tunnel's own counters and handshake
            // say whether our exit answers since the last sample:
            // - data received from our peer, or a newer handshake: a passed check (proof of life);
            // - data sent with nothing received: a failed check;
            // - nothing sent and nothing received (idle): no verdict either way (review R17 B-1:
            //   idle must never turn "Reconnecting" back into "Connected" without proof).
            // Review R17 B-2: health reports are periodic while the UI is visible (Windows every
            // second, Android service loop). None for 12 s: the backend died (service, WinTun).
            // That is a failed and degraded check (as a failed probe was in r9), never "idle".
            if (now()-a->healthAt>12000) {
                std::weak_ptr<Session> weak=self;
                QTimer::singleShot(0,this,[weak,a,s,rx,tx] { if (auto live=weak.lock()) live->onMonitorProbe(a,s,rx,tx,false); });
                return;
            }
            const quint64 handshake=a->health.latestHandshakeEpochMs;
            const bool sameTunnel=monitorFor.lock()==a && monitorGeneration==a->health.generation &&
                a->health.txTotal>=monitorTx && a->health.rxTotal>=monitorRx;
            const bool received=sameTunnel && (a->health.rxTotal>monitorRx || handshake>monitorHandshake);
            const bool sentNothingBack=sameTunnel && !received && a->health.txTotal>monitorTx;
            monitorFor=a; monitorGeneration=a->health.generation; monitorRx=a->health.rxTotal; monitorTx=a->health.txTotal;
            monitorHandshake=handshake;
            if (!received && !sentNothingBack) {
                // A first sample (this tunnel, a network change, a new backend) or idle: baseline only.
                monitorProbing=false; lastMonitor=now();
                return;
            }
            const bool ok=received;
            std::weak_ptr<Session> weak=self;
            QTimer::singleShot(0,this,[weak,a,s,rx,tx,ok] { if (auto live=weak.lock()) live->onMonitorProbe(a,s,rx,tx,ok); });
            return;
        }
        MayakTunnelProbeRequest req; req.attemptTag=a->ticket.opaqueAttempt; req.localAddress=QHostAddress(a->health.localAddress.section('/',0,0));
        req.interfaceName=a->health.interfaceName; req.expectedExitId=QString::fromStdString(a->candidate.id);
        req.nonce=randomId(); req.deadlineMs=int(t.probeDeadlineMs);
        bridge->probe(a->ticket,req,now()+t.probeDeadlineMs,[self,a,s,rx,tx](B::Ticket,bool ok,MayakTunnelProbeProof,QString) {
            self->onMonitorProbe(a,s,rx,tx,ok);
        });
    }
    void onMonitorProbe(const std::shared_ptr<Attempt>& a,ac::Status s,quint64 rx,quint64 tx,bool ok) {
        auto self=shared_from_this();
        {
            self->monitorProbing=false; self->lastMonitor=self->now();
            if(!self->coordinator || self->cancelled || a->cancelled || self->uiHidden) return;
            const auto current=self->coordinator->status();
            if (current.state!=ac::State::Connected || current.cycle!=s.cycle || current.attempt!=s.attempt) return;
            // Idle RX or provider/API failure alone never tears down a tunnel.
            // Xray: no peer telemetry, and interface counters prove nothing (tun2socks answers TCP
            // locally on Windows; Android has none). A failed probe counts only while the network
            // is up and from the second failure in a row, so the third ends the path (2 degraded).
            const bool xray=a->path.kind==ac::PathKind::Xray;
            // AWG: data sent without anything back (ok=false) is only "degraded" once our exit has
            // not answered a handshake for WireGuard's reject-after-time (180 s).
            (void)rx; (void)tx;
            const bool degraded=xray ? (!ok && !self->rec.networkLost && self->rec.probeFailures>=1) :
                (a->reset || self->now()-a->healthAt>12000 ||
                (!ok && QDateTime::currentMSecsSinceEpoch()-qint64(a->health.latestHandshakeEpochMs)>180000));
            if(!ok && degraded) {
                self->reconnectWanted=true;
                // If this ends the cycle, the next one tries another exit first.
                if (self->rec.probeFailures>=1) self->avoidCandidate(a->identity.candidateId);
            }
            self->onMonitorResult(a,ok);
            self->coordinator->onConnectedProbe(s.cycle,ok,degraded);
            if(ok) self->reconnectWanted=false;
        }
    }
};

MayakAutoConnectRuntime::MayakAutoConnectRuntime(SecureQSettings* settings,SecureServersRepository* servers,
    SecureAppSettingsRepository* app,SubscriptionController* subscription,ConnectionController* connection,
    B::Port port,QObject* parent,ad::Transport transport)
    : QObject(parent),m_settings(settings),m_servers(servers),m_app(app),m_subscription(subscription),m_connection(connection),m_port(std::move(port)),
      m_transport(transport?std::move(transport):gatewayTransport()) {}
MayakAutoConnectRuntime::~MayakAutoConnectRuntime() {
    if(m_session) { m_session->facade=nullptr; m_session->stopUser(); m_session->coordinator.reset(); }
}
MayakAutoConnectRuntime::RecoveryTiming MayakAutoConnectRuntime::recoveryTiming() { return recoveryTimingStorage(); }
void MayakAutoConnectRuntime::setRecoveryTimingForTests(const RecoveryTiming& timing) { recoveryTimingStorage()=timing; }
void MayakAutoConnectRuntime::resetFailoverMemoryForTests() { avoidedExitStorage()={}; localStartRetriesStorage()={}; }
void MayakAutoConnectRuntime::setWintunHealForTests(std::function<void(QObject*, std::function<void(bool, QString)>)> hook) {
    wintunHealStorage()=std::move(hook);
}
void MayakAutoConnectRuntime::setPortPrecheckForTests(PortPrecheck hook) { portPrecheckStorage()=hook ? std::move(hook) : PortPrecheck(tcpPortPrecheck); }
MayakAutoConnectRuntime::PortPrecheck MayakAutoConnectRuntime::realPortPrecheckForTests() { return tcpPortPrecheck; }
bool MayakAutoConnectRuntime::sameLocalNetworkForTests(const QStringList& before, const QStringList& now, const QString& tunnelAddress) {
    return sameLocalNetwork(before, now, tunnelAddress);
}
void MayakAutoConnectRuntime::setSplitPrepareForTests(std::function<void(QObject*, std::function<void(bool, QString)>)> hook) {
    splitPrepareStorage()=std::move(hook);
}
void MayakAutoConnectRuntime::setHttpsSocketResetForTests(std::function<int()> hook, bool startStale) {
    httpsSocketResetStorage()=hook ? std::move(hook) : std::function<int()>(shutdownOwnHttpsSockets);
    httpsSocketsMayBeStale()=startStale;
}
bool MayakAutoConnectRuntime::manages(const QString& id) const { return m_app && m_app->isMayakManagedServer(id); }
bool MayakAutoConnectRuntime::busy() const { return m_session && (m_session->cleanupPending || !m_session->terminal || m_session->inFlight>0); }
void MayakAutoConnectRuntime::publish(Vpn::ConnectionState state,const QString& text,const QString& phase,
                                      const QVariantMap& exitLocation,const QVariantMap& route) {
    m_message=text;
    m_connectionPhase=phase;
    m_exitLocation = state == Vpn::ConnectionState::Connected ? exitLocation : QVariantMap{};
    m_route = route;
    emit stateChanged(state,text);
}
void MayakAutoConnectRuntime::begin(const QString& id) {
    if(m_session && m_session->cleanupPending) return;
    if(busy()) return;
    if(m_session) { m_session->facade=nullptr; m_session->coordinator.reset(); m_session.reset(); }
    m_connectionPhase=QStringLiteral("preparing");
    m_session=std::make_shared<Session>(this,id); m_session->initialize();
}
void MayakAutoConnectRuntime::cancel() { if(m_session) m_session->stopUser(); }
bool MayakAutoConnectRuntime::cleanupPending() const { return m_session && m_session->cleanupPending; }
void MayakAutoConnectRuntime::retryCleanup() { if(m_session) m_session->userRetryCleanup(); }
void MayakAutoConnectRuntime::shutdown() {
    cancel();
    QElapsedTimer elapsed; elapsed.start();
    while(busy() && elapsed.elapsed()<5000) {
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents,20);
        QThread::msleep(5);
    }
    // Unconfirmed cleanup remains encrypted for reconciliation at next startup.
}
