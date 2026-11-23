#include "mayakCityPhotoUiController.h"

#include <QBuffer>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QImageReader>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStandardPaths>
#include <QUrl>

namespace {
const QRegularExpression &mediaPath()
{
    static const QRegularExpression re(
        QStringLiteral("^media/servers/[0-9a-f]{32}\\.(jpg|png|webp)\\?v=[0-9a-f]{12}\\z")); // \z: "$" would also accept a trailing newline
    return re;
}

QString defaultCacheDir()
{
    QString base = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
    if (base.isEmpty()) base = QDir::tempPath() + QStringLiteral("/mayak");
    return base + QStringLiteral("/city-photos");
}

constexpr int maxCachedPhotos = 12;
constexpr int maxSide = 4096; // the PNG decoder has no scaled read: bounds memory on phones
}

MayakCityPhotoUiController::MayakCityPhotoUiController(QObject *parent, const QString &cacheDir)
    : QObject(parent), m_cacheDir(cacheDir.isEmpty() ? defaultCacheDir() : cacheDir),
      m_network(new QNetworkAccessManager(this))
{
}

MayakCityPhotoUiController::~MayakCityPhotoUiController()
{
    if (m_reply) {
        m_reply->disconnect(this);
        m_reply->abort();
    }
}

bool MayakCityPhotoUiController::isAllowedUrl(const QString &url) const
{
    return !m_base.isEmpty() && url.startsWith(m_base) && mediaPath().match(url.mid(m_base.size())).hasMatch();
}

QString MayakCityPhotoUiController::cachePathFor(const QString &url) const
{
    const auto match = mediaPath().match(url.mid(m_base.size()));
    const QString ext = match.hasMatch() ? match.captured(1) : QStringLiteral("img");
    const QString name = QString::fromLatin1(
        QCryptographicHash::hash(url.toUtf8(), QCryptographicHash::Sha256).toHex().left(40));
    return QDir(m_cacheDir).filePath(name + QLatin1Char('.') + ext);
}

void MayakCityPhotoUiController::setSource(const QString &source)
{
    if (m_source == source) return;
    m_source = source;
    emit sourceChanged();
}

void MayakCityPhotoUiController::request(const QString &photoUrl)
{
    if (photoUrl == m_requested) return;
    if (m_reply) {
        QNetworkReply *previous = m_reply;
        m_reply = nullptr;
        previous->disconnect(this);
        previous->abort();
        previous->deleteLater();
    }
    m_requested = photoUrl;
    if (photoUrl.isEmpty()) { setSource({}); return; }
    if (!isAllowedUrl(photoUrl)) {
        qInfo().noquote() << "Mayak city photo: event=city_photo result=rejected reason=address";
        setSource({});
        emit finished(photoUrl, false);
        return;
    }
    const QString path = cachePathFor(photoUrl);
    const QFileInfo cached(path);
    if (cached.isFile() && cached.size() > 0 && cached.size() <= maxBytes) {
        setSource(QUrl::fromLocalFile(path).toString());
        emit finished(photoUrl, true);
        return;
    }
    setSource({}); // never keep another card's photo while this one loads
    QNetworkRequest req{QUrl(photoUrl)};
    req.setTransferTimeout(m_timeoutMs);
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    req.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    QNetworkReply *reply = m_network->get(req);
    m_reply = reply;
    connect(reply, &QNetworkReply::downloadProgress, this, [reply](qint64 received, qint64 total) {
        if (received > maxBytes || total > maxBytes) { reply->setProperty("mayakTooLarge", true); reply->abort(); }
    });
    connect(reply, &QNetworkReply::finished, this, [this, reply, photoUrl] { onReplyFinished(reply, photoUrl); });
}

void MayakCityPhotoUiController::onReplyFinished(QNetworkReply *reply, const QString &url)
{
    reply->deleteLater();
    if (m_reply == reply) m_reply = nullptr;
    if (url != m_requested) return;
    QString reason;
    const QString path = cachePathFor(url);
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (reply->property("mayakTooLarge").toBool()) {
        reason = QStringLiteral("size");
    } else if (reply->error() != QNetworkReply::NoError) {
        reason = QStringLiteral("network");
    } else if (status != 200) {
        reason = QStringLiteral("http_%1").arg(status);
    } else {
        const QByteArray data = reply->read(maxBytes + 1);
        if (data.isEmpty() || data.size() > maxBytes) {
            reason = QStringLiteral("size");
        } else {
            QBuffer buffer;
            buffer.setData(data);
            buffer.open(QIODevice::ReadOnly);
            QImageReader reader(&buffer);
            const QByteArray format = reader.format().toLower();
            const QSize size = reader.size();
            if ((format != "jpeg" && format != "jpg" && format != "png" && format != "webp") || !reader.canRead()
                || !size.isValid() || size.isEmpty() || size.width() > maxSide || size.height() > maxSide) {
                reason = QStringLiteral("image");
            } else {
                QDir().mkpath(m_cacheDir);
                QSaveFile file(path);
                if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size() || !file.commit())
                    reason = QStringLiteral("cache");
            }
        }
    }
    const bool ok = reason.isEmpty();
    qInfo().noquote() << QStringLiteral("Mayak city photo: event=city_photo result=%1%2")
                             .arg(ok ? QStringLiteral("ok") : QStringLiteral("failed"),
                                  ok ? QString() : QStringLiteral(" reason=") + reason);
    if (ok) {
        pruneCache(path);
        setSource(QUrl::fromLocalFile(path).toString());
    } else {
        setSource({});
    }
    emit finished(url, ok);
}

void MayakCityPhotoUiController::pruneCache(const QString &keep) const
{
    QDir dir(m_cacheDir);
    const QFileInfoList files = dir.entryInfoList(QDir::Files | QDir::NoDotAndDotDot, QDir::Time);
    int kept = 0;
    for (const QFileInfo &file : files) {
        if (file.absoluteFilePath() == QFileInfo(keep).absoluteFilePath()) { ++kept; continue; }
        if (kept < maxCachedPhotos) { ++kept; continue; }
        QFile::remove(file.absoluteFilePath());
    }
}
