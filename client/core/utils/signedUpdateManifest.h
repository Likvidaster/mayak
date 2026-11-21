#pragma once

// Mayak: signed update feed verification (Ed25519), shared by the app and the Windows service.

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QUrl>

struct SignedUpdateManifest {
    QString product;
    QString channel;
    QString platform;
    QString version;
    quint64 versionCode = 0;
    QUrl url;
    quint64 size = 0;
    QByteArray sha256;
    QDateTime publishedAt;
    QDateTime expiresAt;
    QString releaseNotes;
};

enum class SignedUpdateManifestDisposition { Newer, NoNewer };

namespace mayak::signedupdate {
// Same semantics as UpdateController::verifySignedManifest (it delegates here).
bool verifySignedManifest(const QByteArray &envelope, const QByteArray &publicKeyPem, const QString &expectedPlatform,
                          const QString &installedVersion, quint64 installedVersionCode, const QUrl &manifestUrl,
                          const QDateTime &nowUtc, SignedUpdateManifest *manifest, QString *error = nullptr,
                          SignedUpdateManifestDisposition *disposition = nullptr);
bool isAllowedPackageUrl(const QUrl &url, const QUrl &manifestUrl, QString *error = nullptr);
bool compareVersions(const QString &left, const QString &right, int *comparison = nullptr);
// "stable", or "test" in test builds (MAYAK_UPDATE_TEST_CHANNEL).
QString expectedChannel();
inline QString feedPath()
{
#if defined(MAYAK_UPDATE_TEST_CHANNEL)
    return QStringLiteral("/updates/test/");
#else
    return QStringLiteral("/updates/stable/");
#endif
}
}  // namespace mayak::signedupdate
