// Mayak: signed update feed verification (Ed25519), shared by the app (UpdateController) and the
// Windows service (it verifies an update itself before installing it as SYSTEM). Moved unchanged
// from updateController.cpp (5.1.0.27).
#include "signedUpdateManifest.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStringList>

#include <cmath>
#include <limits>

#include <openssl/evp.h>
#include <openssl/pem.h>

namespace mayak::signedupdate {
// Test builds of the automatic update (MAYAK_UPDATE_TEST_CHANNEL) accept the test channel only;
// every other build accepts "stable" only: a test feed can never update a real user.
QString expectedChannel()
{
#if defined(MAYAK_UPDATE_TEST_CHANNEL)
    return QStringLiteral("test");
#else
    return QStringLiteral("stable");
#endif
}

namespace
{
    constexpr qsizetype kMaxManifestBytes = 128 * 1024;
    constexpr quint64 kMaxPackageBytes = 512ULL * 1024ULL * 1024ULL;

    bool failWith(QString *error, const QString &message)
    {
        if (error) {
            *error = message;
        }
        return false;
    }

    bool isCanonicalBase64(const QString &text, QByteArray *decoded)
    {
        const QByteArray encoded = text.toLatin1();
        if (QString::fromLatin1(encoded) != text) {
            return false;
        }
        const QByteArray value = QByteArray::fromBase64(encoded);
        if (value.toBase64() != encoded) {
            return false;
        }
        *decoded = value;
        return true;
    }

    bool parseUtcTimestamp(const QString &text, QDateTime *result)
    {
        static const QRegularExpression utcPattern(
            QStringLiteral("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,3})?Z$"));
        if (!utcPattern.match(text).hasMatch()) {
            return false;
        }
        const QDateTime value = QDateTime::fromString(text, Qt::ISODateWithMs);
        if (!value.isValid() || value.timeSpec() != Qt::UTC) {
            return false;
        }
        *result = value.toUTC();
        return true;
    }

    QStringList jsonObjectKeys(const QJsonObject &object)
    {
        QStringList keys = object.keys();
        keys.sort();
        return keys;
    }

    bool readPositiveInteger(const QJsonObject &object, const QString &key, quint64 maxValue, quint64 *value)
    {
        const QJsonValue jsonValue = object.value(key);
        if (!jsonValue.isDouble()) {
            return false;
        }
        const double number = jsonValue.toDouble();
        if (!std::isfinite(number) || number < 1.0 || number > static_cast<double>(maxValue)
            || std::floor(number) != number) {
            return false;
        }
        *value = static_cast<quint64>(number);
        return true;
    }

    bool ed25519Verify(const QByteArray &publicKeyPem, const QByteArray &message, const QByteArray &signature)
    {
        if (publicKeyPem.isEmpty() || signature.size() != 64) {
            return false;
        }

        BIO *bio = BIO_new_mem_buf(publicKeyPem.constData(), static_cast<int>(publicKeyPem.size()));
        if (!bio) {
            return false;
        }
        EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_ED25519) {
            EVP_PKEY_free(key);
            return false;
        }

        EVP_MD_CTX *context = EVP_MD_CTX_new();
        const bool verified = context
            && EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1
            && EVP_DigestVerify(context,
                                reinterpret_cast<const unsigned char *>(signature.constData()),
                                static_cast<size_t>(signature.size()),
                                reinterpret_cast<const unsigned char *>(message.constData()),
                                static_cast<size_t>(message.size())) == 1;
        EVP_MD_CTX_free(context);
        EVP_PKEY_free(key);
        return verified;
    }

}  // namespace

bool compareVersions(const QString &left, const QString &right, int *comparison)
{
    static const QRegularExpression pattern(
        QStringLiteral("^(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})$"));
    const QRegularExpressionMatch leftMatch = pattern.match(left);
    const QRegularExpressionMatch rightMatch = pattern.match(right);
    if (!leftMatch.hasMatch() || !rightMatch.hasMatch()) {
        return false;
    }

    std::array<uint, 4> leftComponents{};
    std::array<uint, 4> rightComponents{};
    for (int i = 1; i <= 4; ++i) {
        bool leftOk = false;
        bool rightOk = false;
        leftComponents[static_cast<size_t>(i - 1)] = leftMatch.captured(i).toUInt(&leftOk);
        rightComponents[static_cast<size_t>(i - 1)] = rightMatch.captured(i).toUInt(&rightOk);
        if (!leftOk || !rightOk || leftComponents[static_cast<size_t>(i - 1)] > 65535
            || rightComponents[static_cast<size_t>(i - 1)] > 65535) {
            return false;
        }
    }
    for (size_t i = 0; i < leftComponents.size(); ++i) {
        if (leftComponents[i] != rightComponents[i]) {
            if (comparison) {
                *comparison = leftComponents[i] > rightComponents[i] ? 1 : -1;
            }
            return true;
        }
    }
    if (comparison) {
        *comparison = 0;
    }
    return true;
}

bool isAllowedPackageUrl(const QUrl &url, const QUrl &manifestUrl, QString *error)
{
    if (!url.isValid() || !manifestUrl.isValid() || url.scheme() != QStringLiteral("https")
        || manifestUrl.scheme() != QStringLiteral("https") || url.host().isEmpty()
        || url.host().compare(manifestUrl.host(), Qt::CaseInsensitive) != 0
        || url.port(443) != 443 || manifestUrl.port(443) != 443 || !url.userInfo().isEmpty()
        || !url.query().isEmpty() || !url.fragment().isEmpty()) {
        return failWith(error, QStringLiteral("The package URL must use the feed's HTTPS origin."));
    }

    const QString path = url.path(QUrl::FullyEncoded);
    static const QRegularExpression packagePath(QStringLiteral("^/updates/packages/[A-Za-z0-9][A-Za-z0-9._-]*$"));
    if (!packagePath.match(path).hasMatch() || path.contains(QStringLiteral("..")) || path.contains(QStringLiteral("//"))
        || path.contains(QLatin1Char('%')) || path.contains(QLatin1Char('\\'))) {
        return failWith(error, QStringLiteral("The package path is not allowed."));
    }
    return true;
}

bool verifySignedManifest(const QByteArray &envelopeBytes, const QByteArray &publicKeyPem,
                                            const QString &expectedPlatform, const QString &installedVersion,
                                            quint64 installedVersionCode, const QUrl &manifestUrl,
                                            const QDateTime &nowUtc, SignedUpdateManifest *manifest, QString *error,
                                            SignedUpdateManifestDisposition *disposition)
{
    if (!manifest || envelopeBytes.isEmpty() || envelopeBytes.size() > kMaxManifestBytes) {
        return failWith(error, QStringLiteral("The update manifest is empty or too large."));
    }
    if (expectedPlatform != QStringLiteral("windows-x64") && expectedPlatform != QStringLiteral("android-arm64")) {
        return failWith(error, QStringLiteral("This update platform is not supported."));
    }

    QJsonParseError parseError;
    const QJsonDocument envelopeDocument = QJsonDocument::fromJson(envelopeBytes, &parseError);
    if (parseError.error != QJsonParseError::NoError || !envelopeDocument.isObject()) {
        return failWith(error, QStringLiteral("The update envelope is malformed."));
    }
    const QJsonObject envelope = envelopeDocument.object();
    QStringList envelopeKeys = { QStringLiteral("alg"), QStringLiteral("payload"), QStringLiteral("schema"), QStringLiteral("signature") };
    envelopeKeys.sort();
    if (jsonObjectKeys(envelope) != envelopeKeys || !envelope.value(QStringLiteral("schema")).isDouble()
        || envelope.value(QStringLiteral("schema")).toInt(-1) != 1
        || envelope.value(QStringLiteral("alg")).toString() != QStringLiteral("Ed25519")
        || !envelope.value(QStringLiteral("payload")).isString()
        || !envelope.value(QStringLiteral("signature")).isString()) {
        return failWith(error, QStringLiteral("The update envelope fields are invalid."));
    }

    QByteArray payload;
    QByteArray signature;
    if (!isCanonicalBase64(envelope.value(QStringLiteral("payload")).toString(), &payload)
        || !isCanonicalBase64(envelope.value(QStringLiteral("signature")).toString(), &signature)
        || payload.isEmpty() || signature.size() != 64
        || QString::fromUtf8(payload).toUtf8() != payload) {
        return failWith(error, QStringLiteral("The update envelope encoding is invalid."));
    }
    if (!ed25519Verify(publicKeyPem, payload, signature)) {
        return failWith(error, QStringLiteral("The update signature is invalid."));
    }

    const QJsonDocument payloadDocument = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError || !payloadDocument.isObject()) {
        return failWith(error, QStringLiteral("The signed update payload is malformed."));
    }
    const QJsonObject object = payloadDocument.object();
    QStringList requiredKeys = {
        QStringLiteral("channel"), QStringLiteral("expiresAt"), QStringLiteral("platform"),
        QStringLiteral("product"), QStringLiteral("publishedAt"), QStringLiteral("sha256"),
        QStringLiteral("size"), QStringLiteral("url"), QStringLiteral("version"), QStringLiteral("versionCode")
    };
    if (object.contains(QStringLiteral("releaseNotes"))) {
        requiredKeys.append(QStringLiteral("releaseNotes"));
    }
    requiredKeys.sort();
    if (jsonObjectKeys(object) != requiredKeys) {
        return failWith(error, QStringLiteral("The signed update payload has unexpected fields."));
    }

    const auto isString = [&object](const QString &key) { return object.value(key).isString(); };
    if (!isString(QStringLiteral("product")) || object.value(QStringLiteral("product")).toString() != QStringLiteral("mayak-vpn")
        || !isString(QStringLiteral("channel")) || object.value(QStringLiteral("channel")).toString() != expectedChannel()
        || !isString(QStringLiteral("platform")) || object.value(QStringLiteral("platform")).toString() != expectedPlatform
        || !isString(QStringLiteral("version")) || !isString(QStringLiteral("url"))
        || !isString(QStringLiteral("sha256")) || !isString(QStringLiteral("publishedAt"))
        || !isString(QStringLiteral("expiresAt"))) {
        return failWith(error, QStringLiteral("The signed update does not match this product and platform."));
    }

    SignedUpdateManifest parsed;
    parsed.product = object.value(QStringLiteral("product")).toString();
    parsed.channel = object.value(QStringLiteral("channel")).toString();
    parsed.platform = object.value(QStringLiteral("platform")).toString();
    parsed.version = object.value(QStringLiteral("version")).toString();
    parsed.url = QUrl(object.value(QStringLiteral("url")).toString(), QUrl::StrictMode);
    parsed.sha256 = object.value(QStringLiteral("sha256")).toString().toLatin1();
    if (!QRegularExpression(QStringLiteral("^[0-9a-f]{64}$")).match(QString::fromLatin1(parsed.sha256)).hasMatch()) {
        return failWith(error, QStringLiteral("The signed package hash is malformed."));
    }

    quint64 size = 0;
    quint64 versionCode = 0;
    if (!readPositiveInteger(object, QStringLiteral("size"), kMaxPackageBytes, &size)
        || !readPositiveInteger(object, QStringLiteral("versionCode"), std::numeric_limits<quint32>::max(), &versionCode)) {
        return failWith(error, QStringLiteral("The signed package size or version code is invalid."));
    }
    parsed.size = size;
    parsed.versionCode = versionCode;

    int versionComparison = 0;
    if (!compareVersions(parsed.version, installedVersion, &versionComparison)) {
        return failWith(error, QStringLiteral("The signed update version is invalid."));
    }
    if (versionComparison > 0 && expectedPlatform == QStringLiteral("android-arm64") && versionCode <= installedVersionCode) {
        return failWith(error, QStringLiteral("The Android update version code is not newer than the installed app."));
    }
    if (!isAllowedPackageUrl(parsed.url, manifestUrl, error)) {
        return false;
    }
    if (expectedPlatform == QStringLiteral("windows-x64") && !parsed.url.path().endsWith(QStringLiteral(".exe"), Qt::CaseSensitive)) {
        return failWith(error, QStringLiteral("The Windows package must be an executable installer."));
    }
    if (expectedPlatform == QStringLiteral("android-arm64") && !parsed.url.path().endsWith(QStringLiteral(".apk"), Qt::CaseSensitive)) {
        return failWith(error, QStringLiteral("The Android package must be an APK."));
    }

    if (!parseUtcTimestamp(object.value(QStringLiteral("publishedAt")).toString(), &parsed.publishedAt)
        || !parseUtcTimestamp(object.value(QStringLiteral("expiresAt")).toString(), &parsed.expiresAt)
        || parsed.publishedAt >= parsed.expiresAt || parsed.publishedAt > nowUtc || parsed.expiresAt <= nowUtc) {
        return failWith(error, QStringLiteral("The signed update validity interval is invalid or expired."));
    }

    if (object.contains(QStringLiteral("releaseNotes"))) {
        if (!object.value(QStringLiteral("releaseNotes")).isString()) {
            return failWith(error, QStringLiteral("The update release notes must be plain text."));
        }
        parsed.releaseNotes = object.value(QStringLiteral("releaseNotes")).toString();
        if (parsed.releaseNotes.size() > 10000 || parsed.releaseNotes.contains(QChar::Null)) {
            return failWith(error, QStringLiteral("The update release notes are too long or malformed."));
        }
    }

    const SignedUpdateManifestDisposition parsedDisposition = versionComparison > 0
        ? SignedUpdateManifestDisposition::Newer : SignedUpdateManifestDisposition::NoNewer;
    if (disposition) {
        *disposition = parsedDisposition;
    }
    if (parsedDisposition == SignedUpdateManifestDisposition::NoNewer && !disposition) {
        return failWith(error, QStringLiteral("The signed update version is not newer than the installed version."));
    }

    *manifest = parsed;
    if (error) {
        error->clear();
    }
    return true;
}

}  // namespace mayak::signedupdate
