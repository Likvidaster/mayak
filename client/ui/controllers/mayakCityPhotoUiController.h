#ifndef MAYAKCITYPHOTOUICONTROLLER_H
#define MAYAKCITYPHOTOUICONTROLLER_H

#include <QObject>
#include <QPointer>
#include <QString>

class QNetworkAccessManager;
class QNetworkReply;

// Server photo of the admin city card (exit_location schema 2). QML asks for it only in «Подключено»,
// i.e. after the tunnel probe. Only our gateway's media path is fetched: one try, ~10 s, at most 2 MB,
// a decodable JPEG/PNG/WebP. The file is cached on disk by its full address (the address changes
// whenever the photo changes). Any failure just leaves no server photo; the UI falls back to the
// built-in one.
class MayakCityPhotoUiController final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString source READ source NOTIFY sourceChanged)
public:
    explicit MayakCityPhotoUiController(QObject *parent = nullptr, const QString &cacheDir = {});
    ~MayakCityPhotoUiController() override;

    // Absolute photo address from ConnectionController.exitLocation.card.photoUrl; "" clears.
    Q_INVOKABLE void request(const QString &photoUrl);
    // file: URL of the cached photo for the current request, or "".
    QString source() const { return m_source; }

    bool isAllowedUrl(const QString &url) const;
    QString cachePathFor(const QString &url) const;

    // Tests only: another gateway base (e.g. a local HTTP server) and a shorter timeout.
    void setGatewayBaseForTests(const QString &base) { m_base = base; }
    void setTimeoutForTests(int ms) { m_timeoutMs = ms; }
    static constexpr qint64 maxBytes = 2 * 1024 * 1024;

signals:
    void sourceChanged();
    // Tests/diagnostics: the current request ended (ok = server photo is shown).
    void finished(const QString &url, bool ok);

private:
    void setSource(const QString &source);
    void onReplyFinished(QNetworkReply *reply, const QString &url);
    void pruneCache(const QString &keep) const;

    QString m_cacheDir;
    QString m_base = QStringLiteral("https://mayaklight.ru/gw/");
    int m_timeoutMs = 10000;
    QString m_requested;
    QString m_source;
    QNetworkAccessManager *m_network = nullptr;
    QPointer<QNetworkReply> m_reply;
};

#endif // MAYAKCITYPHOTOUICONTROLLER_H
