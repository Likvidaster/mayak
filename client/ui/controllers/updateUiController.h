#ifndef UPDATEUICONTROLLER_H
#define UPDATEUICONTROLLER_H

#include <QObject>

#include "core/controllers/updateController.h"

class UpdateUiController : public QObject
{
    Q_OBJECT

    Q_PROPERTY(QString version READ getVersion NOTIFY updateMetadataChanged)
    Q_PROPERTY(QString releaseInfoText READ getReleaseInfoText NOTIFY updateMetadataChanged)
    Q_PROPERTY(QString description READ getDescription NOTIFY updateMetadataChanged)
    Q_PROPERTY(QStringList tags READ getTags NOTIFY updateMetadataChanged)
    Q_PROPERTY(QStringList newFeatures READ getNewFeatures NOTIFY updateMetadataChanged)
    Q_PROPERTY(QStringList improvements READ getImprovements NOTIFY updateMetadataChanged)
    Q_PROPERTY(QStringList bugFixes READ getBugFixes NOTIFY updateMetadataChanged)
    Q_PROPERTY(int updateState READ getUpdateState NOTIFY updateStateChanged)
    Q_PROPERTY(bool isStoreUpdate READ isStoreUpdate CONSTANT)
    Q_PROPERTY(bool isCheckRunning READ isCheckRunning NOTIFY isCheckRunningChanged)
    Q_PROPERTY(int downloadProgress READ downloadProgress NOTIFY downloadProgressChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(bool isUpdateSupported READ isUpdateSupported CONSTANT)
    Q_PROPERTY(bool autoUpdateEnabled READ autoUpdateEnabled WRITE setAutoUpdateEnabled NOTIFY autoUpdateEnabledChanged)
    Q_PROPERTY(bool needsInstallPermission READ needsInstallPermission NOTIFY needsInstallPermissionChanged)

public:
    explicit UpdateUiController(UpdateController* updateController, QObject *parent = nullptr);

    QString getVersion() const;
    QString getReleaseInfoText() const;
    QString getDescription() const;
    QStringList getTags() const;
    QStringList getNewFeatures() const;
    QStringList getImprovements() const;
    QStringList getBugFixes() const;
    int getUpdateState() const;
    bool isStoreUpdate() const;
    bool isCheckRunning() const;
    int downloadProgress() const;
    QString statusMessage() const;
    bool isUpdateSupported() const;
    bool autoUpdateEnabled() const;
    void setAutoUpdateEnabled(bool enabled);
    bool needsInstallPermission() const;

public slots:
    void checkForUpdates();
    void update();
    void install();
    void retry();
    void cancel();
    // Android: the "install unknown apps" page of Mayak; Android's VPN page ("Block connections without VPN").
    void openInstallPermissionSettings();
    void openVpnSystemSettings();

signals:
    void updateMetadataChanged();
    void manualCheckStarted();
    void updateFound();
    void updateNotFound();
    void updateCheckFailed();
    void updateStateChanged();
    void isCheckRunningChanged();
    void downloadProgressChanged();
    void statusMessageChanged();
    void autoUpdateEnabledChanged();
    void needsInstallPermissionChanged();

private:
    UpdateController* m_updateController;
};

#endif // UPDATEUICONTROLLER_H
