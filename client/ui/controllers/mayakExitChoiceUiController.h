#pragma once

#include <QObject>
#include <QString>
#include <QVariantList>

class SecureAppSettingsRepository;

// Mayak 5.1.0.29: the owner's manual exit choice under the connect button. The list comes only from the
// gateway (manual_exits, owner accounts); without it the control is hidden and connecting stays automatic.
class MayakExitChoiceUiController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool available READ available NOTIFY changed)
    // [{id, city, auto}] sorted by city; "auto" = the exit is in automatic selection (else a reserve).
    Q_PROPERTY(QVariantList exits READ exits NOTIFY changed)
    Q_PROPERTY(QString selectedId READ selectedId NOTIFY changed)
    // City of the chosen exit ("" = «Авто»); selectedOffered = it is still in the gateway's list.
    Q_PROPERTY(QString selectedCity READ selectedCity NOTIFY changed)
    Q_PROPERTY(bool selectedOffered READ selectedOffered NOTIFY changed)

public:
    explicit MayakExitChoiceUiController(SecureAppSettingsRepository *settings, QObject *parent = nullptr);

    bool available() const;
    QVariantList exits() const;
    QString selectedId() const;
    QString selectedCity() const;
    bool selectedOffered() const;

public slots:
    // "" = «Авто»; an unknown id is ignored. Applied from the next connect.
    void select(const QString &id);

signals:
    void changed();

private:
    SecureAppSettingsRepository *m_settings;
};
