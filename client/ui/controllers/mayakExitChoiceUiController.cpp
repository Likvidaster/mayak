#include "mayakExitChoiceUiController.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QVariantMap>
#include <algorithm>

#include "core/repositories/secureAppSettingsRepository.h"

MayakExitChoiceUiController::MayakExitChoiceUiController(SecureAppSettingsRepository *settings, QObject *parent)
    : QObject(parent), m_settings(settings)
{
    if (m_settings) {
        connect(m_settings, &SecureAppSettingsRepository::mayakManualExitsChanged, this, &MayakExitChoiceUiController::changed);
        connect(m_settings, &SecureAppSettingsRepository::mayakManualExitChanged, this, &MayakExitChoiceUiController::changed);
    }
}

bool MayakExitChoiceUiController::available() const
{
    return m_settings && !m_settings->mayakManualExits().isEmpty();
}

QVariantList MayakExitChoiceUiController::exits() const
{
    QVariantList list;
    if (!m_settings) return list;
    for (const QJsonValue &item : m_settings->mayakManualExits()) {
        const QJsonObject exit = item.toObject();
        const QString id = exit.value(QStringLiteral("id")).toString();
        const QString city = exit.value(QStringLiteral("city")).toString();
        if (id.isEmpty() || city.isEmpty()) continue;
        list.append(QVariantMap{{QStringLiteral("id"), id}, {QStringLiteral("city"), city},
                                {QStringLiteral("auto"), exit.value(QStringLiteral("auto")).toBool()}});
    }
    std::stable_sort(list.begin(), list.end(), [](const QVariant &a, const QVariant &b) {
        return QString::localeAwareCompare(a.toMap().value(QStringLiteral("city")).toString(),
                                           b.toMap().value(QStringLiteral("city")).toString()) < 0;
    });
    return list;
}

QString MayakExitChoiceUiController::selectedId() const
{
    return m_settings ? m_settings->mayakManualExit() : QString();
}

QString MayakExitChoiceUiController::selectedCity() const
{
    return m_settings ? m_settings->mayakManualExitCity() : QString();
}

bool MayakExitChoiceUiController::selectedOffered() const
{
    const QString id = selectedId();
    if (id.isEmpty()) return true;
    for (const QVariant &exit : exits())
        if (exit.toMap().value(QStringLiteral("id")).toString().compare(id, Qt::CaseInsensitive) == 0) return true;
    return false;
}

void MayakExitChoiceUiController::select(const QString &id)
{
    if (m_settings) m_settings->setMayakManualExit(id);
}
