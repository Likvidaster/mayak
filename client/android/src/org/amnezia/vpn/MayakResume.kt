package org.amnezia.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import androidx.core.content.ContextCompat
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.Prefs

private const val TAG = "MayakResume"

/**
 * Mayak, update without losing the VPN (owner's decision 20.11.2026, Android variant 1).
 *
 * An app update kills every process of the app, the VPN services too, and only the app UI (Qt)
 * knows how to choose an exit and get admitted. So while a managed tunnel is CONNECTED, its
 * service keeps a copy of exactly that tunnel's configuration (its own encrypted file, one per
 * service process: AWG and Xray run in different processes) plus an "alive" time refreshed every
 * minute. Right after the update ([Intent.ACTION_MY_PACKAGE_REPLACED]) the same service brings
 * that tunnel back by itself: the allocation on the exit was never released. The next time the
 * app starts it adopts the running tunnel like after any app restart (managedInspect -> adopt).
 *
 * Safety:
 * - only a tunnel that was CONNECTED and alive within [RESUME_FRESH_MS] is restarted (never one the
 *   user or the app stopped: every in-process stop clears the copy);
 * - only with the VPN permission still granted;
 * - the service stops the restarted tunnel again if it did not come up in time
 *   (see AmneziaVpnService.resumeAfterUpdate).
 */
object MayakResume {
    const val ACTION_RESUME_AFTER_UPDATE = "ru.mayaklight.vpn.action.MAYAK_RESUME_AFTER_UPDATE"
    // An update kills the processes within seconds of the install; the heartbeat runs every minute.
    const val RESUME_FRESH_MS = 3 * 60 * 1000L
    const val HEARTBEAT_MS = 60 * 1000L

    private const val KEY_ALIVE_AT = "alive_at"
    private const val KEY_CONFIG = "config"

    fun kindOf(service: AmneziaVpnService): String = if (service is XrayService) "xray" else "awg"

    // Plain file: only a timestamp (read from the main process by the receiver).
    private fun markerPrefs(context: Context, kind: String): SharedPreferences =
        context.getSharedPreferences("mayak_resume_$kind", Context.MODE_PRIVATE)

    // Encrypted file of the service process: the tunnel configuration (it holds the device key).
    @Suppress("UNUSED_PARAMETER")
    private fun configPrefs(context: Context, kind: String): SharedPreferences? = Prefs.secureFile("mayak_resume_$kind")

    /** The managed tunnel of this service is CONNECTED: keep its configuration and mark it alive. */
    fun saveConnected(context: Context, kind: String, config: String) {
        val secure = configPrefs(context, kind) ?: return
        if (!secure.edit().putString(KEY_CONFIG, config).commit()) return
        markerPrefs(context, kind).edit().putLong(KEY_ALIVE_AT, System.currentTimeMillis()).apply()
    }

    fun heartbeat(context: Context, kind: String) {
        markerPrefs(context, kind).edit().putLong(KEY_ALIVE_AT, System.currentTimeMillis()).apply()
    }

    /** Stopped (by the user, the app or a failure) or adopted: never restart it. */
    fun clear(context: Context, kind: String) {
        markerPrefs(context, kind).edit().remove(KEY_ALIVE_AT).commit()
        configPrefs(context, kind)?.edit()?.remove(KEY_CONFIG)?.commit()
    }

    fun aliveAt(context: Context, kind: String): Long = markerPrefs(context, kind).getLong(KEY_ALIVE_AT, 0L)

    fun isFresh(context: Context, kind: String, now: Long = System.currentTimeMillis()): Boolean {
        val at = aliveAt(context, kind)
        return at > 0L && at <= now + 5_000L && now - at <= RESUME_FRESH_MS
    }

    /** The configuration to restart, once: it is removed as it is taken. */
    fun takeConfig(context: Context, kind: String): String? {
        val secure = configPrefs(context, kind) ?: return null
        val config = secure.getString(KEY_CONFIG, null)?.takeIf { it.isNotBlank() }
        secure.edit().remove(KEY_CONFIG).commit()
        markerPrefs(context, kind).edit().remove(KEY_ALIVE_AT).commit()
        return config
    }
}

/**
 * [Intent.ACTION_MY_PACKAGE_REPLACED] (protected: only the system sends it, so exported is safe):
 * restart the tunnel that was running when the update killed the app. Starting a foreground
 * service from this broadcast is allowed by Android's background start exemptions.
 */
class MayakUpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        // A prepared update that is not newer than this version (installed by hand) never runs.
        runCatching { MayakUpdateInstaller.dropStalePending(context) }
        val now = System.currentTimeMillis()
        // AWG and Xray (owner 21.11): the tunnel that was running comes back by itself.
        val kind = listOf("awg", "xray").firstOrNull { MayakResume.isFresh(context, it, now) }
        if (kind == null) {
            // An Xray tunnel (not restarted: no proof of life here) was running: say so, never silently.
            val xrayWasOn = runCatching { MayakLaunch.isManagedXrayActive(context) }.getOrDefault(false)
            Log.i(TAG, "MayakNet event=update_resume skipped=not_running xray=${if (xrayWasOn) 1 else 0}")
            if (xrayWasOn) MayakUpdateInstaller.notifyReconnect(context)
            return
        }
        if (runCatching { VpnService.prepare(context) != null }.getOrDefault(true)) {
            Log.i(TAG, "MayakNet event=update_resume skipped=no_permission")
            MayakResume.clear(context, kind)
            MayakUpdateInstaller.notifyReconnect(context)
            return
        }
        val service = if (kind == "xray") XrayService::class.java else AwgService::class.java
        Log.i(TAG, "MayakNet event=update_resume start=$kind")
        runCatching {
            ContextCompat.startForegroundService(context, Intent(context, service).setAction(MayakResume.ACTION_RESUME_AFTER_UPDATE))
        }.onFailure { Log.e(TAG, "MayakNet event=update_resume failed") }
    }
}
