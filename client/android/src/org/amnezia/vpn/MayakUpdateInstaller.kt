package org.amnezia.vpn

import android.app.PendingIntent
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.os.PersistableBundle
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import java.io.File
import java.util.concurrent.TimeUnit
import org.amnezia.vpn.util.Log

private const val TAG = "MayakUpdateInstaller"
private const val UPDATE_CHANNEL_ID = "ru.mayaklight.vpn.updates"
private const val UPDATE_NOTIFICATION_ID = 1342
private const val INSTALL_JOB_ID = 1343
private const val DOWNLOAD_JOB_ID = 1344
private const val EXTRA_SESSION_ID = "session_id"
private const val EXTRA_URL = "url"
private const val EXTRA_SIZE = "size"
private const val EXTRA_SHA256 = "sha256"
private const val EXTRA_VERSION = "version"
private const val EXTRA_VERSION_CODE = "version_code"
private const val PENDING_PREFS = "mayak_update_pending"
private const val KEY_PENDING_SESSION = "session_id"
private const val KEY_PENDING_CODE = "version_code"
private const val PACKAGE_HOST = "mayaklight.ru"
private const val PACKAGE_PATH = "/updates/packages/"
private const val MAX_PACKAGE_BYTES = 512L * 1024 * 1024

/**
 * Mayak automatic update (owner's decision 20.11.2026): the app verifies the signed feed; a system
 * job downloads and checks the package (MayakUpdateDownloadJob); this installs it in the background
 * through the app's own PackageInstaller session:
 * - always through Mayak's own JobScheduler job: it commits when the phone is idle (screen off
 *   ~31 min) and the battery is not low, never while the user is using Mayak (device test 21.11:
 *   an immediate commit closed the app 4 s after it was opened). Android's
 *   commitSessionAfterInstallConstraintsAreMet is not used: it never re-checked while the VPN ran.
 * - if Android wants a confirmation at that moment (first update after an install by the system
 *   installer), the user gets one notification; afterwards Mayak is the installer.
 * A tunnel running at that moment is restarted after the update (MayakResume).
 */
object MayakUpdateInstaller {
    const val ACTION_STATUS = "ru.mayaklight.vpn.action.MAYAK_UPDATE_STATUS"

    /**
     * 0 failed, 1 accepted (the session is prepared on a background thread: copying ~140 MB must not
     * block the main thread), 2 needs the "install unknown apps" permission.
     */
    fun scheduleAsync(context: Context, apkPath: String): Int {
        val app = context.applicationContext
        if (!File(apkPath).isFile) return 0
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !app.packageManager.canRequestPackageInstalls()) return 2
        Thread({ schedule(app, apkPath) }, "MayakUpdateInstall").start()
        return 1
    }

    /**
     * Test of 20.11.2026: Android freezes the app's process ~35 s after it leaves the screen, so a
     * ~140 MB download inside the app never finished. The download is a system job instead (own
     * process, unmetered network only, retried by the system); the job checks size and SHA-256 of the
     * signed feed (verified by the app before) and then prepares the install as before.
     * 0 failed, 1 scheduled, 2 needs the "install unknown apps" permission.
     */
    fun scheduleDownload(context: Context, url: String, size: Long, sha256: String, version: String): Int {
        val app = context.applicationContext
        if (!acceptablePackage(url, size, sha256)) {
            Log.e(TAG, "MayakNet event=update_download_rejected")
            return 0
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !app.packageManager.canRequestPackageInstalls()) return 2
        val builder = JobInfo.Builder(DOWNLOAD_JOB_ID, ComponentName(app, MayakUpdateDownloadJob::class.java))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
            .setBackoffCriteria(TimeUnit.MINUTES.toMillis(1), JobInfo.BACKOFF_POLICY_EXPONENTIAL)
            .setExtras(PersistableBundle().apply {
                putString(EXTRA_URL, url)
                putLong(EXTRA_SIZE, size)
                putString(EXTRA_SHA256, sha256.lowercase())
                putString(EXTRA_VERSION, version)
            })
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setEstimatedNetworkBytes(size, 0)
        val scheduled = runCatching { app.getSystemService(JobScheduler::class.java).schedule(builder.build()) }
            .getOrDefault(JobScheduler.RESULT_FAILURE)
        if (scheduled != JobScheduler.RESULT_SUCCESS) {
            Log.e(TAG, "MayakNet event=update_download_schedule_failed")
            return 0
        }
        Log.i(TAG, "MayakNet event=update_download_scheduled version=$version size=$size")
        return 1
    }

    /** Only a Mayak package from the update folder of mayaklight.ru, of a sane size, with a SHA-256. */
    internal fun acceptablePackage(url: String, size: Long, sha256: String): Boolean {
        val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return false
        return uri.scheme == "https" && uri.host == PACKAGE_HOST && (uri.port == -1 || uri.port == 443) &&
            uri.rawQuery == null && uri.rawFragment == null && uri.userInfo == null &&
            (uri.rawPath ?: "").startsWith(PACKAGE_PATH) && !(uri.rawPath ?: "").contains("..") &&
            (uri.rawPath ?: "").endsWith(".apk") && size in 1..MAX_PACKAGE_BYTES &&
            sha256.length == 64 && sha256.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
    }

    /** The user turned automatic updates off: drop a prepared install. */
    fun cancel(context: Context) {
        val app = context.applicationContext
        runCatching { app.packageManager.packageInstaller.mySessions.forEach { app.packageManager.packageInstaller.abandonSession(it.sessionId) } }
        runCatching { app.getSystemService(JobScheduler::class.java).cancel(INSTALL_JOB_ID) }
        runCatching { app.getSystemService(JobScheduler::class.java).cancel(DOWNLOAD_JOB_ID) }
        runCatching { pendingPrefs(app).edit().clear().commit() }
        Log.i(TAG, "MayakNet event=update_install_cancelled")
    }

    internal fun downloadJobExtras(extras: PersistableBundle) = DownloadRequest(
        extras.getString(EXTRA_URL).orEmpty(), extras.getLong(EXTRA_SIZE, 0),
        extras.getString(EXTRA_SHA256).orEmpty(), extras.getString(EXTRA_VERSION).orEmpty()
    )

    internal data class DownloadRequest(val url: String, val size: Long, val sha256: String, val version: String)

    fun schedule(context: Context, apkPath: String): Int {
        val app = context.applicationContext
        val apk = File(apkPath)
        if (!apk.isFile || !apk.name.endsWith(".apk", ignoreCase = true)) return 0
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !app.packageManager.canRequestPackageInstalls()) return 2
        val installer = app.packageManager.packageInstaller
        // One pending update at a time: an older session of ours is replaced.
        installer.mySessions.forEach { runCatching { installer.abandonSession(it.sessionId) } }
        // Device test 21.11: only a package newer than the installed Mayak is ever prepared.
        val packageCode = archiveCode(app, apk.absolutePath)
        if (packageCode <= installedCode(app)) {
            Log.i(TAG, "MayakNet event=update_install_skipped reason=not_newer")
            return 0
        }
        return try {
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                setAppPackageName(app.packageName)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) setInstallReason(PackageManager.INSTALL_REASON_USER)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            }
            val sessionId = installer.createSession(params)
            rememberPending(app, sessionId, packageCode)
            installer.openSession(sessionId).use { session ->
                apk.inputStream().use { input ->
                    session.openWrite("base.apk", 0, apk.length()).use { output ->
                        input.copyTo(output)
                        session.fsync(output)
                    }
                }
            }
            // Device test 21.11 (5.1.0.40 -> 41): a session committed at once was installed by Android
            // without a question even for a package installed by adb, 4 s after the user opened Mayak
            // and pressed "connect": the app closed under the user's hands. Every install therefore
            // waits for Mayak's own job "device idle" (screen off ~31 min, nobody uses the phone),
            // whoever installed the current version. Android's "install when constraints are met"
            // is not used: it never re-checked its constraints while the VPN service ran. If Android
            // still wants a confirmation at that moment, the user gets one notification.
            val job = JobInfo.Builder(INSTALL_JOB_ID, ComponentName(app, MayakUpdateJob::class.java))
                .setRequiresDeviceIdle(true)
                .setRequiresBatteryNotLow(true)
                .setPersisted(true) // review R20 V-3: a reboot before the idle window keeps the update
                .setExtras(PersistableBundle().apply {
                    putInt(EXTRA_SESSION_ID, sessionId)
                    putLong(EXTRA_VERSION_CODE, packageCode)
                })
                .build()
            val scheduler = app.getSystemService(JobScheduler::class.java)
            if (scheduler.schedule(job) != JobScheduler.RESULT_SUCCESS) {
                installer.abandonSession(sessionId)
                return 0
            }
            Log.i(TAG, "MayakNet event=update_install_scheduled mode=job own=${if (isOwnInstaller(app)) 1 else 0}")
            1
        } catch (e: Exception) {
            Log.e(TAG, "MayakNet event=update_install_failed stage=schedule reason=${e.javaClass.simpleName}: ${e.message.orEmpty().take(160)}")
            0
        }
    }

    @Suppress("DEPRECATION")
    internal fun installedCode(context: Context): Long = runCatching { context.packageManager.getPackageInfo(context.packageName, 0) }
        .getOrNull()?.let { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) it.longVersionCode else it.versionCode.toLong() }
        ?: Long.MAX_VALUE

    /** Version code of a downloaded package of ours, -1 if it is not a Mayak package. */
    @Suppress("DEPRECATION")
    internal fun archiveCode(context: Context, path: String): Long = runCatching { context.packageManager.getPackageArchiveInfo(path, 0) }
        .getOrNull()?.takeIf { it.packageName == context.packageName }
        ?.let { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) it.longVersionCode else it.versionCode.toLong() } ?: -1L

    private fun pendingPrefs(context: Context) = context.applicationContext.getSharedPreferences(PENDING_PREFS, Context.MODE_PRIVATE)

    private fun rememberPending(context: Context, sessionId: Int, code: Long) {
        pendingPrefs(context).edit().putInt(KEY_PENDING_SESSION, sessionId).putLong(KEY_PENDING_CODE, code).commit()
    }

    /**
     * Device test 21.11: the user installed the same version by hand while Mayak's prepared update
     * waited for the idle window; the job then installed it a second time (one more VPN break).
     * After any update (and before committing) a prepared install that is not newer than the
     * installed Mayak is dropped: its job is cancelled and its session abandoned.
     * Returns true when a prepared newer install is still pending.
     */
    fun dropStalePending(context: Context): Boolean {
        val app = context.applicationContext
        // 5.1.0.28: a download killed half-way leaves its file until the next download; after an update
        // (or at start) such leftovers older than 10 minutes go now (a running download is younger).
        runCatching {
            File(app.noBackupFilesDir, "mayak-update").listFiles()
                ?.filter { System.currentTimeMillis() - it.lastModified() > 10 * 60 * 1000L }?.forEach { it.delete() }
        }
        val prefs = pendingPrefs(app)
        val sessionId = prefs.getInt(KEY_PENDING_SESSION, -1)
        if (sessionId < 0) return false
        val code = prefs.getLong(KEY_PENDING_CODE, -1L)
        val installer = app.packageManager.packageInstaller
        val alive = runCatching { installer.getSessionInfo(sessionId) != null }.getOrDefault(false)
        if (alive && code > installedCode(app)) return true
        runCatching { app.getSystemService(JobScheduler::class.java).cancel(INSTALL_JOB_ID) }
        if (alive) runCatching { installer.abandonSession(sessionId) }
        prefs.edit().clear().commit()
        Log.i(TAG, "MayakNet event=update_install_dropped reason=${if (alive) "not_newer" else "gone"}")
        return false
    }

    /** Mayak installed its current version itself (its own update session). */
    private fun isOwnInstaller(context: Context): Boolean = runCatching {
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
            context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName
        else @Suppress("DEPRECATION") context.packageManager.getInstallerPackageName(context.packageName)
        installer == context.packageName
    }.getOrDefault(false)

    fun commit(context: Context, sessionId: Int): Boolean = try {
        val app = context.applicationContext
        app.packageManager.packageInstaller.openSession(sessionId).use { it.commit(statusSender(app, sessionId)) }
        true
    } catch (e: Exception) {
        Log.e(TAG, "MayakNet event=update_install_failed stage=commit")
        false
    }

    private fun statusSender(context: Context, sessionId: Int) = PendingIntent.getBroadcast(
        context, sessionId,
        Intent(context, MayakUpdateStatusReceiver::class.java).setAction(ACTION_STATUS),
        PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
    ).intentSender

    /** The VPN was on before the update and did not come back by itself (Xray, or AWG not up in time). */
    fun notifyReconnect(context: Context) {
        val manager = NotificationManagerCompat.from(context)
        manager.createNotificationChannel(
            NotificationChannelCompat.Builder(UPDATE_CHANNEL_ID, NotificationManagerCompat.IMPORTANCE_DEFAULT)
                .setName("Обновления Маяка").build()
        )
        val open = PendingIntent.getActivity(context, UPDATE_NOTIFICATION_ID + 1, MayakLaunch.connectIntent(context),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(context, UPDATE_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_amnezia_round)
            .setContentTitle("Маяк обновлён")
            .setContentText("VPN сейчас выключен. Нажмите, чтобы подключить.")
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        runCatching { manager.notify(UPDATE_NOTIFICATION_ID + 1, notification) }
    }

    fun notifyConfirm(context: Context, confirm: Intent) {
        val manager = NotificationManagerCompat.from(context)
        manager.createNotificationChannel(
            NotificationChannelCompat.Builder(UPDATE_CHANNEL_ID, NotificationManagerCompat.IMPORTANCE_DEFAULT)
                .setName("Обновления Маяка").build()
        )
        val open = PendingIntent.getActivity(context, UPDATE_NOTIFICATION_ID,
            confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(context, UPDATE_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_amnezia_round)
            .setContentTitle("Обновление Маяка готово")
            .setContentText("Подтвердите установку один раз — дальше Маяк будет обновляться сам.")
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        runCatching { manager.notify(UPDATE_NOTIFICATION_ID, notification) }
            .onFailure { Log.e(TAG, "MayakNet event=update_confirm_notify_failed") }
    }
}

/** Install session results. */
class MayakUpdateStatusReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != MayakUpdateInstaller.ACTION_STATUS) return
        when (val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                // The first update through the app's own session: Android asks the user once.
                @Suppress("DEPRECATION")
                val confirm = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                    else intent.getParcelableExtra(Intent.EXTRA_INTENT)
                Log.i(TAG, "MayakNet event=update_install_needs_user")
                if (confirm != null) MayakUpdateInstaller.notifyConfirm(context, confirm)
            }
            PackageInstaller.STATUS_SUCCESS -> Log.i(TAG, "MayakNet event=update_install_ok")
            else -> Log.i(TAG, "MayakNet event=update_install_failed status=$status")
        }
    }
}

/** Commits the prepared session in an idle window (Mayak installed the current version itself). */
class MayakUpdateJob : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        val sessionId = params.extras.getInt(EXTRA_SESSION_ID, -1)
        // Never the same or an older version (the user may have installed it by hand meanwhile).
        val code = params.extras.getLong(EXTRA_VERSION_CODE, -1L)
        if (sessionId < 0 || code <= MayakUpdateInstaller.installedCode(this)) {
            if (sessionId >= 0) runCatching { packageManager.packageInstaller.abandonSession(sessionId) }
            runCatching { MayakUpdateInstaller.dropStalePending(this) }
            Log.i(TAG, "MayakNet event=update_install_commit ok=0 reason=not_newer")
            return false
        }
        val ok = MayakUpdateInstaller.commit(this, sessionId)
        Log.i(TAG, "MayakNet event=update_install_commit ok=${if (ok) 1 else 0}")
        return false
    }

    override fun onStopJob(params: JobParameters): Boolean = false
}

/**
 * Downloads the verified update in its own process (":mayakUpdate", never frozen while the job runs,
 * outside the app's socket resets) on an unmetered network, checks size and SHA-256 and prepares the
 * install. Network loss or a stop by the system: retried by the system; a wrong file: dropped (the app
 * schedules the version again after 24 h).
 */
class MayakUpdateDownloadJob : JobService() {
    // One stop flag per run: a stopped run never sees the "go" of the next one.
    private val runs = java.util.concurrent.ConcurrentHashMap<JobParameters, java.util.concurrent.atomic.AtomicBoolean>()

    private enum class Outcome { DONE, RETRY, FAILED }

    override fun onStartJob(params: JobParameters): Boolean {
        val request = MayakUpdateInstaller.downloadJobExtras(params.extras)
        val stopped = java.util.concurrent.atomic.AtomicBoolean(false)
        runs[params] = stopped
        Thread({
            val outcome = try {
                download(request, stopped)
            } catch (e: Exception) {
                Log.i(TAG, "MayakNet event=update_download_failed reason=${e.javaClass.simpleName}")
                Outcome.RETRY
            }
            Log.i(TAG, "MayakNet event=update_download_job_end outcome=${outcome.name.lowercase()}")
            if (runs.remove(params) != null && !stopped.get()) jobFinished(params, outcome == Outcome.RETRY)
        }, "MayakUpdateDownload").start()
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        runs.remove(params)?.set(true)
        Log.i(TAG, "MayakNet event=update_download_stopped reason=${if (Build.VERSION.SDK_INT >= 31) params.stopReason else -1}")
        return true // retried when the conditions hold again
    }

    private fun download(request: MayakUpdateInstaller.DownloadRequest, stopped: java.util.concurrent.atomic.AtomicBoolean): Outcome {
        if (!MayakUpdateInstaller.acceptablePackage(request.url, request.size, request.sha256)) {
            Log.e(TAG, "MayakNet event=update_download_rejected")
            return Outcome.FAILED
        }
        val installed = runCatching { packageManager.getPackageInfo(packageName, 0).versionName }.getOrNull()
        if (installed == request.version) {
            Log.i(TAG, "MayakNet event=update_download_skipped reason=installed version=${request.version}")
            return Outcome.DONE
        }
        val dir = File(noBackupFilesDir, "mayak-update").apply { mkdirs() }
        // Leftovers of earlier runs (a run that is still writing is younger than 10 minutes).
        dir.listFiles()?.filter { System.currentTimeMillis() - it.lastModified() > 10 * 60 * 1000L }?.forEach { it.delete() }
        val file = File(dir, "update-${System.nanoTime()}.apk")
        val started = android.os.SystemClock.elapsedRealtime()
        Log.i(TAG, "MayakNet event=update_download_start version=${request.version} size=${request.size}")
        val connection = (java.net.URL(request.url).openConnection() as javax.net.ssl.HttpsURLConnection).apply {
            instanceFollowRedirects = false
            useCaches = false
            connectTimeout = 20_000
            readTimeout = 30_000
            setRequestProperty("Accept-Encoding", "identity")
        }
        try {
            val code = connection.responseCode
            if (code != 200) {
                Log.i(TAG, "MayakNet event=update_download_failed http=$code")
                return Outcome.RETRY
            }
            val length = connection.contentLengthLong
            if (length >= 0 && length != request.size) {
                Log.e(TAG, "MayakNet event=update_download_failed reason=length")
                return Outcome.FAILED
            }
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            var total = 0L
            connection.inputStream.use { input ->
                file.outputStream().use { output ->
                    val buffer = ByteArray(1 shl 16)
                    while (true) {
                        if (stopped.get()) { file.delete(); return Outcome.RETRY }
                        val read = input.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > request.size) {
                            Log.e(TAG, "MayakNet event=update_download_failed reason=oversize")
                            return Outcome.FAILED
                        }
                        output.write(buffer, 0, read)
                        digest.update(buffer, 0, read)
                    }
                    output.fd.sync()
                }
            }
            if (total != request.size) {
                Log.i(TAG, "MayakNet event=update_download_failed reason=short bytes=$total")
                return Outcome.RETRY
            }
            val hex = digest.digest().joinToString("") { "%02x".format(it) }
            if (hex != request.sha256) {
                file.delete()
                Log.e(TAG, "MayakNet event=update_download_failed reason=sha256")
                return Outcome.FAILED
            }
        } finally {
            connection.disconnect()
        }
        Log.i(TAG, "MayakNet event=update_downloaded elapsed_ms=${android.os.SystemClock.elapsedRealtime() - started}")
        // Only a newer Mayak: a job left from an older feed must never offer an older package.
        val installedCode = MayakUpdateInstaller.installedCode(this)
        val archiveCode = MayakUpdateInstaller.archiveCode(this, file.absolutePath)
        if (archiveCode <= installedCode) {
            file.delete()
            Log.i(TAG, "MayakNet event=update_download_skipped reason=not_newer code=$archiveCode installed=$installedCode")
            return Outcome.DONE
        }
        val result = MayakUpdateInstaller.schedule(this, file.absolutePath)
        file.delete()
        Log.i(TAG, "MayakNet event=update_download_handed result=$result")
        // No retry loop of ~140 MB downloads: a failed install is scheduled again by the app after 24 h.
        return if (result == 1) Outcome.DONE else Outcome.FAILED
    }
}
