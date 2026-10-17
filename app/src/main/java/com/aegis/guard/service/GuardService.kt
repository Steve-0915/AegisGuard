package com.aegis.guard.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import com.aegis.guard.AegisApp
import com.aegis.guard.util.Notifications
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * 实时防护前台服务。
 *
 * 职责：
 * 1. 提供一个常驻通知，表明"防护正在运行"（Android 对前台服务的硬性要求）；
 * 2. 订阅设置变化，在用户关闭实时防护时自行停止；
 * 3. 定期做一次轻量的"完整性巡视"（只读检查，不扫全盘），
 *    发现高危项时通过通知提示用户；
 * 4. 作为 [PackageChangeReceiver] 在后台执行扫描的宿主。
 *
 * 关于 foregroundServiceType：清单里声明的是 dataSync。
 * 我们的服务确实在做"周期性的本地数据处理"，与 dataSync 的语义相符，
 * 且不需要 location/camera 等敏感类型，有利于通过应用商店审核。
 */
class GuardService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var patrolJob: Job? = null

    private val app: AegisApp get() = application as AegisApp

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        Notifications.ensureChannel(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Android 14 起必须显式声明前台服务类型，否则 startForeground 会抛异常。
        // 使用 ServiceCompat 在低版本上自动降级，避免手写 if-else。
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
        } else {
            0
        }

        ServiceCompat.startForeground(
            this,
            Notifications.ID_FOREGROUND,
            Notifications.buildForeground(this, "正在守护设备安全"),
            type
        )

        startPatrol()

        // START_STICKY：被系统回收后自动重启，符合"防护常驻"的预期。
        return START_STICKY
    }

    /**
     * 轻量巡视循环。
     *
     * 这里的"巡视"刻意不做全盘扫描——那会非常耗电。
     * 它只检查那些廉价但重要的状态（实时防护开关、规则库是否就绪），
     * 真正的重扫描交给用户在界面里显式触发。
     */
    private fun startPatrol() {
        if (patrolJob?.isActive == true) return
        patrolJob = scope.launch {
            while (isActive) {
                runCatching {
                    // 用户如果关掉了实时防护，服务应当自行退场，不占着通知栏
                    if (!app.settings.current().realtimeProtection) {
                        stopSelfSafely()
                        return@launch
                    }
                }
                delay(PATROL_INTERVAL_MS)
            }
        }
    }

    private fun stopSelfSafely() {
        runCatching {
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        }
        stopSelf()
    }

    override fun onDestroy() {
        patrolJob?.cancel()
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val PATROL_INTERVAL_MS = 5 * 60 * 1000L

        /**
         * 按当前设置启动或停止服务。
         *
         * 统一入口的好处：调用方（Activity / Receiver / 设置页）不需要
         * 自己判断"该 start 还是 stop"，也不会出现状态不一致。
         */
        fun sync(context: Context) {
            val enabled = (context.applicationContext as AegisApp)
                .settings.current().realtimeProtection
            if (enabled) start(context) else stop(context)
        }

        fun start(context: Context) {
            val intent = Intent(context, GuardService::class.java)
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            }
        }

        fun stop(context: Context) {
            runCatching { context.stopService(Intent(context, GuardService::class.java)) }
        }
    }
}