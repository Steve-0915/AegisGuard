package com.aegis.guard.util

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.aegis.guard.R
import com.aegis.guard.ui.MainActivity

/**
 * 通知工具。
 *
 * 所有与通知渠道、前台服务通知、威胁告警相关的构造逻辑集中在这里，
 * 避免在各 Service / Activity 里重复写渠道判断与 PendingIntent 组装。
 */
object Notifications {

    /** 实时防护常驻通知（低优先级、静默） */
    const val CHANNEL_GUARD = "aegis_guard"

    /** 威胁告警通知（高优先级） */
    const val CHANNEL_ALERT = "aegis_alert"

    /** 前台服务通知 ID */
    const val ID_FOREGROUND = 1001

    /** 威胁告警通知 ID 基数 */
    const val ID_ALERT_BASE = 2000

    /**
     * 创建通知渠道。幂等，重复调用无副作用。
     * Android 8.0 以下无渠道概念，直接返回。
     */
    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = context.getSystemService(NotificationManager::class.java) ?: return

        // 常驻通知：低打扰，不出声、不弹横幅
        if (nm.getNotificationChannel(CHANNEL_GUARD) == null) {
            val guard = NotificationChannel(
                CHANNEL_GUARD,
                context.getString(R.string.card_engine_realtime),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = context.getString(R.string.settings_realtime_desc)
                setShowBadge(false)
                enableVibration(false)
                enableLights(false)
            }
            nm.createNotificationChannel(guard)
        }

        // 告警通知：需要用户注意
        if (nm.getNotificationChannel(CHANNEL_ALERT) == null) {
            val alert = NotificationChannel(
                CHANNEL_ALERT,
                context.getString(R.string.nav_home),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = context.getString(R.string.app_tagline)
                enableVibration(true)
            }
            nm.createNotificationChannel(alert)
        }
    }

    /** 是否已获得通知权限（Android 13+ 需要运行时申请） */
    fun hasPermission(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return ContextCompat.checkSelfPermission(
            context,
            android.Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * 构造前台服务通知。
     *
     * 注意：Android 14（API 34）起，前台服务必须在 startForeground 后
     * 5 秒内提供有效通知，否则系统会抛出 ForegroundServiceDidNotStartInTime。
     * 因此这里必须构造得快速且不依赖异步数据。
     */
    fun buildForeground(context: Context, text: String): Notification {
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val pi = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            },
            flags
        )

        return NotificationCompat.Builder(context, CHANNEL_GUARD)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(context.getString(R.string.realtime_notif_title))
            .setContentText(text)
            .setOngoing(true)
            .setShowWhen(false)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pi)
            .build()
    }

    /**
     * 发布一条威胁告警通知。
     */
    fun alert(context: Context, id: Int, title: String, text: String) {
        if (!hasPermission(context)) return
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val pi = PendingIntent.getActivity(
            context,
            id,
            Intent(context, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            },
            flags
        )

        val n = NotificationCompat.Builder(context, CHANNEL_ALERT)
            .setSmallIcon(R.drawable.ic_warning)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pi)
            .build()

        runCatching { NotificationManagerCompat.from(context).notify(id, n) }
    }
}