package com.aegis.guard.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.aegis.guard.AegisApp

/**
 * 开机自启接收器。
 *
 * 职责：如果用户开启过实时防护，开机后把前台服务重新拉起来。
 * 需要 RECEIVE_BOOT_COMPLETED 权限（已在清单声明）。
 *
 * 注意：Android 8.0+ 不允许从后台直接 startService，
 * 因此这里必须走 GuardService.start()（内部按版本选择 startForegroundService）。
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_LOCKED_BOOT_COMPLETED &&
            action != "android.intent.action.QUICKBOOT_POWERON"
        ) {
            return
        }

        val app = context.applicationContext as? AegisApp ?: return
        if (app.settings.current().realtimeProtection) {
            GuardService.start(context)
        }
    }
}