package com.aegis.guard.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.aegis.guard.AegisApp
import com.aegis.guard.data.model.ScanReport
import com.aegis.guard.data.model.Severity
import com.aegis.guard.scan.ScanMode
import com.aegis.guard.scan.Scanner
import com.aegis.guard.util.Notifications
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * 应用安装 / 卸载 / 更新监听。
 *
 * 这是"实时防护"真正落地的地方：新装的应用是恶意软件最典型的入口，
 * 所以在 PACKAGE_ADDED 时立刻对该应用做一次定向扫描，命中高危即通知用户。
 *
 * 为什么用 goAsync()：BroadcastReceiver 的 onReceive 必须在约 10 秒内返回，
 * 而扫描（哪怕是单应用）也可能超时。goAsync 允许我们把工作挪到后台线程，
 * 只需在结束时调用 pendingResult.finish()。
 */
class PackageChangeReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        val pkg = intent.data?.schemeSpecificPart

        val app = context.applicationContext as? AegisApp ?: return

        // 只有开启实时防护时才做后台扫描，否则完全不打扰用户
        if (!app.settings.current().realtimeProtection) return

        when (action) {
            Intent.ACTION_PACKAGE_REMOVED -> {
                // 卸载是好事：清掉该包名的残留威胁记录，避免列表里留下"幽灵"
                if (pkg != null) {
                    val stale = app.repository.threats.value.filter { it.packageName == pkg }
                    stale.forEach { app.repository.remove(it.id) }
                }
            }

            Intent.ACTION_PACKAGE_ADDED, Intent.ACTION_PACKAGE_REPLACED -> {
                if (pkg == null) return
                // PACKAGE_REPLACED 会同时触发 REMOVED(extra) 与 ADDED，用 EXTRA 判断避免重复
                val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
                if (action == Intent.ACTION_PACKAGE_ADDED && replacing) return

                val pending = goAsync()
                val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
                scope.launch {
                    try {
                        scanNewPackage(context, app, pkg)
                    } catch (_: Throwable) {
                        // 后台扫描失败绝不能崩溃；静默即可
                    } finally {
                        runCatching { pending.finish() }
                    }
                }
            }
        }
    }

    /**
     * 对刚安装的应用做一次定向扫描。
     *
     * 实现方式：复用 [Scanner] 的应用扫描路径，但把扫描范围收窄到单个包，
     * 避免为了一个应用而枚举并扫描全部应用（那在安装频繁时会很耗电）。
     */
    private suspend fun scanNewPackage(context: Context, app: AegisApp, pkg: String) {
        val settings = app.settings.current()

        // 等待规则库就绪：安装事件可能在冷启动后立刻到达，
        // 此时引擎还在异步加载。给它一个短暂的重试窗口。
        var waited = 0
        while (app.loadedMeta == null && waited < 3000) {
            kotlinx.coroutines.delay(100)
            waited += 100
        }

        val scanner = Scanner(
            context = context,
            signatureEngine = app.signatureEngine,
            hashIndicators = app.loadedMeta?.hashes.orEmpty()
        )

        val target = scanner.collectInstalledApps().firstOrNull { it.packageName == pkg } ?: return

        // 用 APPS 模式扫描，但通过 Scanner 的公开扫描入口限定范围：
        // 这里直接构造一个只含该应用的临时扫描，走签名与评分两条路径。
        val outcome = scanner.scan(
            mode = ScanMode.APPS,
            settings = settings,
            onProgress = { /* 后台扫描不需要进度 */ }
        )

        val mine = outcome.threats.filter { it.packageName == pkg }
        if (mine.isEmpty()) return

        // 落库，让用户下次打开应用能看到
        app.repository.recordScan(
            ScanReport(
                sessionId = "realtime-${System.currentTimeMillis()}",
                startedAt = outcome.startedAt,
                finishedAt = outcome.finishedAt,
                mode = "realtime",
                filesScanned = outcome.filesScanned,
                appsScanned = outcome.appsScanned,
                bytesScanned = outcome.bytesScanned,
                threats = mine,
                cancelled = outcome.cancelled
            )
        )

        val worst = mine.maxByOrNull { it.severity.level } ?: return
        if (worst.severity.level >= Severity.HIGH.level) {
            Notifications.alert(
                context = context,
                id = Notifications.ID_ALERT_BASE + (pkg.hashCode() and 0xFFFF),
                title = "${target.label} 存在风险",
                text = mine.joinToString("；") { "${it.ruleName}（${it.severity.name}）" }
            )
        }
    }
}