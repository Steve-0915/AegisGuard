package com.aegis.guard.util

import android.content.Context
import androidx.annotation.ColorRes
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import com.aegis.guard.R
import com.aegis.guard.data.model.DetectionEngine
import com.aegis.guard.data.model.Severity
import com.aegis.guard.data.model.TargetKind
import com.aegis.guard.data.model.ThreatType
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * UI 展示层映射。
 *
 * 把领域模型（Severity / ThreatType / DetectionEngine…）翻译成
 * 字符串资源、颜色资源与图标资源。集中在一处的好处是：
 * 新增一个威胁类型时，编译器只会在这里报"when 不完整"，不会漏改某个界面。
 */
object UiFormat {

    // ------------------------------------------------------------ 严重等级

    @StringRes
    fun severityLabel(s: Severity): Int = when (s) {
        Severity.CRITICAL -> R.string.severity_critical
        Severity.HIGH -> R.string.severity_high
        Severity.MEDIUM -> R.string.severity_medium
        Severity.LOW -> R.string.severity_low
        Severity.INFO -> R.string.severity_info
        Severity.CLEAN -> R.string.severity_clean
    }

    @ColorRes
    fun severityColor(s: Severity): Int = when (s) {
        Severity.CRITICAL -> R.color.threat_critical
        Severity.HIGH -> R.color.threat_high
        Severity.MEDIUM -> R.color.threat_medium
        Severity.LOW -> R.color.threat_low
        Severity.INFO -> R.color.threat_unknown
        Severity.CLEAN -> R.color.threat_clean
    }

    @ColorRes
    fun severityContainerColor(s: Severity): Int = when (s) {
        Severity.CRITICAL -> R.color.threat_critical_container
        Severity.HIGH -> R.color.threat_high_container
        Severity.MEDIUM -> R.color.threat_medium_container
        Severity.LOW -> R.color.threat_low_container
        Severity.INFO -> R.color.threat_unknown_container
        Severity.CLEAN -> R.color.threat_clean_container
    }

    // ------------------------------------------------------------ 威胁类型

    @StringRes
    fun typeLabel(t: ThreatType): Int = when (t) {
        ThreatType.MALWARE -> R.string.threat_type_malware
        ThreatType.TROJAN -> R.string.threat_type_trojan
        ThreatType.SPYWARE -> R.string.threat_type_spyware
        ThreatType.ADWARE -> R.string.threat_type_adware
        ThreatType.RANSOMWARE -> R.string.threat_type_ransomware
        ThreatType.RISKWARE -> R.string.threat_type_riskware
        ThreatType.EXPLOIT -> R.string.threat_type_exploit
        ThreatType.PUP -> R.string.threat_type_pup
        ThreatType.SUSPICIOUS -> R.string.threat_type_suspicious
    }

    @DrawableRes
    fun typeIcon(t: ThreatType): Int = when (t) {
        ThreatType.ADWARE, ThreatType.PUP -> R.drawable.ic_info
        ThreatType.RANSOMWARE, ThreatType.TROJAN, ThreatType.MALWARE -> R.drawable.ic_danger
        ThreatType.EXPLOIT -> R.drawable.ic_warning
        ThreatType.SPYWARE -> R.drawable.ic_bug
        ThreatType.RISKWARE, ThreatType.SUSPICIOUS -> R.drawable.ic_warning
    }

    // ------------------------------------------------------------ 检测引擎

    fun engineLabel(e: DetectionEngine): String = when (e) {
        DetectionEngine.SIGNATURE -> "特征库匹配"
        DetectionEngine.HASH -> "哈希黑名单"
        DetectionEngine.HEURISTIC -> "启发式分析"
        DetectionEngine.PERMISSION -> "权限风险评分"
        DetectionEngine.STRUCTURE -> "结构异常检查"
        DetectionEngine.CLOUD -> "云端情报"
    }

    @DrawableRes
    fun targetIcon(k: TargetKind): Int = when (k) {
        TargetKind.PACKAGE -> R.drawable.ic_apk
        TargetKind.FILE -> R.drawable.ic_file
        TargetKind.APK -> R.drawable.ic_apk
        TargetKind.SYSTEM -> R.drawable.ic_shield
    }

    // ---------------------------------------------------------------- 时间

    private val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
    private val dateOnlyFmt = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())

    fun dateTime(ts: Long): String =
        if (ts <= 0L) "" else dateFmt.format(Date(ts))

    fun dateOnly(ts: Long): String =
        if (ts <= 0L) "" else dateOnlyFmt.format(Date(ts))

    /** 相对时间：3 分钟前 / 2 天前 */
    fun relative(context: Context, ts: Long): String {
        if (ts <= 0L) return context.getString(R.string.stat_never)
        val diff = System.currentTimeMillis() - ts
        val min = TimeUnit.MILLISECONDS.toMinutes(diff)
        val hour = TimeUnit.MILLISECONDS.toHours(diff)
        val day = TimeUnit.MILLISECONDS.toDays(diff)
        return when {
            min < 1 -> "刚刚"
            min < 60 -> "$min 分钟前"
            hour < 24 -> "$hour 小时前"
            day < 30 -> "$day 天前"
            else -> dateOnly(ts)
        }
    }

    /** 耗时：1.2 秒 / 2 分 05 秒 */
    fun duration(ms: Long): String {
        if (ms < 1000) return "$ms 毫秒"
        val totalSec = ms / 1000.0
        if (totalSec < 60) return String.format(Locale.US, "%.1f 秒", totalSec)
        val m = (ms / 60000).toInt()
        val s = ((ms % 60000) / 1000).toInt()
        return String.format(Locale.US, "%d 分 %02d 秒", m, s)
    }

    // ---------------------------------------------------------------- 体积

    fun bytes(v: Long): String {
        if (v < 1024) return "$v B"
        val kb = v / 1024.0
        if (kb < 1024) return String.format(Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format(Locale.US, "%.1f MB", mb)
        return String.format(Locale.US, "%.2f GB", mb / 1024.0)
    }

    /** 大数字加千分位 */
    fun count(v: Int): String = String.format(Locale.US, "%,d", v)
    fun count(v: Long): String = String.format(Locale.US, "%,d", v)

    /** 中间省略的哈希展示 */
    fun shortHash(hash: String?, keep: Int = 16): String {
        if (hash.isNullOrBlank()) return "—"
        return if (hash.length <= keep * 2) hash
        else "${hash.take(keep)}…${hash.takeLast(8)}"
    }
}