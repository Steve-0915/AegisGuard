package com.aegis.guard.data.store

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * 设置项的强类型快照。
 *
 * 做成 data class + StateFlow 的原因：UI 只需要订阅一次 [Settings.state]，
 * 任何开关变化都会自动重组，避免满屏 registerOnSharedPreferenceChangeListener。
 */
data class SettingsState(
    /** 实时防护（前台服务常驻） */
    val realtimeProtection: Boolean = false,
    /** 启发式规则 */
    val heuristic: Boolean = true,
    /** 潜在有害应用（PUP / 广告软件） */
    val detectPup: Boolean = true,
    /** 云端情报查询（默认关闭，隐私优先） */
    val cloudLookup: Boolean = false,
    /** 最大扫描文件体积（字节） */
    val maxFileSize: Long = 64L * 1024 * 1024,
    /** 深入扫描压缩包 */
    val deepArchive: Boolean = true,
    /** DEX 字符串池分析 */
    val dexAnalysis: Boolean = true,
    /** 扫描隐藏文件 */
    val scanHidden: Boolean = false,
    /** 动态取色（Material You） */
    val dynamicColor: Boolean = true,
    /** 已完成引导 */
    val onboardingDone: Boolean = false,
    /** 最近一次扫描完成时间，0 表示从未 */
    val lastScanAt: Long = 0L,
    /** 病毒库版本 */
    val rulesVersion: String = "",
    /** CVE 库版本 */
    val cveVersion: String = ""
) {
    companion object {
        /** 可选的扫描体积上限，用于设置页下拉 */
        val SIZE_CHOICES = listOf(
            16L * 1024 * 1024 to "16 MB",
            32L * 1024 * 1024 to "32 MB",
            64L * 1024 * 1024 to "64 MB",
            128L * 1024 * 1024 to "128 MB",
            256L * 1024 * 1024 to "256 MB"
        )
    }
}

/**
 * 设置仓库。用 SharedPreferences 而非 DataStore：
 * 本应用无需跨进程同步，SharedPreferences 启动更快且零额外依赖。
 */
class Settings(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val _state = MutableStateFlow(read())
    val state: StateFlow<SettingsState> = _state.asStateFlow()

    /** 当前值的即时读取（非订阅） */
    fun current(): SettingsState = _state.value

    private fun read(): SettingsState = SettingsState(
        realtimeProtection = prefs.getBoolean(K.REALTIME, false),
        heuristic = prefs.getBoolean(K.HEURISTIC, true),
        detectPup = prefs.getBoolean(K.PUP, true),
        cloudLookup = prefs.getBoolean(K.CLOUD, false),
        maxFileSize = prefs.getLong(K.MAX_SIZE, 64L * 1024 * 1024),
        deepArchive = prefs.getBoolean(K.ARCHIVE, true),
        dexAnalysis = prefs.getBoolean(K.DEX, true),
        scanHidden = prefs.getBoolean(K.HIDDEN, false),
        dynamicColor = prefs.getBoolean(K.DYNAMIC, true),
        onboardingDone = prefs.getBoolean(K.ONBOARDING, false),
        lastScanAt = prefs.getLong(K.LAST_SCAN, 0L),
        rulesVersion = prefs.getString(K.RULES_VER, "") ?: "",
        cveVersion = prefs.getString(K.CVE_VER, "") ?: ""
    )

    private fun mutate(block: (SharedPreferences.Editor) -> Unit) {
        prefs.edit { block(this) }
        _state.value = read()
    }

    fun setRealtime(v: Boolean) = mutate { it.putBoolean(K.REALTIME, v) }
    fun setHeuristic(v: Boolean) = mutate { it.putBoolean(K.HEURISTIC, v) }
    fun setPup(v: Boolean) = mutate { it.putBoolean(K.PUP, v) }
    fun setCloud(v: Boolean) = mutate { it.putBoolean(K.CLOUD, v) }
    fun setMaxFileSize(v: Long) = mutate { it.putLong(K.MAX_SIZE, v) }
    fun setDeepArchive(v: Boolean) = mutate { it.putBoolean(K.ARCHIVE, v) }
    fun setDex(v: Boolean) = mutate { it.putBoolean(K.DEX, v) }
    fun setScanHidden(v: Boolean) = mutate { it.putBoolean(K.HIDDEN, v) }
    fun setDynamicColor(v: Boolean) = mutate { it.putBoolean(K.DYNAMIC, v) }

    /** 偏好修正：若用户选择静态配色，需要重建 Activity 才能生效 */
    fun setOnboardingDone(v: Boolean) = mutate { it.putBoolean(K.ONBOARDING, v) }
    fun setLastScanAt(v: Long) = mutate { it.putLong(K.LAST_SCAN, v) }
    fun setRulesVersion(v: String) = mutate { it.putString(K.RULES_VER, v) }
    fun setCveVersion(v: String) = mutate { it.putString(K.CVE_VER, v) }

    /** 恢复出厂设置 */
    fun reset() {
        prefs.edit { clear() }
        _state.value = read()
    }

    private object K {
        const val REALTIME = "realtime"
        const val HEURISTIC = "heuristic"
        const val PUP = "pup"
        const val CLOUD = "cloud"
        const val MAX_SIZE = "max_size"
        const val ARCHIVE = "archive"
        const val DEX = "dex"
        const val HIDDEN = "hidden"
        const val DYNAMIC = "dynamic_color"
        const val ONBOARDING = "onboarding"
        const val LAST_SCAN = "last_scan_at"
        const val RULES_VER = "rules_version"
        const val CVE_VER = "cve_version"
    }

    companion object {
        private const val PREFS = "aegis_settings"
    }
}
