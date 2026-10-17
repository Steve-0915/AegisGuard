package com.aegis.guard.data.repo

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import com.aegis.guard.data.model.ScanReport
import com.aegis.guard.data.model.Severity
import com.aegis.guard.data.model.TargetKind
import com.aegis.guard.data.model.Threat
import com.aegis.guard.data.model.ThreatType
import com.aegis.guard.data.model.DetectionEngine
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * 威胁记录仓库。
 *
 * 持久化方案：JSON 字符串存进 SharedPreferences。
 * 为什么不上 Room？本应用的历史记录量级在**几百条**以内（超过这个数量
 * 我们会做上限裁剪），而 Room 会引入注解处理器、schema 导出与额外 dex 体积。
 * 用 Gson + 单文件足以，且零构建期风险。
 */
class ThreatRepository(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val gson = Gson()

    private val _threats = MutableStateFlow(loadThreats())
    /** 全部未清理的威胁记录（含已忽略），按危险等级与时间排序 */
    val threats: StateFlow<List<Threat>> = _threats.asStateFlow()

    private val _whitelist = MutableStateFlow(loadWhitelist())
    /** 白名单：包名或文件路径的集合，命中后不再报告 */
    val whitelist: StateFlow<Set<String>> = _whitelist.asStateFlow()

    private val _history = MutableStateFlow(loadHistory())
    /** 扫描历史（最近的在前） */
    val history: StateFlow<List<ScanReport>> = _history.asStateFlow()

    // ---------------------------------------------------------------- 威胁

    /**
     * 写入一次扫描的结果。
     *
     * 去重语义：同一 [Threat.id] 视为同一个问题。若已存在且被用户忽略过，
     * 则保持忽略状态（尊重用户决定），只刷新检测时间。
     */
    fun recordScan(report: ScanReport) {
        val existing = _threats.value.associateBy { it.id }.toMutableMap()
        val dismissedIds = existing.values.filter { it.dismissed }.map { it.id }.toSet()
        val wl = _whitelist.value

        for (t in report.threats) {
            // 白名单直接不落库
            if (isWhitelisted(t, wl)) continue
            val keepDismissed = t.id in dismissedIds
            existing[t.id] = if (keepDismissed) t.copy(dismissed = true) else t
        }

        // 裁剪：只保留最近 MAX_THREATS 条，优先丢弃低危且旧的
        val trimmed = existing.values
            .sortedWith(
                compareByDescending<Threat> { it.severity.level }
                    .thenByDescending { it.detectedAt }
            )
            .take(MAX_THREATS)

        persistThreats(trimmed)
        _threats.value = trimmed

        pushHistory(report)
    }

    /** 忽略单条威胁 */
    fun dismiss(threatId: String) = updateThreat(threatId) { it.copy(dismissed = true) }

    /** 取消忽略 */
    fun undismiss(threatId: String) = updateThreat(threatId) { it.copy(dismissed = false) }

    /** 从库中移除（用户已处置） */
    fun remove(threatId: String) {
        val next = _threats.value.filterNot { it.id == threatId }
        persistThreats(next)
        _threats.value = next
    }

    fun clearAll() {
        persistThreats(emptyList())
        _threats.value = emptyList()
        persistHistory(emptyList())
        _history.value = emptyList()
    }

    fun findById(id: String): Threat? = _threats.value.firstOrNull { it.id == id }

    /** 未忽略、且危险等级达到阈值的威胁数，用于首页状态卡 */
    fun activeThreatCount(minSeverity: Severity = Severity.LOW): Int =
        _threats.value.count { !it.dismissed && it.severity.level >= minSeverity.level }

    private fun updateThreat(id: String, transform: (Threat) -> Threat) {
        val next = _threats.value.map { if (it.id == id) transform(it) else it }
        persistThreats(next)
        _threats.value = next
    }

    private fun isWhitelisted(t: Threat, wl: Set<String>): Boolean {
        t.packageName?.let { if (it in wl) return true }
        t.filePath?.let { if (it in wl) return true }
        return false
    }

    // ------------------------------------------------------------- 白名单

    fun addToWhitelist(key: String) {
        if (key.isBlank()) return
        val next = _whitelist.value + key
        persistWhitelist(next)
        _whitelist.value = next
        // 加白后立刻清理既有记录
        val remaining = _threats.value.filterNot { isWhitelisted(it, next) }
        if (remaining.size != _threats.value.size) {
            persistThreats(remaining)
            _threats.value = remaining
        }
    }

    fun removeFromWhitelist(key: String) {
        val next = _whitelist.value - key
        persistWhitelist(next)
        _whitelist.value = next
    }

    // --------------------------------------------------------------- 历史

    private fun pushHistory(report: ScanReport) {
        val next = (listOf(report) + _history.value).take(MAX_HISTORY)
        persistHistory(next)
        _history.value = next
    }

    // --------------------------------------------------------- 序列化实现

    private fun loadThreats(): List<Threat> = runCatching {
        prefs.getString(K.THREATS, null)?.let { json ->
            val type = object : TypeToken<List<ThreatDto>>() {}.type
            gson.fromJson<List<ThreatDto>>(json, type).map { it.toModel() }
        }
    }.getOrNull() ?: emptyList()

    private fun persistThreats(list: List<Threat>) {
        runCatching {
            val dto = list.map { ThreatDto.from(it) }
            prefs.edit { putString(K.THREATS, gson.toJson(dto)) }
        }
    }

    private fun loadWhitelist(): Set<String> = runCatching {
        prefs.getStringSet(K.WHITELIST, null)?.toSet()
    }.getOrNull() ?: emptySet()

    private fun persistWhitelist(set: Set<String>) {
        prefs.edit { putStringSet(K.WHITELIST, set) }
    }

    private fun loadHistory(): List<ScanReport> = runCatching {
        prefs.getString(K.HISTORY, null)?.let { json ->
            val type = object : TypeToken<List<ReportDto>>() {}.type
            gson.fromJson<List<ReportDto>>(json, type).map { it.toModel() }
        }
    }.getOrNull() ?: emptyList()

    private fun persistHistory(list: List<ScanReport>) {
        runCatching {
            prefs.edit { putString(K.HISTORY, gson.toJson(list.map { ReportDto.from(it) })) }
        }
    }

    // -------------------------------------------------------------- DTO 层

    /**
     * 显式 DTO：不直接序列化 model，是为了让存储格式与领域模型解耦。
     * 枚举存字符串（可读、可迁移），升级时不会因为枚举常量重排而错位。
     */
    private data class ThreatDto(
        val id: String,
        val title: String,
        val ruleName: String,
        val severity: String,
        val type: String,
        val engine: String,
        val targetKind: String,
        val packageName: String?,
        val filePath: String?,
        val sha256: String?,
        val sizeBytes: Long,
        val detectedAt: Long,
        val evidence: List<String>,
        val advice: String,
        val cveIds: List<String>,
        val dismissed: Boolean
    ) {
        fun toModel() = Threat(
            id = id,
            title = title,
            ruleName = ruleName,
            severity = Severity.fromName(severity),
            type = ThreatType.fromKey(type),
            engine = runCatching { DetectionEngine.valueOf(engine) }.getOrDefault(DetectionEngine.SIGNATURE),
            targetKind = runCatching { TargetKind.valueOf(targetKind) }.getOrDefault(TargetKind.FILE),
            packageName = packageName,
            filePath = filePath,
            sha256 = sha256,
            sizeBytes = sizeBytes,
            detectedAt = detectedAt,
            evidence = evidence,
            advice = advice,
            cveIds = cveIds,
            dismissed = dismissed
        )

        companion object {
            fun from(t: Threat) = ThreatDto(
                id = t.id,
                title = t.title,
                ruleName = t.ruleName,
                severity = t.severity.name,
                type = t.type.key,
                engine = t.engine.name,
                targetKind = t.targetKind.name,
                packageName = t.packageName,
                filePath = t.filePath,
                sha256 = t.sha256,
                sizeBytes = t.sizeBytes,
                detectedAt = t.detectedAt,
                evidence = t.evidence,
                advice = t.advice,
                cveIds = t.cveIds,
                dismissed = t.dismissed
            )
        }
    }

    /** 历史只存摘要，不重复存威胁明细，避免数据膨胀 */
    private data class ReportDto(
        val sessionId: String,
        val startedAt: Long,
        val finishedAt: Long,
        val mode: String,
        val filesScanned: Int,
        val appsScanned: Int,
        val bytesScanned: Long,
        val threatCount: Int,
        val maxSeverity: String,
        val cancelled: Boolean
    ) {
        fun toModel() = ScanReport(
            sessionId = sessionId,
            startedAt = startedAt,
            finishedAt = finishedAt,
            mode = mode,
            filesScanned = filesScanned,
            appsScanned = appsScanned,
            bytesScanned = bytesScanned,
            threats = emptyList(),
            cancelled = cancelled
        )

        companion object {
            fun from(r: ScanReport) = ReportDto(
                sessionId = r.sessionId,
                startedAt = r.startedAt,
                finishedAt = r.finishedAt,
                mode = r.mode,
                filesScanned = r.filesScanned,
                appsScanned = r.appsScanned,
                bytesScanned = r.bytesScanned,
                threatCount = r.threatCount,
                maxSeverity = r.maxSeverity.name,
                cancelled = r.cancelled
            )
        }
    }

    private object K {
        const val THREATS = "threats_json"
        const val HISTORY = "history_json"
        const val WHITELIST = "whitelist"
    }

    companion object {
        private const val PREFS = "aegis_threats"
        private const val MAX_THREATS = 300
        private const val MAX_HISTORY = 30
    }
}
