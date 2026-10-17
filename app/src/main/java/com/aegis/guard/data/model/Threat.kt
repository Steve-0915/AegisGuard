package com.aegis.guard.data.model

/**
 * 一条威胁发现记录。既是扫描器的输出，也是历史库中的持久化单元。
 */
data class Threat(
    /** 稳定 ID，用于去重与详情页跳转 */
    val id: String,

    /** 展示名，如应用名或文件名 */
    val title: String,

    /** 命中规则名，如 ANDROID/Trojan.Dropper */
    val ruleName: String,

    val severity: Severity,
    val type: ThreatType,
    val engine: DetectionEngine,
    val targetKind: TargetKind,

    /** 包名（应用类威胁才有） */
    val packageName: String? = null,

    /** 文件绝对路径（文件类威胁才有） */
    val filePath: String? = null,

    /** 文件 SHA-256 */
    val sha256: String? = null,

    /** 文件大小（字节） */
    val sizeBytes: Long = 0L,

    /** 检测时间戳 */
    val detectedAt: Long = System.currentTimeMillis(),

    /** 人类可读的检测依据列表 */
    val evidence: List<String> = emptyList(),

    /** 处置建议 */
    val advice: String = "",

    /** 相关 CVE 编号（若与已知漏洞关联） */
    val cveIds: List<String> = emptyList(),

    /** 是否已被用户忽略/加白 */
    val dismissed: Boolean = false
) {
    /** 用于"最近威胁"排序 */
    val isCriticalOrHigh: Boolean
        get() = severity.level >= Severity.HIGH.level
}

/**
 * 一次扫描的汇总统计。
 */
data class ScanReport(
    val sessionId: String,
    val startedAt: Long,
    val finishedAt: Long,
    val mode: String,
    val filesScanned: Int,
    val appsScanned: Int,
    val bytesScanned: Long,
    val threats: List<Threat>,
    val cancelled: Boolean = false
) {
    val durationMs: Long get() = finishedAt - startedAt
    val threatCount: Int get() = threats.size
    val maxSeverity: Severity
        get() = threats.maxOfOrNull { it.severity } ?: Severity.CLEAN
}
