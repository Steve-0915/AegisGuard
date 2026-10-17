package com.aegis.guard.data.model

/**
 * 一条 CVE 漏洞定义。
 *
 * 说明：本应用**不内置完整 NVD 数据库**（体积过大且需频繁更新）。
 * 内置的是一份针对 Android 生态高频组件的"版本区间匹配表"，
 * 结构对齐 CVE JSON 5.x 的关键字段，可通过设置页从公开源增量更新。
 */
data class CveEntry(
    /** CVE-2023-1234 */
    val id: String,

    /** 简述 */
    val summary: String,

    /** 受影响的组件标识，如 "com.google.android.exoplayer:exoplayer" 或 "libwebp" */
    val component: String,

    /** 组件匹配别名（用于宽松的包名/库名匹配） */
    val aliases: List<String> = emptyList(),

    /**
     * 版本区间。使用 Maven 式比较：
     * affectedBelow 为"修复版本"，即 [minVersion, fixedVersion) 区间受影响。
     */
    val minVersion: String? = null,
    val fixedVersion: String? = null,
    val maxVersion: String? = null,

    /** CVSS 3.1 基础分 */
    val cvss: Double = 0.0,

    /** CVSS 向量串 */
    val cvssVector: String? = null,

    /** 披露日期 ISO-8601（yyyy-MM-dd） */
    val published: String? = null,

    /** 参考链接 */
    val references: List<String> = emptyList(),

    /** CWE 分类 */
    val cwe: String? = null,

    /** 是否已被在野利用（KEV） */
    val knownExploited: Boolean = false,

    val source: String = "AegisGuard CVE"
) {
    /** 由 CVSS 分数推导严重程度 */
    val severity: Severity
        get() = when {
            cvss >= 9.0 -> Severity.CRITICAL
            cvss >= 7.0 -> Severity.HIGH
            cvss >= 4.0 -> Severity.MEDIUM
            cvss > 0.0 -> Severity.LOW
            else -> Severity.INFO
        }
}

/**
 * 匹配结果：一条 CVE 命中了某个已安装应用或文件。
 */
data class CveMatch(
    val cve: CveEntry,

    /** 命中的组件版本 */
    val detectedVersion: String,

    /** 承载该组件的应用包名（可为空，例如系统库） */
    val packageName: String? = null,

    /** 应用展示名 */
    val appLabel: String? = null,

    /** 匹配依据说明 */
    val reason: String = ""
) {
    val severity: Severity get() = cve.severity
}