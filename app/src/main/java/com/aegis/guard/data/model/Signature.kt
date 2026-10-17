package com.aegis.guard.data.model

/**
 * 一条病毒特征规则。
 *
 * 设计原则：规则库是可离线分发的 JSON，加载后编译为正则或字面量匹配器。
 * 这样既能引用开源规则集（如 YARA-lite 思路、社区规则），又不依赖任何
 * 私有二进制格式。
 */
data class SignatureRule(
    /** 规则唯一名，如 ANDROID/Trojan.Banker.A */
    val name: String,

    val severity: Severity,
    val type: ThreatType,

    /** 匹配模式（正则表达式，Java 语法子集） */
    val pattern: String,

    /**
     * 匹配目标：
     * - `string`  任意文本内容（DEX 字符串、清单文本、脚本内容）
     * - `package` 包名精确/前缀匹配
     * - `path`    文件路径
     * - `filename` 文件名
     */
    val target: String = "string",

    /** 是否大小写敏感 */
    val caseSensitive: Boolean = false,

    /** 命中后的权重，用于启发式累计评分 */
    val weight: Int = 1,

    /** 证据描述模板，用于展示 */
    val description: String = "",

    /** 处置建议 */
    val advice: String = "",

    /** 关联 CVE */
    val cveIds: List<String> = emptyList(),

    /** 数据来源标注，如 "AegisGuard Core" / "STIX-Community" */
    val source: String = "AegisGuard Core",

    /** 是否为启发式规则（更易误报，可在设置中关闭） */
    val heuristic: Boolean = false
)

/**
 * 已知恶意哈希条目（IOC）。
 */
data class HashIndicator(
    val sha256: String,
    val family: String,
    val severity: Severity,
    val type: ThreatType,
    val source: String = "AegisGuard IOC"
)
