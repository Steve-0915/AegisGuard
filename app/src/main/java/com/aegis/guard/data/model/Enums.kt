package com.aegis.guard.data.model

/**
 * 危险等级。数值越大越危险，便于排序与聚合。
 */
enum class Severity(val level: Int) {
    CLEAN(0),
    INFO(1),
    LOW(2),
    MEDIUM(3),
    HIGH(4),
    CRITICAL(5);

    companion object {
        fun fromName(raw: String?): Severity =
            entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: INFO

        fun ofLevel(level: Int): Severity =
            entries.firstOrNull { it.level == level } ?: INFO
    }
}

/**
 * 威胁类别。对应签名库中的 category 字段。
 */
enum class ThreatType(val key: String) {
    MALWARE("malware"),
    TROJAN("trojan"),
    SPYWARE("spyware"),
    ADWARE("adware"),
    RANSOMWARE("ransomware"),
    RISKWARE("riskware"),
    EXPLOIT("exploit"),
    PUP("pup"),
    SUSPICIOUS("suspicious");

    companion object {
        fun fromKey(raw: String?): ThreatType =
            entries.firstOrNull { it.key.equals(raw, ignoreCase = true) } ?: SUSPICIOUS
    }
}

/**
 * 被扫描对象类型。
 */
enum class TargetKind {
    /** 已安装应用（以包为中心分析） */
    PACKAGE,

    /** 存储中的普通文件 */
    FILE,

    /** 独立 APK 文件静态分析 */
    APK,

    /** 系统配置/完整性检查项 */
    SYSTEM
}

/**
 * 威胁来源引擎，用于在详情页展示"检测依据"来自哪一层。
 */
enum class DetectionEngine {
    /** 规则签名（正则/字面量匹配） */
    SIGNATURE,

    /** 已知恶意哈希黑名单 */
    HASH,

    /** 启发式行为与结构分析 */
    HEURISTIC,

    /** 应用权限组合风险评分 */
    PERMISSION,

    /** APK 结构/清单异常 */
    STRUCTURE,

    /** 云端情报 */
    CLOUD
}
