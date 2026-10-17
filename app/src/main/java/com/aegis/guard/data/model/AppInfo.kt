package com.aegis.guard.data.model

/**
 * 一个已安装应用的静态信息快照。
 * 只读取公开可得的元数据，不涉及任何隐私内容。
 */
data class AppInfo(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val versionCode: Long,
    val targetSdk: Int,
    val minSdk: Int,
    val installedAt: Long,
    val updatedAt: Long,
    val apkPath: String,
    val apkSize: Long,
    /** 声明的危险权限 */
    val permissions: List<String>,
    /** 是否为系统应用 */
    val isSystem: Boolean,
    /** 是否已启用的无障碍服务（高风险行为面） */
    val usesAccessibility: Boolean,
    /** 是否请求设备管理器 */
    val usesDeviceAdmin: Boolean,
    /** 是否可从非商店来源安装（安装其他包） */
    val canInstallPackages: Boolean,
    /** 是否具备通知监听 */
    val usesNotificationListener: Boolean,
    /** 是否声明悬浮窗 */
    val usesOverlay: Boolean,
    /** 安装来源包名（Android 11+ 可能为空） */
    val installer: String?,
    /** 签名证书 SHA-256（首个签名者） */
    val signerSha256: String?
)

/**
 * 应用风险评分结果。
 */
data class AppRiskScore(
    val packageName: String,
    val score: Int,
    val severity: Severity,
    val reasons: List<RiskReason>
) {
    companion object {
        const val MAX_SCORE = 100
    }
}

/**
 * 单条评分理由，用于向用户解释"为什么这个应用可疑"。
 */
data class RiskReason(
    val title: String,
    val detail: String,
    val weight: Int,
    val severity: Severity,
    val engine: DetectionEngine = DetectionEngine.HEURISTIC
)

/**
 * 系统完整性体检项。
 */
data class IntegrityCheck(
    val id: String,
    val title: String,
    val passed: Boolean,
    val detail: String,
    val severityIfFailed: Severity = Severity.MEDIUM,
    val advice: String = ""
)