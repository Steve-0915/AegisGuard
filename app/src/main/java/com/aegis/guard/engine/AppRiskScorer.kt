package com.aegis.guard.engine

import com.aegis.guard.data.model.AppInfo
import com.aegis.guard.data.model.AppRiskScore
import com.aegis.guard.data.model.DetectionEngine
import com.aegis.guard.data.model.RiskReason
import com.aegis.guard.data.model.Severity

/**
 * 应用风险评分器（启发式）。
 *
 * 评分不是"有罪判决"，而是把难以用单条规则描述的**权限组合风险**
 * 量化成一个可解释的分数，并把每一条扣分理由回传给用户。
 *
 * 评分模型参考了学术界与工业界公开的 Android 恶意软件静态特征研究：
 * 危险权限组合、动态代码加载、无障碍滥用、安装源异常等，
 * 都是长期被验证为高区分度的特征。
 */
class AppRiskScorer {

    /**
     * 已知的危险权限及其基础权重。
     * 单个权限通常不足以判定恶意，但组合起来区分度很高。
     */
    private val dangerousPermissions: Map<String, Pair<Int, String>> = mapOf(
        // 短信/电话：资费消耗与短信拦截
        "android.permission.SEND_SMS" to (18 to "可直接发送短信，可能造成资费损失"),
        "android.permission.READ_SMS" to (20 to "可读取短信，可能窃取验证码"),
        "android.permission.RECEIVE_SMS" to (16 to "可拦截接收短信，常用于窃取验证码"),
        "android.permission.READ_PHONE_STATE" to (6 to "可读取设备标识与通话状态"),
        "android.permission.CALL_PHONE" to (12 to "可在无交互情况下拨打电话"),
        "android.permission.READ_CALL_LOG" to (16 to "可读取通话记录，属敏感隐私"),
        "android.permission.PROCESS_OUTGOING_CALLS" to (14 to "可监听并修改呼出电话"),

        // 联系人/账户
        "android.permission.READ_CONTACTS" to (14 to "可读取通讯录，存在隐私泄露风险"),
        "android.permission.WRITE_CONTACTS" to (12 to "可篡改通讯录"),
        "android.permission.GET_ACCOUNTS" to (10 to "可枚举设备上的账户"),

        // 位置
        "android.permission.ACCESS_FINE_LOCATION" to (10 to "可获取精确位置"),
        "android.permission.ACCESS_BACKGROUND_LOCATION" to (18 to "可在后台持续获取位置，隐私风险高"),

        // 存储与外部写入
        "android.permission.WRITE_EXTERNAL_STORAGE" to (4 to "可写入外部存储"),
        "android.permission.MANAGE_EXTERNAL_STORAGE" to (16 to "可访问全部文件，权限范围极大"),
        "android.permission.READ_EXTERNAL_STORAGE" to (3 to "可读取外部存储"),

        // 设备控制
        "android.permission.SYSTEM_ALERT_WINDOW" to (16 to "可悬浮于其他应用之上，常被用于界面劫持"),
        "android.permission.REQUEST_INSTALL_PACKAGES" to (20 to "可静默引导安装其他应用，常见于投放器"),
        "android.permission.BIND_DEVICE_ADMIN" to (22 to "可申请设备管理器权限，难以卸载"),
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to (26 to "可读取屏幕内容并模拟操作，风险极高"),
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" to (20 to "可读取所有通知，可能截获验证码"),
        "android.permission.PACKAGE_USAGE_STATS" to (8 to "可获取应用使用记录"),

        // 摄像头/麦克风/录音
        "android.permission.CAMERA" to (12 to "可调用摄像头"),
        "android.permission.RECORD_AUDIO" to (14 to "可录制音频，具备窃听能力"),

        // 自启与常驻
        "android.permission.RECEIVE_BOOT_COMPLETED" to (6 to "可开机自启并常驻后台"),
        "android.permission.FOREGROUND_SERVICE" to (3 to "可长期驻留前台"),
        "android.permission.WAKE_LOCK" to (3 to "可阻止设备休眠"),
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" to (10 to "可申请忽略电池优化，便于长期后台运行"),

        // 网络
        "android.permission.INTERNET" to (0 to ""),
        "android.permission.ACCESS_NETWORK_STATE" to (0 to "")
    )

    /**
     * 高区分度的组合模式：当多个权限同时出现时额外加权。
     * 这是"1+1>2"的部分，单看每个权限都还算常见。
     */
    private val combos: List<ComboRule> = listOf(
        ComboRule(
            required = setOf(
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS"
            ),
            bonus = 20,
            title = "短信三件套",
            detail = "同时申请读、收、发短信权限，是短信扣费/验证码窃取类木马的典型特征",
            severity = Severity.CRITICAL
        ),
        ComboRule(
            required = setOf("android.permission.READ_SMS", "android.permission.INTERNET"),
            bonus = 14,
            title = "短信外传组合",
            detail = "读取短信并具备联网能力，存在验证码外传风险",
            severity = Severity.HIGH
        ),
        ComboRule(
            required = setOf("android.permission.RECORD_AUDIO", "android.permission.INTERNET"),
            bonus = 10,
            title = "录音上传组合",
            detail = "可录音并联网，存在环境窃听风险",
            severity = Severity.HIGH
        ),
        ComboRule(
            required = setOf(
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            ),
            bonus = 24,
            title = "无障碍 + 悬浮窗",
            detail = "这是当前最常见的一类远控/银行木马的权限组合，可自动点击与读取账号页面",
            severity = Severity.CRITICAL
        ),
        ComboRule(
            required = setOf(
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ),
            bonus = 18,
            title = "投放器特征",
            detail = "可安装其他应用并可覆盖界面，常见于诱导安装的投放器家族",
            severity = Severity.HIGH
        ),
        ComboRule(
            required = setOf(
                "android.permission.READ_CONTACTS",
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO"
            ),
            bonus = 12,
            title = "全量隐私采集",
            detail = "同时索取通讯录、摄像头与麦克风，远超普通应用所需",
            severity = Severity.HIGH
        ),
        ComboRule(
            required = setOf(
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
                "android.permission.FOREGROUND_SERVICE"
            ),
            bonus = 10,
            title = "强常驻组合",
            detail = "开机自启 + 忽略电池优化 + 前台服务，倾向于长期驻留而难以退出",
            severity = Severity.MEDIUM
        )
    )

    private data class ComboRule(
        val required: Set<String>,
        val bonus: Int,
        val title: String,
        val detail: String,
        val severity: Severity
    )

    /**
     * 计算风险分数。返回的 [AppRiskScore.reasons] 可直接展示给用户。
     */
    fun score(app: AppInfo): AppRiskScore {
        val reasons = ArrayList<RiskReason>(8)
        val granted = app.permissions.map { it.trim() }.toSet()

        // --- 层 1：单个危险权限 ---
        for (p in granted) {
            val (weight, desc) = dangerousPermissions[p] ?: continue
            if (weight <= 0) continue
            reasons += RiskReason(
                title = p.substringAfterLast('.'),
                detail = desc,
                weight = weight,
                severity = severityOfWeight(weight)
            )
        }

        // --- 层 2：权限组合 ---
        for (combo in combos) {
            if (granted.containsAll(combo.required)) {
                reasons += RiskReason(
                    title = combo.title,
                    detail = combo.detail,
                    weight = combo.bonus,
                    severity = combo.severity
                )
            }
        }

        // --- 层 3：结构与来源特征 ---
        if (app.usesAccessibility && !app.isSystem) {
            reasons += RiskReason(
                title = "无障碍服务",
                detail = "该应用注册了无障碍服务。若来源不可信，可读取屏幕上的全部内容并模拟点击",
                weight = 22,
                severity = Severity.CRITICAL
            )
        }
        if (app.usesDeviceAdmin) {
            reasons += RiskReason(
                title = "设备管理器",
                detail = "申请设备管理器权限，会显著提高卸载难度",
                weight = 18,
                severity = Severity.HIGH
            )
        }
        if (app.usesNotificationListener) {
            reasons += RiskReason(
                title = "通知监听",
                detail = "可读取系统全部通知，存在截获验证码与消息的风险",
                weight = 16,
                severity = Severity.HIGH
            )
        }
        if (app.usesOverlay) {
            reasons += RiskReason(
                title = "悬浮窗",
                detail = "可覆盖在其他应用之上，可能被用于诱导点击",
                weight = 12,
                severity = Severity.MEDIUM
            )
        }

        // 安装来源异常：非应用商店安装且不在系统白名单内
        val installer = app.installer
        if (!app.isSystem && installer != null && installer !in TRUSTED_INSTALLERS) {
            val weight = if (installer == "null" || installer.isBlank()) 10 else 6
            reasons += RiskReason(
                title = "安装来源非主流商店",
                detail = "安装来源：$installer。侧载应用缺少商店上架审核环节",
                weight = weight,
                severity = Severity.LOW
            )
        }

        // 目标 SDK 过低：说明长期未适配新系统，安全机制缺失
        if (app.targetSdk in 1..22 && !app.isSystem) {
            reasons += RiskReason(
                title = "目标 API 过低",
                detail = "targetSdk=${app.targetSdk}，低于 Android 6.0 的运行时权限模型，可能绕过权限收敛",
                weight = 14,
                severity = Severity.MEDIUM
            )
        } else if (app.targetSdk in 23..28 && !app.isSystem) {
            reasons += RiskReason(
                title = "目标 API 偏旧",
                detail = "targetSdk=${app.targetSdk}，缺少近年新增的隐私与沙箱限制",
                weight = 6,
                severity = Severity.LOW
            )
        }

        // 版本号与更新时间的异常：极久未更新但仍持有高危权限
        val ageDays = (System.currentTimeMillis() - app.updatedAt) / 86_400_000L
        if (ageDays > 730 && !app.isSystem && granted.any { dangerousPermissions[it]?.first ?: 0 >= 16 }) {
            reasons += RiskReason(
                title = "长期未更新且持高危权限",
                detail = "该应用超过 2 年未更新，却仍持有高风险权限",
                weight = 10,
                severity = Severity.MEDIUM
            )
        }

        // 无签名信息（极少数异常情况）
        if (app.signerSha256.isNullOrBlank() && !app.isSystem) {
            reasons += RiskReason(
                title = "无法读取签名",
                detail = "未能获取应用签名指纹，可能为异常安装包或被篡改",
                weight = 20,
                severity = Severity.HIGH,
                engine = DetectionEngine.STRUCTURE
            )
        }

        // --- 聚合：取平方根衰减，避免大量低权重理由让分数爆炸到 100 ---
        val raw = reasons.sumOf { it.weight }
        val score = if (raw <= 0) 0 else {
            val normalized = (kotlin.math.sqrt(raw.toDouble()) * 9.0).toInt()
            normalized.coerceIn(0, AppRiskScore.MAX_SCORE)
        }

        return AppRiskScore(
            packageName = app.packageName,
            score = score,
            severity = severityOfScore(score),
            reasons = reasons.sortedByDescending { it.weight }
        )
    }

    private fun severityOfScore(score: Int): Severity = when {
        score >= 80 -> Severity.CRITICAL
        score >= 60 -> Severity.HIGH
        score >= 38 -> Severity.MEDIUM
        score >= 18 -> Severity.LOW
        score > 0 -> Severity.INFO
        else -> Severity.CLEAN
    }

    private fun severityOfWeight(w: Int): Severity = when {
        w >= 24 -> Severity.CRITICAL
        w >= 16 -> Severity.HIGH
        w >= 10 -> Severity.MEDIUM
        else -> Severity.LOW
    }

    companion object {
        /**
         * 可信安装来源。命中这些来源可以减少"侧载"扣分。
         */
        val TRUSTED_INSTALLERS = setOf(
            "com.android.vending",              // Google Play
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",      // AOSP 安装器
            "com.miui.packageinstaller",         // MIUI
            "com.huawei.appmarket",              // 华为应用市场
            "com.oppo.market",
            "com.heytap.market",
            "com.bbk.appstore",                  // vivo
            "com.sec.android.app.samsungapps",   // 三星
            "com.tencent.android.qqdownloader",  // 应用宝
            "com.xiaomi.market"
        )
    }
}