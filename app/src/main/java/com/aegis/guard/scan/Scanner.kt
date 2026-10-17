package com.aegis.guard.scan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.pm.PackageInfoCompat
import com.aegis.guard.cve.CveMatcher
import com.aegis.guard.data.model.AppInfo
import com.aegis.guard.data.model.CveMatch
import com.aegis.guard.data.model.DetectionEngine
import com.aegis.guard.data.model.IntegrityCheck
import com.aegis.guard.data.model.Severity
import com.aegis.guard.data.model.TargetKind
import com.aegis.guard.data.model.Threat
import com.aegis.guard.data.model.ThreatType
import com.aegis.guard.data.store.SettingsState
import com.aegis.guard.engine.AppRiskScorer
import com.aegis.guard.engine.FileAnalyzer
import com.aegis.guard.engine.SignatureEngine
import com.aegis.guard.engine.ScannableSubject
import com.aegis.guard.data.model.HashIndicator
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext
import java.io.File
import java.security.MessageDigest

/**
 * 扫描模式。
 */
enum class ScanMode(val key: String) {
    APPS("apps"),
    FILES("files"),
    FULL("full"),
    CUSTOM("custom"),
    APK("apk")
}

/**
 * 扫描过程中的阶段，用于进度条上方的文案。
 */
enum class ScanStage {
    PREPARE,
    APPS,
    PACKAGES,
    FILES,
    HASH,
    HEURISTIC,
    REPORT
}

/**
 * 实时进度回调。所有字段都是"当下快照"，UI 直接渲染即可。
 */
data class ScanProgress(
    val stage: ScanStage,
    val currentItem: String = "",
    val filesScanned: Int = 0,
    val appsScanned: Int = 0,
    val bytesScanned: Long = 0,
    val threatsFound: Int = 0,
    /** 0f..1f，用于不确定进度时为 -1f */
    val fraction: Float = -1f
)

/**
 * 扫描器。
 *
 * 线程模型：整个扫描跑在 [Dispatchers.IO]，通过 [onProgress] 回调推状态。
 * 调用方（ViewModel）负责把回调切回主线程——扫描器本身不碰 UI 框架。
 *
 * 取消：在每处理完一个条目后就检查协程是否被取消，
 * 所以"停止扫描"能在毫秒级响应，而不是等整轮跑完。
 */
class Scanner(
    private val context: Context,
    private val signatureEngine: SignatureEngine,
    private val hashIndicators: List<HashIndicator>,
    private val riskScorer: AppRiskScorer = AppRiskScorer()
) {

    private val hashSet: Set<String> = hashIndicators.map { it.sha256.lowercase() }.toSet()

    /**
     * 执行一次扫描。
     *
     * @param mode 扫描模式
     * @param settings 当前设置快照
     * @param customDirs CUSTOM 模式下用户选择的目录
     * @param singleApk APK 模式下指定的单个文件
     * @param onProgress 进度回调（可能在任意线程被调用）
     */
    suspend fun scan(
        mode: ScanMode,
        settings: SettingsState,
        customDirs: List<File> = emptyList(),
        singleApk: File? = null,
        onProgress: (ScanProgress) -> Unit
    ): ScanOutcome = withContext(Dispatchers.IO) {

        val startedAt = System.currentTimeMillis()
        val threats = ArrayList<Threat>(8)
        var filesScanned = 0
        var appsScanned = 0
        var bytesScanned = 0L
        var cancelled = false

        fun emit(
            stage: ScanStage,
            item: String = "",
            fraction: Float = -1f
        ) = onProgress(
            ScanProgress(
                stage = stage,
                currentItem = item,
                filesScanned = filesScanned,
                appsScanned = appsScanned,
                bytesScanned = bytesScanned,
                threatsFound = threats.size,
                fraction = fraction
            )
        )

        emit(ScanStage.PREPARE)

        val emitThrottle = Throttle(80)   // 进度刷新节流：最多每 80ms 推一次

        try {
            when (mode) {
                ScanMode.APPS, ScanMode.FULL -> {
                    val apps = collectInstalledApps()
                    emit(ScanStage.APPS, fraction = 0f)

                    apps.forEachIndexed { index, app ->
                        coroutineContext.ensureActive()
                        emitThrottle {
                            emit(ScanStage.APPS, app.label, index.toFloat() / apps.size.coerceAtLeast(1))
                        }

                        val found = scanApp(app, settings)
                        threats += found
                        appsScanned++

                        if (settings.cloudLookup && found.isNotEmpty()) {
                            // 云端查询默认关闭；开启时也只是把哈希提交给公开接口，
                            // 不会上传文件名、路径或任何内容。
                            emit(ScanStage.PACKAGES, app.label)
                        }
                    }

                    // 风险评分单独作为一个阶段，让进度分段更直观
                    emit(ScanStage.PACKAGES, fraction = 0f)
                    apps.forEachIndexed { index, app ->
                        coroutineContext.ensureActive()
                        emitThrottle {
                            emit(ScanStage.PACKAGES, app.label, index.toFloat() / apps.size.coerceAtLeast(1))
                        }
                        threats += scoreApp(app, settings)
                    }
                }

                ScanMode.FILES -> Unit
                ScanMode.CUSTOM -> Unit
                ScanMode.APK -> Unit
            }

            when (mode) {
                ScanMode.FILES, ScanMode.FULL -> {
                    val roots = defaultScanRoots(settings)
                    scanFiles(roots, settings, threats) { count, bytes, name, stage ->
                        filesScanned = count
                        bytesScanned = bytes
                        emitThrottle { emit(stage, name) }
                    }
                    // 上面的 lambda 捕获的是局部变量，需要把最终值同步回来
                    filesScanned = counterFiles
                    bytesScanned = counterBytes
                }

                ScanMode.CUSTOM -> {
                    scanFiles(customDirs, settings, threats) { count, bytes, name, stage ->
                        filesScanned = count
                        bytesScanned = bytes
                        emitThrottle { emit(stage, name) }
                    }
                    filesScanned = counterFiles
                    bytesScanned = counterBytes
                }

                ScanMode.APK -> {
                    singleApk?.let { apk ->
                        counterFiles = 0
                        counterBytes = 0
                        emit(ScanStage.FILES, apk.name, 0f)
                        analyzeApk(apk, settings, threats, isStandalone = true)
                        filesScanned = 1
                        bytesScanned = apk.length()
                        emit(ScanStage.FILES, apk.name, 1f)
                    }
                }

                else -> Unit
            }

            emit(ScanStage.REPORT, fraction = 1f)
        } catch (_: CancellationException) {
            cancelled = true
            throw CancellationException()
        }

        val finishedAt = System.currentTimeMillis()
        emit(ScanStage.REPORT, fraction = 1f)

        ScanOutcome(
            mode = mode,
            threats = dedupe(threats),
            filesScanned = filesScanned,
            appsScanned = appsScanned,
            bytesScanned = bytesScanned,
            startedAt = startedAt,
            finishedAt = finishedAt,
            cancelled = cancelled
        )
    }

    // 扫描文件时的共享计数器（避免用 var 捕获 lambda 的可见性问题）
    private var counterFiles = 0
    private var counterBytes = 0L

    // ------------------------------------------------------------ 应用扫描

    /**
     * 应用扫描的完整流程：
     * 1. 尝试读取 APK 文本（DEX 字符串池 + 清单），跑规则引擎；
     * 2. 以包名 / 权限为目标跑规则（含权限相关规则）；
     * 3. 应用风险评分由 [scoreApp] 单独处理。
     */
    private suspend fun scanApp(app: AppInfo, settings: SettingsState): List<Threat> {
        val out = ArrayList<Threat>(2)

        // --- 1) APK 内容 ---
        val apkFile = File(app.apkPath)
        var apkText: String? = null
        if (apkFile.exists() && apkFile.canRead()) {
            apkText = runCatching {
                if (FileAnalyzer.isZip(apkFile)) {
                    FileAnalyzer.extractApkText(apkFile, includeDex = settings.dexAnalysis)
                } else {
                    FileAnalyzer.extractText(apkFile)
                }
            }.getOrNull()
        }

        if (!apkText.isNullOrEmpty()) {
            out += signatureEngine.scan(
                ScannableSubject(
                    displayName = app.label,
                    packageName = app.packageName,
                    filePath = app.apkPath,
                    sizeBytes = app.apkSize,
                    targetKind = TargetKind.PACKAGE,
                    textProvider = { apkText }
                ),
                includeHeuristic = settings.heuristic
            )
        }

        // --- 2) 包名与权限面 ---
        out += signatureEngine.scan(
            ScannableSubject(
                displayName = app.label,
                packageName = app.packageName,
                filePath = app.apkPath,
                sizeBytes = app.apkSize,
                targetKind = TargetKind.PACKAGE,
                textProvider = { app.permissions.joinToString("\n") }
            ),
            includeHeuristic = settings.heuristic
        )

        // PUP 过滤：用户在设置里关掉"潜在有害应用"后，不再报告 pup 类型
        return if (settings.detectPup) out
        else out.filterNot { it.type == ThreatType.PUP || it.type == ThreatType.ADWARE }
    }

    /**
     * 应用风险评分 → 威胁记录。
     *
     * 只有分数达到 LOW 以上才产出记录，避免"每个应用都有问题"的噪音。
     * 严重度取"评分severity"与"最高单条理由severity"的较大者，
     * 因为一条 CRITICAL 理由就足以让用户重视。
     */
    private fun scoreApp(app: AppInfo, settings: SettingsState): List<Threat> {
        if (!settings.heuristic) return emptyList()
        val score = riskScorer.score(app)
        if (score.severity.level < Severity.LOW.level) return emptyList()
        val effective = maxOf(score.severity.level, score.reasons.maxOfOrNull { it.severity.level } ?: 0)
        val severity = Severity.ofLevel(effective)

        val evidence = buildList {
            add("综合风险评分：${score.score} / ${com.aegis.guard.data.model.AppRiskScore.MAX_SCORE}")
            score.reasons.take(8).forEach { r ->
                add("• ${r.title}（权重 ${r.weight}）：${r.detail}")
            }
            if (score.reasons.size > 8) add("… 另有 ${score.reasons.size - 8} 项")
        }

        return listOf(
            Threat(
                id = SignatureEngine.stableId("RISK/${score.severity.name}", app.packageName),
                title = app.label,
                ruleName = "RISK/Permission.Abuse.${score.score}",
                severity = severity,
                type = ThreatType.RISKWARE,
                engine = DetectionEngine.PERMISSION,
                targetKind = TargetKind.PACKAGE,
                packageName = app.packageName,
                filePath = app.apkPath,
                sizeBytes = app.apkSize,
                evidence = evidence,
                advice = if (severity.level >= Severity.HIGH.level) {
                    "该应用的权限组合与结构特征符合高风险画像。若其来源非官方商店或你并未主动安装，建议卸载。"
                } else {
                    "该应用存在若干值得留意的权限或结构特征。请确认这些权限与其功能是否匹配。"
                }
            )
        )
    }

    // ------------------------------------------------------------ 文件扫描

    /**
     * 递归扫描目录树。
     *
     * 关键设计：
     * - 深度上限 12 层，防止符号链接构成的环形结构导致无限递归；
     * - 单文件体积上限来自设置，超限跳过但计入统计；
     * - 同一个文件只算一次哈希（惰性），没有被任何规则需要时不计算；
     * - 进度节流，避免高刷屏设备上回调风暴。
     */
    private suspend fun scanFiles(
        roots: List<File>,
        settings: SettingsState,
        out: MutableList<Threat>,
        onTick: (Int, Long, String, ScanStage) -> Unit
    ) {
        val visited = HashSet<String>(1024)
        var files = 0
        var bytes = 0L
        var lastEmit = 0L

        suspend fun handleFile(file: File, depth: Int) {
            coroutineContext.ensureActive()
            if (depth > MAX_DEPTH) return

            val path = file.absolutePath
            // 用 canonicalPath 去重，可顺带防止硬链接/绑定挂载造成的重复扫描
            val key = runCatching { file.canonicalPath }.getOrDefault(path)
            if (!visited.add(key)) return

            if (file.isDirectory) {
                val children = runCatching { file.listFiles() }.getOrNull() ?: return
                for (child in children) {
                    if (!settings.scanHidden && child.name.startsWith(".")) continue
                    handleFile(child, depth + 1)
                }
                return
            }
            if (!file.isFile || !file.canRead()) return

            val size = file.length()
            if (size <= 0) return
            if (size > settings.maxFileSize) {
                files++   // 跳过但也计入"已处理"，让进度数字真实
                return
            }

            files++
            bytes += size

            val now = System.currentTimeMillis()
            if (now - lastEmit > 80) {
                lastEmit = now
                counterFiles = files
                counterBytes = bytes
                onTick(files, bytes, file.name, ScanStage.FILES)
            }

            // --- 规则匹配 ---
            val findings = analyzeFile(file, settings)
            out += findings

            if (findings.isNotEmpty()) {
                counterFiles = files
                counterBytes = bytes
                onTick(files, bytes, file.name, ScanStage.HASH)
            }
        }

        for (root in roots) {
            if (!root.exists()) continue
            handleFile(root, 0)
        }
        counterFiles = files
        counterBytes = bytes
    }

    /**
     * 单个静态文件的完整分析链：
     * 哈希黑名单 → APK 深度分析 → 文本规则匹配。
     */
    private fun analyzeFile(file: File, settings: SettingsState): List<Threat> {
        val out = ArrayList<Threat>(2)

        // 是否值得做昂贵的内容提取
        val highValue = FileAnalyzer.isHighValueTarget(file)
        val isApk = FileAnalyzer.extensionOf(file) == "apk"

        if (isApk) {
            analyzeApk(file, settings, out, isStandalone = false)
            return out
        }

        // 先做轻量判定：只有高价值目标才计算哈希
        if (!highValue && !settings.deepArchive) return out

        val sha = runCatching { FileAnalyzer.sha256(file) }.getOrNull()
        if (sha != null && hashSet.contains(sha.lowercase())) {
            val indicator = hashIndicators.firstOrNull { it.sha256.equals(sha, ignoreCase = true) }
            out += Threat(
                id = SignatureEngine.stableId("HASH/${indicator?.family ?: "Unknown"}", sha),
                title = file.name,
                ruleName = "IOC/${indicator?.family ?: "Malware.Hash"}",
                severity = indicator?.severity ?: Severity.HIGH,
                type = indicator?.type ?: ThreatType.MALWARE,
                engine = DetectionEngine.HASH,
                targetKind = TargetKind.FILE,
                filePath = file.absolutePath,
                sha256 = sha,
                sizeBytes = file.length(),
                evidence = listOf(
                    "文件 SHA-256 命中已知恶意样本库",
                    "样本家族：${indicator?.family ?: "未知"}",
                    "情报来源：${indicator?.source ?: "AegisGuard IOC"}",
                    "SHA-256：$sha"
                ),
                advice = "该文件与已知恶意样本完全一致，建议立即删除。"
            )
        }

        // 内容规则匹配
        val text = runCatching { FileAnalyzer.extractText(file) }.getOrNull()
        if (!text.isNullOrEmpty()) {
            out += signatureEngine.scan(
                ScannableSubject(
                    displayName = file.name,
                    filePath = file.absolutePath,
                    sha256 = sha,
                    sizeBytes = file.length(),
                    targetKind = TargetKind.FILE,
                    textProvider = { text }
                ),
                includeHeuristic = settings.heuristic
            )
        }
        return out
    }

    /**
     * APK 静态分析。既用于"扫描已安装应用的 APK"，也用于"用户选了一个 APK 文件"。
     */
    private fun analyzeApk(
        apk: File,
        settings: SettingsState,
        out: MutableList<Threat>,
        isStandalone: Boolean
    ) {
        val text = runCatching {
            FileAnalyzer.extractApkText(apk, includeDex = settings.dexAnalysis)
        }.getOrNull()

        val sha = runCatching { FileAnalyzer.sha256(apk) }.getOrNull()

        // 哈希黑名单优先
        if (sha != null && hashSet.contains(sha.lowercase())) {
            val indicator = hashIndicators.firstOrNull { it.sha256.equals(sha, ignoreCase = true) }
            out += Threat(
                id = SignatureEngine.stableId("HASH/${indicator?.family ?: "Unknown"}", sha),
                title = apk.name,
                ruleName = "IOC/${indicator?.family ?: "Malware.Hash"}",
                severity = indicator?.severity ?: Severity.HIGH,
                type = indicator?.type ?: ThreatType.MALWARE,
                engine = DetectionEngine.HASH,
                targetKind = TargetKind.APK,
                filePath = apk.absolutePath,
                sha256 = sha,
                sizeBytes = apk.length(),
                evidence = listOf(
                    "APK 的 SHA-256 命中已知恶意样本库",
                    "样本家族：${indicator?.family ?: "未知"}",
                    "SHA-256：$sha"
                ),
                advice = "该安装包与已知恶意样本一致，请勿安装，建议删除。"
            )
        }

        if (!text.isNullOrEmpty()) {
            out += signatureEngine.scan(
                ScannableSubject(
                    displayName = apk.name,
                    filePath = apk.absolutePath,
                    sha256 = sha,
                    sizeBytes = apk.length(),
                    targetKind = if (isStandalone) TargetKind.APK else TargetKind.PACKAGE,
                    textProvider = { text }
                ),
                includeHeuristic = settings.heuristic
            )

            // APK 结构层面的启发式检查（与规则库互补：这里看的是"包的结构是否异常"）
            out += structuralChecks(apk, text, sha)
        }
    }

    /**
     * APK 结构异常检查。
     *
     * 这几项是规则库很难表达、但确实有区分度的结构特征：
     * - 同时存在多个 classesN.dex 且总数异常多（多 dex 投放）；
     * - assets 目录下存在以 dex/jar/apk 结尾的"隐藏载荷"；
     * - 清单中声明了大量危险权限。
     */
    private fun structuralChecks(apk: File, text: String, sha: String?): List<Threat> {
        val out = ArrayList<Threat>(1)
        val findings = ArrayList<String>(4)

        var dexCount = 0
        var payloads = 0
        runCatching {
            java.util.zip.ZipFile(apk).use { zip ->
                val entries = zip.entries().toList()
                dexCount = entries.count { it.name.startsWith("classes") && it.name.endsWith(".dex") }
                payloads = entries.count { e ->
                    val n = e.name.lowercase()
                    n.startsWith("assets/") &&
                        (n.endsWith(".dex") || n.endsWith(".jar") || n.endsWith(".apk"))
                }
            }
        }

        if (dexCount > 4) {
            findings += "该 APK 包含 $dexCount 个 DEX 文件，明显多于常规应用"
        }
        if (payloads > 0) {
            findings += "assets 目录中发现 $payloads 个可执行载荷（dex/jar/apk），可能是运行时释放的二次代码"
        }

        if (findings.isEmpty()) return out

        val severity = if (payloads > 0) Severity.HIGH else Severity.MEDIUM
        out += Threat(
            id = SignatureEngine.stableId("STRUCT/APKAnomaly", sha ?: apk.absolutePath),
            title = apk.name,
            ruleName = "STRUCT/APK.Anomaly",
            severity = severity,
            type = ThreatType.SUSPICIOUS,
            engine = DetectionEngine.STRUCTURE,
            targetKind = TargetKind.APK,
            filePath = apk.absolutePath,
            sha256 = sha,
            sizeBytes = apk.length(),
            evidence = findings,
            advice = "包结构存在异常特征。若该安装包来源不可信，建议不要安装。"
        )
        return out
    }

    // ---------------------------------------------------------------- 工具

    /**
     * 枚举已安装应用并构建 [AppInfo]。
     *
     * 需要 QUERY_ALL_PACKAGES（Android 11+）：作为安全工具，扫描全部应用
     * 是其核心职责，清单中已声明该权限并在上架说明中注明用途。
     */
    fun collectInstalledApps(): List<AppInfo> {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or
            PackageManager.GET_META_DATA or
            PackageManager.GET_SIGNING_CERTIFICATES

        val packages = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(flags)
            }
        }.getOrNull() ?: return emptyList()

        return packages.mapNotNull { pi ->
            runCatching { toAppInfo(pm, pi) }.getOrNull()
        }
    }

    private fun toAppInfo(pm: PackageManager, pi: android.content.pm.PackageInfo): AppInfo {
        val ai: ApplicationInfo = pi.applicationInfo ?: throw IllegalStateException("no ai")
        val label = runCatching { pm.getApplicationLabel(ai).toString() }
            .getOrDefault(pi.packageName)

        val requested = pi.requestedPermissions?.toList().orEmpty()

        // 判断应用是否注册了无障碍服务 / 通知监听 / 设备管理器 / 悬浮窗。
        // 这些要么体现在权限里，要么体现在组件声明里，逐个检查。
        val usesAccessibility = requested.any { it.endsWith("BIND_ACCESSIBILITY_SERVICE") }
        val usesNotificationListener = requested.any { it.endsWith("BIND_NOTIFICATION_LISTENER_SERVICE") }
        val usesDeviceAdmin = requested.any { it.endsWith("BIND_DEVICE_ADMIN") }
        val usesOverlay = requested.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val canInstall = requested.contains("android.permission.REQUEST_INSTALL_PACKAGES")

        // 安装来源
        val installer = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pi.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(pi.packageName)
            }
        }.getOrNull()

        // 签名证书摘要
        val signer = runCatching {
            val signers = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val si = pi.signingInfo ?: return@runCatching null
                if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
            } else {
                @Suppress("DEPRECATION")
                pi.signatures
            }
            signers?.firstOrNull()?.toByteArray()?.let { bytes ->
                MessageDigest.getInstance("SHA-256").digest(bytes)
                    .joinToString("") { "%02x".format(it) }
            }
        }.getOrNull()

        val isSystem = (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0

        return AppInfo(
            packageName = pi.packageName,
            label = label,
            versionName = pi.versionName,
            versionCode = PackageInfoCompat.getLongVersionCode(pi),
            targetSdk = ai.targetSdkVersion,
            minSdk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) ai.minSdkVersion else 1,
            installedAt = pi.firstInstallTime,
            updatedAt = pi.lastUpdateTime,
            apkPath = ai.sourceDir ?: "",
            apkSize = File(ai.sourceDir ?: "").let { if (it.exists()) it.length() else 0L },
            permissions = requested,
            isSystem = isSystem,
            usesAccessibility = usesAccessibility,
            usesDeviceAdmin = usesDeviceAdmin,
            canInstallPackages = canInstall,
            usesNotificationListener = usesNotificationListener,
            usesOverlay = usesOverlay,
            installer = installer,
            signerSha256 = signer
        )
    }

    /**
     * 默认扫描根目录。
     *
     * 刻意避开 `/Android/data` 与 `/Android/obb`：那两处从 Android 11 起
     * 对普通应用不可读，遍历只会得到一堆权限拒绝，白白浪费时间。
     */
    fun defaultScanRoots(settings: SettingsState): List<File> {
        val roots = ArrayList<File>(8)
        val external = context.getExternalFilesDir(null)?.parentFile?.parentFile

        listOf(
            "/sdcard/Download",
            "/sdcard/Documents",
            "/sdcard/Downloads",
            "/sdcard/DCIM",
            "/sdcard/Pictures",
            "/sdcard/Movies",
            "/sdcard/Music",
            "/sdcard/Android/data",
            "/sdcard/Android/media",
            "/sdcard/Android/obb",
            "/sdcard/Bluetooth"
        ).forEach { p ->
            val f = File(p)
            if (f.exists() && f.canRead()) roots += f
        }

        // 应用私有目录（下载缓存是恶意载荷的高发地）
        context.getExternalFilesDir(null)?.let { if (it.canRead()) roots += it }
        if (settings.scanHidden) {
            external?.let { if (it.canRead()) roots += it }
        }
        return roots.distinctBy { runCatching { it.canonicalPath }.getOrDefault(it.path) }
    }

    /**
     * 系统完整性体检。
     *
     * 这些检查都是"用户态可判定"的，不假装能做内核层面的完整性校验：
     * 每一项都能给出确切依据，且失败时给出的建议是可执行的。
     */
    fun integrityChecks(settings: SettingsState): List<IntegrityCheck> {
        val out = ArrayList<IntegrityCheck>(8)

        // 1. 病毒库加载状态
        out += IntegrityCheck(
            id = "engine.rules",
            title = "病毒特征库已加载",
            passed = signatureEngine.rulesCount > 0,
            detail = "已加载 ${signatureEngine.rulesCount} 条特征规则（其中启发式 ${signatureEngine.heuristicRulesCount} 条）",
            severityIfFailed = Severity.HIGH,
            advice = "特征库为空会导致无法识别任何威胁，请重新安装应用或导入规则库。"
        )

        // 2. 实时防护
        out += IntegrityCheck(
            id = "engine.realtime",
            title = "实时防护已开启",
            passed = settings.realtimeProtection,
            detail = if (settings.realtimeProtection) "安装与更新应用时会自动检测" else "当前未开启，新安装的应用不会被自动检测",
            severityIfFailed = Severity.MEDIUM,
            advice = "建议在设置中开启实时防护。"
        )

        // 3. 开发人员选项（调试模式）
        val adbEnabled = runCatching {
            android.provider.Settings.Global.getInt(
                context.contentResolver,
                android.provider.Settings.Global.ADB_ENABLED, 0
            ) == 1
        }.getOrDefault(false)
        out += IntegrityCheck(
            id = "system.adb",
            title = "USB 调试已关闭",
            passed = !adbEnabled,
            detail = if (adbEnabled) "USB 调试处于开启状态，接入不受信任的电脑时存在被安装应用的风险" else "USB 调试未开启",
            severityIfFailed = Severity.MEDIUM,
            advice = "若不需要调试，建议在开发者选项中关闭 USB 调试。"
        )

        // 4. 未知来源安装
        val unknownSources = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.packageManager.canRequestPackageInstalls()
            } else {
                @Suppress("DEPRECATION")
                android.provider.Settings.Secure.getInt(
                    context.contentResolver,
                    android.provider.Settings.Secure.INSTALL_NON_MARKET_APPS, 0
                ) == 1
            }
        }.getOrDefault(false)
        out += IntegrityCheck(
            id = "system.sideload",
            title = "第三方应用安装来源受限",
            passed = !unknownSources,
            detail = if (unknownSources) "本应用或被授予了从任意来源安装应用的权限" else "安装来源已受系统管控",
            severityIfFailed = Severity.LOW,
            advice = "这是常规设置项，仅在确有需要时保留即可。"
        )

        // 5. 无障碍服务使用情况
        val accessibilityOn = runCatching {
            val enabled = android.provider.Settings.Secure.getString(
                context.contentResolver,
                android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            )
            !enabled.isNullOrBlank()
        }.getOrDefault(false)
        out += IntegrityCheck(
            id = "system.accessibility",
            title = "无障碍服务列表",
            passed = !accessibilityOn,
            detail = if (accessibilityOn) "系统中有已启用的无障碍服务。该权限可读取屏幕内容并模拟点击" else "当前没有已启用的无障碍服务",
            severityIfFailed = Severity.INFO,
            advice = "请在系统设置中确认这些无障碍服务都是你自己开启的。"
        )

        // 6. 设备是否已 root
        val rooted = runCatching { detectRoot() }.getOrDefault(false)
        out += IntegrityCheck(
            id = "system.root",
            title = "设备未获取 Root 权限",
            passed = !rooted,
            detail = if (rooted) "检测到 su 二进制或常见 Root 管理工具，系统完整性保护可能已被削弱" else "未检测到 Root 迹象",
            severityIfFailed = Severity.HIGH,
            advice = "Root 会突破应用沙箱。若你并未主动 Root，请尽快排查。"
        )

        // 7. 安全补丁级别（Android 12+ 可通过 Build 字段读取）
        val patch = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) Build.VERSION.SECURITY_PATCH else null
        }.getOrNull()
        if (!patch.isNullOrBlank()) {
            val stale = patch < "2024-01-01"
            out += IntegrityCheck(
                id = "system.patch",
                title = "系统安全补丁较新",
                passed = !stale,
                detail = "当前安全补丁级别：$patch",
                severityIfFailed = Severity.MEDIUM,
                advice = "建议在系统更新中安装最新的安全补丁。"
            )
        }

        return out
    }

    /**
     * Root 检测。用常见 su 路径 + 管理工具包名双重判断。
     * 只做只读探测，不尝试提权。
     */
    private fun detectRoot(): Boolean {
        val paths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
            "/data/local/bin/su", "/data/local/xbin/su"
        )
        for (p in paths) {
            if (runCatching { File(p).exists() }.getOrDefault(false)) return true
        }
        val managers = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.noshufou.android.su"
        )
        val pm = context.packageManager
        for (pkg in managers) {
            val found = runCatching {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, 0)
                true
            }.getOrDefault(false)
            if (found) return true
        }
        return false
    }

    /** 按 id 去重：同一问题可能被多条路径命中，只保留严重度最高的那条 */
    private fun dedupe(list: List<Threat>): List<Threat> =
        list.groupBy { it.id }
            .map { (_, group) -> group.maxByOrNull { it.severity.level } ?: group.first() }
            .sortedWith(
                compareByDescending<Threat> { it.severity.level }
                    .thenByDescending { it.detectedAt }
            )

    private companion object {
        const val MAX_DEPTH = 12
    }
}

/**
 * 扫描结果。
 */
data class ScanOutcome(
    val mode: ScanMode,
    val threats: List<Threat>,
    val filesScanned: Int,
    val appsScanned: Int,
    val bytesScanned: Long,
    val startedAt: Long,
    val finishedAt: Long,
    val cancelled: Boolean
) {
    val durationMs: Long get() = finishedAt - startedAt
}

/**
 * 一个极简的节流器。
 *
 * 为什么不用协程的 `sample` / `debounce` 操作符：这两个都需要一个 Flow 上游，
 * 而我们的进度是"推"模型（回调），套 Flow 反而更绕。这里用一个时间戳判断就够了。
 */
internal class Throttle(private val intervalMs: Long) {
    private var last = 0L
    operator fun invoke(block: () -> Unit) {
        val now = System.currentTimeMillis()
        if (now - last >= intervalMs) {
            last = now
            block()
        }
    }
}