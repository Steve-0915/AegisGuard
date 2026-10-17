package com.aegis.guard.ui.scan

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.guard.AegisApp
import com.aegis.guard.data.model.ScanReport
import com.aegis.guard.data.model.Severity
import com.aegis.guard.data.model.Threat
import com.aegis.guard.scan.ScanMode
import com.aegis.guard.scan.ScanOutcome
import com.aegis.guard.scan.ScanProgress
import com.aegis.guard.scan.Scanner
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.util.UUID

/**
 * 扫描页状态。
 */
data class ScanUiState(
    val running: Boolean = false,
    val stage: String = "",
    val currentItem: String = "",
    val filesScanned: Int = 0,
    val appsScanned: Int = 0,
    val bytesScanned: Long = 0L,
    val threatsFound: Int = 0,
    /** 0f..1f；-1 表示不确定进度 */
    val fraction: Float = -1f,
    /** 已运行的毫秒数，用于展示"已用时" */
    val elapsedMs: Long = 0L,
    val finished: Boolean = false,
    val cancelled: Boolean = false,
    val threats: List<Threat> = emptyList(),
    val error: String? = null
)

/**
 * 扫描 ViewModel。
 *
 * 承载一次扫描的完整生命周期：启动 → 进度回调 → 结果入库 → 结束。
 *
 * 关键点：
 * - 扫描任务放在 [viewModelScope]，但内部跑在 Dispatchers.IO（Scanner 自己切）；
 *   因此配置变更（旋转屏幕）不会中断扫描；
 * - 进度回调切回主线程后再写 StateFlow，保证 UI 侧看到一致的顺序；
 * - 扫描结束后调用 repository.recordScan，首页会自动刷新（Flow 驱动）。
 */
class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val aegis: AegisApp = AegisApp.from(app)

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    private var job: Job? = null
    private var ticker: Job? = null
    private var startedAt = 0L

    /** 当前实际使用的模式，供"重新扫描"复用 */
    private var lastMode: ScanMode = ScanMode.FULL
    private var lastDirs: List<File> = emptyList()
    private var lastApk: File? = null

    /**
     * 开始一次扫描。
     *
     * 若上一次还在跑，先取消——避免两个扫描同时推进度造成界面跳变。
     */
    fun start(
        mode: ScanMode,
        dirs: List<File> = emptyList(),
        apk: File? = null
    ) {
        job?.cancel()
        ticker?.cancel()

        lastMode = mode
        lastDirs = dirs
        lastApk = apk
        startedAt = System.currentTimeMillis()

        _state.value = ScanUiState(running = true, stage = "正在准备…")

        // 计时器：每 200ms 刷新"已用时"，与进度回调解耦，避免进度不动时秒表也停
        ticker = viewModelScope.launch {
            while (true) {
                delay(200)
                if (!_state.value.running) break
                _state.value = _state.value.copy(
                    elapsedMs = System.currentTimeMillis() - startedAt
                )
            }
        }

        job = viewModelScope.launch {
            try {
                val scanner = Scanner(
                    context = getApplication(),
                    signatureEngine = aegis.signatureEngine,
                    hashIndicators = aegis.loadedMeta?.hashes.orEmpty()
                )

                val outcome: ScanOutcome = scanner.scan(
                    mode = mode,
                    settings = aegis.settings.current(),
                    customDirs = dirs,
                    singleApk = apk
                ) { progress: ScanProgress ->
                    // 回调来自 IO 线程；StateFlow 本身线程安全，直接写即可。
                    // 但要保留 running/finished 等由本类管理的字段，所以用 copy 而不是整体替换。
                    val cur = _state.value
                    _state.value = cur.copy(
                        stage = stageLabel(progress.stage),
                        currentItem = progress.currentItem,
                        filesScanned = progress.filesScanned,
                        appsScanned = progress.appsScanned,
                        bytesScanned = progress.bytesScanned,
                        threatsFound = progress.threatsFound,
                        fraction = progress.fraction
                    )
                }

                finish(outcome)
            } catch (c: kotlinx.coroutines.CancellationException) {
                // 主动取消：把状态标记为"已取消"，但保留已发现的结果
                _state.value = _state.value.copy(
                    running = false,
                    finished = true,
                    cancelled = true,
                    stage = "已取消"
                )
                throw c
            } catch (t: Throwable) {
                _state.value = _state.value.copy(
                    running = false,
                    finished = true,
                    error = t.message ?: "扫描失败"
                )
            }
        }
    }

    /** 用户点"停止" */
    fun stop() {
        job?.cancel()
        ticker?.cancel()
        _state.value = _state.value.copy(running = false, finished = true, cancelled = true)
    }

    /** 按上次参数重扫 */
    fun rescan() = start(lastMode, lastDirs, lastApk)

    /**
     * 结束流程：写入仓库 + 更新设置里的"最近扫描时间"。
     *
     * 之所以在这里（而不是 Scanner 内部）做持久化：
     * Scanner 保持"纯计算"的定位，不做副作用，方便测试与复用。
     */
    private suspend fun finish(outcome: ScanOutcome) {
        val threats = outcome.threats
        val report = ScanReport(
            sessionId = UUID.randomUUID().toString(),
            startedAt = outcome.startedAt,
            finishedAt = outcome.finishedAt,
            mode = outcome.mode.key,
            filesScanned = outcome.filesScanned,
            appsScanned = outcome.appsScanned,
            bytesScanned = outcome.bytesScanned,
            threats = threats,
            cancelled = outcome.cancelled
        )

        aegis.repository.recordScan(report)
        aegis.settings.setLastScanAt(outcome.finishedAt)

        _state.value = _state.value.copy(
            running = false,
            finished = true,
            cancelled = outcome.cancelled,
            threats = threats,
            elapsedMs = outcome.durationMs,
            stage = "扫描完成"
        )
    }

    /** 把枚举阶段翻译成界面文案 */
    private fun stageLabel(stage: com.aegis.guard.scan.ScanStage): String = when (stage) {
        com.aegis.guard.scan.ScanStage.PREPARE -> "正在准备扫描引擎…"
        com.aegis.guard.scan.ScanStage.APPS -> "正在检查已安装应用…"
        com.aegis.guard.scan.ScanStage.PACKAGES -> "正在评估应用风险…"
        com.aegis.guard.scan.ScanStage.FILES -> "正在扫描存储文件…"
        com.aegis.guard.scan.ScanStage.HASH -> "正在比对哈希黑名单…"
        com.aegis.guard.scan.ScanStage.HEURISTIC -> "正在进行启发式分析…"
        com.aegis.guard.scan.ScanStage.REPORT -> "正在汇总结果…"
    }

    /** 供界面判断是否需要显示"危险"配色 */
    val maxSeverity: Severity
        get() = _state.value.threats.maxOfOrNull { it.severity } ?: Severity.CLEAN
}