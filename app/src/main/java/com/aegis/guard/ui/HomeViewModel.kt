package com.aegis.guard.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.guard.AegisApp
import com.aegis.guard.data.model.IntegrityCheck
import com.aegis.guard.data.model.Severity
import com.aegis.guard.data.model.Threat
import com.aegis.guard.data.store.SettingsState
import com.aegis.guard.scan.Scanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 首页状态。
 *
 * 把"首页需要展示的全部信息"打包成一个不可变快照，
 * 让 Activity 的渲染逻辑只需要一个 when，而不必去组合四五个 Flow。
 */
data class HomeUiState(
    val loading: Boolean = true,
    val rulesCount: Int = 0,
    val heuristicCount: Int = 0,
    val cveCount: Int = 0,
    val rulesVersion: String = "",
    val cveVersion: String = "",
    val engineFailed: String? = null,
    val activeThreats: List<Threat> = emptyList(),
    val dismissedCount: Int = 0,
    val lastScanAt: Long = 0L,
    val appsScanned: Int = 0,
    val totalThreats: Int = 0,
    val integrity: List<IntegrityCheck> = emptyList(),
    val settings: SettingsState = SettingsState()
) {
    /** 首页顶部状态卡的等级：取最高威胁等级 */
    val maxSeverity: Severity
        get() = activeThreats.maxOfOrNull { it.severity } ?: Severity.CLEAN

    val hasThreats: Boolean get() = activeThreats.isNotEmpty()
    val failedChecks: List<IntegrityCheck> get() = integrity.filter { !it.passed }
}

/**
 * 首页 ViewModel。
 *
 * 数据来源三路合并：
 * 1. [AegisApp.engineState] —— 规则库加载状态；
 * 2. [com.aegis.guard.data.repo.ThreatRepository.threats] —— 威胁列表；
 * 3. [com.aegis.guard.data.store.Settings.state] —— 设置快照。
 */
class HomeViewModel(app: Application) : AndroidViewModel(app) {

    private val aegis: AegisApp = AegisApp.from(app)

    private val _integrity = MutableStateFlow<List<IntegrityCheck>>(emptyList())
    private val _loadingIntegrity = MutableStateFlow(true)

    val state: StateFlow<HomeUiState> = combine(
        aegis.engineState,
        aegis.repository.threats,
        aegis.settings.state
    ) { engine, threats, settings ->
        val active = threats.filter { !it.dismissed }
        HomeUiState(
            loading = engine is AegisApp.EngineState.Loading,
            rulesCount = (engine as? AegisApp.EngineState.Ready)?.rules ?: 0,
            heuristicCount = (engine as? AegisApp.EngineState.Ready)?.heuristic ?: 0,
            cveCount = (engine as? AegisApp.EngineState.Ready)?.cves ?: 0,
            rulesVersion = (engine as? AegisApp.EngineState.Ready)?.rulesVersion ?: settings.rulesVersion,
            cveVersion = (engine as? AegisApp.EngineState.Ready)?.cveVersion ?: settings.cveVersion,
            engineFailed = (engine as? AegisApp.EngineState.Failed)?.message,
            activeThreats = active,
            dismissedCount = threats.count { it.dismissed },
            lastScanAt = settings.lastScanAt,
            appsScanned = aegis.repository.history.value.firstOrNull()?.appsScanned ?: 0,
            totalThreats = threats.size,
            integrity = _integrity.value,
            settings = settings
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = HomeUiState()
    )

    /** 体检项加载状态，供界面显示骨架屏 */
    val loadingIntegrity: StateFlow<Boolean> = _loadingIntegrity.asStateFlow()

    init {
        refreshIntegrity()
    }

    /**
     * 执行系统完整性体检。
     *
     * 这些检查全部是只读探测，耗时在毫秒级，可以直接在主流程里跑，
     * 但仍然放到 IO 线程以保持"UI 线程不做任何文件访问"的纪律。
     */
    fun refreshIntegrity() {
        viewModelScope.launch {
            _loadingIntegrity.value = true
            val checks = withContext(Dispatchers.IO) {
                runCatching {
                    val settings = aegis.settings.current()
                    Scanner(
                        context = getApplication(),
                        signatureEngine = aegis.signatureEngine,
                        hashIndicators = aegis.loadedMeta?.hashes.orEmpty()
                    ).integrityChecks(settings)
                }.getOrElse { emptyList() }
            }
            _integrity.value = checks
            _loadingIntegrity.value = false
        }
    }

    /** 重新加载规则库（设置页"更新病毒库"） */
    fun reloadEngine() {
        aegis.loadEngine()
    }

    /** 忽略一条威胁 */
    fun dismiss(threatId: String) {
        aegis.repository.dismiss(threatId)
        refreshIntegrity()
    }

    /** 把某个键（包名或路径）加入白名单 */
    fun whitelist(key: String) {
        aegis.repository.addToWhitelist(key)
    }

    fun remove(threatId: String) {
        aegis.repository.remove(threatId)
    }
}