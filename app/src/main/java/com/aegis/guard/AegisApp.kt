package com.aegis.guard

import android.app.Application
import com.aegis.guard.data.repo.ThreatRepository
import com.aegis.guard.data.store.Settings
import com.aegis.guard.engine.RuleLoader
import com.aegis.guard.engine.SignatureEngine
import com.aegis.guard.cve.CveMatcher
import com.aegis.guard.data.model.CveEntry
import com.aegis.guard.util.Notifications
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * 应用级单例容器。
 *
 * 为什么不用依赖注入框架：本项目只有 5 个长期存活对象，
 * 一个手写的容器就足够，还能省下 Hilt/Koin 带来的注解处理与启动开销。
 *
 * 加载时机：规则库（assets 里的两份 JSON）在 [onCreate] 里异步载入。
 * UI 通过订阅 [engineState] 感知"加载中 / 就绪"，避免在首帧做磁盘 IO。
 */
class AegisApp : Application() {

    /** 设置仓库 */
    val settings by lazy { Settings(this) }

    /** 威胁记录仓库 */
    val repository by lazy { ThreatRepository(this) }

    /** 规则引擎（初始为空，载入后填充） */
    val signatureEngine by lazy { SignatureEngine() }

    /** 应用级作用域：生命周期与进程一致，不做取消 */
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** 引擎加载状态 */
    private val _engineState = MutableStateFlow<EngineState>(EngineState.Loading)
    val engineState: StateFlow<EngineState> = _engineState.asStateFlow()

    /** CVE 匹配器（随规则库一起构建） */
    @Volatile
    private var cveEntries: List<CveEntry> = emptyList()

    /** 规则库元数据，供首页/关于页展示 */
    @Volatile
    var loadedMeta: RuleLoader.Loaded? = null
        private set

    override fun onCreate() {
        super.onCreate()
        Notifications.ensureChannel(this)
        appScope.launch { loadEngine() }
    }

    /**
     * 载入规则库。
     *
     * 幂等：重复调用是安全的（例如用户手动"更新病毒库"后触发）。
     */
    fun loadEngine() {
        appScope.launch {
            _engineState.value = EngineState.Loading
            try {
                val loaded = RuleLoader.load(this@AegisApp)
                signatureEngine.loadRules(loaded.rules)
                cveEntries = loaded.cves
                loadedMeta = loaded

                // 把版本号写回设置，供首页展示"更新于"
                if (loaded.rulesVersion.isNotBlank()) {
                    settings.setRulesVersion(loaded.rulesVersion)
                }
                if (loaded.cveVersion.isNotBlank()) {
                    settings.setCveVersion(loaded.cveVersion)
                }

                _engineState.value = EngineState.Ready(
                    rules = signatureEngine.rulesCount,
                    heuristic = signatureEngine.heuristicRulesCount,
                    cves = loaded.cves.size,
                    dropped = loaded.dropped,
                    rulesVersion = loaded.rulesVersion,
                    cveVersion = loaded.cveVersion
                )
            } catch (t: Throwable) {
                _engineState.value = EngineState.Failed(t.message ?: "未知错误")
            }
        }
    }

    /** 获取 CVE 匹配器。规则库未就绪时返回空匹配器而不是 null，简化调用方。 */
    fun cveMatcher(): CveMatcher = CveMatcher(cveEntries)

    /** 当前已加载的 CVE 条目（关于页展示用） */
    fun currentCves(): List<CveEntry> = cveEntries

    sealed interface EngineState {
        data object Loading : EngineState

        data class Ready(
            val rules: Int,
            val heuristic: Int,
            val cves: Int,
            val dropped: Int,
            val rulesVersion: String,
            val cveVersion: String
        ) : EngineState

        data class Failed(val message: String) : EngineState
    }

    companion object {
        fun from(app: Application): AegisApp = app as AegisApp
    }
}
