package com.aegis.guard.ui.cve

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.guard.AegisApp
import com.aegis.guard.cve.CveMatcher
import com.aegis.guard.data.model.AppInfo
import com.aegis.guard.data.model.CveMatch
import com.aegis.guard.engine.FileAnalyzer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 漏洞检测页的 ViewModel。
 *
 * 与 ScanViewModel 的区别：这里不做文件遍历，只对"已安装应用"逐个提取
 * 依赖坐标再比对 CVE 区间，因此进度以"应用数"为单位而不是字节数。
 */
class CveViewModel(app: Application) : AndroidViewModel(app) {

    private val aegis = app as AegisApp

    data class UiState(
        val scanning: Boolean = false,
        val scannedApps: Int = 0,
        val totalApps: Int = 0,
        val matches: List<CveMatch> = emptyList(),
        val hasRun: Boolean = false,
        val error: String? = null
    ) {
        /** 命中的不同组件数与覆盖的不同应用数 */
        val componentCount: Int get() = matches.map { it.cve.id }.distinct().size
        val appCount: Int get() = matches.mapNotNull { it.packageName }.distinct().size
        val hasMatches: Boolean get() = matches.isNotEmpty()
    }

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private var job: Job? = null

    /** 开始检测。重复调用时先取消上一次。 */
    fun scan() {
        job?.cancel()
        job = viewModelScope.launch {
            _state.value = UiState(scanning = true, hasRun = false)

            try {
                val matcher: CveMatcher = aegis.cveMatcher()

                // 1) 采集已安装应用（IO 密集，切到 IO 线程）
                val apps: List<AppInfo> = withContext(Dispatchers.IO) {
                    com.aegis.guard.scan.Scanner(
                        context = getApplication(),
                        signatureEngine = aegis.signatureEngine,
                        hashIndicators = aegis.loadedMeta?.hashes.orEmpty()
                    ).collectInstalledApps()
                }

                _state.value = _state.value.copy(totalApps = apps.size)

                // 2) 规则库未就绪时给出明确提示，而不是静默返回空列表
                if (matcher.size == 0) {
                    _state.value = _state.value.copy(
                        scanning = false,
                        hasRun = true,
                        error = "规则库尚未加载完成"
                    )
                    return@launch
                }

                val found = ArrayList<CveMatch>(8)
                var done = 0

                for (app in apps) {
                    if (!isActive) return@launch

                    val components = withContext(Dispatchers.IO) {
                        val text = readApkText(app)
                        matcher.componentsOf(app, text)
                    }

                    for (c in components) {
                        found += matcher.match(c, app.packageName, app.label)
                    }

                    done++
                    _state.value = _state.value.copy(
                        scannedApps = done,
                        matches = dedupe(found)
                    )
                }

                _state.value = _state.value.copy(
                    scanning = false,
                    hasRun = true,
                    matches = dedupe(found),
                    error = null
                )
            } catch (t: Throwable) {
                _state.value = _state.value.copy(
                    scanning = false,
                    hasRun = true,
                    error = t.message ?: t.javaClass.simpleName
                )
            }
        }
    }

    /** 从 APK 中提取可读文本（供依赖坐标解析），失败返回 null。 */
    private fun readApkText(app: AppInfo): String? = runCatching {
        val f = File(app.apkPath)
        if (!f.exists() || !f.canRead()) return@runCatching null
        if (FileAnalyzer.isZip(f)) {
            FileAnalyzer.extractApkText(f, includeDex = aegis.settings.current().dexAnalysis)
        } else {
            FileAnalyzer.extractText(f)
        }
    }.getOrNull()

    /**
     * 按 (CVE, 版本, 包名) 去重，并按 CVSS 从高到低排序。
     * 同一个 CVE 命中多个应用时保留多条，但同一应用的同一组件只留一条。
     */
    private fun dedupe(list: List<CveMatch>): List<CveMatch> = list
        .distinctBy { Triple(it.cve.id, it.detectedVersion, it.packageName) }
        .sortedByDescending { it.cve.cvss }

    override fun onCleared() {
        super.onCleared()
        job?.cancel()
    }
}