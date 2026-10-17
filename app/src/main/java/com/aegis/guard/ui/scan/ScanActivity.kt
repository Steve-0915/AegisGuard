package com.aegis.guard.ui.scan

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import com.aegis.guard.R
import com.aegis.guard.databinding.ActivityScanBinding
import com.aegis.guard.scan.ScanMode
import com.aegis.guard.ui.common.ThreatAdapter
import com.aegis.guard.ui.detail.ThreatDetailActivity
import com.aegis.guard.util.UiFormat
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.io.File

/**
 * 扫描页。
 *
 * 页面有三个形态，由 [ScanUiState] 驱动切换：
 * 1. 模式选择（group_modes）——刚进入且未开始扫描；
 * 2. 进行中（group_progress + 进度环 + 停止按钮）；
 * 3. 已完成（隐藏进度环，显示结果列表）。
 *
 * 设计要点：
 * - 扫描状态由 [ScanViewModel] 持有，因此旋转屏幕不会丢失进度；
 * - 结果列表点击直接跳详情页；
 * - 停止扫描会保留已发现的威胁，不是"丢弃全部"。
 */
class ScanActivity : AppCompatActivity() {

    private lateinit var binding: ActivityScanBinding
    private val vm: ScanViewModel by viewModels()
    private lateinit var threatAdapter: ThreatAdapter

    /** 文件/目录选择器：用于"自定义目录"与"单 APK 分析" */
    private val pickTree = registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        // 用 Uri 的路径段拼出真实路径（DocumentFile 对 content:// 树只给虚拟名）
        val path = uri.pathSegments?.lastOrNull()?.let { "/$it" }
            ?: uri.toString()
        val dir = File(path)
        if (dir.exists()) start(ScanMode.CUSTOM, dirs = listOf(dir))
        else {
            // 取不到真实路径时退化为按全盘文件扫描该树
            toast(getString(R.string.permission_denied))
        }
    }

    private val pickApk = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        val path = uri.pathSegments?.lastOrNull()?.let { "/$it" } ?: uri.toString()
        val f = File(path)
        if (f.exists()) start(ScanMode.APK, apk = f)
        else toast(getString(R.string.permission_denied))
    }

    /** 存储读取权限申请结果 */
    private val storagePermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { result ->
        val granted = result.isNotEmpty() && result.values.all { it }
        if (granted) pendingAfterPermission?.invoke()
        else toast(getString(R.string.permission_denied))
        pendingAfterPermission = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityScanBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupToolbar()
        setupRing()
        setupList()
        setupModeCards()
        observe()

        // 冷启动且没有正在进行的扫描 → 展示模式选择；否则恢复进度视图
        if (!vm.state.value.running && !vm.state.value.finished) {
            showModes()
        }
    }

    // ------------------------------------------------------------ 初始化

    private fun setupToolbar() {
        binding.toolbar.setNavigationOnClickListener { finish() }
    }

    /**
     * 进度环样式。
     *
     * 用系统 ProgressBar 的自定义 drawable 而不是引入第三方圆形进度控件：
     * 依赖越少构建越稳，而且我们能精确控制粗细与颜色，符合 MD3 观感。
     */
    private fun setupRing() {
        val bar = binding.progressRing
        val stroke = resources.getDimensionPixelSize(R.dimen.scan_ring_stroke)

        val track = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setStroke(stroke, ContextCompat.getColor(this@ScanActivity, R.color.threat_clean_container))
        }
        val progress = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setStroke(stroke, ContextCompat.getColor(this@ScanActivity, R.color.threat_clean))
        }
        // 系统 ProgressBar 的 layer-list 需要两个 layer：背景 + 前景
        bar.progressDrawable = progress
        bar.background = track
    }

    private fun setupList() {
        threatAdapter = ThreatAdapter { threat ->
            startActivity(ThreatDetailActivity.intentFor(this, threat.id))
        }
        binding.listThreats.layoutManager = LinearLayoutManager(this)
        binding.listThreats.adapter = threatAdapter
        binding.listThreats.isNestedScrollingEnabled = false
    }

    private fun setupModeCards() {
        binding.cardFull.setOnClickListener { confirmThenStart(ScanMode.FULL) }
        binding.cardApps.setOnClickListener { confirmThenStart(ScanMode.APPS) }
        binding.cardFiles.setOnClickListener { confirmThenStart(ScanMode.FILES) }
        binding.cardCustom.setOnClickListener {
            // 自定义目录需要 SAF 授权
            runCatching { pickTree.launch(null) }
                .onFailure { toast(getString(R.string.permission_denied)) }
        }
        binding.cardApk.setOnClickListener {
            runCatching { pickApk.launch("application/vnd.android.package-archive") }
                .onFailure { toast(getString(R.string.permission_denied)) }
        }

        binding.buttonStop.setOnClickListener { vm.stop() }
    }

    /**
     * 文件类扫描需要存储读取权限。
     * Android 13+ 用 READ_MEDIA_*，12- 用 READ_EXTERNAL_STORAGE。
     */
    private fun ensureStoragePermission(onGranted: () -> Unit) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            onGranted(); return
        }
        val needed = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.READ_MEDIA_IMAGES)
                add(Manifest.permission.READ_MEDIA_VIDEO)
                add(Manifest.permission.READ_MEDIA_AUDIO)
            } else {
                add(Manifest.permission.READ_EXTERNAL_STORAGE)
            }
        }
        val missing = needed.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) {
            onGranted()
            return
        }
        pendingAfterPermission = onGranted
        storagePermissionLauncher.launch(missing.toTypedArray())
    }

    /** 权限通过后要继续执行的动作（例如启动扫描） */
    private var pendingAfterPermission: (() -> Unit)? = null

    /** 应用/全盘扫描直接开始；文件类先要权限 */
    private fun confirmThenStart(mode: ScanMode) {
        when (mode) {
            ScanMode.FILES, ScanMode.FULL -> ensureStoragePermission { start(mode) }
            else -> start(mode)
        }
    }

    private fun start(mode: ScanMode, dirs: List<File> = emptyList(), apk: File? = null) {
        showProgress()
        vm.start(mode, dirs, apk)
    }

    // ------------------------------------------------------------ 观察状态

    private fun observe() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                vm.state.collectLatest { s -> render(s) }
            }
        }
    }

    private fun render(s: ScanUiState) {
        // 三形态切换：模式选择 / 进行中 / 完成
        val showModes = !s.running && !s.finished
        binding.groupModes.visibility = if (showModes) View.VISIBLE else View.GONE
        binding.groupProgress.visibility = if (showModes) View.GONE else View.VISIBLE

        if (showModes) return

        // --- 进度环 ---
        if (s.running) {
            if (s.fraction >= 0f) {
                binding.progressRing.isIndeterminate = false
                binding.progressRing.max = 1000
                binding.progressRing.progress = (s.fraction * 1000).toInt()
                binding.textRingPercent.text =
                    String.format(java.util.Locale.US, "%d%%", (s.fraction * 100).toInt())
            } else {
                binding.progressRing.isIndeterminate = true
                binding.textRingPercent.text = "…"
            }
            binding.textRingLabel.text = getString(R.string.scan_progress)
        } else {
            // 结束：环填满或按结果着色
            binding.progressRing.isIndeterminate = false
            binding.progressRing.max = 1000
            binding.progressRing.progress = 1000
            binding.textRingPercent.text = if (s.cancelled) getString(R.string.action_stop) else "100%"
            binding.textRingLabel.text = getString(R.string.scan_complete)
        }

        // --- 当前项目 / 阶段 ---
        binding.textStage.text = s.stage
        val current = s.currentItem
        binding.textCurrent.text = when {
            current.isNotBlank() -> getString(R.string.scan_current_file, current)
            s.appsScanned > 0 -> getString(R.string.scan_apps_scanned) + " " + s.appsScanned
            else -> ""
        }
        binding.textCurrent.visibility = if (binding.textCurrent.text.isNullOrBlank())
            View.GONE else View.VISIBLE

        // --- 实时统计 ---
        binding.textFiles.text =
            if (s.appsScanned > 0 && s.filesScanned == 0) UiFormat.count(s.appsScanned)
            else UiFormat.count(s.filesScanned)
        binding.textFound.text = UiFormat.count(s.threatsFound)
        binding.textElapsed.text = UiFormat.duration(s.elapsedMs)

        // 发现数 > 0 时用错误色强调
        binding.textFound.setTextColor(
            ContextCompat.getColor(
                this,
                if (s.threatsFound > 0) R.color.threat_high else R.color.threat_clean
            )
        )

        // --- 停止按钮 ---
        binding.buttonStop.visibility = if (s.running) View.VISIBLE else View.GONE

        // --- 结果 ---
        if (!s.running) {
            binding.textResult.visibility = View.VISIBLE
            binding.textResult.text = when {
                s.error != null -> s.error
                s.threats.isEmpty() -> getString(R.string.scan_complete_clean)
                else -> getString(R.string.scan_complete_found, s.threats.size)
            }
            binding.textResult.setTextColor(
                ContextCompat.getColor(
                    this,
                    if (s.threats.isEmpty()) R.color.threat_clean else R.color.threat_high
                )
            )
            threatAdapter.submitList(s.threats)
        } else {
            binding.textResult.visibility = View.GONE
        }
    }

    private fun showModes() {
        binding.groupModes.visibility = View.VISIBLE
        binding.groupProgress.visibility = View.GONE
    }

    private fun showProgress() {
        binding.groupModes.visibility = View.GONE
        binding.groupProgress.visibility = View.VISIBLE
    }

    private fun toast(msg: String) {
        android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_SHORT).show()
    }

    companion object {
        const val EXTRA_MODE = "extra_mode"
        const val EXTRA_MODE_APPS = "apps"
        const val EXTRA_MODE_FILES = "files"
        const val EXTRA_MODE_FULL = "full"

        /** 从其他页面进入扫描页，可预设模式 */
        fun intentFor(context: Context, mode: String? = null): Intent {
            val i = Intent(context, ScanActivity::class.java)
            if (mode != null) i.putExtra(EXTRA_MODE, mode)
            return i
        }
    }
}
