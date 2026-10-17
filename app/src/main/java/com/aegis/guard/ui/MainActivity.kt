package com.aegis.guard.ui

import android.Manifest
import android.content.Intent
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
import com.aegis.guard.AegisApp
import com.aegis.guard.R
import com.aegis.guard.data.model.Severity
import com.aegis.guard.data.model.Threat
import com.aegis.guard.databinding.ActivityMainBinding
import com.aegis.guard.databinding.RowStatBinding
import com.aegis.guard.service.GuardService
import com.aegis.guard.ui.about.AboutActivity
import com.aegis.guard.ui.common.IntegrityAdapter
import com.aegis.guard.ui.common.ThreatAdapter
import com.aegis.guard.ui.cve.CveActivity
import com.aegis.guard.ui.detail.ThreatDetailActivity
import com.aegis.guard.ui.scan.ScanActivity
import com.aegis.guard.ui.settings.SettingsActivity
import com.aegis.guard.util.UiFormat
import com.aegis.guard.util.setupMaterialYou
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * 首页。
 *
 * 设计原则：
 * - 单一数据源：所有信息来自 [HomeViewModel.state] 这一个 StateFlow，
 *   collectLatest 里一次性刷新全部控件，避免"多个监听器各改各的"导致状态错乱；
 * - 无网络请求、无阻塞 IO，首帧渲染只依赖内存中的状态；
 * - 所有可点击项都有明确的语义（打开扫描、切换页面、查看详情）。
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val vm: HomeViewModel by viewModels()

    /** 最近威胁列表适配器，最多展示 3 条 */
    private val recentAdapter = ThreatAdapter { openDetail(it) }

    /** 通知权限申请（Android 13+） */
    private val notifPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* 用户选择与否都不阻塞功能，实时防护依然可用 */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        // 动态取色必须在 setContentView 之前，否则 MD3 组件已经用静态色完成了一次解析
        setupMaterialYou((application as AegisApp).settings.current().dynamicColor)
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupLists()
        setupClicks()
        observeState()
        requestNotificationPermissionIfNeeded()
    }

    // ------------------------------------------------------------ 初始化

    private fun setupLists() {
        binding.listRecent.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = recentAdapter
            isNestedScrollingEnabled = false
            setHasFixedSize(false)
        }
        binding.listIntegrity.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            isNestedScrollingEnabled = false
        }
    }

    /**
     * 绑定全部点击事件。
     *
     * 集中在一处而不是散落在各处 setOnClickListener，
     * 是为了让"这个页面能做什么"一眼可见，便于后续加功能时检查是否有遗漏。
     */
    private fun setupClicks() {
        binding.buttonScan.setOnClickListener {
            startActivity(Intent(this, ScanActivity::class.java))
        }

        binding.buttonViewAll.setOnClickListener {
            // "查看全部"跳到 CVE 页旁边的威胁列表——这里复用扫描页的历史视图
            startActivity(Intent(this, ScanActivity::class.java))
        }

        binding.tileAppScan.setOnClickListener {
            startActivity(
                ScanActivity.intentFor(this, ScanActivity.EXTRA_MODE_APPS)
            )
        }
        binding.tileFileScan.setOnClickListener {
            startActivity(
                ScanActivity.intentFor(this, ScanActivity.EXTRA_MODE_FILES)
            )
        }
        binding.tileCve.setOnClickListener {
            startActivity(Intent(this, CveActivity::class.java))
        }
        binding.tileIntegrity.setOnClickListener {
            // 体检卡片就在本页，滚动到它并刷新
            vm.refreshIntegrity()
            binding.scroll.smoothScrollTo(0, binding.cardIntegrity.top)
        }

        binding.bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_home -> true
                R.id.nav_cve -> {
                    startActivity(Intent(this, CveActivity::class.java))
                    true
                }
                R.id.nav_settings -> {
                    startActivity(Intent(this, SettingsActivity::class.java))
                    true
                }
                else -> false
            }
        }
        binding.bottomNav.selectedItemId = R.id.nav_home

        binding.toolbar.setOnClickListener {
            startActivity(Intent(this, AboutActivity::class.java))
        }
    }

    // -------------------------------------------------------------- 状态

    private fun observeState() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                vm.state.collectLatest { s -> render(s) }
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                vm.loadingIntegrity.collectLatest {
                    binding.progressIntegrity.visibility = if (it) View.VISIBLE else View.GONE
                }
            }
        }
    }

    /**
     * 把状态快照渲染到界面。
     *
     * 刻意不做"差异比对"，直接全量赋值：这些控件加起来也就十几个，
     * 全量赋值比维护一套 diff 逻辑更不容易出错，性能开销可忽略。
     */
    private fun render(s: HomeUiState) {
        val ctx = this

        // ---- 顶部状态卡 ----
        binding.progressLoading.visibility = if (s.loading) View.VISIBLE else View.GONE

        when {
            s.engineFailed != null -> {
                binding.textStatus.setText(R.string.home_status_idle)
                binding.textSubtitle.text = s.engineFailed
                binding.iconStatus.setImageResource(R.drawable.ic_warning)
            }
            s.loading -> {
                binding.textStatus.setText(R.string.loading)
                binding.textSubtitle.setText(R.string.card_engine_sig)
                binding.iconStatus.setImageResource(R.drawable.ic_shield)
            }
            s.hasThreats && s.maxSeverity.level >= Severity.HIGH.level -> {
                binding.textStatus.setText(R.string.home_status_at_risk)
                binding.textSubtitle.text = ctx.getString(
                    R.string.home_subtitle_at_risk,
                    s.activeThreats.size
                )
                binding.iconStatus.setImageResource(R.drawable.ic_danger)
            }
            else -> {
                binding.textStatus.setText(R.string.home_status_protected)
                binding.textSubtitle.setText(
                    if (s.settings.realtimeProtection) R.string.home_subtitle_protected
                    else R.string.home_subtitle_idle
                )
                binding.iconStatus.setImageResource(
                    if (s.settings.realtimeProtection) R.drawable.ic_shield
                    else R.drawable.ic_shield_off
                )
            }
        }

        // 状态卡底色随最高威胁等级变化，让用户余光扫一眼就知道情况
        val heroColor = if (s.hasThreats && s.maxSeverity.level >= Severity.HIGH.level) {
            R.color.threat_critical_container
        } else {
            R.color.md_theme_primaryContainer
        }
        binding.cardStatus.setCardBackgroundColor(ContextCompat.getColor(this, heroColor))

        // ---- 引擎信息卡 ----
        bindRow(
            binding.rowEngineSig,
            R.drawable.ic_shield,
            R.string.card_engine_sig,
            ctx.getString(R.string.card_engine_sig_value, s.rulesCount, s.heuristicCount),
            if (s.rulesCount > 0) ctx.getString(R.string.card_engine_sig_updated, s.rulesVersion)
            else ctx.getString(R.string.loading)
        )
        bindRow(
            binding.rowEngineRealtime,
            if (s.settings.realtimeProtection) R.drawable.ic_shield else R.drawable.ic_shield_off,
            R.string.card_engine_realtime,
            ctx.getString(R.string.card_engine_realtime),
            if (s.settings.realtimeProtection) ctx.getString(R.string.card_engine_realtime_on)
            else ctx.getString(R.string.card_engine_realtime_off)
        )
        bindRow(
            binding.rowEngineHeuristic,
            R.drawable.ic_bug,
            R.string.card_engine_heuristic,
            ctx.getString(R.string.card_engine_heuristic),
            if (s.settings.heuristic) ctx.getString(R.string.card_engine_realtime_on)
            else ctx.getString(R.string.card_engine_realtime_off)
        )
        bindRow(
            binding.rowEngineCve,
            R.drawable.ic_warning,
            R.string.cve_title,
            ctx.getString(
                R.string.cve_db_version,
                s.cveVersion.ifBlank { "—" },
                s.cveCount
            ),
            if (s.cveCount > 0) ctx.getString(R.string.card_engine_sig_updated, s.cveVersion)
            else ctx.getString(R.string.loading)
        )

        // ---- 统计卡 ----
        binding.textStatApps.text = if (s.appsScanned > 0) UiFormat.count(s.appsScanned) else "—"
        binding.textStatThreats.text = UiFormat.count(s.activeThreats.size)
        binding.textStatLastScan.text = UiFormat.relative(this, s.lastScanAt)

        // ---- 最近威胁 ----
        val recent = s.activeThreats.take(3)
        binding.textRecentEmpty.visibility = if (recent.isEmpty()) View.VISIBLE else View.GONE
        binding.listRecent.visibility = if (recent.isEmpty()) View.GONE else View.VISIBLE
        recentAdapter.submitList(recent)

        // ---- 系统体检 ----
        val total = s.integrity.size
        val passed = s.integrity.count { it.passed }
        binding.textIntegritySummary.text =
            if (total == 0) ctx.getString(R.string.loading) else "$passed/$total"
        binding.listIntegrity.adapter = IntegrityAdapter(s.integrity)

        // ---- 引擎异常提示 ----
        binding.textEngineFailed.visibility =
            if (s.engineFailed != null) View.VISIBLE else View.GONE
        binding.textEngineFailed.text = s.engineFailed
    }

    /**
     * 绑定一行引擎信息。
     *
     * 注意：<include> 里带上 android:id 后，ViewBinding 会把被包含布局的
     * binding 作为字段暴露出来（如 binding.rowEngineSig），
     * 直接访问它的子控件即可，不需要再 findViewById。
     */
    private fun bindRow(
        row: RowStatBinding,
        iconRes: Int,
        labelRes: Int,
        desc: String,
        value: String
    ) {
        row.iconRow.setImageResource(iconRes)
        row.textLabel.setText(labelRes)
        row.textDesc.text = desc
        row.textValue.text = value
    }

    // -------------------------------------------------------------- 行动

    private fun openDetail(t: Threat) {
        startActivity(ThreatDetailActivity.intentFor(this, t.id))
    }

    /**
     * Android 13+ 需要运行时申请通知权限。
     * 只有实时防护被打开时才值得打扰用户——否则一个纯本地扫描应用
     * 上来就要通知权限会显得可疑。
     */
    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (!(application as AegisApp).settings.current().realtimeProtection) return
        if (com.aegis.guard.util.Notifications.hasPermission(this)) return
        notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    override fun onResume() {
        super.onResume()
        // 从设置页返回时，实时防护开关可能变了；服务状态需要跟着走
        GuardService.sync(this)
        vm.refreshIntegrity()
        binding.bottomNav.selectedItemId = R.id.nav_home
    }
}
