package com.aegis.guard.ui.settings

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.aegis.guard.AegisApp
import com.aegis.guard.R
import com.aegis.guard.data.store.SettingsState
import com.aegis.guard.databinding.ActivitySettingsBinding
import com.aegis.guard.service.GuardService
import com.aegis.guard.util.Notifications
import com.aegis.guard.ui.about.AboutActivity
import com.aegis.guard.util.UiFormat
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * 设置页。
 *
 * 设计取舍：不使用 PreferenceFragment 体系。原因有三：
 * 1) 系统 Preference 控件与 MD3 的 DynamicColor 联动很差，取色后仍是旧配色；
 * 2) 本页只有 12 个条目，手写 8 个 Switch 绑定比 XML preference 树更直观；
 * 3) 全部状态走 Settings.state 这一个 StateFlow，UI 永远不会有"开关和实际值不一致"。
 */
class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding
    private val aegis get() = application as AegisApp
    /** 防止程序化设置开关时触发监听器造成回写 */
    private var bindingUi = false
    /** 通知权限申请（Android 13+，打开实时防护时才会触发） */
    private val notifPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* 拒绝也不阻塞：前台服务仍以低打扰方式运行 */ }
    /** Android 13+ 上，打开实时防护前主动申请通知权限，避免服务静默失效 */
    private fun requestNotificationPermissionIfMissing() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (Notifications.hasPermission(this)) return
        notifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.toolbar.setNavigationOnClickListener { finish() }

        bindSwitches()
        bindRows()
        observe()
    }

    // ------------------------------------------------------------------ 开关

    private fun bindSwitches() {
        binding.switchRealtime.setOnCheckedChangeListener { _, v ->
            if (bindingUi) return@setOnCheckedChangeListener
            aegis.settings.setRealtime(v)
            // 实时防护与常驻前台服务是同一件事：开就拉起，关就停掉。
            if (v) {
                requestNotificationPermissionIfMissing()
                GuardService.start(this)
            } else {
                GuardService.stop(this)
            }
        }

        binding.switchHeuristic.setOnCheckedChangeListener { _, v ->
            if (!bindingUi) aegis.settings.setHeuristic(v)
        }

        binding.switchPup.setOnCheckedChangeListener { _, v ->
            if (!bindingUi) aegis.settings.setPup(v)
        }

        binding.switchCloud.setOnCheckedChangeListener { _, v ->
            if (!bindingUi) aegis.settings.setCloud(v)
        }

        binding.switchArchives.setOnCheckedChangeListener { _, v ->
            if (!bindingUi) aegis.settings.setDeepArchive(v)
        }

        binding.switchDex.setOnCheckedChangeListener { _, v ->
            if (!bindingUi) aegis.settings.setDex(v)
        }

        binding.switchHidden.setOnCheckedChangeListener { _, v ->
            if (!bindingUi) aegis.settings.setScanHidden(v)
        }

        binding.switchDynamic.setOnCheckedChangeListener { _, v ->
            if (bindingUi) return@setOnCheckedChangeListener
            aegis.settings.setDynamicColor(v)
            // 取色状态在 Application 启动时注入，切换后必须重建进程级 UI 才生效。
            toast(getString(if (v) R.string.settings_dynamic_color else R.string.settings_dynamic_color_desc))
            recreate()
        }
    }

    // ------------------------------------------------------------------ 行

    private fun bindRows() {
        binding.rowUpdateDb.setOnClickListener { reloadRules() }

        binding.rowMaxSize.setOnClickListener { pickMaxSize() }

        binding.rowClear.setOnClickListener { confirmClear() }

        binding.rowAbout.setOnClickListener {
            startActivity(Intent(this, AboutActivity::class.java))
        }

        // 白名单/历史目前没有独立页面，先给出准确的数量反馈，避免点了没反应。
        binding.rowWhitelist.setOnClickListener {
            val n = aegis.repository.whitelist.value.size
            toast(getString(R.string.settings_whitelist) + " · " + n)
        }
        binding.rowHistory.setOnClickListener {
            val n = aegis.repository.history.value.size
            toast(getString(R.string.settings_history) + " · " + n)
        }
    }

    /** 重新载入 assets 中的规则库（离线更新语义：这里等价于重载内置库） */
    private fun reloadRules() {
        binding.textDbStatus.text = getString(R.string.loading)
        aegis.loadEngine()
    }

    private fun pickMaxSize() {
        val choices = SettingsState.SIZE_CHOICES
        val labels = choices.map { it.second }.toTypedArray()
        val current = aegis.settings.current().maxFileSize
        val checked = choices.indexOfFirst { it.first == current }.coerceAtLeast(0)

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.settings_max_size)
            .setSingleChoiceItems(labels, checked) { dialog, which ->
                aegis.settings.setMaxFileSize(choices[which].first)
                renderMaxSize(choices[which].second)
                dialog.dismiss()
            }
            .setNegativeButton(R.string.action_cancel, null)
            .show()
    }

    private fun confirmClear() {
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.settings_clear)
            .setMessage(R.string.settings_clear_confirm)
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_confirm) { _, _ ->
                aegis.repository.clearAll()
                toast(getString(R.string.settings_clear_done))
            }
            .show()
    }

    // ------------------------------------------------------------------ 订阅

    private fun observe() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                aegis.settings.state.collectLatest { render(it) }
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                aegis.repository.whitelist.collectLatest { list ->
                    binding.textWhitelistCount.text =
                        getString(R.string.settings_whitelist_count, list.size)
                }
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                aegis.repository.history.collectLatest { list ->
                    binding.textHistoryCount.text =
                        getString(R.string.settings_history_count, list.size)
                }
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                aegis.engineState.collectLatest { st -> renderEngine(st) }
            }
        }
    }

    private fun renderEngine(state: AegisApp.EngineState) {
        when (state) {
            is AegisApp.EngineState.Loading -> {
                binding.textDbStatus.text = getString(R.string.loading)
            }

            is AegisApp.EngineState.Ready -> {
                binding.textDbStatus.text = getString(
                    R.string.settings_db_ready,
                    state.rules,
                    state.cves,
                    state.rulesVersion
                )
            }

            is AegisApp.EngineState.Failed -> {
                binding.textDbStatus.text = getString(R.string.settings_db_failed, state.message)
            }
        }
    }

    private fun render(s: SettingsState) {
        bindingUi = true
        binding.switchRealtime.isChecked = s.realtimeProtection
        binding.switchHeuristic.isChecked = s.heuristic
        binding.switchPup.isChecked = s.detectPup
        binding.switchCloud.isChecked = s.cloudLookup
        binding.switchArchives.isChecked = s.deepArchive
        binding.switchDex.isChecked = s.dexAnalysis
        binding.switchHidden.isChecked = s.scanHidden
        binding.switchDynamic.isChecked = s.dynamicColor
        bindingUi = false

        val label = SettingsState.SIZE_CHOICES
            .firstOrNull { it.first == s.maxFileSize }?.second
            ?: UiFormat.bytes(s.maxFileSize)
        renderMaxSize(label)

        binding.textVersion.text = getString(
            R.string.settings_version_format,
            com.aegis.guard.BuildConfig.VERSION_NAME
        )
    }

    private fun renderMaxSize(label: String) {
        binding.textMaxSize.text = label
    }

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }

    companion object {
        fun intentFor(context: Context): Intent =
            Intent(context, SettingsActivity::class.java)
    }
}
