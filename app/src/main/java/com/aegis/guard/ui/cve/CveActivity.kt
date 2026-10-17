package com.aegis.guard.ui.cve

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.aegis.guard.R
import com.aegis.guard.data.model.CveMatch
import com.aegis.guard.databinding.ActivityCveBinding
import com.aegis.guard.ui.common.CveAdapter
import com.aegis.guard.util.UiFormat
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * 漏洞检测页。
 *
 * 交互设计：进入页面不自动扫描——CVE 比对需要读取全部 APK，开销不小。
 * 用户点按钮才开始，符合"按需触发"的预期；点条目看详情。
 */
class CveActivity : AppCompatActivity() {

    private lateinit var binding: ActivityCveBinding
    private val vm: CveViewModel by viewModels()

    private lateinit var adapter: CveAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityCveBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.toolbar.setNavigationOnClickListener { finish() }

        adapter = CveAdapter { match -> showDetail(match) }
        binding.listCve.layoutManager = androidx.recyclerview.widget.LinearLayoutManager(this)
        binding.listCve.adapter = adapter
        binding.listCve.setHasFixedSize(false)

        binding.buttonScan.setOnClickListener { vm.scan() }

        observe()
    }

    private fun observe() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                vm.state.collectLatest { render(it) }
            }
        }
    }

    private fun render(s: CveViewModel.UiState) {
        // 进度条
        binding.progress.visibility = if (s.scanning) View.VISIBLE else View.GONE

        // 按钮：扫描中禁用并改文案
        binding.buttonScan.isEnabled = !s.scanning
        binding.buttonScan.text = getString(
            if (s.scanning) R.string.cve_scanning else R.string.cve_scan_action
        )

        // 状态摘要
        binding.textStatus.text = when {
            s.error != null -> getString(R.string.settings_db_failed, s.error)
            s.scanning && s.totalApps > 0 ->
                getString(R.string.cve_scanning) + " " + s.scannedApps + "/" + s.totalApps

            s.scanning -> getString(R.string.cve_scanning)
            s.hasMatches -> getString(R.string.cve_summary_format, s.componentCount, s.appCount)
            s.hasRun -> getString(R.string.cve_empty)
            else -> getString(R.string.cve_idle)
        }

        // 图标随结果变色
        val tint = when {
            s.error != null -> UiFormat.severityColor(com.aegis.guard.data.model.Severity.MEDIUM)
            s.hasMatches -> UiFormat.severityColor(com.aegis.guard.data.model.Severity.HIGH)
            else -> UiFormat.severityColor(com.aegis.guard.data.model.Severity.CLEAN)
        }
        binding.iconStatus.imageTintList =
            android.content.res.ColorStateList.valueOf(
                androidx.core.content.ContextCompat.getColor(this, tint)
            )

        // 列表与空态
        val showEmpty = s.hasRun && !s.scanning && !s.hasMatches && s.error == null
        binding.groupEmpty.visibility = if (showEmpty) View.VISIBLE else View.GONE
        binding.listCve.visibility = if (showEmpty) View.GONE else View.VISIBLE

        adapter.submitList(s.matches)
    }

    private fun showDetail(m: CveMatch) {
        val cve = m.cve
        val sb = StringBuilder()

        sb.append(cve.summary).append("\n\n")
        sb.append(getString(R.string.cve_component_format, cve.component)).append('\n')
        sb.append(getString(R.string.cve_detected_format, m.detectedVersion))
        m.appLabel?.let { sb.append(" · ").append(it) }
        sb.append("\n\n")

        sb.append(getString(R.string.cve_label_vector)).append(": ")
        sb.append(cve.cvssVector ?: getString(R.string.cve_value_unknown)).append('\n')
        sb.append(getString(R.string.cve_label_published)).append(": ")
        sb.append(cve.published ?: getString(R.string.cve_value_unknown)).append('\n')
        sb.append(getString(R.string.cve_label_cwe)).append(": ")
        sb.append(cve.cwe ?: getString(R.string.cve_value_unknown)).append('\n')
        sb.append(getString(R.string.cve_label_exploited)).append(": ")
        sb.append(
            if (cve.knownExploited) getString(R.string.cve_value_yes)
            else getString(R.string.cve_value_no)
        )

        if (m.reason.isNotBlank()) {
            sb.append("\n\n").append(getString(R.string.cve_reason_title)).append('\n')
            sb.append(m.reason)
        }

        if (cve.references.isNotEmpty()) {
            sb.append("\n\n").append(getString(R.string.cve_reference_title)).append('\n')
            cve.references.take(3).forEach { sb.append(it).append('\n') }
        }

        MaterialAlertDialogBuilder(this)
            .setTitle(cve.id)
            .setMessage(sb.toString())
            .setPositiveButton(R.string.action_confirm, null)
            .show()
    }

    companion object {
        fun intentFor(context: Context): Intent =
            Intent(context, CveActivity::class.java)
    }
}