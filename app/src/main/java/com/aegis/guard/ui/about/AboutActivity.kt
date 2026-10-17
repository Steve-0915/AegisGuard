package com.aegis.guard.ui.about

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.aegis.guard.AegisApp
import com.aegis.guard.BuildConfig
import com.aegis.guard.R
import com.aegis.guard.databinding.ActivityAboutBinding
import com.aegis.guard.util.UiFormat
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * 关于页。
 *
 * 只做一件事：把 [AegisApp.EngineState] 里的真实数字渲染出来。
 * 不写死任何"32 条规则"之类的假数据——引擎没就绪就显示"加载中"。
 */
class AboutActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAboutBinding
    private val aegis get() = application as AegisApp

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAboutBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.toolbar.setNavigationOnClickListener { finish() }

        binding.textVersion.text = getString(R.string.settings_version_format, BuildConfig.VERSION_NAME)

        // 静态文案
        binding.rowRules.textLabel.setText(R.string.about_row_rules)
        binding.rowRules.textDesc.setText(R.string.about_row_rules_desc)
        binding.rowCves.textLabel.setText(R.string.about_row_cves)
        binding.rowCves.textDesc.setText(R.string.about_row_cves_desc)
        binding.rowHeuristic.textLabel.setText(R.string.about_row_heuristic)
        binding.rowHeuristic.textDesc.setText(R.string.about_row_heuristic_desc)
        binding.rowPrivacy.textLabel.setText(R.string.about_row_privacy)
        binding.rowPrivacy.textDesc.setText(R.string.about_row_privacy_desc)
        binding.rowPrivacy.textValue.setText(R.string.about_value_local)

        observe()
    }

    private fun observe() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                aegis.engineState.collectLatest { st -> render(st) }
            }
        }
    }

    private fun render(state: AegisApp.EngineState) {
        when (state) {
            is AegisApp.EngineState.Loading -> {
                binding.rowRules.textValue.text = getString(R.string.loading)
                binding.rowCves.textValue.text = getString(R.string.loading)
                binding.rowHeuristic.textValue.text = getString(R.string.loading)
            }

            is AegisApp.EngineState.Ready -> {
                binding.rowRules.textValue.text = UiFormat.count(state.rules)
                binding.rowCves.textValue.text = UiFormat.count(state.cves)
                binding.rowHeuristic.textValue.text = UiFormat.count(state.heuristic)
                binding.rowRules.textDesc.text = getString(R.string.about_row_rules_desc) +
                    " · " + state.rulesVersion
                binding.rowCves.textDesc.text = getString(R.string.about_row_cves_desc) +
                    " · " + state.cveVersion
            }

            is AegisApp.EngineState.Failed -> {
                val err = getString(R.string.settings_db_failed, state.message)
                binding.rowRules.textValue.text = err
                binding.rowCves.textValue.text = err
                binding.rowHeuristic.textValue.text = err
            }
        }
    }
}