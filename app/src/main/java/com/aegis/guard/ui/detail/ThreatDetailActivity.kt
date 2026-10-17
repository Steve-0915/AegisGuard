package com.aegis.guard.ui.detail

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.net.Uri
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.aegis.guard.AegisApp
import com.aegis.guard.R
import com.aegis.guard.data.model.TargetKind
import com.aegis.guard.data.model.Threat
import com.aegis.guard.databinding.ActivityDetailBinding
import com.aegis.guard.util.UiFormat
import java.io.File

/**
 * 威胁详情页。
 *
 * 负责把一条 [Threat] 的全部字段完整呈现，并提供三种处置动作：
 * 卸载应用 / 删除文件 / 忽略或加白。
 *
 * 设计取舍：处置动作不做"自动执行"以外的花活——
 * 卸载走系统 Intent（用户需在系统弹窗里确认），删除走 File.delete，
 * 两者都保证"用户明确点击才会发生"。
 */
class ThreatDetailActivity : AppCompatActivity() {

    private lateinit var binding: ActivityDetailBinding

    private val aegis: AegisApp by lazy { AegisApp.from(application) }

    /** 当前查看的威胁。找不到（例如已被移除）时直接关闭页面。 */
    private var threat: Threat? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDetailBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.toolbar.setNavigationOnClickListener { finish() }

        val id = intent.getStringExtra(EXTRA_THREAT_ID)
        val found = id?.let { aegis.repository.findById(it) }
        if (found == null) {
            // 记录可能已被移除（用户在其他页面清理过）
            toast(getString(R.string.empty_state))
            finish()
            return
        }
        threat = found
        bind(found)
        setupActions(found)
    }

    // ---------------------------------------------------------------- 渲染

    private fun bind(t: Threat) {
        val ctx = this

        // --- 英雄卡 ---
        binding.iconType.setImageResource(UiFormat.typeIcon(t.type))
        binding.iconType.imageTintList = ColorStateList.valueOf(
            ContextCompat.getColor(ctx, UiFormat.severityColor(t.severity))
        )
        binding.textTitle.text = t.title
        binding.textRule.text = t.ruleName

        binding.chipSeverity.text = getString(UiFormat.severityLabel(t.severity))
        binding.chipSeverity.setTextColor(ContextCompat.getColor(ctx, UiFormat.severityColor(t.severity)))
        binding.chipType.text = getString(UiFormat.typeLabel(t.type))

        // --- 包名 ---
        val pkg = t.packageName
        binding.rowPackage.visibility = if (pkg.isNullOrBlank()) View.GONE else View.VISIBLE
        binding.textPackage.text = pkg

        // --- 路径 ---
        val path = t.filePath
        binding.rowPath.visibility = if (path.isNullOrBlank()) View.GONE else View.VISIBLE
        binding.textPath.text = path

        // --- 哈希 ---
        val sha = t.sha256
        binding.rowSha.visibility = if (sha.isNullOrBlank()) View.GONE else View.VISIBLE
        binding.textSha.text = sha
        binding.actionCopy.setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("SHA-256", sha ?: ""))
            toast(getString(R.string.copied))
        }

        // --- 检测时间 + 体积 ---
        binding.textDetected.text = buildString {
            append(UiFormat.dateTime(t.detectedAt))
            if (t.sizeBytes > 0) {
                append("　·　")
                append(UiFormat.bytes(t.sizeBytes))
            }
        }

        // --- 检测依据 ---
        binding.textEvidence.text = if (t.evidence.isEmpty()) {
            "—"
        } else {
            t.evidence.joinToString("\n") { line -> if (line.startsWith("•")) line else "• $line" }
        }

        // --- 处置建议 ---
        binding.textAdvice.text = t.advice.ifBlank { getString(R.string.detail_advice) }

        // --- 关联 CVE ---
        if (t.cveIds.isEmpty()) {
            binding.groupCve.visibility = View.GONE
        } else {
            binding.groupCve.visibility = View.VISIBLE
            binding.textCve.text = t.cveIds.joinToString("\n")
        }
    }

    // ---------------------------------------------------------------- 动作

    private fun setupActions(t: Threat) {
        // 1) 卸载应用：需要对方向系统发起卸载请求
        val canUninstall = t.packageName != null && t.targetKind == TargetKind.PACKAGE
        binding.buttonUninstall.visibility = if (canUninstall) View.VISIBLE else View.GONE
        binding.buttonUninstall.setOnClickListener { confirmUninstall(t.packageName!!) }

        // 2) 删除文件：只在文件/APK 类型且确实存在时显示
        val path = t.filePath
        val canDelete = path != null && t.targetKind != TargetKind.PACKAGE && File(path).exists()
        binding.buttonDelete.visibility = if (canDelete) View.VISIBLE else View.GONE
        binding.buttonDelete.setOnClickListener { confirmDelete(path!!) }

        // 3) 忽略：保留记录但弱化显示
        binding.buttonIgnore.text = if (t.dismissed) {
            getString(R.string.action_resume)
        } else {
            getString(R.string.action_ignore)
        }
        binding.buttonIgnore.setOnClickListener {
            val cur = threat ?: return@setOnClickListener
            if (cur.dismissed) {
                aegis.repository.undismiss(cur.id)
                toast("已恢复该记录")
            } else {
                aegis.repository.dismiss(cur.id)
                toast("已忽略该记录")
            }
            finish()
        }

        // 4) 加白：把包名或路径写入白名单，后续不再报告
        val key = t.packageName ?: t.filePath
        binding.buttonWhitelist.visibility = if (key.isNullOrBlank()) View.GONE else View.VISIBLE
        binding.buttonWhitelist.setOnClickListener {
            key?.let { k ->
                aegis.repository.addToWhitelist(k)
                toast("已加入白名单")
                finish()
            }
        }
    }

    /**
     * 卸载应用。
     *
     * 依次尝试三种路径，因为不同 OEM 对 ACTION_DELETE 的处理不一致：
     * - ACTION_DELETE（标准卸载对话框）；
     * - ACTION_UNINSTALL_PACKAGE（旧 API，部分设备仍需要）；
     * - 兜底跳转到系统"应用详情"页，用户可手动卸载。
     */
    private fun confirmUninstall(packageName: String) {
        AlertDialog.Builder(this)
            .setTitle(R.string.confirm_uninstall_title)
            .setMessage(getString(R.string.confirm_uninstall_msg, packageName, getString(UiFormat.severityLabel(threat!!.severity))))
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_uninstall) { _, _ ->
                val launched = try {
                    startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName")))
                    true
                } catch (_: Throwable) {
                    false
                }
                if (!launched) {
                    // 兜底：打开系统应用详情页
                    runCatching {
                        startActivity(
                            Intent(
                                android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                Uri.parse("package:$packageName")
                            )
                        )
                    }
                }
                aegis.repository.remove(threat!!.id)
                finish()
            }
            .show()
    }

    /**
     * 删除文件。
     *
     * 只删这一个文件，不做递归删除——恶意载荷有时会放在目录里，
     * 但"整目录删除"对用户来说风险过大，宁可保守。
     */
    private fun confirmDelete(path: String) {
        AlertDialog.Builder(this)
            .setTitle(R.string.confirm_delete_title)
            .setMessage(getString(R.string.confirm_delete_msg))
            .setNegativeButton(R.string.action_cancel, null)
            .setPositiveButton(R.string.action_delete_file) { _, _ ->
                val f = File(path)
                val ok = runCatching { f.delete() }.getOrDefault(false)
                if (ok) {
                    aegis.repository.remove(threat!!.id)
                    toast("已删除")
                    finish()
                } else {
                    toast(getString(R.string.generic_error, "文件无法删除"))
                }
            }
            .show()
    }

    private fun toast(msg: String) =
        android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_SHORT).show()

    companion object {
        private const val EXTRA_THREAT_ID = "extra_threat_id"

        fun intentFor(context: Context, threatId: String): Intent =
            Intent(context, ThreatDetailActivity::class.java)
                .putExtra(EXTRA_THREAT_ID, threatId)
    }
}