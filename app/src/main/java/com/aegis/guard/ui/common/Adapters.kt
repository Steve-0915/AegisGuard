package com.aegis.guard.ui.common

import android.content.res.ColorStateList
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.aegis.guard.R
import com.aegis.guard.data.model.Threat
import com.aegis.guard.data.model.CveMatch
import com.aegis.guard.databinding.ItemCveBinding
import com.aegis.guard.databinding.ItemThreatBinding
import com.aegis.guard.util.UiFormat

/**
 * 威胁列表适配器。
 *
 * 用 [ListAdapter] + [DiffUtil] 而不是 notifyDataSetChanged：
 * 扫描结果会整批刷新，DiffUtil 能保证只有真正变化的行才重绘，
 * 在几百条记录时滚动体验差别很明显。
 */
class ThreatAdapter(
    private val onClick: (Threat) -> Unit
) : ListAdapter<Threat, ThreatAdapter.VH>(DIFF) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val binding = ItemThreatBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return VH(binding)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        holder.bind(getItem(position))
    }

    inner class VH(private val b: ItemThreatBinding) : RecyclerView.ViewHolder(b.root) {

        fun bind(t: Threat) {
            val ctx = b.root.context

            // 图标：按威胁类型选
            b.iconType.setImageResource(UiFormat.typeIcon(t.type))
            val fg = ContextCompat.getColorStateList(ctx, UiFormat.severityColor(t.severity))
            b.iconType.imageTintList = fg

            // 图标底色容器：低饱和度的同色系
            val bgColor = ContextCompat.getColor(ctx, UiFormat.severityContainerColor(t.severity))
            b.iconContainer.backgroundTintList = ColorStateList.valueOf(bgColor)

            b.textTitle.text = t.title
            b.textSubtitle.text = t.ruleName

            // 等级徽标
            b.chipSeverity.text = ctx.getString(UiFormat.severityLabel(t.severity))
            b.chipSeverity.setTextColor(ContextCompat.getColor(ctx, UiFormat.severityColor(t.severity)))

            // 来源（包名或路径），路径取末段避免过长
            val origin = t.packageName
                ?: t.filePath?.substringAfterLast('/')
                ?: ctx.getString(UiFormat.typeLabel(t.type))
            b.textOrigin.text = origin

            // 检测引擎标签
            b.textEngine.text = UiFormat.engineLabel(t.engine)

            // 已忽略的在视觉上弱化
            b.root.alpha = if (t.dismissed) 0.5f else 1f

            b.root.setOnClickListener { onClick(t) }
        }
    }

    companion object {
        private val DIFF = object : DiffUtil.ItemCallback<Threat>() {
            override fun areItemsTheSame(a: Threat, b: Threat) = a.id == b.id
            override fun areContentsTheSame(a: Threat, b: Threat) = a == b
        }
    }
}

/**
 * 体检项适配器。
 */
class IntegrityAdapter(
    private val items: List<com.aegis.guard.data.model.IntegrityCheck>
) : RecyclerView.Adapter<IntegrityAdapter.VH>() {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val binding = com.aegis.guard.databinding.ItemIntegrityBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return VH(binding)
    }

    override fun getItemCount(): Int = items.size

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(items[position])

    class VH(private val b: com.aegis.guard.databinding.ItemIntegrityBinding) :
        RecyclerView.ViewHolder(b.root) {

        fun bind(c: com.aegis.guard.data.model.IntegrityCheck) {
            val ctx = b.root.context
            b.textTitle.text = c.title
            b.textDetail.text = c.detail

            if (c.passed) {
                b.iconStatus.setImageResource(R.drawable.ic_check)
                b.iconStatus.imageTintList = ColorStateList.valueOf(
                    ContextCompat.getColor(ctx, R.color.threat_clean)
                )
            } else {
                b.iconStatus.setImageResource(R.drawable.ic_warning)
                b.iconStatus.imageTintList = ColorStateList.valueOf(
                    ContextCompat.getColor(ctx, UiFormat.severityColor(c.severityIfFailed))
                )
            }

            // 建议只在未通过且非空时展示
            b.textAdvice.text = c.advice
            b.textAdvice.visibility =
                if (!c.passed && c.advice.isNotBlank()) android.view.View.VISIBLE
                else android.view.View.GONE
        }
    }
}
/**
 * CVE 列表适配器。
 *
 * 与 ThreatAdapter 同构：ListAdapter + DiffUtil，key 用 (cve.id, detectedVersion, packageName)。
 * 同一个 CVE 可能命中多个应用，因此不能只用 id 做 identity。
 */
class CveAdapter(
    private val onClick: (CveMatch) -> Unit
) : ListAdapter<CveMatch, CveAdapter.VH>(DIFF) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val binding = ItemCveBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return VH(binding)
    }

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(getItem(position))

    inner class VH(private val b: ItemCveBinding) :
        RecyclerView.ViewHolder(b.root) {

        fun bind(m: CveMatch) {
            val ctx = b.root.context
            val cve = m.cve

            b.textCveId.text = cve.id

            // CVSS 徽标：有分数显示分数，没有分数则退化为严重等级文案
            b.chipCvss.text = if (cve.cvss > 0.0) {
                ctx.getString(R.string.cve_cvss_format, cve.cvss)
            } else {
                ctx.getString(UiFormat.severityLabel(m.severity))
            }
            b.chipCvss.setTextColor(
                ContextCompat.getColor(ctx, UiFormat.severityColor(m.severity))
            )

            b.textComponent.text = ctx.getString(R.string.cve_component_format, cve.component)
            b.textSummary.text = cve.summary

            // 检测信息：版本 + 命中应用
            val host = m.appLabel ?: m.packageName
            b.textDetected.text = if (host.isNullOrBlank()) {
                ctx.getString(R.string.cve_detected_format, m.detectedVersion)
            } else {
                ctx.getString(R.string.cve_detected_host_format, m.detectedVersion, host)
            }

            val fixed = cve.fixedVersion
            if (fixed.isNullOrBlank()) {
                b.textFixed.visibility = android.view.View.GONE
            } else {
                b.textFixed.visibility = android.view.View.VISIBLE
                b.textFixed.text = ctx.getString(R.string.cve_fixed_format, fixed)
            }

            b.root.setOnClickListener { onClick(m) }
        }
    }

    companion object {
        private val DIFF = object : DiffUtil.ItemCallback<CveMatch>() {
            override fun areItemsTheSame(a: CveMatch, b: CveMatch): Boolean =
                a.cve.id == b.cve.id &&
                    a.detectedVersion == b.detectedVersion &&
                    a.packageName == b.packageName

            override fun areContentsTheSame(a: CveMatch, b: CveMatch): Boolean = a == b
        }
    }
}
