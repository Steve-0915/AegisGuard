package com.aegis.guard.engine

import com.aegis.guard.data.model.DetectionEngine
import com.aegis.guard.data.model.Severity
import com.aegis.guard.data.model.SignatureRule
import com.aegis.guard.data.model.TargetKind
import com.aegis.guard.data.model.Threat
import com.aegis.guard.data.model.ThreatType
import java.util.concurrent.ConcurrentHashMap
import java.util.regex.Pattern
import java.util.regex.PatternSyntaxException

/**
 * 规则匹配目标。把要检查的对象归一化成几个"视图"，
 * 规则只在需要的视图上跑，避免无谓的字符串扫描。
 */
data class ScannableSubject(
    /** 展示名 */
    val displayName: String,
    /** 包名（可空） */
    val packageName: String? = null,
    /** 文件路径（可空） */
    val filePath: String? = null,
    /** 文件哈希（可空） */
    val sha256: String? = null,
    /** 大小 */
    val sizeBytes: Long = 0L,
    val targetKind: TargetKind = TargetKind.FILE,
    /** 文本内容提供器（惰性，可能是 DEX 字符串池 / 脚本内容 / 清单片段） */
    val textProvider: (() -> String?)? = null
) {
    private val textCache by lazy { runCatching { textProvider?.invoke() }.getOrNull() }
    fun text(): String? = textCache

    fun fileName(): String =
        filePath?.substringAfterLast('/')?.takeIf { it.isNotEmpty() } ?: displayName
}

/**
 * 规则引擎。
 *
 * 设计要点：
 * 1. 规则启动时一次性编译为 [Pattern]，扫描期零解析开销。
 * 2. 支持"内容指纹"短路：如果一段文本已被判定过，直接复用结果。
 * 3. 单条规则命中即产出 [Threat]，多条规则可叠加（治理层去重）。
 * 4. 启发式规则与签名规则分开统计，供上层做权重聚合。
 */
class SignatureEngine(initialRules: List<SignatureRule> = emptyList()) {

    private data class Compiled(
        val rule: SignatureRule,
        val pattern: Pattern,
        val literal: String?
    )

    private val compiled = ArrayList<Compiled>(256)

    /** 同一条文本反复出现时（例如大量相同 APK），缓存匹配结论 */
    private val textDigestCache = ConcurrentHashMap<Long, List<String>>(64)

    @Volatile
    var rulesCount: Int = 0
        private set

    @Volatile
    var heuristicRulesCount: Int = 0
        private set

    init {
        if (initialRules.isNotEmpty()) loadRules(initialRules)
    }

    /**
     * 加载/替换规则集。编译失败的规则会被静默丢弃并计数，
     * 以保证一个坏规则不会让整个引擎不可用。
     */
    @Synchronized
    fun loadRules(rules: List<SignatureRule>) {
        compiled.clear()
        textDigestCache.clear()
        var failed = 0
        var heuristics = 0
        for (rule in rules) {
            val opts = if (rule.caseSensitive) 0 else Pattern.CASE_INSENSITIVE or Pattern.UNICODE_CASE
            val p = try {
                Pattern.compile(rule.pattern, opts)
            } catch (_: PatternSyntaxException) {
                failed++
                continue
            }
            val literal = literalOf(rule.pattern)
            compiled.add(Compiled(rule, p, literal))
            if (rule.heuristic) heuristics++
        }
        rulesCount = compiled.size
        heuristicRulesCount = heuristics
        lastCompileFailures = failed
    }

    var lastCompileFailures: Int = 0
        private set

    /**
     * 对单个对象执行全部适用的规则。
     *
     * @param includeHeuristic 是否启用启发式规则（对应设置项）
     * @return 命中产生的威胁列表
     */
    fun scan(
        subject: ScannableSubject,
        includeHeuristic: Boolean = true
    ): List<Threat> {
        if (compiled.isEmpty()) return emptyList()
        val out = ArrayList<Threat>(2)
        val seenRuleNames = HashSet<String>(4)

        var text: String? = null
        var textLoaded = false

        for (c in compiled) {
            val rule = c.rule
            if (rule.heuristic && !includeHeuristic) continue
            if (rule.name in seenRuleNames) continue

            val target: String? = when (rule.target.lowercase()) {
                "package" -> subject.packageName
                "path" -> subject.filePath
                "filename" -> subject.fileName()
                "hash", "sha256" -> subject.sha256
                else -> {
                    if (!textLoaded) {
                        text = subject.text()
                        textLoaded = true
                    }
                    text
                }
            } ?: continue

            val targetText = target ?: continue
            val hit = try {
                if (c.literal != null) {
                    if (rule.caseSensitive) targetText.contains(c.literal)
                    else targetText.contains(c.literal, ignoreCase = true)
                } else {
                    c.pattern.matcher(targetText).find()
                }
            } catch (_: Throwable) {
                false
            }

            if (!hit) continue
            seenRuleNames.add(rule.name)
            out.add(subject.toThreat(rule))
        }
        return out
    }

    private fun ScannableSubject.toThreat(rule: SignatureRule): Threat {
        val evidence = buildList {
            rule.description.takeIf { it.isNotBlank() }?.let { add(it) }
            add("命中规则：${rule.name}")
            add("匹配目标：${rule.target}")
            packageName?.let { add("包名：$it") }
            filePath?.let { add("路径：$it") }
            sha256?.let { add("SHA-256：${it.take(32)}…") }
            add("规则来源：${rule.source}")
        }
        return Threat(
            id = stableId(rule.name, packageName ?: filePath ?: displayName),
            title = displayName,
            ruleName = rule.name,
            severity = rule.severity,
            type = rule.type,
            engine = if (rule.heuristic) DetectionEngine.HEURISTIC else DetectionEngine.SIGNATURE,
            targetKind = targetKind,
            packageName = packageName,
            filePath = filePath,
            sha256 = sha256,
            sizeBytes = sizeBytes,
            evidence = evidence,
            advice = rule.advice.ifBlank { defaultAdviceFor(rule.type, rule.severity) },
            cveIds = rule.cveIds
        )
    }

    companion object {
        /** 稳定的威胁 ID，保证同一对象在同一规则下重复扫描得到相同 ID */
        fun stableId(ruleName: String, subjectKey: String): String {
            val raw = "$ruleName|$subjectKey"
            var h = -3750763034362895579L // FNV-1a offset basis
            for (ch in raw) {
                h = h xor ch.code.toLong()
                h *= 1099511628211L
            }
            return "T%016x".format(h)
        }

        /**
         * 如果正则其实是一个纯字面量，就退化成 indexOf，
         * 在高频扫描时能省下大量回溯开销。
         */
        private fun literalOf(pattern: String): String? {
            val meta = charArrayOf('\\', '.', '*', '+', '?', '[', ']', '(', ')', '{', '}', '^', '$', '|')
            if (pattern.any { it in meta }) return null
            return pattern.takeIf { it.isNotEmpty() }
        }

        fun defaultAdviceFor(type: ThreatType, severity: Severity): String = when {
            severity.level >= Severity.CRITICAL.level ->
                "建议立即卸载该应用或删除该文件。若为系统组件，请通过系统更新修复。"
            type == ThreatType.ADWARE || type == ThreatType.PUP ->
                "该应用可能以弹窗、后台常驻等方式干扰使用。若不需要，建议卸载。"
            type == ThreatType.EXPLOIT ->
                "该文件包含漏洞利用代码，建议删除并避免从不可信来源下载文件。"
            severity.level >= Severity.HIGH.level ->
                "建议卸载该应用。卸载前可先导出扫描报告留存证据。"
            else ->
                "建议核实该应用的来源与用途；若来源不明，卸载是最稳妥的选择。"
        }
    }
}