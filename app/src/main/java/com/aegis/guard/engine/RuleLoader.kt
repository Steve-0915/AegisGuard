package com.aegis.guard.engine

import android.content.Context
import com.aegis.guard.data.model.CveEntry
import com.aegis.guard.data.model.HashIndicator
import com.aegis.guard.data.model.Severity
import com.aegis.guard.data.model.SignatureRule
import com.aegis.guard.data.model.ThreatType
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 规则库装载器。
 *
 * 数据来源是 assets 目录下的 rules 系列 json —— 纯文本、可审计、可离线分发，
 * 也允许用户在设置页导入本地文件做覆盖（扩展而不必重新编译）。
 *
 * 解析使用 Gson 而不是手写 JSON reader：规则数量在数百量级，
 * 解析耗时在毫秒级，可读性收益远大于那点开销。
 */
object RuleLoader {

    private const val SIG_ASSET = "rules/signatures.json"
    private const val CVE_ASSET = "rules/cve.json"

    private val gson = Gson()

    /**
     * 规则库装载结果。
     */
    data class Loaded(
        val rules: List<SignatureRule>,
        val hashes: List<HashIndicator>,
        val cves: List<CveEntry>,
        val rulesVersion: String,
        val cveVersion: String,
        /** 解析时被丢弃的条目数，用于在关于页显示"数据完整性" */
        val dropped: Int
    )

    suspend fun load(context: Context): Loaded = withContext(Dispatchers.IO) {
        var dropped = 0

        val sig = runCatching {
            context.assets.open(SIG_ASSET).use { it.readBytes().toString(Charsets.UTF_8) }
        }.getOrNull()

        val sigDoc = runCatching {
            sig?.let { gson.fromJson(it, SignatureDoc::class.java) }
        }.getOrNull()

        val rules = ArrayList<SignatureRule>(64)
        val hashes = ArrayList<HashIndicator>(8)
        sigDoc?.rules?.forEach { dto ->
            val r = dto.toModel()
            if (r == null) dropped++ else rules += r
        }
        sigDoc?.hashIndicators?.forEach { h ->
            // 只接受服务端格式正确的 64 位十六进制摘要，避免脏数据污染比对
            if (h.sha256.length == 64 && h.sha256.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
                hashes += HashIndicator(
                    sha256 = h.sha256.lowercase(),
                    family = h.family,
                    severity = Severity.fromName(h.severity),
                    type = ThreatType.fromKey(h.type),
                    source = h.source ?: "AegisGuard IOC"
                )
            } else {
                dropped++
            }
        }

        val cveDoc = runCatching {
            context.assets.open(CVE_ASSET).use { it.readBytes().toString(Charsets.UTF_8) }
        }.getOrNull().let { raw ->
            runCatching { raw?.let { gson.fromJson(it, CveDoc::class.java) } }.getOrNull()
        }

        val cves = ArrayList<CveEntry>(32)
        cveDoc?.entries?.forEach { dto ->
            val c = dto.toModel()
            if (c == null) dropped++ else cves += c
        }

        Loaded(
            rules = rules,
            hashes = hashes,
            cves = cves,
            rulesVersion = sigDoc?.version ?: "",
            cveVersion = cveDoc?.version ?: "",
            dropped = dropped
        )
    }

    // ------------------------------------------------------------- JSON DTO

    private data class SignatureDoc(
        val schema: Int = 1,
        val version: String? = null,
        val generated: String? = null,
        val rules: List<RuleDto>? = null,
        val hashIndicators: List<HashDto>? = null
    )

    private data class RuleDto(
        val name: String? = null,
        val severity: String? = null,
        val type: String? = null,
        val pattern: String? = null,
        val target: String? = null,
        val caseSensitive: Boolean = false,
        val weight: Int = 1,
        val description: String? = null,
        val advice: String? = null,
        val cveIds: List<String>? = null,
        val source: String? = null,
        val heuristic: Boolean = false
    ) {
        fun toModel(): SignatureRule? {
            val n = name?.takeIf { it.isNotBlank() } ?: return null
            val p = pattern?.takeIf { it.isNotBlank() } ?: return null
            return SignatureRule(
                name = n,
                severity = Severity.fromName(severity),
                type = ThreatType.fromKey(type),
                pattern = p,
                target = target ?: "string",
                caseSensitive = caseSensitive,
                weight = weight.coerceIn(1, 100),
                description = description.orEmpty(),
                advice = advice.orEmpty(),
                cveIds = cveIds.orEmpty(),
                source = source ?: "AegisGuard Core",
                heuristic = heuristic
            )
        }
    }

    private data class HashDto(
        val sha256: String = "",
        val family: String = "",
        val severity: String? = null,
        val type: String? = null,
        val source: String? = null
    )

    private data class CveDoc(
        val schema: Int = 1,
        val version: String? = null,
        val entries: List<CveDto>? = null
    )

    private data class CveDto(
        val id: String? = null,
        val summary: String? = null,
        val component: String? = null,
        val aliases: List<String>? = null,
        @SerializedName("package") val packageName: String? = null,
        val minVersion: String? = null,
        val fixedVersion: String? = null,
        val maxVersion: String? = null,
        val cvss: Double = 0.0,
        val cvssVector: String? = null,
        val published: String? = null,
        val references: List<String>? = null,
        val cwe: String? = null,
        val knownExploited: Boolean = false,
        val source: String? = null
    ) {
        fun toModel(): CveEntry? {
            val i = id?.takeIf { it.length >= 8 } ?: return null
            val comp = component?.takeIf { it.isNotBlank() } ?: return null
            return CveEntry(
                id = i,
                summary = summary.orEmpty(),
                component = comp,
                aliases = aliases.orEmpty(),
                minVersion = minVersion,
                fixedVersion = fixedVersion,
                maxVersion = maxVersion,
                cvss = cvss.coerceIn(0.0, 10.0),
                cvssVector = cvssVector,
                published = published,
                references = references.orEmpty(),
                cwe = cwe,
                knownExploited = knownExploited,
                source = source ?: "AegisGuard CVE"
            )
        }
    }
}