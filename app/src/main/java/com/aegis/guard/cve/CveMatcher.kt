package com.aegis.guard.cve

import android.content.pm.PackageInfo
import com.aegis.guard.data.model.AppInfo
import com.aegis.guard.data.model.CveEntry
import com.aegis.guard.data.model.CveMatch

/**
 * 版本号比较器。
 *
 * 为什么不能直接用字符串比较：`1.10` > `1.9` 但字符串比较会给出相反结果。
 * 这里实现的是**宽松的 Maven 风格**比较：
 *
 * - 按 `.`、`-`、`_` 切分为数字段与字母段；
 * - 数字段按数值比较，字母段按字典序；
 * - 数字段 > 字母段（`1.0.0` > `1.0.0-RC1` 的常见语义）；
 * - 缺失段视为 0（因此 `1.3` == `1.3.0`）。
 *
 * 它不追求完全符合 SemVer 规范，而是要在"组件版本区间匹配"这个场景下
 * 给出符合直觉且不会误报的结果。
 */
object VersionComparator : Comparator<String> {

    override fun compare(a: String, b: String): Int {
        val pa = tokenize(a)
        val pb = tokenize(b)
        val n = maxOf(pa.size, pb.size)
        for (i in 0 until n) {
            val x = pa.getOrNull(i)
            val y = pb.getOrNull(i)
            val c = compareToken(x, y)
            if (c != 0) return c
        }
        return 0
    }

    private sealed interface Token {
        data class Num(val v: Long) : Token
        data class Word(val v: String) : Token
    }

    private fun tokenize(raw: String): List<Token> {
        val s = raw.trim().removePrefix("v").removePrefix("V")
        if (s.isEmpty()) return emptyList()
        val out = ArrayList<Token>(8)
        val cur = StringBuilder(8)
        var numeric = false

        fun flush() {
            if (cur.isEmpty()) return
            val text = cur.toString()
            cur.setLength(0)
            if (numeric) {
                out += Token.Num(text.toLongOrNull() ?: 0L)
            } else {
                out += Token.Word(text.lowercase())
            }
        }

        for (ch in s) {
            when {
                ch.isDigit() -> {
                    if (!numeric) {
                        flush()
                        numeric = true
                    }
                    cur.append(ch)
                }
                ch == '.' || ch == '-' || ch == '_' || ch == '+' -> {
                    flush()
                    numeric = false
                }
                else -> {
                    if (numeric) {
                        flush()
                        numeric = false
                    }
                    cur.append(ch)
                }
            }
        }
        flush()
        return out
    }

    private fun compareToken(a: Token?, b: Token?): Int {
        // 缺失段等价于 0 / 空串
        val x = a ?: Token.Num(0L)
        val y = b ?: Token.Num(0L)
        return when {
            x is Token.Num && y is Token.Num -> x.v.compareTo(y.v)
            // 数字 > 字母：让 1.0.0 视为高于 1.0.0-rc
            x is Token.Num -> 1
            y is Token.Num -> -1
            else -> (x as Token.Word).v.compareTo((y as Token.Word).v)
        }
    }

    /** 便捷函数：a < b */
    fun lessThan(a: String, b: String): Boolean = compare(a, b) < 0
}

/**
 * CVE 匹配引擎。
 *
 * 定位说明（重要）：本引擎做的是**已打包组件的版本区间比对**，
 * 即"这个应用内嵌了受影响版本的某开源库/组件"。
 * 它无法、也不声称能够验证系统内核或固件的实际补丁状态——
 * 那需要 root 读取内核与分区信息，超出普通应用的能力边界。
 *
 * 匹配流程：
 * 1. 从应用信息与 APK 文本中收集"组件 → 版本"候选对；
 * 2. 对每个候选遍历 CVE 表，用别名宽松匹配组件名；
 * 3. 命中区间 [minVersion, fixedVersion) 即视为受影响。
 */
class CveMatcher(private val entries: List<CveEntry>) {

    val size: Int get() = entries.size

    /**
     * 一个被检测到的组件版本。
     *
     * @param name 组件名（包名 / 库名 / 别名）
     * @param version 检测到的版本号
     * @param evidence 该结论是怎么得出的，直接展示给用户
     */
    data class DetectedComponent(
        val name: String,
        val version: String,
        val evidence: String
    )

    /**
     * 把已安装应用转换成待匹配的组件列表。
     *
     * 数据来源（全部为本地可读的公开元数据）：
     * - 应用自身版本号：可命中 android.framework / android.system 这类
     *   以 Android 版本为区间的条目，方式是比对 targetSdk；
     * - APK 文本中提取的依赖坐标：形如 `com.squareup.okhttp3:okhttp:4.9.0`
     *   这类字符串在构建产物中很常见（BuildConfig、资源、清单 meta-data），
     *   可以高置信度地还原出依赖版本。
     */
    fun componentsOf(app: AppInfo, apkText: String?): List<DetectedComponent> {
        val out = ArrayList<DetectedComponent>(16)

        // -- 1) 依赖坐标（最高置信度） --
        if (!apkText.isNullOrEmpty()) {
            out += extractMavenCoordinates(apkText)
            out += extractNamedVersions(apkText)
        }

        // -- 2) 从应用元数据推导系统组件版本 --
        out += DetectedComponent(
            name = "android.framework",
            version = app.targetSdk.toString(),
            evidence = "由应用 targetSdk=${app.targetSdk} 推导系统 Framework 能力级别"
        )
        out += DetectedComponent(
            name = "android.system",
            version = app.targetSdk.toString(),
            evidence = "由应用 targetSdk=${app.targetSdk} 推导"
        )

        // 去重：同名组件可能来自多个来源，保留置信度最高（先加入）的一个
        return out.distinctBy { it.name.lowercase() to it.version }
    }

    /**
     * 从文本中提取 Maven/Gradle 依赖坐标。
     *
     * 形如：
     *   com.squareup.okhttp3:okhttp:4.9.0
     *   androidx.core:core-ktx:1.13.1
     *   org.apache.logging.log4j:log4j-core-2.14.1
     */
    fun extractMavenCoordinates(text: String): List<DetectedComponent> {
        val out = ArrayList<DetectedComponent>(8)
        var m = MAVEN_COORD.matcher(text)
        var guard = 0
        while (m.find() && guard++ < 200) {
            val group = m.group(1) ?: continue
            val artifact = m.group(2) ?: continue
            val version = m.group(3) ?: continue
            if (version.isEmpty() || !version.any { it.isDigit() }) continue
            out += DetectedComponent(
                name = "$group:$artifact",
                version = version,
                evidence = "从应用构建产物中提取到依赖坐标 $group:$artifact:$version"
            )
        }
        return out
    }

    /**
     * 提取"库名 + 版本"形式的字符串，覆盖那些不以 Maven 坐标出现的库。
     *
     * 形如：libwebp 1.3.0 / okhttp/4.9.3 / zstd-1.5.5
     */
    fun extractNamedVersions(text: String): List<DetectedComponent> {
        val out = ArrayList<DetectedComponent>(8)
        var m = NAMED_VERSION.matcher(text)
        var guard = 0
        while (m.find() && guard++ < 300) {
            val name = m.group(1)?.lowercase() ?: continue
            val version = m.group(2) ?: continue
            if (name.length < 3 || name.length > 40) continue
            if (!version.any { it.isDigit() }) continue
            out += DetectedComponent(
                name = name,
                version = version,
                evidence = "在应用中检测到组件标识 $name $version"
            )
        }
        return out
    }

    /**
     * 主干匹配：给定组件与版本，返回所有受影响的 CVE。
     */
    fun match(component: DetectedComponent, packageName: String?, appLabel: String?): List<CveMatch> {
        val out = ArrayList<CveMatch>(2)
        val name = component.name.lowercase()
        val simple = name.substringAfterLast(':').substringAfterLast('/').substringAfterLast('.')

        for (cve in entries) {
            if (!componentMatches(cve, name, simple)) continue
            if (!versionAffected(cve, component.version)) continue

            out += CveMatch(
                cve = cve,
                detectedVersion = component.version,
                packageName = packageName,
                appLabel = appLabel,
                reason = buildReason(cve, component)
            )
        }
        return out
    }

    /**
     * 组件名匹配。三级宽松度：
     * 1. 完全相等（CVE 的 component 与检测名一致）；
     * 2. CVE 的别名集合包含检测名；
     * 3. 检测名"包含"组件名（处理 `com.squareup.okhttp3:okhttp` 与 `okhttp` 的差异）。
     */
    private fun componentMatches(cve: CveEntry, fullName: String, simpleName: String): Boolean {
        val comp = cve.component.lowercase()
        if (comp == fullName || comp == simpleName) return true

        val compSimple = comp.substringAfterLast(':').substringAfterLast('.').lowercase()
        if (compSimple == simpleName) return true

        for (alias in cve.aliases) {
            val a = alias.lowercase()
            if (a == fullName || a == simpleName) return true
            if (a.length >= 4 && fullName.contains(a)) return true
        }
        // 反向包含：检测名比组件名更短时（例如把 okhttp 归到 okhttp3）
        if (simpleName.length >= 4 && compSimple.contains(simpleName)) return true
        return false
    }

    /**
     * 版本区间判定：受影响当且仅当
     *   (minVersion 为空 或 detected >= minVersion)
     *   且 (fixedVersion 为空 或 detected < fixedVersion)
     *   且 (maxVersion 为空 或 detected <= maxVersion)
     */
    fun versionAffected(cve: CveEntry, detected: String): Boolean {
        cve.minVersion?.let {
            if (VersionComparator.compare(detected, it) < 0) return false
        }
        cve.fixedVersion?.let {
            // 已修复版本本身是安全的
            if (VersionComparator.compare(detected, it) >= 0) return false
        }
        cve.maxVersion?.let {
            if (VersionComparator.compare(detected, it) > 0) return false
        }
        return true
    }

    private fun buildReason(cve: CveEntry, c: DetectedComponent): String = buildString {
        append("检测到组件 ")
        append(c.name)
        append(" 版本 ")
        append(c.version)
        append("，落在受影响区间 ")
        val lower = cve.minVersion
        val upper = cve.fixedVersion
        when {
            lower != null && upper != null -> append("[$lower, $upper)")
            lower != null -> append(">= $lower")
            upper != null -> append("< $upper")
            else -> append("（全部版本）")
        }
        if (cve.knownExploited) append("；该漏洞已被证实存在在野利用")
    }

    companion object {
        /**
         * Maven 坐标：group:artifact:version
         * group 允许 `com.example` 或 `com.example.sub`；
         * version 允许 `1.2.3`、`1.2.3-rc1`、`1.2.3.RELEASE` 等形式。
         */
        private val MAVEN_COORD = Regex(
            """([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+){1,5})""" +
                """[:/]([a-zA-Z][a-zA-Z0-9_.\-]{1,40})""" +
                """[:@](\d[\w.\-]*)"""
        ).toPattern()

        /**
         * 名称 + 版本：`libwebp 1.3.0`、`okhttp/4.9.3`、`zstd-1.5.5`
         */
        private val NAMED_VERSION = Regex(
            """\b([a-z][a-z0-9_]{2,30})[\s/\-](\d+(?:\.\d+){1,3}(?:[-.][a-zA-Z0-9]+)?)\b""",
            RegexOption.IGNORE_CASE
        ).toPattern()
    }
}
